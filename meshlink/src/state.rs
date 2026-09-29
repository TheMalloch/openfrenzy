use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A 32-byte X25519 public key used as peer identity.
pub type PeerPublicKey = [u8; 32];

/// Per-peer traffic counters. Shared by `Arc` so the packet path can bump
/// them without taking the peer-table write lock.
#[derive(Debug, Default)]
pub struct PeerStats {
    tx: AtomicU64,
    rx: AtomicU64,
}

impl PeerStats {
    pub fn add_tx(&self, n: u64) {
        self.tx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_rx(&self, n: u64) {
        self.rx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: PeerPublicKey,
    pub endpoint: Option<SocketAddr>,
    pub virtual_ip: Ipv4Addr,
    pub allowed_ips: Vec<ipnet::Ipv4Net>,
    /// Configured by hand (`static = true` in config); never removed because
    /// the coordination server does not list it.
    pub static_peer: bool,
    pub stats: Arc<PeerStats>,
}

impl PeerInfo {
    pub fn new(
        public_key: PeerPublicKey,
        endpoint: Option<SocketAddr>,
        virtual_ip: Ipv4Addr,
        allowed_ips: Vec<ipnet::Ipv4Net>,
    ) -> Self {
        Self {
            public_key,
            endpoint,
            virtual_ip,
            allowed_ips,
            static_peer: false,
            stats: Arc::default(),
        }
    }

    pub fn tx_bytes(&self) -> u64 {
        self.stats.tx()
    }

    pub fn rx_bytes(&self) -> u64 {
        self.stats.rx()
    }
}

/// Packet with routing metadata, passed between tasks via channels.
#[derive(Debug)]
pub struct RoutedPacket {
    pub data: Vec<u8>,
    pub peer_endpoint: SocketAddr,
}

/// Result of attributing an inbound packet to a peer.
pub enum InboundVerdict {
    /// No peer has this endpoint.
    UnknownEndpoint,
    /// The peer exists but the inner source IP is outside its allowed_ips.
    SourceNotAllowed,
    Accept(Arc<PeerStats>),
}

/// Shared state accessible by all tasks. Uses RwLock for the peer/route tables
/// which are read-heavy. The hot-path packet pipeline uses channels, not locks.
///
/// Lock order when more than one is held: peers → routes → endpoints.
#[derive(Clone)]
pub struct SharedState {
    /// Peer table: public_key -> PeerInfo
    pub peers: Arc<RwLock<HashMap<PeerPublicKey, PeerInfo>>>,
    /// Route table: virtual_ip -> public_key (for fast outbound lookup)
    pub routes: Arc<RwLock<HashMap<Ipv4Addr, PeerPublicKey>>>,
    /// Endpoint index: endpoint -> public_key (for fast inbound attribution)
    endpoints: Arc<RwLock<HashMap<SocketAddr, PeerPublicKey>>>,
    /// Our detected public IP (from NAT detection), used for same-NAT peer detection.
    pub our_public_ip: Arc<RwLock<Option<IpAddr>>>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            our_public_ip: Arc::new(RwLock::new(None)),
        }
    }

    /// Store our detected public IP address.
    pub async fn set_our_public_ip(&self, ip: IpAddr) {
        *self.our_public_ip.write().await = Some(ip);
    }

    /// Get our detected public IP address.
    pub async fn get_our_public_ip(&self) -> Option<IpAddr> {
        *self.our_public_ip.read().await
    }

    /// Register a peer and update the route table for their allowed IPs.
    pub async fn add_peer(&self, info: PeerInfo) {
        let pub_key = info.public_key;
        let mut peers = self.peers.write().await;
        let mut routes = self.routes.write().await;
        let mut endpoints = self.endpoints.write().await;

        if let Some(old) = peers.remove(&pub_key) {
            Self::unindex(&old, &mut routes, &mut endpoints);
        }
        for net in &info.allowed_ips {
            // For /32 routes, use the addr directly; for subnets, map the network
            routes.insert(net.addr(), pub_key);
        }
        if let Some(ep) = info.endpoint {
            endpoints.insert(ep, pub_key);
        }
        peers.insert(pub_key, info);
    }

    /// Remove a peer's routes and endpoint index entries, but only where they
    /// still point at that peer (another peer may have taken them over).
    fn unindex(
        peer: &PeerInfo,
        routes: &mut HashMap<Ipv4Addr, PeerPublicKey>,
        endpoints: &mut HashMap<SocketAddr, PeerPublicKey>,
    ) {
        for net in &peer.allowed_ips {
            if routes.get(&net.addr()) == Some(&peer.public_key) {
                routes.remove(&net.addr());
            }
        }
        if let Some(ep) = peer.endpoint {
            if endpoints.get(&ep) == Some(&peer.public_key) {
                endpoints.remove(&ep);
            }
        }
    }

    /// Look up which peer owns a given destination virtual IP.
    pub async fn lookup_route(&self, dest_ip: Ipv4Addr) -> Option<PeerPublicKey> {
        self.routes.read().await.get(&dest_ip).copied()
    }

    /// Resolve an outbound destination to the owning peer's endpoint and
    /// counters, without cloning the peer entry.
    pub async fn outbound_target(
        &self,
        dest_ip: Ipv4Addr,
    ) -> Option<(PeerPublicKey, Option<SocketAddr>, Arc<PeerStats>)> {
        let key = self.lookup_route(dest_ip).await?;
        let peers = self.peers.read().await;
        let peer = peers.get(&key)?;
        Some((key, peer.endpoint, peer.stats.clone()))
    }

    /// Attribute an inbound packet from `src` whose inner IPv4 source is
    /// `inner_src` (None for non-IPv4 payloads, which are not filtered here).
    pub async fn inbound_verdict(
        &self,
        src: SocketAddr,
        inner_src: Option<Ipv4Addr>,
    ) -> InboundVerdict {
        let Some(key) = self.endpoints.read().await.get(&src).copied() else {
            return InboundVerdict::UnknownEndpoint;
        };
        let peers = self.peers.read().await;
        let Some(peer) = peers.get(&key) else {
            return InboundVerdict::UnknownEndpoint;
        };
        if let Some(ip) = inner_src {
            if !peer.allowed_ips.iter().any(|net| net.contains(&ip)) {
                return InboundVerdict::SourceNotAllowed;
            }
        }
        InboundVerdict::Accept(peer.stats.clone())
    }

    /// Get a peer's info by public key.
    pub async fn get_peer(&self, key: &PeerPublicKey) -> Option<PeerInfo> {
        self.peers.read().await.get(key).cloned()
    }

    /// Update a peer's endpoint address.
    pub async fn set_peer_endpoint(&self, key: &PeerPublicKey, endpoint: SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(key) {
            let mut endpoints = self.endpoints.write().await;
            if let Some(old) = peer.endpoint {
                if endpoints.get(&old) == Some(key) {
                    endpoints.remove(&old);
                }
            }
            endpoints.insert(endpoint, *key);
            peer.endpoint = Some(endpoint);
        }
    }

    /// Remove a peer by public key and clean up its routes.
    pub async fn remove_peer(&self, key: &PeerPublicKey) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.remove(key) {
            let mut routes = self.routes.write().await;
            let mut endpoints = self.endpoints.write().await;
            Self::unindex(&peer, &mut routes, &mut endpoints);
        }
    }
}

/// Channel endpoints for the packet pipeline. Created once, endpoints moved into tasks.
pub struct PipelineChannels {
    // TUN reader -> router (outbound raw packets)
    pub tun_to_router_tx: mpsc::Sender<Vec<u8>>,
    pub tun_to_router_rx: mpsc::Receiver<Vec<u8>>,

    // Router -> UDP writer (outbound wrapped)
    pub router_to_udp_tx: mpsc::Sender<RoutedPacket>,
    pub router_to_udp_rx: mpsc::Receiver<RoutedPacket>,

    // UDP reader -> router (inbound)
    pub udp_to_router_tx: mpsc::Sender<RoutedPacket>,
    pub udp_to_router_rx: mpsc::Receiver<RoutedPacket>,

    // Router -> TUN writer (inbound unwrapped)
    pub router_to_tun_tx: mpsc::Sender<Vec<u8>>,
    pub router_to_tun_rx: mpsc::Receiver<Vec<u8>>,
}

impl PipelineChannels {
    pub fn new(buffer_size: usize) -> Self {
        let (tun_to_router_tx, tun_to_router_rx) = mpsc::channel(buffer_size);
        let (router_to_udp_tx, router_to_udp_rx) = mpsc::channel(buffer_size);
        let (udp_to_router_tx, udp_to_router_rx) = mpsc::channel(buffer_size);
        let (router_to_tun_tx, router_to_tun_rx) = mpsc::channel(buffer_size);

        Self {
            tun_to_router_tx,
            tun_to_router_rx,
            router_to_udp_tx,
            router_to_udp_rx,
            udp_to_router_tx,
            udp_to_router_rx,
            router_to_tun_tx,
            router_to_tun_rx,
        }
    }
}
