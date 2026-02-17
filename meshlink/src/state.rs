use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A 32-byte X25519 public key used as peer identity.
pub type PeerPublicKey = [u8; 32];

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: PeerPublicKey,
    pub endpoint: Option<SocketAddr>,
    pub virtual_ip: std::net::Ipv4Addr,
    pub allowed_ips: Vec<ipnet::Ipv4Net>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Packet with routing metadata, passed between tasks via channels.
#[derive(Debug)]
pub struct RoutedPacket {
    pub data: Vec<u8>,
    pub peer_endpoint: SocketAddr,
}

/// Shared state accessible by all tasks. Uses RwLock for the peer/route tables
/// which are read-heavy. The hot-path packet pipeline uses channels, not locks.
#[derive(Clone)]
pub struct SharedState {
    /// Peer table: public_key -> PeerInfo
    pub peers: Arc<RwLock<HashMap<PeerPublicKey, PeerInfo>>>,
    /// Route table: virtual_ip -> public_key (for fast outbound lookup)
    pub routes: Arc<RwLock<HashMap<std::net::Ipv4Addr, PeerPublicKey>>>,
    /// Our detected public IP (from NAT detection), used for same-NAT peer detection.
    pub our_public_ip: Arc<RwLock<Option<IpAddr>>>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
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
        // Add routes for all allowed IPs (using the network host address)
        {
            let mut routes = self.routes.write().await;
            for net in &info.allowed_ips {
                // For /32 routes, use the addr directly; for subnets, map the network
                routes.insert(net.addr(), pub_key);
            }
        }
        self.peers.write().await.insert(pub_key, info);
    }

    /// Look up which peer owns a given destination virtual IP.
    pub async fn lookup_route(&self, dest_ip: std::net::Ipv4Addr) -> Option<PeerPublicKey> {
        self.routes.read().await.get(&dest_ip).copied()
    }

    /// Get a peer's info by public key.
    pub async fn get_peer(&self, key: &PeerPublicKey) -> Option<PeerInfo> {
        self.peers.read().await.get(key).cloned()
    }

    /// Update a peer's endpoint address.
    pub async fn set_peer_endpoint(&self, key: &PeerPublicKey, endpoint: SocketAddr) {
        if let Some(peer) = self.peers.write().await.get_mut(key) {
            peer.endpoint = Some(endpoint);
        }
    }

    /// Increment TX stats for a peer.
    pub async fn add_tx_bytes(&self, key: &PeerPublicKey, n: u64) {
        if let Some(peer) = self.peers.write().await.get_mut(key) {
            peer.tx_bytes += n;
        }
    }

    /// Increment RX stats for a peer.
    pub async fn add_rx_bytes(&self, key: &PeerPublicKey, n: u64) {
        if let Some(peer) = self.peers.write().await.get_mut(key) {
            peer.rx_bytes += n;
        }
    }

    /// Remove a peer by public key and clean up its routes.
    pub async fn remove_peer(&self, key: &PeerPublicKey) {
        if let Some(peer) = self.peers.write().await.remove(key) {
            let mut routes = self.routes.write().await;
            for net in &peer.allowed_ips {
                routes.remove(&net.addr());
            }
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
