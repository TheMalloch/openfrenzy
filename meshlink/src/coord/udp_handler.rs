use super::db;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};

/// Convert IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4.
fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

/// A registered peer on the coordination server (in-memory UDP registry).
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub public_key: [u8; 32],
    /// Source address of the most recent message (where replies go).
    pub endpoint: SocketAddr,
    /// Most recent IPv4 source address. Advertised to other peers in
    /// preference to an IPv6 `endpoint`, which many peers cannot reach.
    pub v4_endpoint: Option<SocketAddr>,
    pub listen_port: u16,
    pub last_seen: Instant,
    pub virtual_ip: Option<Ipv4Addr>,
    pub lan_ip: Option<Ipv4Addr>,
    /// Peer understands chunked peer lists (`PEER_LIST_CHUNK`).
    pub chunked: bool,
}

impl RegisteredPeer {
    pub fn new(public_key: [u8; 32], src: SocketAddr, listen_port: u16) -> Self {
        Self {
            public_key,
            endpoint: src,
            v4_endpoint: src.is_ipv4().then_some(src),
            listen_port,
            last_seen: Instant::now(),
            virtual_ip: None,
            lan_ip: None,
            chunked: false,
        }
    }

    /// Record a message from `src`.
    pub fn seen_from(&mut self, src: SocketAddr) {
        self.endpoint = src;
        if src.is_ipv4() {
            self.v4_endpoint = Some(src);
        }
        self.last_seen = Instant::now();
    }
}

/// Shared peer map type used across UDP server and stale checker.
pub type PeerMap = Arc<Mutex<HashMap<[u8; 32], RegisteredPeer>>>;

/// Protocol constants (must match meshlink client).
mod proto {
    pub const NAT_DETECT_REQ: u8 = 0x10;
    pub const NAT_DETECT_RESP: u8 = 0x11;
    pub const REGISTER: u8 = 0x30;
    pub const PEER_LIST_REQ: u8 = 0x31;
    pub const PEER_LIST_RESP: u8 = 0x32;
    pub const KEEPALIVE: u8 = 0x33;
    /// Chunked peer list: [0x34][list_id:2][idx:1][total:1][count:2](entries)*
    pub const PEER_LIST_CHUNK: u8 = 0x34;

    /// Capability flag (trailing byte of REGISTER/KEEPALIVE): chunked peer lists.
    pub const CAP_CHUNKED: u8 = 0x01;
}

/// Keep each datagram under a typical path MTU so it is never IP-fragmented.
const MAX_DATAGRAM: usize = 1400;

/// Upper bound on concurrently handled coordination messages. Excess packets
/// are dropped rather than queued, so a flood cannot build unbounded work.
const MAX_IN_FLIGHT: usize = 256;

/// Run the UDP coordination server event loop.
pub async fn run_udp_server(
    socket: Arc<UdpSocket>,
    peers: PeerMap,
    database: db::Db,
    stale_timeout_secs: u64,
    cleanup_interval_secs: u64,
) -> Result<()> {
    info!("UDP coordination server started");

    let mut buf = vec![0u8; 4096];
    let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs));
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if n == 0 {
                            continue;
                        }
                        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
                            debug!(%src, "coordination server busy, dropping message");
                            continue;
                        };
                        let src = normalize_addr(src);
                        let data = buf[..n].to_vec();
                        let socket = socket.clone();
                        let peers = peers.clone();
                        let database = database.clone();
                        // Handle off the receive loop: one slow DB query must
                        // not stall every other peer's keepalives.
                        tokio::spawn(async move {
                            handle_message(&socket, &peers, &database, &data, src).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "recv error");
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let mut map = peers.lock().await;
                let before = map.len();
                let cutoff = Instant::now() - std::time::Duration::from_secs(stale_timeout_secs);
                map.retain(|_, p| p.last_seen > cutoff);
                let removed = before - map.len();
                if removed > 0 {
                    info!(removed, remaining = map.len(), "cleaned stale UDP peers");
                }
            }
        }
    }
}

/// Background task: periodically mark stale nodes in the database and broadcast updated peer list.
pub async fn stale_node_checker(
    database: db::Db,
    socket: Arc<UdpSocket>,
    peers: PeerMap,
    stale_timeout_secs: u64,
    cleanup_interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs));
    loop {
        interval.tick().await;
        match database.mark_stale_nodes(stale_timeout_secs as i64).await {
            Ok(count) if count > 0 => {
                info!(count, "marked stale nodes in database");
                // Broadcast updated peer list to all connected peers
                broadcast_peer_list(&socket, &peers, &database).await;
            }
            Err(e) => {
                warn!(error = %e, "failed to mark stale nodes");
            }
            _ => {}
        }
    }
}

/// Broadcast a personalized peer list to every connected peer.
pub async fn broadcast_peer_list(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
) {
    let db_nodes = match database.list_active_nodes().await {
        Ok(nodes) => nodes,
        Err(e) => {
            warn!(error = %e, "failed to query nodes for broadcast");
            return;
        }
    };

    // Snapshot once; building every response from the same snapshot avoids
    // re-locking the map per recipient.
    let snapshot: HashMap<[u8; 32], RegisteredPeer> = peers.lock().await.clone();

    for peer in snapshot.values() {
        for datagram in build_peer_list_datagrams(&peer.public_key, &db_nodes, &snapshot, peer.chunked) {
            if let Err(e) = socket.send_to(&datagram, peer.endpoint).await {
                warn!(error = %e, endpoint = %peer.endpoint, "failed to send broadcast peer list");
            }
        }
    }

    debug!(peer_count = snapshot.len(), "broadcast peer list to all peers");
}

/// Encode one peer-list entry:
/// [pub_key:32][vip:4][addr_type:1][ip:4|16][port:2][lan_ip:4][lan_port:2]
fn encode_entry(
    out: &mut Vec<u8>,
    node: &db::NodeRecord,
    pub_key: &[u8; 32],
    live: Option<&RegisteredPeer>,
) {
    out.extend_from_slice(pub_key);

    let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
    let vip: Ipv4Addr = ip_str.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    out.extend_from_slice(&vip.octets());

    // Endpoint preference: live IPv4, stored IPv4, then live IPv6 as a last resort.
    let endpoint: Option<SocketAddr> = live
        .and_then(|p| p.v4_endpoint)
        .or_else(|| node.endpoint.as_ref().and_then(|ep| ep.parse().ok()))
        .or_else(|| live.map(|p| p.endpoint))
        .map(normalize_addr);

    match endpoint {
        Some(ep) => {
            match ep.ip() {
                IpAddr::V4(ip) => {
                    out.push(0x04);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(0x06);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&ep.port().to_be_bytes());
        }
        None => {
            // No endpoint known — use IPv4 0.0.0.0:0
            out.push(0x04);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    // LAN IP + port: prefer in-memory, fall back to DB ("ip:port")
    let (lan_ip, lan_port) = live
        .and_then(|p| p.lan_ip.map(|ip| (ip, p.listen_port)))
        .or_else(|| {
            node.lan_endpoint.as_deref().and_then(|ep| {
                let (ip, port) = ep.split_once(':').unwrap_or((ep, ""));
                let ip = ip.parse::<Ipv4Addr>().ok()?;
                let port = port.parse::<u16>().unwrap_or(node.listen_port as u16);
                Some((ip, port))
            })
        })
        .unwrap_or((Ipv4Addr::UNSPECIFIED, 0));
    out.extend_from_slice(&lan_ip.octets());
    out.extend_from_slice(&lan_port.to_be_bytes());
}

static NEXT_LIST_ID: AtomicU16 = AtomicU16::new(0);

/// Build the peer list for one requester (excluding itself).
///
/// Peers that advertised `CAP_CHUNKED` get `PEER_LIST_CHUNK` datagrams that
/// each fit in `MAX_DATAGRAM`; older peers get the single legacy
/// `PEER_LIST_RESP` datagram.
fn build_peer_list_datagrams(
    requester_key: &[u8; 32],
    db_nodes: &[db::NodeRecord],
    peer_map: &HashMap<[u8; 32], RegisteredPeer>,
    chunked: bool,
) -> Vec<Vec<u8>> {
    // Filter before counting so the header count always matches the entries.
    let entries: Vec<Vec<u8>> = db_nodes
        .iter()
        .filter_map(|n| <[u8; 32]>::try_from(n.public_key.as_slice()).ok().map(|k| (n, k)))
        .filter(|(_, k)| k != requester_key)
        .take(u16::MAX as usize)
        .map(|(node, key)| {
            let mut e = Vec::with_capacity(32 + 4 + 1 + 16 + 2 + 6);
            encode_entry(&mut e, node, &key, peer_map.get(&key));
            e
        })
        .collect();

    if !chunked {
        let mut resp = Vec::with_capacity(3 + entries.iter().map(Vec::len).sum::<usize>());
        resp.push(proto::PEER_LIST_RESP);
        resp.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for e in &entries {
            resp.extend_from_slice(e);
        }
        return vec![resp];
    }

    const HEADER: usize = 1 + 2 + 1 + 1 + 2;
    let mut groups: Vec<Vec<&Vec<u8>>> = vec![Vec::new()];
    let mut size = HEADER;
    for e in &entries {
        if size + e.len() > MAX_DATAGRAM && !groups.last().unwrap().is_empty() {
            groups.push(Vec::new());
            size = HEADER;
        }
        size += e.len();
        groups.last_mut().unwrap().push(e);
    }
    groups.truncate(u8::MAX as usize);

    let list_id = NEXT_LIST_ID.fetch_add(1, Ordering::Relaxed);
    let total = groups.len() as u8;
    groups
        .iter()
        .enumerate()
        .map(|(idx, group)| {
            let mut d = Vec::with_capacity(MAX_DATAGRAM);
            d.push(proto::PEER_LIST_CHUNK);
            d.extend_from_slice(&list_id.to_be_bytes());
            d.push(idx as u8);
            d.push(total);
            d.extend_from_slice(&(group.len() as u16).to_be_bytes());
            for e in group {
                d.extend_from_slice(e);
            }
            d
        })
        .collect()
}

/// Parse the optional tail of REGISTER / KEEPALIVE starting at `offset`:
/// `[lan_count:1][lan_ip:4]*[caps:1]`.
/// Returns the first usable LAN IP and the capability flags (0 if absent).
fn parse_tail(data: &[u8], offset: usize) -> (Option<Ipv4Addr>, u8) {
    if offset >= data.len() {
        return (None, 0);
    }
    let count = data[offset] as usize;
    let mut pos = offset + 1;
    let mut lan_ip = None;
    for _ in 0..count {
        if pos + 4 > data.len() {
            return (lan_ip, 0);
        }
        let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;
        if lan_ip.is_none() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
            lan_ip = Some(ip);
        }
    }
    (lan_ip, data.get(pos).copied().unwrap_or(0))
}

/// Look up a node that is allowed to take part in coordination: it must exist
/// in the database and not be deregistered (disabled).
async fn known_node(database: &db::Db, public_key: &[u8; 32]) -> Option<db::NodeRecord> {
    match database.get_node_by_pubkey(public_key).await {
        Ok(Some(node)) if node.status != "deregistered" => Some(node),
        Ok(_) => None,
        Err(e) => {
            warn!(error = %e, "failed to look up node by public key");
            None
        }
    }
}

fn node_vip(node: &db::NodeRecord) -> Option<Ipv4Addr> {
    node.virtual_ip.split('/').next().and_then(|s| s.parse().ok())
}

async fn handle_message(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    match data[0] {
        proto::NAT_DETECT_REQ => {
            handle_nat_detect(socket, src).await;
        }
        proto::REGISTER => {
            handle_register(socket, peers, database, data, src).await;
        }
        proto::PEER_LIST_REQ => {
            handle_peer_list_req(socket, peers, database, data, src).await;
        }
        proto::KEEPALIVE => {
            handle_keepalive(socket, peers, database, data, src).await;
        }
        t => {
            debug!(msg_type = t, %src, "unknown message type");
        }
    }
}

async fn handle_nat_detect(socket: &UdpSocket, src: SocketAddr) {
    debug!(%src, "NAT detection request");

    let mut resp = vec![proto::NAT_DETECT_RESP];
    match src.ip() {
        IpAddr::V4(ip) => {
            resp.push(0x04);
            resp.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            resp.push(0x06);
            resp.extend_from_slice(&ip.octets());
        }
    }
    resp.extend_from_slice(&src.port().to_be_bytes());

    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send NAT detect response");
    }
}

/// Persist a peer's current endpoints. IPv6 sources go to `ipv6_endpoint`
/// only, so they never replace the IPv4 endpoint other peers rely on.
async fn persist_endpoints(
    database: &db::Db,
    public_key: &[u8; 32],
    src: SocketAddr,
    lan: Option<(Ipv4Addr, u16)>,
) {
    if src.ip().is_loopback() {
        debug!(%src, "skipping DB endpoint update for loopback address");
    } else {
        let v4 = src.is_ipv4().then(|| src.to_string());
        if let Err(e) = database.update_endpoint_by_pubkey(public_key, v4.as_deref()).await {
            warn!(error = %e, %src, "failed to persist endpoint to database");
        }
        if src.is_ipv6() {
            if let Err(e) = database.update_ipv6_endpoint_by_pubkey(public_key, &src.to_string()).await {
                warn!(error = %e, %src, "failed to persist IPv6 endpoint");
            }
        }
    }

    if let Some((ip, port)) = lan {
        let lan_str = format!("{ip}:{port}");
        if let Err(e) = database.update_lan_endpoint_by_pubkey(public_key, Some(&lan_str)).await {
            warn!(error = %e, %src, "failed to persist LAN endpoint");
        }
    }
}

async fn handle_register(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    if data.len() < 35 {
        debug!(%src, "register message too short");
        return;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[1..33]);
    let listen_port = u16::from_be_bytes([data[33], data[34]]);
    let (lan_ip, caps) = parse_tail(data, 35);

    // Unknown or disabled keys get nothing: no map entry, no broadcast.
    let Some(node) = known_node(database, &public_key).await else {
        debug!(%src, "register from unknown or disabled key, ignoring");
        return;
    };

    let is_new = {
        let mut map = peers.lock().await;
        let is_new = !map.contains_key(&public_key);
        let entry = map
            .entry(public_key)
            .or_insert_with(|| RegisteredPeer::new(public_key, src, listen_port));
        entry.seen_from(src);
        entry.listen_port = listen_port;
        entry.virtual_ip = node_vip(&node);
        entry.lan_ip = lan_ip;
        entry.chunked = caps & proto::CAP_CHUNKED != 0;
        is_new
    };

    persist_endpoints(database, &public_key, src, lan_ip.map(|ip| (ip, listen_port))).await;

    if is_new {
        info!(%src, listen_port, ?lan_ip, "new peer registered");
        broadcast_peer_list(socket, peers, database).await;
    } else {
        debug!(%src, "peer re-registered");
    }
}

async fn handle_peer_list_req(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    if data.len() < 33 {
        debug!(%src, "peer list request too short");
        return;
    }

    let mut requester_key = [0u8; 32];
    requester_key.copy_from_slice(&data[1..33]);

    // Only answer a key that registered from this exact address. This stops
    // anonymous topology dumps and reflection off spoofed sources. It is not
    // authentication (REGISTER itself is unauthenticated until Phase 2).
    let chunked = {
        let map = peers.lock().await;
        match map.get(&requester_key) {
            Some(p) if p.endpoint == src => p.chunked,
            _ => {
                debug!(%src, "peer list request from unregistered key/address, ignoring");
                return;
            }
        }
    };

    let db_nodes = match database.list_active_nodes().await {
        Ok(nodes) => nodes,
        Err(e) => {
            warn!(error = %e, "failed to query nodes from database for peer list");
            return;
        }
    };

    let snapshot = peers.lock().await.clone();
    let datagrams = build_peer_list_datagrams(&requester_key, &db_nodes, &snapshot, chunked);
    debug!(%src, datagrams = datagrams.len(), "sending peer list");
    for d in datagrams {
        if let Err(e) = socket.send_to(&d, src).await {
            warn!(error = %e, "failed to send peer list");
        }
    }
}

async fn handle_keepalive(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    if data.len() < 33 {
        return;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[1..33]);
    let (lan_ip, caps) = parse_tail(data, 33);

    // Fast path: known peer, update in place without touching the DB first.
    let known_listen_port = {
        let mut map = peers.lock().await;
        map.get_mut(&public_key).map(|peer| {
            peer.seen_from(src);
            peer.lan_ip = lan_ip.or(peer.lan_ip);
            peer.chunked = caps & proto::CAP_CHUNKED != 0;
            debug!(%src, ?lan_ip, "keepalive received");
            peer.listen_port
        })
    };

    let listen_port = match known_listen_port {
        Some(port) => port,
        None => {
            // After a server restart the in-memory map is empty. Re-register
            // the peer, but only if the database knows it. The DB lookup runs
            // without holding the map lock.
            let Some(node) = known_node(database, &public_key).await else {
                debug!(%src, "keepalive from unknown or disabled key, ignoring");
                return;
            };
            // `src.port()` is the NAT mapping, not the listen port; prefer the
            // port recorded with the LAN endpoint, then the DB listen_port.
            let listen_port = node
                .lan_endpoint
                .as_deref()
                .and_then(|ep| ep.rsplit_once(':'))
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(node.listen_port as u16);
            let mut peer = RegisteredPeer::new(public_key, src, listen_port);
            peer.virtual_ip = node_vip(&node);
            peer.lan_ip = lan_ip;
            peer.chunked = caps & proto::CAP_CHUNKED != 0;
            peers.lock().await.insert(public_key, peer);
            info!(%src, "re-registered peer from keepalive");
            broadcast_peer_list(socket, peers, database).await;
            listen_port
        }
    };

    persist_endpoints(database, &public_key, src, lan_ip.map(|ip| (ip, listen_port))).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn node(key: u8, endpoint: Option<&str>) -> db::NodeRecord {
        db::NodeRecord {
            node_id: format!("node-{key}"),
            node_name: None,
            public_key: vec![key; 32],
            private_key_encrypted: vec![],
            virtual_ip: format!("10.0.0.{key}/24"),
            auth_token: format!("t{key}"),
            status: "active".into(),
            endpoint: endpoint.map(String::from),
            ipv6_endpoint: None,
            lan_endpoint: None,
            listen_port: 51820,
            last_heartbeat: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            port_range_start: None,
            port_range_size: None,
        }
    }

    #[test]
    fn legacy_count_matches_entries_and_skips_bad_keys() {
        let mut bad = node(9, None);
        bad.public_key = vec![1, 2, 3];
        let nodes = vec![node(1, Some("1.2.3.4:5")), bad, node(2, None), node(3, None)];
        let d = build_peer_list_datagrams(&[1; 32], &nodes, &HashMap::new(), false);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0][0], proto::PEER_LIST_RESP);
        assert_eq!(u16::from_be_bytes([d[0][1], d[0][2]]), 2);
        assert_eq!(d[0].len(), 3 + 2 * 49);
    }

    #[test]
    fn chunked_lists_fit_mtu_and_cover_all_entries() {
        let nodes: Vec<_> = (1..=200u8).map(|k| node(k, Some("1.2.3.4:5"))).collect();
        let d = build_peer_list_datagrams(&[0; 32], &nodes, &HashMap::new(), true);
        assert!(d.len() > 1);
        let total: usize = d
            .iter()
            .map(|c| {
                assert!(c.len() <= MAX_DATAGRAM);
                assert_eq!(c[0], proto::PEER_LIST_CHUNK);
                assert_eq!(c[4] as usize, d.len());
                u16::from_be_bytes([c[5], c[6]]) as usize
            })
            .sum();
        assert_eq!(total, 200);
        assert!(d.iter().all(|c| c[1..3] == d[0][1..3]), "one list id per list");
    }

    #[test]
    fn prefers_ipv4_over_live_ipv6() {
        let key = [7u8; 32];
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        let mut map = HashMap::new();
        map.insert(key, RegisteredPeer::new(key, v6, 51820));
        let nodes = vec![node(7, Some("5.6.7.8:9"))];
        let d = build_peer_list_datagrams(&[0; 32], &nodes, &map, false);
        // entry starts at 3: key(32) vip(4) type(1)
        assert_eq!(d[0][3 + 36], 0x04);
        assert_eq!(&d[0][3 + 37..3 + 41], &[5, 6, 7, 8]);
    }

    #[test]
    fn parse_tail_reads_lan_and_caps() {
        let mut m = vec![0u8; 35];
        m.extend_from_slice(&[2, 127, 0, 0, 1, 192, 168, 1, 5, proto::CAP_CHUNKED]);
        assert_eq!(parse_tail(&m, 35), (Some(Ipv4Addr::new(192, 168, 1, 5)), 1));
        assert_eq!(parse_tail(&m[..44], 35), (Some(Ipv4Addr::new(192, 168, 1, 5)), 0));
        assert_eq!(parse_tail(&m[..35], 35), (None, 0));
    }
}
