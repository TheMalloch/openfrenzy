use super::db;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
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
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub last_seen: Instant,
    pub virtual_ip: Option<std::net::Ipv4Addr>,
    pub lan_ip: Option<std::net::Ipv4Addr>,
}

/// Shared peer map type used across UDP server and stale checker.
pub type PeerMap = Arc<Mutex<HashMap<[u8; 32], RegisteredPeer>>>;

/// Protocol constants (must match meshlink client).
mod proto {
    pub const REGISTER: u8 = 0x30;
    pub const PEER_LIST_REQ: u8 = 0x31;
    pub const PEER_LIST_RESP: u8 = 0x32;
    pub const KEEPALIVE: u8 = 0x33;
}

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

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if n == 0 {
                            continue;
                        }
                        let src = normalize_addr(src);
                        handle_message(&socket, &peers, &database, &buf[..n], src).await;
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

/// Broadcast a personalized PEER_LIST_RESP to every connected peer.
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

    let peer_map = peers.lock().await;
    let endpoints: Vec<([u8; 32], SocketAddr)> = peer_map
        .values()
        .map(|p| (p.public_key, p.endpoint))
        .collect();
    drop(peer_map);

    for (requester_key, endpoint) in &endpoints {
        let resp = build_peer_list_response(requester_key, &db_nodes, peers).await;
        if let Err(e) = socket.send_to(&resp, endpoint).await {
            warn!(error = %e, %endpoint, "failed to send broadcast peer list");
        }
    }

    debug!(peer_count = endpoints.len(), "broadcast peer list to all peers");
}

/// Build a PEER_LIST_RESP message for a specific requester, excluding them from the list.
async fn build_peer_list_response(
    requester_key: &[u8; 32],
    db_nodes: &[db::NodeRecord],
    peers: &PeerMap,
) -> Vec<u8> {
    let peer_map = peers.lock().await;

    let other_nodes: Vec<&db::NodeRecord> = db_nodes
        .iter()
        .filter(|n| n.public_key.as_slice() != requester_key.as_slice())
        .collect();

    let count = other_nodes.len().min(u16::MAX as usize);
    let mut resp = Vec::with_capacity(3 + count * (32 + 4 + 1 + 16 + 2));

    resp.push(proto::PEER_LIST_RESP);
    resp.extend_from_slice(&(count as u16).to_be_bytes());

    for node in other_nodes.iter().take(count) {
        // Public key (32 bytes)
        if node.public_key.len() != 32 {
            continue;
        }
        resp.extend_from_slice(&node.public_key);

        // Virtual IP (4 bytes)
        let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
        let vip: std::net::Ipv4Addr = ip_str.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        resp.extend_from_slice(&vip.octets());

        // Endpoint: prefer live UDP endpoint, fall back to DB endpoint
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&node.public_key);
        let endpoint: Option<SocketAddr> = peer_map
            .get(&pub_key)
            .map(|p| p.endpoint)
            .or_else(|| node.endpoint.as_ref().and_then(|ep| ep.parse().ok()))
            .map(normalize_addr);

        if let Some(ep) = endpoint {
            match ep.ip() {
                std::net::IpAddr::V4(ip) => {
                    resp.push(0x04);
                    resp.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    resp.push(0x06);
                    resp.extend_from_slice(&ip.octets());
                }
            }
            resp.extend_from_slice(&ep.port().to_be_bytes());
        } else {
            // No endpoint known — use IPv4 0.0.0.0:0
            resp.push(0x04);
            resp.extend_from_slice(&[0, 0, 0, 0]);
            resp.extend_from_slice(&0u16.to_be_bytes());
        }

        // Append LAN IP (4 bytes) + LAN port (2 bytes): prefer in-memory, fall back to DB
        let (lan_ip, lan_port) = peer_map
            .get(&pub_key)
            .and_then(|p| p.lan_ip.map(|ip| (ip, p.listen_port)))
            .or_else(|| {
                node.lan_endpoint.as_ref().and_then(|ep| {
                    // lan_endpoint is stored as "ip:port"
                    let parts: Vec<&str> = ep.splitn(2, ':').collect();
                    let ip = parts.first()?.parse::<std::net::Ipv4Addr>().ok()?;
                    let port = parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(node.listen_port as u16);
                    Some((ip, port))
                })
            })
            .unwrap_or((std::net::Ipv4Addr::UNSPECIFIED, 0));
        resp.extend_from_slice(&lan_ip.octets());
        resp.extend_from_slice(&lan_port.to_be_bytes());
    }

    resp
}

/// Parse optional LAN IPs from the tail of a message.
/// Format: [lan_count:1][lan_ip_0:4]...[lan_ip_n:4]
/// Returns the first non-loopback, non-link-local LAN IP found.
fn parse_lan_ips(data: &[u8], offset: usize) -> Option<std::net::Ipv4Addr> {
    if offset >= data.len() {
        return None;
    }
    let count = data[offset] as usize;
    let mut pos = offset + 1;
    for _ in 0..count {
        if pos + 4 > data.len() {
            break;
        }
        let ip = std::net::Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;
        if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
            return Some(ip);
        }
    }
    None
}

async fn handle_message(
    socket: &UdpSocket,
    peers: &PeerMap,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    match data[0] {
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

    // Parse optional LAN IPs from extended register message (byte 35+)
    let lan_ip = parse_lan_ips(data, 35);

    let is_new = {
        let map = peers.lock().await;
        !map.contains_key(&public_key)
    };

    // Look up virtual_ip from database for this public key
    let virtual_ip = match database.get_node_by_pubkey(&public_key).await {
        Ok(Some(node)) => {
            let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
            ip_str.parse::<std::net::Ipv4Addr>().ok()
        }
        _ => None,
    };

    {
        let mut map = peers.lock().await;
        map.insert(
            public_key,
            RegisteredPeer {
                public_key,
                endpoint: src,
                listen_port,
                last_seen: Instant::now(),
                virtual_ip,
                lan_ip,
            },
        );
    }

    // Persist endpoint to the database so config endpoints return it.
    // Skip loopback addresses.
    let is_loopback = src.ip().is_loopback();
    if !is_loopback {
        let endpoint_str = src.to_string();
        match database
            .update_endpoint_by_pubkey(&public_key, &endpoint_str)
            .await
        {
            Ok(true) => {
                debug!(%src, %endpoint_str, "persisted endpoint to database");
            }
            Ok(false) => {
                debug!(%src, "UDP register: no matching node in database for this public key");
            }
            Err(e) => {
                warn!(error = %e, %src, "failed to persist endpoint to database");
            }
        }

        // If the source is IPv6 (non-mapped), also store as ipv6_endpoint
        if src.is_ipv6() {
            let ipv6_str = src.to_string();
            if let Err(e) = database.update_ipv6_endpoint_by_pubkey(&public_key, &ipv6_str).await {
                warn!(error = %e, %src, "failed to persist IPv6 endpoint");
            }
        }
    } else {
        debug!(%src, "skipping DB endpoint update for loopback address");
    }

    // Persist LAN endpoint to database
    if let Some(lip) = lan_ip {
        let lan_str = format!("{}:{}", lip, listen_port);
        if let Err(e) = database.update_lan_endpoint_by_pubkey(&public_key, Some(&lan_str)).await {
            warn!(error = %e, %src, "failed to persist LAN endpoint");
        }
    }

    if is_new {
        info!(%src, listen_port, ?lan_ip, "new peer registered");
        // Broadcast updated peer list to all connected peers
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

    // Query ALL active nodes from DB (not just UDP-registered ones)
    let db_nodes = match database.list_active_nodes().await {
        Ok(nodes) => nodes,
        Err(e) => {
            warn!(error = %e, "failed to query nodes from database for peer list");
            return;
        }
    };

    let resp = build_peer_list_response(&requester_key, &db_nodes, peers).await;

    let count = u16::from_be_bytes([resp[1], resp[2]]);
    debug!(%src, count, "sending peer list");
    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send peer list");
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

    // Parse optional LAN IPs from extended keepalive (byte 33+)
    let lan_ip = parse_lan_ips(data, 33);

    let mut should_broadcast = false;

    {
        let mut map = peers.lock().await;
        if let Some(peer) = map.get_mut(&public_key) {
            peer.last_seen = Instant::now();
            peer.endpoint = src;
            peer.lan_ip = lan_ip.or(peer.lan_ip);
            debug!(%src, ?lan_ip, "keepalive received");
        } else {
            // After server restart, in-memory map is empty. Re-register the peer.
            let virtual_ip = match database.get_node_by_pubkey(&public_key).await {
                Ok(Some(node)) => {
                    let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
                    ip_str.parse::<std::net::Ipv4Addr>().ok()
                }
                _ => None,
            };
            map.insert(
                public_key,
                RegisteredPeer {
                    public_key,
                    endpoint: src,
                    listen_port: src.port(),
                    last_seen: Instant::now(),
                    virtual_ip,
                    lan_ip,
                },
            );
            info!(%src, "re-registered peer from keepalive");
            should_broadcast = true;
        }
    }

    if should_broadcast {
        broadcast_peer_list(socket, peers, database).await;
    }

    // Persist endpoint to database
    let endpoint_str = src.to_string();
    if let Err(e) = database
        .update_endpoint_by_pubkey(&public_key, &endpoint_str)
        .await
    {
        warn!(error = %e, %src, "failed to persist keepalive endpoint to database");
    }

    // Persist LAN endpoint to database if provided
    if let Some(lip) = lan_ip {
        let listen_port = {
            let map = peers.lock().await;
            map.get(&public_key).map(|p| p.listen_port).unwrap_or(src.port())
        };
        let lan_str = format!("{}:{}", lip, listen_port);
        if let Err(e) = database.update_lan_endpoint_by_pubkey(&public_key, Some(&lan_str)).await {
            warn!(error = %e, %src, "failed to persist keepalive LAN endpoint");
        }
    }
}
