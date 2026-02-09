use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// A registered peer on the coordination server.
#[derive(Debug, Clone)]
struct RegisteredPeer {
    public_key: [u8; 32],
    endpoint: SocketAddr,
    listen_port: u16,
    last_seen: Instant,
}

/// Protocol constants (must match meshlink client).
mod proto {
    pub const NAT_DETECT_REQ: u8 = 0x10;
    pub const NAT_DETECT_RESP: u8 = 0x11;
    pub const REGISTER: u8 = 0x30;
    pub const PEER_LIST_REQ: u8 = 0x31;
    pub const PEER_LIST_RESP: u8 = 0x32;
    pub const KEEPALIVE: u8 = 0x33;
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("coord_server=info".parse().unwrap()),
        )
        .init();

    let listen_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:4000".to_string());

    let socket = UdpSocket::bind(&listen_addr)
        .await
        .with_context(|| format!("binding to {listen_addr}"))?;

    info!(%listen_addr, "coordination server started");

    // Peer table: public_key -> RegisteredPeer
    let mut peers: HashMap<[u8; 32], RegisteredPeer> = HashMap::new();
    let mut buf = vec![0u8; 4096];

    // Periodic stale peer cleanup
    let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if n == 0 {
                            continue;
                        }
                        handle_message(&socket, &mut peers, &buf[..n], src).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "recv error");
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let before = peers.len();
                let cutoff = Instant::now() - std::time::Duration::from_secs(120);
                peers.retain(|_, p| p.last_seen > cutoff);
                let removed = before - peers.len();
                if removed > 0 {
                    info!(removed, remaining = peers.len(), "cleaned stale peers");
                }
            }
        }
    }
}

async fn handle_message(
    socket: &UdpSocket,
    peers: &mut HashMap<[u8; 32], RegisteredPeer>,
    data: &[u8],
    src: SocketAddr,
) {
    match data[0] {
        proto::NAT_DETECT_REQ => {
            // Echo back the sender's observed endpoint
            handle_nat_detect(socket, src).await;
        }
        proto::REGISTER => {
            handle_register(peers, data, src);
        }
        proto::PEER_LIST_REQ => {
            handle_peer_list_req(socket, peers, data, src).await;
        }
        proto::KEEPALIVE => {
            handle_keepalive(peers, data, src);
        }
        t => {
            debug!(msg_type = t, %src, "unknown message type");
        }
    }
}

async fn handle_nat_detect(socket: &UdpSocket, src: SocketAddr) {
    debug!(%src, "NAT detection request");

    // Response: [0x11][ip: 4 bytes][port: 2 bytes]
    let mut resp = vec![proto::NAT_DETECT_RESP];
    match src.ip() {
        std::net::IpAddr::V4(ip) => resp.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => {
            // Only support IPv4 for now
            warn!(%src, "IPv6 NAT detection not supported");
            return;
        }
    }
    resp.extend_from_slice(&src.port().to_be_bytes());

    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send NAT detect response");
    }
}

fn handle_register(peers: &mut HashMap<[u8; 32], RegisteredPeer>, data: &[u8], src: SocketAddr) {
    // [0x30][pub_key: 32][listen_port: 2]
    if data.len() < 35 {
        debug!(%src, "register message too short");
        return;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[1..33]);
    let listen_port = u16::from_be_bytes([data[33], data[34]]);

    let is_new = !peers.contains_key(&public_key);

    peers.insert(
        public_key,
        RegisteredPeer {
            public_key,
            endpoint: src,
            listen_port,
            last_seen: Instant::now(),
        },
    );

    if is_new {
        info!(%src, listen_port, "new peer registered");
    } else {
        debug!(%src, "peer re-registered");
    }
}

async fn handle_peer_list_req(
    socket: &UdpSocket,
    peers: &HashMap<[u8; 32], RegisteredPeer>,
    data: &[u8],
    src: SocketAddr,
) {
    if data.len() < 33 {
        debug!(%src, "peer list request too short");
        return;
    }

    let mut requester_key = [0u8; 32];
    requester_key.copy_from_slice(&data[1..33]);

    // Build response with all peers except the requester
    let other_peers: Vec<&RegisteredPeer> = peers
        .values()
        .filter(|p| p.public_key != requester_key)
        .collect();

    let count = other_peers.len().min(u16::MAX as usize);
    let entry_size = 32 + 4 + 2;
    let mut resp = Vec::with_capacity(3 + count * entry_size);

    resp.push(proto::PEER_LIST_RESP);
    resp.extend_from_slice(&(count as u16).to_be_bytes());

    for peer in other_peers.iter().take(count) {
        resp.extend_from_slice(&peer.public_key);
        match peer.endpoint.ip() {
            std::net::IpAddr::V4(ip) => resp.extend_from_slice(&ip.octets()),
            std::net::IpAddr::V6(_) => {
                // Skip IPv6 peers for now
                continue;
            }
        }
        resp.extend_from_slice(&peer.endpoint.port().to_be_bytes());
    }

    debug!(%src, count, "sending peer list");
    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send peer list");
    }
}

fn handle_keepalive(peers: &mut HashMap<[u8; 32], RegisteredPeer>, data: &[u8], src: SocketAddr) {
    if data.len() < 33 {
        return;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[1..33]);

    if let Some(peer) = peers.get_mut(&public_key) {
        peer.last_seen = Instant::now();
        peer.endpoint = src; // Update in case endpoint changed
        debug!(%src, "keepalive received");
    } else {
        debug!(%src, "keepalive from unknown peer");
    }
}
