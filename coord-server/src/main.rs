mod api;
mod config_generator;
mod db;
mod ip_allocator;
mod key_manager;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// A registered peer on the coordination server (in-memory UDP registry).
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("coord_server=info".parse().unwrap())
                .add_directive("tower_http=debug".parse().unwrap()),
        )
        .init();

    // Load config from env vars
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/meshlink".into());
    let mesh_network = std::env::var("MESH_NETWORK").unwrap_or_else(|_| "10.0.0.0/24".into());
    let http_port: u16 = std::env::var("HTTP_PORT")
        .unwrap_or_else(|_| "4001".into())
        .parse()
        .context("parsing HTTP_PORT")?;
    let udp_port: u16 = std::env::var("UDP_PORT")
        .unwrap_or_else(|_| "4000".into())
        .parse()
        .context("parsing UDP_PORT")?;

    // Also allow passing UDP address as CLI arg for backward compatibility
    let udp_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("[::]:{udp_port}"));

    // Connect to PostgreSQL and run migrations
    let database = db::Db::connect(&database_url).await?;
    database.migrate().await?;

    // Set up IP allocator
    let ip_allocator = ip_allocator::IpAllocator::new(&mesh_network)
        .context("initializing IP allocator")?;

    // Public address that nodes use to reach the coordination server.
    // Must be set to the server's reachable hostname/IP (e.g. "r.rasporar.org:4000").
    let coord_server_addr = std::env::var("COORD_SERVER_ADDR")
        .unwrap_or_else(|_| format!("0.0.0.0:{udp_port}"));

    // Optional admin token for IAM override endpoints
    let admin_token = std::env::var("ADMIN_TOKEN").ok();
    if admin_token.is_some() {
        info!("admin API enabled (ADMIN_TOKEN set)");
    }

    // Build API state and router
    let app_state = api::AppState {
        db: database.clone(),
        ip_allocator,
        coord_server_addr,
        admin_token,
    };

    let app = api::router(app_state);

    // Start HTTP server
    let http_addr: SocketAddr = format!("[::]:{http_port}").parse()?;
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    info!(%http_addr, "HTTP API server starting");

    let http_server = tokio::spawn(async move {
        if let Err(e) = axum::serve(http_listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            warn!(error = %e, "HTTP server error");
        }
    });

    // Start UDP coordination server (existing protocol handler)
    let socket = UdpSocket::bind(&udp_addr)
        .await
        .with_context(|| format!("binding UDP to {udp_addr}"))?;
    info!(listen_addr = %udp_addr, "UDP coordination server started");

    // Background task: mark stale nodes in the database
    let stale_db = database.clone();
    let stale_checker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match stale_db.mark_stale_nodes(120).await {
                Ok(count) if count > 0 => {
                    info!(count, "marked stale nodes in database");
                }
                Err(e) => {
                    warn!(error = %e, "failed to mark stale nodes");
                }
                _ => {}
            }
        }
    });

    // UDP event loop (existing logic)
    let mut peers: HashMap<[u8; 32], RegisteredPeer> = HashMap::new();
    let mut buf = vec![0u8; 4096];
    let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if n == 0 {
                            continue;
                        }
                        handle_message(&socket, &mut peers, &database, &buf[..n], src).await;
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
                    info!(removed, remaining = peers.len(), "cleaned stale UDP peers");
                }
            }
        }
    }

    // These are unreachable but kept for completeness
    #[allow(unreachable_code)]
    {
        http_server.abort();
        stale_checker.abort();
        Ok(())
    }
}

async fn handle_message(
    socket: &UdpSocket,
    peers: &mut HashMap<[u8; 32], RegisteredPeer>,
    database: &db::Db,
    data: &[u8],
    src: SocketAddr,
) {
    match data[0] {
        proto::NAT_DETECT_REQ => {
            handle_nat_detect(socket, src).await;
        }
        proto::REGISTER => {
            handle_register(peers, database, data, src).await;
        }
        proto::PEER_LIST_REQ => {
            handle_peer_list_req(socket, peers, data, src).await;
        }
        proto::KEEPALIVE => {
            handle_keepalive(peers, database, data, src).await;
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
        std::net::IpAddr::V4(ip) => {
            resp.push(0x04);
            resp.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            resp.push(0x06);
            resp.extend_from_slice(&ip.octets());
        }
    }
    resp.extend_from_slice(&src.port().to_be_bytes());

    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send NAT detect response");
    }
}

async fn handle_register(peers: &mut HashMap<[u8; 32], RegisteredPeer>, database: &db::Db, data: &[u8], src: SocketAddr) {
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

    // Persist endpoint to the database so HTTP config endpoints return it.
    // Use src directly — it's the NAT-visible IP:port.
    let endpoint_str = src.to_string();
    match database.update_endpoint_by_pubkey(&public_key, &endpoint_str).await {
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

    let other_peers: Vec<&RegisteredPeer> = peers
        .values()
        .filter(|p| p.public_key != requester_key)
        .collect();

    let count = other_peers.len().min(u16::MAX as usize);
    // Variable-size entries: pub_key(32) + type(1) + ip(4 or 16) + port(2)
    let mut resp = Vec::with_capacity(3 + count * (32 + 1 + 16 + 2));

    resp.push(proto::PEER_LIST_RESP);
    resp.extend_from_slice(&(count as u16).to_be_bytes());

    for peer in other_peers.iter().take(count) {
        resp.extend_from_slice(&peer.public_key);
        match peer.endpoint.ip() {
            std::net::IpAddr::V4(ip) => {
                resp.push(0x04);
                resp.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                resp.push(0x06);
                resp.extend_from_slice(&ip.octets());
            }
        }
        resp.extend_from_slice(&peer.endpoint.port().to_be_bytes());
    }

    debug!(%src, count, "sending peer list");
    if let Err(e) = socket.send_to(&resp, src).await {
        warn!(error = %e, "failed to send peer list");
    }
}

async fn handle_keepalive(peers: &mut HashMap<[u8; 32], RegisteredPeer>, database: &db::Db, data: &[u8], src: SocketAddr) {
    if data.len() < 33 {
        return;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[1..33]);

    if let Some(peer) = peers.get_mut(&public_key) {
        peer.last_seen = Instant::now();
        peer.endpoint = src;
        debug!(%src, "keepalive received");
    } else {
        // After server restart, in-memory map is empty. Re-register the peer.
        peers.insert(
            public_key,
            RegisteredPeer {
                public_key,
                endpoint: src,
                listen_port: src.port(),
                last_seen: Instant::now(),
            },
        );
        info!(%src, "re-registered peer from keepalive");
    }

    // Persist endpoint to database
    let endpoint_str = src.to_string();
    if let Err(e) = database.update_endpoint_by_pubkey(&public_key, &endpoint_str).await {
        warn!(error = %e, %src, "failed to persist keepalive endpoint to database");
    }
}
