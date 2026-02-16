mod api;
mod config_generator;
mod db;
mod ip_allocator;
mod jwt;
mod key_manager;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::UdpSocket;
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
struct RegisteredPeer {
    public_key: [u8; 32],
    endpoint: SocketAddr,
    listen_port: u16,
    last_seen: Instant,
    /// Virtual IP from the database (e.g. 10.0.0.2). None if not yet resolved.
    virtual_ip: Option<std::net::Ipv4Addr>,
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
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres:///meshlink?user=meshlink".into());
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

    // Initialize JWT signing key
    let jwt_state = jwt::init_signing_key(&database.pool)
        .await
        .context("initializing JWT signing key")?;
    info!(key_id = %jwt_state.key_id, "JWT signing key ready");

    // Build API state and router
    let app_state = api::AppState {
        db: database.clone(),
        ip_allocator,
        coord_server_addr,
        admin_token,
        jwt: jwt_state,
    };

    let app = api::router(app_state);

    // Start HTTP API server
    let http_addr: SocketAddr = format!("[::]:{http_port}").parse()?;
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    info!(%http_addr, "HTTP API server starting");

    let http_server = tokio::spawn(async move {
        if let Err(e) = axum::serve(http_listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            warn!(error = %e, "HTTP server error");
        }
    });

    // Start landing page server on port 4002
    let landing_port: u16 = std::env::var("LANDING_PORT")
        .unwrap_or_else(|_| "4002".into())
        .parse()
        .context("parsing LANDING_PORT")?;
    let landing_addr: SocketAddr = format!("[::]:{landing_port}").parse()?;
    let landing_listener = tokio::net::TcpListener::bind(landing_addr).await?;
    info!(%landing_addr, "landing page server starting");

    let landing_app = axum::Router::new().route(
        "/",
        axum::routing::get(|| async {
            axum::response::Html(
r#"<!-- https://apiopenfrenzy.rasporar.org -->
<html>
<head>
<title>OpenFrenzy API</title>
<style>
*{margin:0;padding:0}
body{background:#000;color:#00ff41;font-family:'Courier New',monospace;font-size:14px;padding:40px;overflow-x:hidden}
pre{line-height:1.6}
.dim{color:#005f15}
.bright{color:#00ff41;text-shadow:0 0 5px #00ff41}
.header{color:#00ff41;text-shadow:0 0 10px #00ff41,0 0 20px #003b00}
.method{color:#39ff14}
.path{color:#00cc33}
.desc{color:#008f11}
.section{color:#00ff41;text-shadow:0 0 8px #00ff41;border-bottom:1px solid #003b00;padding-bottom:4px;margin-bottom:8px;display:inline-block}
canvas{position:fixed;top:0;left:0;z-index:-1;opacity:0.15}
</style>
</head>
<body>
<canvas id="m"></canvas>
<pre>
<span class="header">  ___                 _____
 / _ \ _ __  ___ _ _ |  ___| __ ___ _ __  _____   _
| | | | '_ \/ _ \ ' \| |_ | '__/ _ \ '_ \|_  / | | |
| |_| | |_) |  __/ | ||  _|| | |  __/ | | |/ /| |_| |
 \___/| .__/ \___|_||_|_|  |_|  \___|_| |_/___|\__, |
      |_|                                       |___/  </span>

<span class="dim">Coordination server for the MeshLink peer-to-peer network.</span>

<span class="section">=== Node API ===</span>
<span class="method">POST  </span> <span class="path">/api/v1/register</span>                              <span class="desc">Register node (invite_code, node_name)</span>
<span class="method">GET   </span> <span class="path">/api/v1/node/{id}/config</span>                      <span class="desc">Get node config [Bearer node_token]</span>
<span class="method">POST  </span> <span class="path">/api/v1/node/{id}/heartbeat</span>                   <span class="desc">Send heartbeat [Bearer node_token]</span>
<span class="method">DELETE</span> <span class="path">/api/v1/node/{id}</span>                              <span class="desc">Deregister node [Bearer node_token]</span>

<span class="section">=== Service / ACL ===</span>
<span class="method">POST  </span> <span class="path">/api/v1/node/{id}/services</span>                    <span class="desc">Declare service (name, port, protocol) [Bearer node_token]</span>
<span class="method">GET   </span> <span class="path">/api/v1/node/{id}/services</span>                     <span class="desc">List node services [Bearer node_token]</span>
<span class="method">DELETE</span> <span class="path">/api/v1/node/{id}/services/{svc_id}</span>            <span class="desc">Delete service [Bearer node_token]</span>
<span class="method">POST  </span> <span class="path">/api/v1/node/{id}/services/{svc_id}/rules</span>      <span class="desc">Create access rule [Bearer node_token]</span>
<span class="method">GET   </span> <span class="path">/api/v1/node/{id}/services/{svc_id}/rules</span>       <span class="desc">List rules [Bearer node_token]</span>
<span class="method">DELETE</span> <span class="path">/api/v1/node/{id}/services/{svc_id}/rules/{rid}</span> <span class="desc">Delete rule [Bearer node_token]</span>

<span class="section">=== Admin ===</span>
<span class="method">POST  </span> <span class="path">/api/v1/admin/invite</span>                           <span class="desc">Create node invite [Bearer admin_token]</span>
<span class="method">POST  </span> <span class="path">/api/v1/admin/services/{svc_id}/rules</span>          <span class="desc">Create admin rule [Bearer admin_token]</span>
<span class="method">DELETE</span> <span class="path">/api/v1/admin/services/{svc_id}/rules/{rid}</span>     <span class="desc">Delete admin rule [Bearer admin_token]</span>
<span class="method">POST  </span> <span class="path">/api/v1/admin/user-invite</span>                       <span class="desc">Create user invite [Bearer admin_token]</span>
<span class="method">POST  </span> <span class="path">/api/v1/admin/users/{user_id}/approve</span>           <span class="desc">Approve user [Bearer admin_token]</span>
<span class="method">GET   </span> <span class="path">/api/v1/admin/users?status=</span>                     <span class="desc">List users [Bearer admin_token]</span>

<span class="section">=== Auth ===</span>
<span class="method">POST  </span> <span class="path">/api/v1/auth/register</span>                          <span class="desc">Register user (invite_code, username, password)</span>
<span class="method">POST  </span> <span class="path">/api/v1/auth/login</span>                              <span class="desc">Login (username, password) -> tokens</span>
<span class="method">POST  </span> <span class="path">/api/v1/auth/refresh</span>                            <span class="desc">Refresh access token (refresh_token)</span>
<span class="method">GET   </span> <span class="path">/api/v1/auth/userinfo</span>                           <span class="desc">Get current user [Bearer JWT]</span>

<span class="section">=== Discovery ===</span>
<span class="method">GET   </span> <span class="path">/api/v1/.well-known/jwks.json</span>                   <span class="desc">Public signing key (JWK)</span>
</pre>
<script>
var c=document.getElementById('m'),x=c.getContext('2d');
c.width=window.innerWidth;c.height=window.innerHeight;
var cols=Math.floor(c.width/14),drops=[];
for(var i=0;i<cols;i++)drops[i]=Math.random()*-100;
var chars='01';
function draw(){
x.fillStyle='rgba(0,0,0,0.05)';x.fillRect(0,0,c.width,c.height);
x.fillStyle='#00ff41';x.font='14px monospace';
for(var i=0;i<drops.length;i++){
var t=chars[Math.floor(Math.random()*chars.length)];
x.fillText(t,i*14,drops[i]*14);
if(drops[i]*14>c.height&&Math.random()>0.975)drops[i]=0;
drops[i]++;
}}
setInterval(draw,50);
</script>
</body>
</html>
"#,
            )
        }),
    );

    let _landing_server = tokio::spawn(async move {
        if let Err(e) = axum::serve(landing_listener, landing_app).await {
            warn!(error = %e, "landing page server error");
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
                        let src = normalize_addr(src);
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
            handle_peer_list_req(socket, peers, database, data, src).await;
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

    // Look up virtual_ip from database for this public key
    let virtual_ip = match database.get_node_by_pubkey(&public_key).await {
        Ok(Some(node)) => {
            let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
            ip_str.parse::<std::net::Ipv4Addr>().ok()
        }
        _ => None,
    };

    peers.insert(
        public_key,
        RegisteredPeer {
            public_key,
            endpoint: src,
            listen_port,
            last_seen: Instant::now(),
            virtual_ip,
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

    // Filter out the requester
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
        let endpoint: Option<SocketAddr> = peers
            .get(&pub_key)
            .map(|p| p.endpoint)
            .or_else(|| {
                node.endpoint.as_ref().and_then(|ep| ep.parse().ok())
            })
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
        let virtual_ip = match database.get_node_by_pubkey(&public_key).await {
            Ok(Some(node)) => {
                let ip_str = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);
                ip_str.parse::<std::net::Ipv4Addr>().ok()
            }
            _ => None,
        };
        peers.insert(
            public_key,
            RegisteredPeer {
                public_key,
                endpoint: src,
                listen_port: src.port(),
                last_seen: Instant::now(),
                virtual_ip,
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
