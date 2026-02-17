pub mod api;
pub mod config_generator;
pub mod db;
pub mod ip_allocator;
pub mod key_manager;
pub mod udp_handler;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::info;

/// Configuration for the coordination server, loaded from environment variables.
pub struct CoordServerConfig {
    pub database_url: String,
    pub mesh_network: String,
    pub http_port: u16,
    pub udp_port: u16,
    pub admin_token: Option<String>,
    pub coord_server_addr: String,
}

impl CoordServerConfig {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres:///meshlink?user=meshlink".into());
        let mesh_network =
            std::env::var("MESH_NETWORK").unwrap_or_else(|_| "10.0.0.0/24".into());
        let http_port: u16 = std::env::var("HTTP_PORT")
            .unwrap_or_else(|_| "4001".into())
            .parse()
            .context("parsing HTTP_PORT")?;
        let udp_port: u16 = std::env::var("UDP_PORT")
            .unwrap_or_else(|_| "4000".into())
            .parse()
            .context("parsing UDP_PORT")?;
        let admin_token = std::env::var("ADMIN_TOKEN").ok();
        let coord_server_addr = std::env::var("COORD_SERVER_ADDR")
            .unwrap_or_else(|_| format!("0.0.0.0:{udp_port}"));

        Ok(Self {
            database_url,
            mesh_network,
            http_port,
            udp_port,
            admin_token,
            coord_server_addr,
        })
    }
}

/// Start the coordination server (UDP + HTTP + stale node checker).
pub async fn run(config: CoordServerConfig) -> Result<()> {
    // Connect to PostgreSQL
    let database = db::Db::connect(&config.database_url).await?;

    // Set up IP allocator
    let ip_allocator = ip_allocator::IpAllocator::new(&config.mesh_network)
        .context("initializing IP allocator")?;

    if config.admin_token.is_some() {
        info!("admin API enabled (ADMIN_TOKEN set)");
    }

    // Create shared UDP socket
    let udp_addr = format!("[::]:{}", config.udp_port);
    let udp_socket = Arc::new(
        UdpSocket::bind(&udp_addr)
            .await
            .with_context(|| format!("binding UDP to {udp_addr}"))?,
    );
    info!(listen_addr = %udp_addr, "UDP socket bound");

    // Create shared peer map
    let peers: udp_handler::PeerMap = Arc::new(Mutex::new(HashMap::new()));

    // Start UDP server
    let udp_db = database.clone();
    let udp_socket_clone = udp_socket.clone();
    let udp_peers = peers.clone();
    let udp_server = tokio::spawn(async move {
        if let Err(e) = udp_handler::run_udp_server(udp_socket_clone, udp_peers, udp_db).await {
            tracing::error!(error = %e, "UDP server error");
        }
    });

    // Start HTTP server
    let http_db = database.clone();
    let http_server = tokio::spawn(api::run_http_server(
        config.http_port,
        http_db,
        ip_allocator,
        config.coord_server_addr,
        config.admin_token,
    ));

    // Start stale node checker with shared socket and peers for broadcasting
    let stale_db = database.clone();
    let stale_socket = udp_socket.clone();
    let stale_peers = peers.clone();
    let stale_checker = tokio::spawn(udp_handler::stale_node_checker(
        stale_db,
        stale_socket,
        stale_peers,
    ));

    info!(
        udp_port = config.udp_port,
        http_port = config.http_port,
        "coordination server running — press Ctrl+C to stop"
    );

    // Wait for shutdown
    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl-c")?;

    info!("shutting down coordination server");
    udp_server.abort();
    http_server.abort();
    stale_checker.abort();

    Ok(())
}
