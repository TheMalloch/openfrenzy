pub mod api;
pub mod config_generator;
pub mod db;
pub mod ip_allocator;
pub mod key_manager;
pub mod udp_handler;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::info;

/// Configuration for the coordination server (runtime, flattened).
pub struct CoordServerConfig {
    pub database_url: String,
    pub mesh_network: String,
    pub http_port: u16,
    pub udp_port: u16,
    pub bind_address: String,
    pub external_address: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub admin_token: Option<String>,
    pub coord_server_addr: String,
    pub stale_timeout_secs: u64,
    pub cleanup_interval_secs: u64,
    pub max_peers: u32,
    pub default_listen_port: u16,
    pub default_expiry_hours: i64,
    pub default_max_uses: i32,
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct CoordConfigFile {
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub peers: PeersConfig,
    #[serde(default)]
    pub invites: InvitesConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres:///meshlink?user=meshlink".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub mesh_cidr: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mesh_cidr: "10.0.0.0/24".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub http_port: u16,
    pub udp_port: u16,
    pub coord_addr: Option<String>,
    pub bind_address: String,
    pub external_address: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: 4001,
            udp_port: 4000,
            coord_addr: None,
            bind_address: "[::]".into(),
            external_address: String::new(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct PeersConfig {
    pub stale_timeout_secs: u64,
    pub cleanup_interval_secs: u64,
    pub max_peers: u32,
    pub default_listen_port: u16,
}

impl Default for PeersConfig {
    fn default() -> Self {
        Self {
            stale_timeout_secs: 120,
            cleanup_interval_secs: 60,
            max_peers: 0,
            default_listen_port: 51820,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct InvitesConfig {
    pub default_expiry_hours: i64,
    pub default_max_uses: i32,
}

impl Default for InvitesConfig {
    fn default() -> Self {
        Self {
            default_expiry_hours: 24,
            default_max_uses: 1,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl CoordServerConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        let file: CoordConfigFile =
            toml::from_str(&contents).context("parsing coord config TOML")?;
        Ok(Self::from_file(file))
    }

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
        let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "[::]".into());
        let coord_server_addr = std::env::var("COORD_SERVER_ADDR")
            .unwrap_or_else(|_| format!("0.0.0.0:{udp_port}"));

        Ok(Self {
            database_url,
            mesh_network,
            http_port,
            udp_port,
            bind_address,
            external_address: std::env::var("EXTERNAL_ADDRESS").unwrap_or_default(),
            tls_cert: std::env::var("TLS_CERT").ok(),
            tls_key: std::env::var("TLS_KEY").ok(),
            admin_token,
            coord_server_addr,
            stale_timeout_secs: 120,
            cleanup_interval_secs: 60,
            max_peers: 0,
            default_listen_port: 51820,
            default_expiry_hours: 24,
            default_max_uses: 1,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        })
    }

    fn from_file(file: CoordConfigFile) -> Self {
        let coord_server_addr = file
            .server
            .coord_addr
            .unwrap_or_else(|| format!("0.0.0.0:{}", file.server.udp_port));
        Self {
            database_url: file.database.url,
            mesh_network: file.network.mesh_cidr,
            http_port: file.server.http_port,
            udp_port: file.server.udp_port,
            bind_address: file.server.bind_address,
            external_address: file.server.external_address,
            tls_cert: file.server.tls_cert,
            tls_key: file.server.tls_key,
            admin_token: file.admin.token,
            coord_server_addr,
            stale_timeout_secs: file.peers.stale_timeout_secs,
            cleanup_interval_secs: file.peers.cleanup_interval_secs,
            max_peers: file.peers.max_peers,
            default_listen_port: file.peers.default_listen_port,
            default_expiry_hours: file.invites.default_expiry_hours,
            default_max_uses: file.invites.default_max_uses,
            log_level: file.logging.level,
        }
    }
}

/// Start the coordination server (UDP + HTTP + stale node checker).
pub async fn run(config: CoordServerConfig) -> Result<()> {
    // Connect to PostgreSQL and run migrations
    let database = db::Db::connect(&config.database_url).await?;
    database.setup_tables().await?;

    // Set up IP allocator
    let ip_allocator = ip_allocator::IpAllocator::new(&config.mesh_network)
        .context("initializing IP allocator")?;

    if config.admin_token.is_some() {
        info!("admin API enabled (ADMIN_TOKEN set)");
    }

    // Create shared UDP socket
    let udp_addr = format!("{}:{}", config.bind_address, config.udp_port);
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
    let stale_timeout = config.stale_timeout_secs;
    let cleanup_interval = config.cleanup_interval_secs;
    let udp_server = tokio::spawn(async move {
        if let Err(e) = udp_handler::run_udp_server(
            udp_socket_clone, udp_peers, udp_db,
            stale_timeout, cleanup_interval,
        ).await {
            tracing::error!(error = %e, "UDP server error");
        }
    });

    // Start HTTP server
    let http_db = database.clone();
    let http_server = tokio::spawn(api::run_http_server(
        config.http_port,
        config.bind_address.clone(),
        http_db,
        ip_allocator,
        config.coord_server_addr,
        config.admin_token,
        config.default_listen_port,
        config.default_expiry_hours,
        config.default_max_uses,
    ));

    // Start stale node checker with shared socket and peers for broadcasting
    let stale_db = database.clone();
    let stale_socket = udp_socket.clone();
    let stale_peers = peers.clone();
    let stale_checker = tokio::spawn(udp_handler::stale_node_checker(
        stale_db,
        stale_socket,
        stale_peers,
        config.stale_timeout_secs,
        config.cleanup_interval_secs,
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
