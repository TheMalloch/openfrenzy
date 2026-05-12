use crate::state::SharedState;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

/// MeshLink — peer-to-peer LAN mesh networking daemon.
#[derive(Parser, Debug)]
#[command(name = "meshlink", version, about)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/meshlink/config.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the meshlink daemon (registers first if --invite is provided).
    Up {
        /// Server HTTP base URL (e.g., http://coord.example.com:4001).
        /// Required for first-time registration with --invite.
        #[arg(long)]
        server: Option<String>,

        /// Invite code for first-time registration.
        #[arg(long)]
        invite: Option<String>,

        /// Optional name for this node (used with --invite).
        #[arg(long)]
        name: Option<String>,

        /// Coordination server address for UDP peer discovery (e.g., r.rasporar.org:4000).
        /// Overrides the [coordination] server value in config.
        #[arg(long)]
        coord_server: Option<String>,

        /// Run in the foreground instead of daemonizing.
        #[arg(short = 'f', long)]
        foreground: bool,
    },
    /// Stop the meshlink daemon.
    Down,
    /// Show current status and peers.
    Status,
    /// Show peer list with statistics.
    Peers,
    /// Generate a new keypair.
    Genkey,
    /// Initialize system directories, group, and permissions for meshlink.
    Setup {
        /// Configuration directory path.
        #[arg(long, default_value = "/etc/meshlink")]
        config_dir: PathBuf,
    },
    /// Coordination server management commands.
    Cs {
        /// Path to the coord server config file.
        #[arg(short, long, default_value = "/etc/meshlink/coord.toml")]
        config: PathBuf,

        #[command(subcommand)]
        action: CsAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum CsAction {
    /// Start the coordination server (UDP + HTTP).
    Start {
        /// PostgreSQL connection URL.
        #[arg(long)]
        database_url: Option<String>,
        /// Mesh network CIDR (e.g. 10.0.0.0/24).
        #[arg(long)]
        mesh_cidr: Option<String>,
        /// HTTP API port.
        #[arg(long)]
        http_port: Option<u16>,
        /// UDP coordination port.
        #[arg(long)]
        udp_port: Option<u16>,
        /// Interface to bind on (e.g. [::] or 0.0.0.0).
        #[arg(long)]
        bind_address: Option<String>,
        /// Public address peers use to reach this server.
        #[arg(long)]
        external_address: Option<String>,
        /// Path to TLS certificate file.
        #[arg(long)]
        tls_cert: Option<String>,
        /// Path to TLS private key file.
        #[arg(long)]
        tls_key: Option<String>,
        /// Admin API bearer token.
        #[arg(long)]
        admin_token: Option<String>,
        /// Seconds before a peer is considered stale.
        #[arg(long)]
        stale_timeout_secs: Option<u64>,
        /// Seconds between stale-peer cleanup runs.
        #[arg(long)]
        cleanup_interval_secs: Option<u64>,
        /// Maximum number of peers (0 = unlimited).
        #[arg(long)]
        max_peers: Option<u32>,
        /// Default listen port for new nodes.
        #[arg(long)]
        default_listen_port: Option<u16>,
        /// Default invite expiry in hours.
        #[arg(long)]
        default_expiry_hours: Option<i64>,
        /// Default max uses for new invites.
        #[arg(long)]
        default_max_uses: Option<i32>,
        /// Log level (trace, debug, info, warn, error).
        #[arg(long)]
        log_level: Option<String>,
        /// Base port for per-peer port range allocation.
        #[arg(long)]
        port_range_base: Option<u16>,
        /// Number of ports per peer block.
        #[arg(long)]
        port_range_block_size: Option<u16>,
        /// Path to write the generated Caddy config file.
        #[arg(long)]
        caddy_config_path: Option<String>,
        /// Caddy admin API URL (e.g. http://localhost:2019).
        #[arg(long)]
        caddy_admin_api: Option<String>,
        /// Public domain used in generated Caddy server blocks.
        #[arg(long)]
        caddy_external_domain: Option<String>,
    },
    /// Create database tables.
    DbSetup,
    /// Drop all database tables (destructive!).
    DbWipe,
    /// Generate and print an X25519 keypair.
    KeyGen,
    /// Create a new node invite code.
    CreateInvite {
        /// Allow the invite to be used multiple times.
        #[arg(long, default_value_t = false)]
        multi_use: bool,
        /// Maximum number of uses (0 = unlimited when --multi-use is set).
        #[arg(long, default_value_t = 0)]
        max_uses: i32,
        /// Hours until the invite expires.
        #[arg(long, default_value_t = 24)]
        expires_hours: i64,
    },
    /// List all registered peers.
    ListPeers,
    /// Show detail for a single peer.
    ShowPeer {
        /// Node ID of the peer to show.
        id: String,
    },
    /// Disable a peer (sets status to deregistered).
    DisablePeer {
        /// Node ID of the peer to disable.
        id: String,
    },
    /// Re-enable a disabled peer.
    EnablePeer {
        /// Node ID of the peer to enable.
        id: String,
    },
    /// List all invite codes.
    ListInvites,
    /// Revoke an invite code immediately.
    RevokeInvite {
        /// The invite code to revoke.
        code: String,
    },
    /// Regenerate Caddy config from database and reload Caddy.
    CaddyRegen,
}

/// Parameters for server-orchestrated mode, resolved from CLI args, credentials, or env vars.
pub struct ServerParams {
    pub server: String,
    pub node_id: String,
    pub auth_token: String,
}

impl ServerParams {
    /// Resolve server params from stored credentials, falling back to env vars.
    pub fn resolve(config_dir: &Path) -> Option<Self> {
        // Try credentials file
        if let Ok(creds) = crate::credentials::Credentials::load(config_dir) {
            return Some(Self {
                server: creds.server,
                node_id: creds.node_id,
                auth_token: creds.auth_token,
            });
        }

        // Try env vars
        let server = std::env::var("MESHLINK_SERVER").ok();
        let node_id = std::env::var("MESHLINK_NODE_ID").ok();
        let auth_token = std::env::var("MESHLINK_AUTH_TOKEN").ok();

        if let (Some(s), Some(n), Some(t)) = (server, node_id, auth_token) {
            return Some(Self {
                server: s,
                node_id: n,
                auth_token: t,
            });
        }

        None
    }
}

/// Default path for the runtime control unix socket.
pub fn socket_path() -> PathBuf {
    // Prefer /run/meshlink/ (created by systemd RuntimeDirectory=meshlink),
    // fall back to /var/run for non-systemd invocations.
    let preferred = PathBuf::from("/run/meshlink/meshlink.sock");
    if preferred.parent().map(|p| p.exists()).unwrap_or(false) {
        preferred
    } else {
        PathBuf::from("/var/run/meshlink.sock")
    }
}

/// Default path for the PID file.
pub fn pid_path() -> PathBuf {
    let preferred = PathBuf::from("/run/meshlink/meshlink.pid");
    if preferred.parent().map(|p| p.exists()).unwrap_or(false) {
        preferred
    } else {
        PathBuf::from("/var/run/meshlink.pid")
    }
}

/// Task: listen on a unix socket for runtime control commands.
pub async fn cli_listener_task(state: SharedState) {
    let sock_path = socket_path();

    // Remove stale socket file if it exists
    let _ = std::fs::remove_file(&sock_path);

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => {
            info!(path = %sock_path.display(), "CLI listener started");
            l
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %sock_path.display(), "CLI socket unavailable, runtime control disabled");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_cli_connection(stream, state).await {
                        debug!(error = %e, "CLI connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "CLI accept error");
            }
        }
    }
}

async fn handle_cli_connection(stream: UnixStream, state: SharedState) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = process_command(line.trim(), &state).await;
        writer
            .write_all(response.as_bytes())
            .await
            .context("writing CLI response")?;
        writer
            .write_all(b"\n")
            .await
            .context("writing newline")?;
        line.clear();
    }

    Ok(())
}

async fn process_command(cmd: &str, state: &SharedState) -> String {
    match cmd {
        "status" => {
            let peers = state.peers.read().await;
            let connected = peers.values().filter(|p| p.endpoint.is_some()).count();
            format!(
                "MeshLink running\nPeers: {} total, {} connected",
                peers.len(),
                connected
            )
        }
        "peers" => {
            let peers = state.peers.read().await;
            if peers.is_empty() {
                return "No peers configured".to_string();
            }
            let mut output = String::from("Peers:\n");
            for peer in peers.values() {
                let status = if peer.endpoint.is_some() {
                    "connected"
                } else {
                    "disconnected"
                };
                let endpoint = peer
                    .endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let pub_key_short = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &peer.public_key[..8],
                );
                output.push_str(&format!(
                    "  {pub_key_short}... {status} endpoint={endpoint} \
                     tx={} rx={} vip={}\n",
                    peer.tx_bytes, peer.rx_bytes, peer.virtual_ip
                ));
            }
            output
        }
        "ping" => "pong".to_string(),
        _ => format!("unknown command: {cmd}"),
    }
}

/// Generate a new X25519 keypair and print it.
pub fn generate_keypair() {
    let identity = crate::crypto::handshake::Identity::generate();
    let private_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        identity.secret.as_bytes(),
    );
    let public_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        identity.public.as_bytes(),
    );
    println!("Private key: {private_b64}");
    println!("Public key:  {public_b64}");
}

/// Send a command to the running daemon via the unix socket.
pub async fn send_command(cmd: &str) -> Result<String> {
    let sock_path = socket_path();
    let mut stream = UnixStream::connect(&sock_path)
        .await
        .with_context(|| format!("connecting to {}", sock_path.display()))?;

    stream
        .write_all(cmd.as_bytes())
        .await
        .context("sending command")?;
    stream
        .write_all(b"\n")
        .await
        .context("sending newline")?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader
        .read_line(&mut response)
        .await
        .context("reading response")?;

    Ok(response)
}
