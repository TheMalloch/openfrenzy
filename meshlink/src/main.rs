mod api_client;
mod cli;
mod config;
mod credentials;
mod crypto;
mod discovery;
mod net;
mod router;
mod setup;
mod state;
mod tun;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("meshlink=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Genkey) => {
            cli::generate_keypair();
            return Ok(());
        }
        Some(Command::Status) => {
            let resp = cli::send_command("status").await?;
            print!("{resp}");
            return Ok(());
        }
        Some(Command::Peers) => {
            let resp = cli::send_command("peers").await?;
            print!("{resp}");
            return Ok(());
        }
        Some(Command::Down) => {
            // TODO: signal the running daemon to shut down
            println!("Sending shutdown signal...");
            return Ok(());
        }
        Some(Command::Unregister { server }) => {
            let config_dir = cli.config.parent().unwrap_or(Path::new("/etc/meshlink"));
            return handle_unregister(server.as_deref(), config_dir).await;
        }
        Some(Command::Setup { config_dir }) => {
            setup::run_setup(&config_dir)?;
            return Ok(());
        }
        Some(Command::Up {
            server,
            invite,
            name,
            coord_server,
        }) => {
            let config_dir = cli.config.parent().unwrap_or(Path::new("/etc/meshlink"));

            // If --invite is provided, register first
            if let Some(invite_code) = invite {
                let server_url = server.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--server is required when using --invite")
                })?;

                info!("registering with server {server_url}");
                let client = api_client::ApiClient::new(server_url, None);
                let resp = client.register(&invite_code, name.as_deref()).await?;

                // Save credentials
                let creds = credentials::Credentials {
                    server: server_url.to_string(),
                    node_id: resp.node_id.clone(),
                    auth_token: resp.auth_token.clone(),
                };
                creds.save(config_dir)?;

                // Write the config file
                if let Some(parent) = cli.config.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| wrap_permission_error(e, "creating config directory"))?;
                }
                std::fs::write(&cli.config, &resp.config_toml)
                    .map_err(|e| wrap_permission_error(e, "writing config file"))?;

                println!("Registration successful!");
                println!("  Node ID:    {}", resp.node_id);
                println!("  Virtual IP: {}", resp.virtual_ip);
                println!("  Public Key: {}", resp.public_key);
                println!();
            }

            let server_params = cli::ServerParams::resolve(config_dir);
            if server_params.is_none() {
                anyhow::bail!(
                    "No credentials found. Register first with:\n  \
                     sudo meshlink up --server <URL> --invite <CODE>"
                );
            }
            run_daemon(&cli.config, server_params, coord_server).await?;
        }
        None => {
            // Default: start the daemon with no server params
            run_daemon(&cli.config, None, None).await?;
        }
    }

    Ok(())
}

/// Handle the `unregister` subcommand.
async fn handle_unregister(server: Option<&str>, config_dir: &Path) -> Result<()> {
    let creds = credentials::Credentials::load(config_dir)
        .context("no credentials found — are you registered?")?;

    let server_url = server.unwrap_or(&creds.server);
    let client = api_client::ApiClient::new(server_url, Some(creds.auth_token.clone()));

    client.unregister(&creds.node_id).await?;

    // Clean up local files
    let _ = std::fs::remove_file(credentials::Credentials::path_in(config_dir));

    println!("Node {} unregistered successfully.", creds.node_id);
    Ok(())
}

async fn run_daemon(
    config_path: &std::path::Path,
    server_params: Option<cli::ServerParams>,
    coord_server_override: Option<String>,
) -> Result<()> {
    info!("MeshLink starting");

    // If server mode, fetch config from API first
    let mut config = if let Some(ref params) = server_params {
        info!(server = %params.server, node_id = %params.node_id, "fetching config from server");
        let client =
            api_client::ApiClient::new(&params.server, Some(params.auth_token.clone()));
        let config_toml = client.fetch_config(&params.node_id).await?;

        // Write to disk for reference
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| wrap_permission_error(e, "creating config directory"))?;
        }
        std::fs::write(config_path, &config_toml)
            .map_err(|e| wrap_permission_error(e, "writing config file"))?;

        config::Config::from_toml_string(&config_toml)?
    } else {
        config::Config::load(config_path)?
    };

    // Override coordination server if provided via CLI
    if let Some(addr) = coord_server_override {
        info!(coord_server = %addr, "overriding coordination server from CLI");
        config.coordination.server = addr;
    }

    info!(
        virtual_ip = %config.node.virtual_ip,
        listen_port = config.node.listen_port,
        peers = config.peers.len(),
        "configuration loaded"
    );

    // Initialize identity from private key
    let identity = Arc::new(
        crypto::handshake::Identity::from_base64(&config.node.private_key)
            .context("loading identity")?,
    );
    let our_pub_key = identity.public_key_bytes();
    info!(
        public_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            our_pub_key
        ),
        "node identity loaded"
    );

    // Initialize shared state
    let shared_state = state::SharedState::new();

    // Register configured peers in state
    for peer_config in &config.peers {
        let pub_key_bytes: [u8; 32] = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &peer_config.public_key,
        )
        .context("decoding peer public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer key not 32 bytes"))?;

        // Determine virtual IP from allowed_ips (use the first /32 or first network addr)
        let virtual_ip = peer_config
            .allowed_ips
            .first()
            .map(|net| net.addr())
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        // Collect outbound ACL rules matching this peer's virtual IP
        let peer_acl: Vec<config::AclRule> = config
            .acl
            .iter()
            .filter(|r| r.peer_ip == virtual_ip)
            .cloned()
            .collect();

        let peer_info = state::PeerInfo {
            public_key: pub_key_bytes,
            endpoint: peer_config.endpoint,
            virtual_ip,
            allowed_ips: peer_config.allowed_ips.clone(),
            tx_bytes: 0,
            rx_bytes: 0,
            acl_rules: peer_acl,
        };
        shared_state.add_peer(peer_info).await;
    }

    // Load inbound ACL rules
    if !config.inbound_acl.is_empty() {
        info!(rules = config.inbound_acl.len(), "loading inbound ACL rules");
        *shared_state.inbound_acl.write().await = config.inbound_acl.clone();
    }

    // Create TUN device
    let tun_dev = tun::create_tun_device(&config.node.tun_name, config.node.virtual_ip)?;
    let (tun_read, tun_write) = tokio::io::split(tun_dev);

    // Bind UDP socket (tries configured port, then up to +10 if in use)
    let (udp_raw, actual_port) = net::udp::bind_udp(config.node.listen_port).await?;
    let udp_socket = Arc::new(udp_raw);

    // Create pipeline channels
    let channels = state::PipelineChannels::new(256);

    // Create coord protocol channel (for NAT detection + peer list responses)
    let (coord_tx, coord_rx) = tokio::sync::mpsc::channel::<state::RoutedPacket>(64);

    // Parse coordination server address (prefer IPv6 for dual-stack, fall back to IPv4)
    let coord_addr: std::net::SocketAddr = tokio::net::lookup_host(&config.coordination.server)
        .await
        .context("resolving coordination server")?
        .next()
        .context("no addresses for coordination server")?;

    info!("spawning async tasks");

    // Spawn all tasks
    let tun_reader = tokio::spawn(tun::tun_reader_task(tun_read, channels.tun_to_router_tx));

    let tun_writer = tokio::spawn(tun::tun_writer_task(tun_write, channels.router_to_tun_rx));

    let udp_reader = tokio::spawn(net::udp::udp_reader_task(
        udp_socket.clone(),
        channels.udp_to_router_tx,
        coord_tx,
    ));

    let udp_writer = tokio::spawn(net::udp::udp_writer_task(
        udp_socket.clone(),
        channels.router_to_udp_rx,
    ));

    let outbound_router = tokio::spawn(router::outbound_router_task(
        shared_state.clone(),
        channels.tun_to_router_rx,
        channels.router_to_udp_tx.clone(),
    ));

    let inbound_router = tokio::spawn(router::inbound_router_task(
        shared_state.clone(),
        channels.udp_to_router_rx,
        channels.router_to_tun_tx,
    ));

    let discovery = tokio::spawn(discovery::discovery_task(
        shared_state.clone(),
        identity.clone(),
        udp_socket.clone(),
        coord_addr,
        actual_port,
        config_path.to_path_buf(),
        coord_rx,
    ));

    let cli_listener = tokio::spawn(cli::cli_listener_task(shared_state.clone()));

    // Spawn server heartbeat task if in server-orchestrated mode
    let heartbeat_task = if let Some(params) = server_params {
        Some(tokio::spawn(discovery::server_heartbeat_task(
            shared_state.clone(),
            params.server,
            params.node_id,
            params.auth_token,
        )))
    } else {
        None
    };

    info!("MeshLink running — press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl-c")?;

    info!("shutting down");

    // Abort all tasks
    tun_reader.abort();
    tun_writer.abort();
    udp_reader.abort();
    udp_writer.abort();
    outbound_router.abort();
    inbound_router.abort();
    discovery.abort();
    cli_listener.abort();
    if let Some(ht) = heartbeat_task {
        ht.abort();
    }

    // Clean up socket file
    let _ = std::fs::remove_file(cli::socket_path());

    info!("MeshLink stopped");
    Ok(())
}

/// If an IO error is a permission error, wrap it with a suggestion to run `meshlink setup`.
fn wrap_permission_error(err: std::io::Error, context: &str) -> anyhow::Error {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "{context}: permission denied\n\n\
             Hint: Run 'sudo meshlink setup' first to configure directory permissions,\n\
             then retry this command."
        )
    } else {
        anyhow::Error::new(err).context(context.to_string())
    }
}
