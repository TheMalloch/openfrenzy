mod api_client;
mod cli;
mod config;
mod coord;
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
        Some(Command::Setup { config_dir }) => {
            setup::run_setup(&config_dir)?;
            return Ok(());
        }
        Some(Command::Cs { action }) => {
            return handle_cs_action(action).await;
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
                let client = api_client::ApiClient::new(server_url);
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

            run_daemon(&cli.config, coord_server).await?;
        }
        None => {
            // Default: start the daemon
            run_daemon(&cli.config, None).await?;
        }
    }

    Ok(())
}

/// Handle coordination server subcommands.
async fn handle_cs_action(action: cli::CsAction) -> Result<()> {
    let config = coord::CoordServerConfig::from_env()?;

    match action {
        cli::CsAction::Start => {
            coord::run(config).await?;
        }
        cli::CsAction::DbSetup => {
            let db = coord::db::Db::connect(&config.database_url).await?;
            db.setup_tables().await?;
            println!("Database tables created.");
        }
        cli::CsAction::DbWipe => {
            let db = coord::db::Db::connect(&config.database_url).await?;
            db.drop_all_tables().await?;
            println!("All tables dropped.");
        }
        cli::CsAction::KeyGen => {
            let (private_key, public_key) = coord::key_manager::generate_node_keypair();
            let priv_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                private_key,
            );
            let pub_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public_key,
            );
            println!("Private key: {priv_b64}");
            println!("Public key:  {pub_b64}");
        }
        cli::CsAction::CreateInvite { multi_use, max_uses, expires_hours } => {
            let db = coord::db::Db::connect(&config.database_url).await?;
            let code = uuid::Uuid::new_v4().to_string();
            let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);
            let effective_max_uses = if multi_use { max_uses } else { 1 };
            db.create_invite(&code, expires_at, effective_max_uses).await?;
            println!("Invite code: {code}");
            println!("Expires at:  {}", expires_at.to_rfc3339());
            if multi_use {
                if effective_max_uses == 0 {
                    println!("Max uses:    unlimited");
                } else {
                    println!("Max uses:    {effective_max_uses}");
                }
            } else {
                println!("Max uses:    1 (single-use)");
            }
        }
    }

    Ok(())
}

async fn run_daemon(
    config_path: &std::path::Path,
    coord_server_override: Option<String>,
) -> Result<()> {
    info!("MeshLink starting");

    let mut config = config::Config::load(config_path)?;

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

        let peer_info = state::PeerInfo {
            public_key: pub_key_bytes,
            endpoint: peer_config.endpoint,
            virtual_ip,
            allowed_ips: peer_config.allowed_ips.clone(),
            tx_bytes: 0,
            rx_bytes: 0,
        };
        shared_state.add_peer(peer_info).await;
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

    // Parse coordination server address — prefer IPv4 so the coord server sees our
    // IPv4 source address (peers without IPv6 can't reach an IPv6-only endpoint).
    let coord_addr: std::net::SocketAddr = {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&config.coordination.server)
            .await
            .context("resolving coordination server")?
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .copied()
            .context("no addresses for coordination server")?
    };

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
