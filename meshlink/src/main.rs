mod cli;
mod config;
mod crypto;
mod discovery;
mod net;
mod router;
mod state;
mod tun;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
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
        Some(Command::Up) | None => {
            // Default: start the daemon
            run_daemon(&cli.config).await?;
        }
    }

    Ok(())
}

async fn run_daemon(config_path: &std::path::Path) -> Result<()> {
    info!("MeshLink starting");

    // Load configuration
    let config = config::Config::load(config_path)?;
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
            session_key: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        };
        shared_state.add_peer(peer_info).await;
    }

    // Create TUN device
    let tun_dev = tun::create_tun_device(&config.node.tun_name, config.node.virtual_ip)?;
    let (tun_read, tun_write) = tokio::io::split(tun_dev);

    // Bind UDP socket
    let udp_socket = Arc::new(net::udp::bind_udp(config.node.listen_port).await?);

    // Create pipeline channels
    let channels = state::PipelineChannels::new(256);

    // Parse coordination server address
    let coord_addr: std::net::SocketAddr = tokio::net::lookup_host(&config.coordination.server)
        .await
        .context("resolving coordination server")?
        .next()
        .context("no addresses for coordination server")?;

    info!("spawning async tasks");

    // Spawn all 6 tasks
    let tun_reader = tokio::spawn(tun::tun_reader_task(tun_read, channels.tun_to_router_tx));

    let tun_writer = tokio::spawn(tun::tun_writer_task(tun_write, channels.router_to_tun_rx));

    let udp_reader = tokio::spawn(net::udp::udp_reader_task(
        udp_socket.clone(),
        channels.udp_to_router_tx,
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
        identity.clone(),
        channels.udp_to_router_rx,
        channels.router_to_tun_tx,
        channels.router_to_udp_tx.clone(),
    ));

    let discovery = tokio::spawn(discovery::discovery_task(
        shared_state.clone(),
        identity.clone(),
        udp_socket.clone(),
        coord_addr,
        config.node.listen_port,
        channels.router_to_udp_tx,
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
