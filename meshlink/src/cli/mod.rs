use crate::state::SharedState;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
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
    /// Start the meshlink daemon.
    Up,
    /// Stop the meshlink daemon.
    Down,
    /// Show current status and peers.
    Status,
    /// Show peer list with statistics.
    Peers,
    /// Generate a new keypair.
    Genkey,
}

/// Default path for the runtime control unix socket.
pub fn socket_path() -> PathBuf {
    PathBuf::from("/var/run/meshlink.sock")
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
            error!(error = %e, "failed to bind CLI socket");
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
            let connected = peers.values().filter(|p| p.session_key.is_some()).count();
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
                let status = if peer.session_key.is_some() {
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
