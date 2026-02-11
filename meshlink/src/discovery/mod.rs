use crate::api_client::ApiClient;
use crate::crypto::handshake::{self, Identity};
use crate::net::hole_punch;
use crate::state::SharedState;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Protocol message types for coordination server communication.
mod proto {
    /// Register with coord server: [0x30][pub_key: 32][listen_port: 2]
    pub const REGISTER: u8 = 0x30;
    /// Peer list request: [0x31][pub_key: 32]
    pub const PEER_LIST_REQ: u8 = 0x31;
    /// Peer list response: [0x32][count: 2]([pub_key: 32][ip: 4][port: 2])*
    pub const PEER_LIST_RESP: u8 = 0x32;
    /// Keepalive: [0x33][pub_key: 32]
    pub const KEEPALIVE: u8 = 0x33;
}

/// Parsed peer entry from the coordination server's peer list response.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
}

/// Build a registration message.
fn build_register_msg(public_key: &[u8; 32], listen_port: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(35);
    msg.push(proto::REGISTER);
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(&listen_port.to_be_bytes());
    msg
}

/// Build a peer list request message.
fn build_peer_list_req(public_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(33);
    msg.push(proto::PEER_LIST_REQ);
    msg.extend_from_slice(public_key);
    msg
}

/// Build a keepalive message.
fn build_keepalive(public_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(33);
    msg.push(proto::KEEPALIVE);
    msg.extend_from_slice(public_key);
    msg
}

/// Parse a peer list response from the coordination server.
fn parse_peer_list(data: &[u8]) -> Result<Vec<DiscoveredPeer>> {
    if data.is_empty() || data[0] != proto::PEER_LIST_RESP {
        anyhow::bail!("not a peer list response");
    }
    if data.len() < 3 {
        anyhow::bail!("peer list response too short");
    }

    let count = u16::from_be_bytes([data[1], data[2]]) as usize;
    let entry_size = 32 + 4 + 2; // pub_key + ipv4 + port
    let expected_len = 3 + count * entry_size;

    if data.len() < expected_len {
        anyhow::bail!(
            "peer list truncated: expected {} bytes, got {}",
            expected_len,
            data.len()
        );
    }

    let mut peers = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 3 + i * entry_size;

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);

        let ip = std::net::Ipv4Addr::new(
            data[offset + 32],
            data[offset + 33],
            data[offset + 34],
            data[offset + 35],
        );
        let port = u16::from_be_bytes([data[offset + 36], data[offset + 37]]);

        peers.push(DiscoveredPeer {
            public_key,
            endpoint: SocketAddr::new(std::net::IpAddr::V4(ip), port),
        });
    }

    Ok(peers)
}

/// Task: periodic peer discovery and keepalive with the coordination server.
///
/// 1. Register ourselves on startup
/// 2. Periodically request peer list
/// 3. For new peers, attempt hole punching then handshake
/// 4. Send keepalives to maintain our registration
pub async fn discovery_task(
    state: SharedState,
    identity: Arc<Identity>,
    socket: Arc<UdpSocket>,
    coord_addr: SocketAddr,
    listen_port: u16,
    udp_tx: tokio::sync::mpsc::Sender<crate::state::RoutedPacket>,
) {
    let our_pub_key = identity.public_key_bytes();

    // Initial registration
    let reg_msg = build_register_msg(&our_pub_key, listen_port);
    if let Err(e) = socket.send_to(&reg_msg, coord_addr).await {
        error!(error = %e, "failed to register with coordination server");
        return;
    }
    info!(%coord_addr, "registered with coordination server");

    // NAT detection
    match hole_punch::detect_nat(&socket, &coord_addr).await {
        Ok(detection) => {
            info!(?detection, "NAT detection result");
        }
        Err(e) => {
            warn!(error = %e, "NAT detection failed, continuing anyway");
        }
    }

    let mut discovery_interval = interval(Duration::from_secs(30));
    let mut keepalive_interval = interval(Duration::from_secs(25));

    loop {
        tokio::select! {
            _ = discovery_interval.tick() => {
                // Request peer list
                let req = build_peer_list_req(&our_pub_key);
                if let Err(e) = socket.send_to(&req, coord_addr).await {
                    error!(error = %e, "failed to send peer list request");
                    continue;
                }

                // Receive response (with timeout)
                let mut buf = vec![0u8; 4096];
                match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, src))) if src == coord_addr && n > 0 && buf[0] == proto::PEER_LIST_RESP => {
                        match parse_peer_list(&buf[..n]) {
                            Ok(peers) => {
                                debug!(count = peers.len(), "received peer list");
                                for discovered in peers {
                                    if discovered.public_key == our_pub_key {
                                        continue; // Skip ourselves
                                    }
                                    process_discovered_peer(
                                        &state,
                                        &identity,
                                        &socket,
                                        &discovered,
                                        &udp_tx,
                                    ).await;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to parse peer list");
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        debug!("received non-peer-list response from coord server");
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "UDP recv error during discovery");
                    }
                    Err(_) => {
                        debug!("peer list request timed out");
                    }
                }
            }
            _ = keepalive_interval.tick() => {
                let msg = build_keepalive(&our_pub_key);
                if let Err(e) = socket.send_to(&msg, coord_addr).await {
                    warn!(error = %e, "keepalive send failed");
                }
            }
        }
    }
}

/// Task: periodic heartbeat to the coordination server's REST API.
/// If peers have changed, re-fetches the config and updates state.
pub async fn server_heartbeat_task(
    state: SharedState,
    server_url: String,
    node_id: String,
    auth_token: String,
) {
    let client = ApiClient::new(&server_url, Some(auth_token));
    let mut heartbeat_interval = interval(Duration::from_secs(30));

    loop {
        heartbeat_interval.tick().await;

        match client.heartbeat(&node_id).await {
            Ok(resp) => {
                debug!(peers_changed = resp.peers_changed, "server heartbeat sent");

                if resp.peers_changed {
                    info!("peers changed, fetching updated config from server");

                    match client.fetch_config(&node_id).await {
                        Ok(config_toml) => {
                            match crate::config::Config::from_toml_string(&config_toml) {
                                Ok(config) => {
                                    // Update peer state with new config
                                    for peer_config in &config.peers {
                                        let pub_key_bytes: [u8; 32] = match base64::Engine::decode(
                                            &base64::engine::general_purpose::STANDARD,
                                            &peer_config.public_key,
                                        ) {
                                            Ok(bytes) => match bytes.try_into() {
                                                Ok(arr) => arr,
                                                Err(_) => continue,
                                            },
                                            Err(_) => continue,
                                        };

                                        if state.get_peer(&pub_key_bytes).await.is_some() {
                                            // Peer already known — update endpoint if the config has one
                                            if let Some(ep) = peer_config.endpoint {
                                                state.set_peer_endpoint(&pub_key_bytes, ep).await;
                                            }
                                        } else {
                                            let virtual_ip = peer_config
                                                .allowed_ips
                                                .first()
                                                .map(|net| net.addr())
                                                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

                                            let peer_info = crate::state::PeerInfo {
                                                public_key: pub_key_bytes,
                                                endpoint: peer_config.endpoint,
                                                virtual_ip,
                                                allowed_ips: peer_config.allowed_ips.clone(),
                                                session_key: None,
                                                last_handshake: None,
                                                tx_bytes: 0,
                                                rx_bytes: 0,
                                            };
                                            state.add_peer(peer_info).await;
                                            info!(vip = %virtual_ip, "added new peer from server config");
                                        }
                                    }

                                    // Write updated config to disk
                                    let _ = std::fs::write(
                                        "/etc/meshlink/config.toml",
                                        &config_toml,
                                    );
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse updated config");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to fetch updated config");
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "server heartbeat failed");
            }
        }
    }
}

/// Process a newly discovered peer: update state, hole punch, initiate handshake.
async fn process_discovered_peer(
    state: &SharedState,
    identity: &Identity,
    socket: &Arc<UdpSocket>,
    discovered: &DiscoveredPeer,
    udp_tx: &tokio::sync::mpsc::Sender<crate::state::RoutedPacket>,
) {
    // Update endpoint if peer is already known
    state
        .set_peer_endpoint(&discovered.public_key, discovered.endpoint)
        .await;

    let peer = state.get_peer(&discovered.public_key).await;

    // If no session key, initiate handshake
    let needs_handshake = match &peer {
        Some(p) => p.session_key.is_none(),
        None => {
            debug!(endpoint = %discovered.endpoint, "discovered unknown peer, skipping (not in config)");
            return;
        }
    };

    if needs_handshake {
        info!(endpoint = %discovered.endpoint, "initiating handshake with peer");

        // Attempt hole punch first
        if let Err(e) = hole_punch::punch_hole(
            socket,
            discovered.endpoint,
            &identity.public_key_bytes(),
        )
        .await
        {
            warn!(error = %e, "hole punch failed");
        }

        // Send handshake initiation
        let hs = handshake::initiate_handshake(&discovered.public_key);
        let msg = handshake::build_handshake_init(
            &identity.public_key_bytes(),
            &hs.ephemeral_public,
        );

        let _ = udp_tx
            .send(crate::state::RoutedPacket {
                data: msg,
                peer_endpoint: discovered.endpoint,
            })
            .await;

        // Store the session key from our side
        state
            .set_session_key(&discovered.public_key, hs.session_key)
            .await;
    }
}
