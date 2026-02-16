use crate::api_client::ApiClient;
use crate::crypto::handshake::Identity;
use crate::net::hole_punch;
use crate::state::{RoutedPacket, SharedState};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration};
use tracing::{debug, error, info, warn};

/// Protocol message types for coordination server communication.
mod proto {
    /// Register with coord server: [0x30][pub_key: 32][listen_port: 2]
    pub const REGISTER: u8 = 0x30;
    /// Peer list request: [0x31][pub_key: 32]
    pub const PEER_LIST_REQ: u8 = 0x31;
    /// Peer list response: [0x32][count: 2]([pub_key: 32][type: 1][ip: 4|16][port: 2])*
    pub const PEER_LIST_RESP: u8 = 0x32;
    /// Keepalive: [0x33][pub_key: 32]
    pub const KEEPALIVE: u8 = 0x33;
}

/// Parsed peer entry from the coordination server's peer list response.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub public_key: [u8; 32],
    pub virtual_ip: std::net::Ipv4Addr,
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

    let mut peers = Vec::with_capacity(count);
    let mut offset = 3;
    for _ in 0..count {
        // pub_key(32) + virtual_ip(4) + addr_type(1) = 37 bytes minimum
        if offset + 37 > data.len() {
            anyhow::bail!("peer list truncated at entry header");
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);
        let virtual_ip = std::net::Ipv4Addr::new(
            data[offset + 32], data[offset + 33], data[offset + 34], data[offset + 35],
        );
        let addr_type = data[offset + 36];
        offset += 37;

        let endpoint = match addr_type {
            0x04 => {
                if offset + 6 > data.len() {
                    anyhow::bail!("peer list truncated at IPv4 entry");
                }
                let ip = std::net::Ipv4Addr::new(
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                );
                let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
                offset += 6;
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            0x06 => {
                if offset + 18 > data.len() {
                    anyhow::bail!("peer list truncated at IPv6 entry");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
                offset += 18;
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            _ => {
                anyhow::bail!("unknown address type 0x{:02x} in peer list", addr_type);
            }
        };

        peers.push(DiscoveredPeer {
            public_key,
            virtual_ip,
            endpoint,
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
///
/// Coord protocol responses (0x11 NAT, 0x32 peer list) arrive via `coord_rx`,
/// dispatched by `udp_reader_task`. This task only *sends* on the socket.
pub async fn discovery_task(
    state: SharedState,
    identity: Arc<Identity>,
    socket: Arc<UdpSocket>,
    coord_addr: SocketAddr,
    listen_port: u16,
    config_path: std::path::PathBuf,
    mut coord_rx: mpsc::Receiver<RoutedPacket>,
) {
    let our_pub_key = identity.public_key_bytes();

    // Initial registration
    let reg_msg = build_register_msg(&our_pub_key, listen_port);
    if let Err(e) = socket.send_to(&reg_msg, coord_addr).await {
        error!(error = %e, "failed to register with coordination server");
        return;
    }
    info!(%coord_addr, "registered with coordination server");

    // NAT detection (response comes through coord_rx)
    match hole_punch::detect_nat(&socket, &coord_addr, &mut coord_rx).await {
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

                // Wait for peer list response on the coord channel
                match timeout(Duration::from_secs(5), recv_peer_list(&mut coord_rx)).await {
                    Ok(Some(data)) => {
                        match parse_peer_list(&data) {
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
                                        &config_path,
                                    ).await;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to parse peer list");
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("coord channel closed");
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

/// Read from the coord channel until we get a peer list response (0x32).
/// Returns the raw packet data, or None if the channel closed.
async fn recv_peer_list(coord_rx: &mut mpsc::Receiver<RoutedPacket>) -> Option<Vec<u8>> {
    while let Some(pkt) = coord_rx.recv().await {
        if !pkt.data.is_empty() && pkt.data[0] == 0x32 {
            return Some(pkt.data);
        }
        // Not a peer list response — discard (could be a late NAT response)
        debug!(msg_type = format!("0x{:02x}", pkt.data.first().copied().unwrap_or(0)), "discarding non-peer-list coord packet");
    }
    None
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
                                                tx_bytes: 0,
                                                rx_bytes: 0,
                                                acl_rules: Vec::new(),
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

/// Process a newly discovered peer: update state, add if new, and hole punch for NAT traversal.
async fn process_discovered_peer(
    state: &SharedState,
    identity: &Identity,
    socket: &Arc<UdpSocket>,
    discovered: &DiscoveredPeer,
    config_path: &std::path::Path,
) {
    // Skip peers with real IPv6 endpoints — our socket is dual-stack but the
    // peer may be unreachable if we have no IPv6 route. IPv4-mapped addresses
    // are already normalized by udp_reader / coord server, so any remaining V6
    // here is genuinely IPv6-only.
    if discovered.endpoint.is_ipv6() {
        debug!(
            endpoint = %discovered.endpoint,
            vip = %discovered.virtual_ip,
            "skipping peer with IPv6 endpoint"
        );
        return;
    }

    let existing = state.get_peer(&discovered.public_key).await;

    if let Some(_) = existing {
        // Peer already known — just update endpoint
        state
            .set_peer_endpoint(&discovered.public_key, discovered.endpoint)
            .await;
    } else if !discovered.virtual_ip.is_unspecified() {
        // New peer with a valid virtual IP — add to state and config
        let allowed_ip: ipnet::Ipv4Net = format!("{}/32", discovered.virtual_ip)
            .parse()
            .expect("valid /32 net");

        let peer_info = crate::state::PeerInfo {
            public_key: discovered.public_key,
            endpoint: Some(discovered.endpoint),
            virtual_ip: discovered.virtual_ip,
            allowed_ips: vec![allowed_ip],
            tx_bytes: 0,
            rx_bytes: 0,
            acl_rules: Vec::new(),
        };
        state.add_peer(peer_info).await;

        let pub_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            discovered.public_key,
        );
        info!(
            vip = %discovered.virtual_ip,
            endpoint = %discovered.endpoint,
            public_key = %pub_key_b64,
            "added new discovered peer"
        );

        // Append peer to config file
        append_peer_to_config(config_path, &pub_key_b64, discovered.virtual_ip, discovered.endpoint);
    } else {
        debug!(endpoint = %discovered.endpoint, "discovered peer has no virtual IP, skipping");
        return;
    }

    // Attempt hole punch for NAT traversal
    if let Err(e) = hole_punch::punch_hole(
        socket,
        discovered.endpoint,
        &identity.public_key_bytes(),
    )
    .await
    {
        warn!(error = %e, "hole punch failed");
    }
}

/// Append a new peer entry to the config TOML file.
fn append_peer_to_config(
    config_path: &std::path::Path,
    public_key_b64: &str,
    virtual_ip: std::net::Ipv4Addr,
    endpoint: SocketAddr,
) {
    let peer_block = format!(
        r#"
[[peers]]
public_key = "{public_key_b64}"
allowed_ips = ["{virtual_ip}/32"]
endpoint = "{endpoint}"
"#,
    );

    match std::fs::OpenOptions::new().append(true).open(config_path) {
        Ok(mut file) => {
            use std::io::Write;
            if let Err(e) = file.write_all(peer_block.as_bytes()) {
                warn!(error = %e, "failed to append peer to config file");
            } else {
                info!(path = %config_path.display(), "appended new peer to config file");
            }
        }
        Err(e) => {
            warn!(error = %e, path = %config_path.display(), "failed to open config file for appending");
        }
    }
}
