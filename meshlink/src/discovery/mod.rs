use crate::crypto::handshake::Identity;
use crate::net::hole_punch;
use crate::state::{RoutedPacket, SharedState};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    pub virtual_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub lan_endpoint: Option<SocketAddr>,
}

/// Get LAN IPv4 addresses for this machine, excluding loopback, link-local,
/// and the mesh virtual IP. Returns up to 4 addresses.
fn get_lan_ips(exclude_vip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if let std::net::IpAddr::V4(ip) = iface.ip() {
                if ip.is_loopback() || ip.is_link_local() || ip == exclude_vip || ip.is_unspecified() {
                    continue;
                }
                ips.push(ip);
                if ips.len() >= 4 {
                    break;
                }
            }
        }
    }
    ips
}

/// Append LAN IPs to a message buffer: [lan_count:1][lan_ip_0:4]...[lan_ip_n:4]
fn append_lan_ips(msg: &mut Vec<u8>, lan_ips: &[Ipv4Addr]) {
    msg.push(lan_ips.len() as u8);
    for ip in lan_ips {
        msg.extend_from_slice(&ip.octets());
    }
}

/// Build a registration message with LAN IPs.
fn build_register_msg(public_key: &[u8; 32], listen_port: u16, lan_ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(35 + 1 + lan_ips.len() * 4);
    msg.push(proto::REGISTER);
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(&listen_port.to_be_bytes());
    append_lan_ips(&mut msg, lan_ips);
    msg
}

/// Build a peer list request message.
fn build_peer_list_req(public_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(33);
    msg.push(proto::PEER_LIST_REQ);
    msg.extend_from_slice(public_key);
    msg
}

/// Build a keepalive message with LAN IPs.
fn build_keepalive(public_key: &[u8; 32], lan_ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(33 + 1 + lan_ips.len() * 4);
    msg.push(proto::KEEPALIVE);
    msg.extend_from_slice(public_key);
    append_lan_ips(&mut msg, lan_ips);
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

        // Read optional LAN IP (4 bytes) appended by new-format servers
        let lan_endpoint = if offset + 4 <= data.len() {
            let lan_ip = Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
            offset += 4;
            if !lan_ip.is_unspecified() {
                Some(SocketAddr::new(IpAddr::V4(lan_ip), endpoint.port()))
            } else {
                None
            }
        } else {
            None
        };

        peers.push(DiscoveredPeer {
            public_key,
            virtual_ip,
            endpoint,
            lan_endpoint,
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
/// 5. Handle unsolicited peer list pushes from the server
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
    virtual_ip: Ipv4Addr,
    mut coord_rx: mpsc::Receiver<RoutedPacket>,
) {
    let our_pub_key = identity.public_key_bytes();
    let lan_ips = get_lan_ips(virtual_ip);
    info!(?lan_ips, "detected LAN IPs");

    // Initial registration with LAN IPs
    let reg_msg = build_register_msg(&our_pub_key, listen_port, &lan_ips);
    if let Err(e) = socket.send_to(&reg_msg, coord_addr).await {
        error!(error = %e, "failed to register with coordination server");
        return;
    }
    info!(%coord_addr, "registered with coordination server");

    // NAT detection (response comes through coord_rx)
    match hole_punch::detect_nat(&socket, &coord_addr, &mut coord_rx).await {
        Ok(detection) => {
            info!(?detection, "NAT detection result");
            if let Some(ep) = detection.public_endpoint {
                state.set_our_public_ip(ep.ip()).await;
            }
        }
        Err(e) => {
            warn!(error = %e, "NAT detection failed, continuing anyway");
        }
    }

    let mut discovery_interval = interval(Duration::from_secs(30));
    let mut keepalive_interval = interval(Duration::from_secs(25));
    let mut reregister_interval = interval(Duration::from_secs(300)); // 5 minutes

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
                        process_peer_list_data(&data, &our_pub_key, &state, &identity, &socket, &config_path).await;
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
                let current_lan_ips = get_lan_ips(virtual_ip);
                let msg = build_keepalive(&our_pub_key, &current_lan_ips);
                if let Err(e) = socket.send_to(&msg, coord_addr).await {
                    warn!(error = %e, "keepalive send failed");
                }
            }
            _ = reregister_interval.tick() => {
                // Periodic re-register: updates coord server with our current
                // public IP (UDP source) and fresh LAN IPs
                let current_lan_ips = get_lan_ips(virtual_ip);
                let reg_msg = build_register_msg(&our_pub_key, listen_port, &current_lan_ips);
                if let Err(e) = socket.send_to(&reg_msg, coord_addr).await {
                    warn!(error = %e, "periodic re-register failed");
                } else {
                    debug!(?current_lan_ips, "periodic re-register sent");
                }

                // Re-run NAT detection to catch public IP changes
                match hole_punch::detect_nat(&socket, &coord_addr, &mut coord_rx).await {
                    Ok(detection) => {
                        if let Some(ep) = detection.public_endpoint {
                            let old_ip = state.get_our_public_ip().await;
                            let new_ip = ep.ip();
                            if old_ip != Some(new_ip) {
                                info!(?old_ip, %new_ip, "public IP changed");
                            }
                            state.set_our_public_ip(new_ip).await;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "periodic NAT re-detection failed");
                    }
                }
            }
            // Handle unsolicited peer list pushes from the coordination server
            Some(pkt) = coord_rx.recv() => {
                if !pkt.data.is_empty() && pkt.data[0] == proto::PEER_LIST_RESP {
                    info!("received pushed peer list from coordination server");
                    process_peer_list_data(&pkt.data, &our_pub_key, &state, &identity, &socket, &config_path).await;
                }
            }
        }
    }
}

/// Process a raw peer list response: parse, update state, rewrite config.
async fn process_peer_list_data(
    data: &[u8],
    our_pub_key: &[u8; 32],
    state: &SharedState,
    identity: &Identity,
    socket: &Arc<UdpSocket>,
    config_path: &std::path::Path,
) {
    match parse_peer_list(data) {
        Ok(peers) => {
            debug!(count = peers.len(), "received peer list");
            let mut changed = false;
            for discovered in &peers {
                if discovered.public_key == *our_pub_key {
                    continue; // Skip ourselves
                }
                let was_new = process_discovered_peer(
                    state,
                    identity,
                    socket,
                    discovered,
                ).await;
                if was_new {
                    changed = true;
                }
            }

            // Remove peers that are no longer in the server's list
            let server_keys: Vec<[u8; 32]> = peers.iter()
                .filter(|p| p.public_key != *our_pub_key)
                .map(|p| p.public_key)
                .collect();
            let current_keys: Vec<[u8; 32]> = {
                let peer_map = state.peers.read().await;
                peer_map.keys().copied().collect()
            };
            for key in &current_keys {
                if !server_keys.contains(key) {
                    state.remove_peer(key).await;
                    changed = true;
                    let pub_key_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        key,
                    );
                    info!(public_key = %pub_key_b64, "removed stale peer");
                }
            }

            if changed {
                rewrite_config_peers(config_path, state).await;
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to parse peer list");
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

/// Choose the best endpoint for a discovered peer.
/// If the peer shares our public IP (same NAT), prefer the LAN endpoint.
fn select_endpoint(discovered: &DiscoveredPeer, our_public_ip: Option<IpAddr>) -> SocketAddr {
    if let (Some(our_ip), Some(lan_ep)) = (our_public_ip, discovered.lan_endpoint) {
        if discovered.endpoint.ip() == our_ip {
            info!(
                public = %discovered.endpoint,
                lan = %lan_ep,
                vip = %discovered.virtual_ip,
                "same-NAT peer detected, using LAN endpoint"
            );
            return lan_ep;
        }
    }
    discovered.endpoint
}

/// Process a newly discovered peer: update state, add if new, and hole punch for NAT traversal.
/// Returns true if the peer was newly added.
async fn process_discovered_peer(
    state: &SharedState,
    identity: &Identity,
    socket: &Arc<UdpSocket>,
    discovered: &DiscoveredPeer,
) -> bool {
    // Skip peers with real IPv6 endpoints — our socket is dual-stack but the
    // peer may be unreachable if we have no IPv6 route.
    if discovered.endpoint.is_ipv6() {
        debug!(
            endpoint = %discovered.endpoint,
            vip = %discovered.virtual_ip,
            "skipping peer with IPv6 endpoint"
        );
        return false;
    }

    let our_public_ip = state.get_our_public_ip().await;
    let effective_endpoint = select_endpoint(discovered, our_public_ip);

    let existing = state.get_peer(&discovered.public_key).await;
    let is_new;

    if existing.is_some() {
        // Peer already known — just update endpoint
        state
            .set_peer_endpoint(&discovered.public_key, effective_endpoint)
            .await;
        is_new = false;
    } else if !discovered.virtual_ip.is_unspecified() {
        // New peer with a valid virtual IP — add to state
        let allowed_ip: ipnet::Ipv4Net = format!("{}/32", discovered.virtual_ip)
            .parse()
            .expect("valid /32 net");

        let peer_info = crate::state::PeerInfo {
            public_key: discovered.public_key,
            endpoint: Some(effective_endpoint),
            virtual_ip: discovered.virtual_ip,
            allowed_ips: vec![allowed_ip],
            tx_bytes: 0,
            rx_bytes: 0,
        };
        state.add_peer(peer_info).await;

        let pub_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            discovered.public_key,
        );
        info!(
            vip = %discovered.virtual_ip,
            endpoint = %effective_endpoint,
            public_key = %pub_key_b64,
            "added new discovered peer"
        );
        is_new = true;
    } else {
        debug!(endpoint = %discovered.endpoint, "discovered peer has no virtual IP, skipping");
        return false;
    }

    // Attempt hole punch for NAT traversal (use effective endpoint)
    if let Err(e) = hole_punch::punch_hole(
        socket,
        effective_endpoint,
        &identity.public_key_bytes(),
    )
    .await
    {
        warn!(error = %e, "hole punch failed");
    }

    is_new
}

/// Rewrite the [[peers]] section of the config file from current SharedState.
/// Preserves [node] and [coordination] sections, replaces all [[peers]] entries.
async fn rewrite_config_peers(config_path: &std::path::Path, state: &SharedState) {
    let peers = state.peers.read().await;

    // Read existing config and keep everything before the first [[peers]]
    let existing = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to read config file for rewrite");
            return;
        }
    };

    // Find where [[peers]] section starts (or end of file)
    let peers_start = existing.find("\n[[peers]]")
        .map(|i| i + 1) // keep the newline before
        .unwrap_or(existing.len());

    let mut new_config = existing[..peers_start].to_string();

    // Ensure there's a trailing newline before peers section
    if !new_config.ends_with('\n') {
        new_config.push('\n');
    }

    // Write all current peers
    for peer in peers.values() {
        let pub_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            peer.public_key,
        );
        new_config.push_str(&format!(
            "\n[[peers]]\npublic_key = \"{pub_key_b64}\"\nallowed_ips = [\"{}/32\"]\n",
            peer.virtual_ip,
        ));
        if let Some(ep) = peer.endpoint {
            new_config.push_str(&format!("endpoint = \"{ep}\"\n"));
        }
    }

    if let Err(e) = std::fs::write(config_path, &new_config) {
        warn!(error = %e, "failed to rewrite config file");
    } else {
        info!(path = %config_path.display(), peers = peers.len(), "rewrote config peers section");
    }
}
