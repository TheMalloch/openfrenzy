use crate::crypto::handshake::Identity;
use crate::net::hole_punch;
use crate::state::{RoutedPacket, SharedState};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep, timeout, Duration};
use tracing::{debug, info, warn};

#[derive(Clone)]
pub(crate) struct HttpFallback {
    client: reqwest::Client,
    api_url: String,
    /// Shared with the peer API so a token rotation takes effect here too.
    auth_token: Arc<RwLock<String>>,
}

#[derive(serde::Deserialize)]
struct HttpPeerEntry {
    public_key: String,
    virtual_ip: String,
    endpoint: Option<String>,
    lan_endpoint: Option<String>,
}

#[derive(serde::Serialize)]
struct HttpKeepaliveBody<'a> {
    listen_port: u16,
    lan_ips: &'a [String],
}

/// Protocol message types for coordination server communication.
mod proto {
    /// Register with coord server: [0x30][pub_key: 32][listen_port: 2][lan_count: 1][lan_ip: 4]*[caps: 1]
    pub const REGISTER: u8 = 0x30;
    /// Peer list request: [0x31][pub_key: 32]
    pub const PEER_LIST_REQ: u8 = 0x31;
    /// Peer list response: [0x32][count: 2]([pub_key: 32][vip: 4][type: 1][ip: 4|16][port: 2][lan_ip: 4][lan_port: 2])*
    pub const PEER_LIST_RESP: u8 = 0x32;
    /// Keepalive: [0x33][pub_key: 32][lan_count: 1][lan_ip: 4]*[caps: 1]
    pub const KEEPALIVE: u8 = 0x33;
    /// Chunked peer list: [0x34][list_id: 2][idx: 1][total: 1][count: 2](entries as in 0x32)*
    pub const PEER_LIST_CHUNK: u8 = 0x34;

    /// Capability flags advertised in REGISTER / KEEPALIVE.
    pub const CAP_CHUNKED: u8 = 0x01;
}

/// How long to wait for the remaining chunks of a peer list.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Append LAN IPs and capability flags to a message buffer:
/// [lan_count:1][lan_ip_0:4]...[lan_ip_n:4][caps:1]
fn append_tail(msg: &mut Vec<u8>, lan_ips: &[Ipv4Addr]) {
    msg.push(lan_ips.len() as u8);
    for ip in lan_ips {
        msg.extend_from_slice(&ip.octets());
    }
    msg.push(proto::CAP_CHUNKED);
}

/// Build a registration message with LAN IPs.
fn build_register_msg(public_key: &[u8; 32], listen_port: u16, lan_ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(35 + 2 + lan_ips.len() * 4);
    msg.push(proto::REGISTER);
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(&listen_port.to_be_bytes());
    append_tail(&mut msg, lan_ips);
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
    let mut msg = Vec::with_capacity(33 + 2 + lan_ips.len() * 4);
    msg.push(proto::KEEPALIVE);
    msg.extend_from_slice(public_key);
    append_tail(&mut msg, lan_ips);
    msg
}

struct PendingList {
    total: u8,
    chunks: HashMap<u8, (u16, Vec<u8>)>,
    started: Instant,
}

/// Reassembles chunked peer lists (`PEER_LIST_CHUNK`) into the legacy
/// `PEER_LIST_RESP` layout, so the rest of discovery only sees whole lists.
/// A partial list is never returned: acting on one would remove real peers.
#[derive(Default)]
struct PeerListAssembler {
    pending: HashMap<u16, PendingList>,
}

impl PeerListAssembler {
    /// Feed one coord packet. Returns a complete legacy-format peer list when one is ready.
    fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        match *data.first()? {
            proto::PEER_LIST_RESP => Some(data.to_vec()),
            proto::PEER_LIST_CHUNK if data.len() >= 7 => {
                let id = u16::from_be_bytes([data[1], data[2]]);
                let (idx, total) = (data[3], data[4]);
                let count = u16::from_be_bytes([data[5], data[6]]);
                if total == 0 || idx >= total {
                    return None;
                }

                self.pending.retain(|_, p| p.started.elapsed() < CHUNK_TIMEOUT);
                if self.pending.len() >= 16 && !self.pending.contains_key(&id) {
                    self.pending.clear();
                }
                let p = self.pending.entry(id).or_insert_with(|| PendingList {
                    total,
                    chunks: HashMap::new(),
                    started: Instant::now(),
                });
                if p.total != total {
                    return None;
                }
                p.chunks.insert(idx, (count, data[7..].to_vec()));
                if p.chunks.len() < total as usize {
                    return None;
                }

                let p = self.pending.remove(&id)?;
                let mut out = vec![proto::PEER_LIST_RESP, 0, 0];
                let mut n = 0usize;
                for i in 0..p.total {
                    let (c, body) = p.chunks.get(&i)?;
                    n += *c as usize;
                    out.extend_from_slice(body);
                }
                out[1..3].copy_from_slice(&(n.min(u16::MAX as usize) as u16).to_be_bytes());
                Some(out)
            }
            _ => None,
        }
    }
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

        // Read optional LAN IP (4 bytes) + LAN port (2 bytes) appended by new-format servers
        let lan_endpoint = if offset + 6 <= data.len() {
            let lan_ip = Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
            let lan_port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            offset += 6;
            if !lan_ip.is_unspecified() && lan_port != 0 {
                Some(SocketAddr::new(IpAddr::V4(lan_ip), lan_port))
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

/// Send REGISTER and confirm the coordinator actually heard us. A UDP send
/// succeeding proves nothing; the NAT detection reply does.
async fn register_and_confirm(
    state: &SharedState,
    socket: &Arc<UdpSocket>,
    coord_addr: SocketAddr,
    coord_rx: &mut mpsc::Receiver<RoutedPacket>,
    reg_msg: &[u8],
) -> bool {
    if let Err(e) = socket.send_to(reg_msg, coord_addr).await {
        debug!(error = %e, "register send failed");
        return false;
    }
    match hole_punch::detect_nat(socket, &coord_addr, coord_rx).await {
        Ok(detection) => {
            let Some(ep) = detection.public_endpoint else {
                return false;
            };
            info!(?detection, "NAT detection result");
            state.set_our_public_ip(ep.ip()).await;
            true
        }
        Err(e) => {
            debug!(error = %e, "NAT detection failed");
            false
        }
    }
}

/// Task: periodic peer discovery and keepalive with the coordination server.
///
/// Primary path: UDP binary protocol (registration, peer list, keepalive, hole punching).
/// Fallback path: HTTPS polling via `api_url` when UDP becomes unreachable.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn discovery_task(
    state: SharedState,
    identity: Arc<Identity>,
    socket: Arc<UdpSocket>,
    coord_addr: SocketAddr,
    listen_port: u16,
    config_path: std::path::PathBuf,
    virtual_ip: Ipv4Addr,
    mut coord_rx: mpsc::Receiver<RoutedPacket>,
    http_fallback: Option<HttpFallback>,
) {
    let our_pub_key = identity.public_key_bytes();
    let lan_ips = get_lan_ips(virtual_ip);
    info!(?lan_ips, "detected LAN IPs");

    // Fallback state: consecutive UDP failures before switching, retry UDP every 5 min in fallback.
    const UDP_FAIL_THRESHOLD: u32 = 3;
    let mut udp_consecutive_failures: u32 = 0;
    let mut using_http_fallback = false;
    let mut assembler = PeerListAssembler::default();

    // Initial registration with retry/backoff. Static/cached peers keep working
    // meanwhile: the data plane does not depend on this task.
    let mut backoff = Duration::from_secs(1);
    let mut attempts: u32 = 0;
    loop {
        let reg_msg = build_register_msg(&our_pub_key, listen_port, &get_lan_ips(virtual_ip));
        if register_and_confirm(&state, &socket, coord_addr, &mut coord_rx, &reg_msg).await {
            info!(%coord_addr, "registered with coordination server");
            break;
        }
        attempts += 1;
        if attempts >= UDP_FAIL_THRESHOLD && http_fallback.is_some() {
            warn!(attempts, "UDP coord unreachable, starting in HTTP fallback");
            using_http_fallback = true;
            break;
        }
        warn!(?backoff, "coord unreachable over UDP, will retry");
        sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }

    let mut discovery_interval = interval(Duration::from_secs(30));
    let mut keepalive_interval = interval(Duration::from_secs(25));
    let mut reregister_interval = interval(Duration::from_secs(300)); // 5 minutes
    let mut http_retry_interval = interval(Duration::from_secs(300));
    // The first tick of an interval fires immediately; we just registered.
    reregister_interval.tick().await;
    http_retry_interval.tick().await;

    loop {
        tokio::select! {
            _ = discovery_interval.tick() => {
                if using_http_fallback {
                    if let Some(ref fb) = http_fallback {
                        http_fetch_peers(fb, &our_pub_key, &state, &identity, &socket, &config_path).await;
                    }
                    continue;
                }

                // UDP peer list request
                let req = build_peer_list_req(&our_pub_key);
                if let Err(e) = socket.send_to(&req, coord_addr).await {
                    warn!(error = %e, "failed to send peer list request");
                    udp_consecutive_failures += 1;
                } else {
                    match timeout(Duration::from_secs(5), recv_peer_list(&mut coord_rx, &mut assembler)).await {
                        Ok(Some(data)) => {
                            udp_consecutive_failures = 0;
                            process_peer_list_data(&data, &our_pub_key, &state, &identity, &socket, &config_path).await;
                        }
                        Ok(None) => debug!("coord channel closed"),
                        Err(_) => {
                            debug!("peer list request timed out");
                            udp_consecutive_failures += 1;
                        }
                    }
                }

                if udp_consecutive_failures >= UDP_FAIL_THRESHOLD {
                    if http_fallback.is_some() {
                        warn!(failures = udp_consecutive_failures, "UDP coord unreachable, switching to HTTP fallback");
                        using_http_fallback = true;
                        http_retry_interval.reset();
                    } else {
                        warn!(failures = udp_consecutive_failures, "UDP coord unreachable, no HTTP fallback configured");
                        udp_consecutive_failures = 0; // reset so we keep logging periodically
                    }
                }
            }
            _ = keepalive_interval.tick() => {
                if using_http_fallback {
                    if let Some(ref fb) = http_fallback {
                        let current_lan_ips: Vec<String> = get_lan_ips(virtual_ip)
                            .iter().map(|ip| ip.to_string()).collect();
                        http_send_keepalive(fb, listen_port, &current_lan_ips).await;
                    }
                    continue;
                }

                let current_lan_ips = get_lan_ips(virtual_ip);
                let msg = build_keepalive(&our_pub_key, &current_lan_ips);
                if let Err(e) = socket.send_to(&msg, coord_addr).await {
                    warn!(error = %e, "keepalive send failed");
                }
            }
            _ = reregister_interval.tick(), if !using_http_fallback => {
                // Periodic re-register: updates coord server with our current
                // public IP (UDP source) and fresh LAN IPs, and re-runs NAT
                // detection to catch public IP changes.
                let old_ip = state.get_our_public_ip().await;
                let current_lan_ips = get_lan_ips(virtual_ip);
                let reg_msg = build_register_msg(&our_pub_key, listen_port, &current_lan_ips);
                if register_and_confirm(&state, &socket, coord_addr, &mut coord_rx, &reg_msg).await {
                    let new_ip = state.get_our_public_ip().await;
                    if old_ip != new_ip {
                        info!(?old_ip, ?new_ip, "public IP changed");
                    }
                    debug!(?current_lan_ips, "periodic re-register confirmed");
                } else {
                    debug!("periodic re-register not confirmed");
                }
            }
            // Handle unsolicited peer list pushes from the coordination server
            Some(pkt) = coord_rx.recv() => {
                if let Some(list) = assembler.push(&pkt.data) {
                    info!("received pushed peer list from coordination server");
                    process_peer_list_data(&list, &our_pub_key, &state, &identity, &socket, &config_path).await;
                }
            }
            // Periodically retry UDP while in fallback mode. Leave fallback
            // only once the coordinator actually answers over UDP.
            _ = http_retry_interval.tick(), if using_http_fallback => {
                let reg_msg = build_register_msg(&our_pub_key, listen_port, &get_lan_ips(virtual_ip));
                if register_and_confirm(&state, &socket, coord_addr, &mut coord_rx, &reg_msg).await {
                    // The coordinator only answers PEER_LIST_REQ from the
                    // address a key registered from; allow a couple of tries
                    // in case the REGISTER is still being processed.
                    let req = build_peer_list_req(&our_pub_key);
                    let mut reply = None;
                    for _ in 0..3 {
                        if socket.send_to(&req, coord_addr).await.is_err() {
                            break;
                        }
                        if let Ok(Some(data)) = timeout(Duration::from_secs(2), recv_peer_list(&mut coord_rx, &mut assembler)).await {
                            reply = Some(data);
                            break;
                        }
                    }
                    if let Some(data) = reply {
                        info!("UDP coord reachable again, leaving HTTP fallback");
                        using_http_fallback = false;
                        udp_consecutive_failures = 0;
                        process_peer_list_data(&data, &our_pub_key, &state, &identity, &socket, &config_path).await;
                        continue;
                    }
                }
                debug!("UDP coord still unreachable, staying in HTTP fallback");
            }
        }
    }
}

/// Send a keepalive via HTTPS.
async fn http_send_keepalive(fb: &HttpFallback, listen_port: u16, lan_ips: &[String]) {
    let body = HttpKeepaliveBody { listen_port, lan_ips };
    let url = format!("{}/api/v1/node/keepalive", fb.api_url);
    let token = fb.auth_token.read().await.clone();
    match fb.client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => warn!(status = %resp.status(), "HTTP keepalive rejected by coordination server"),
        Err(e) => warn!(error = %e, "HTTP keepalive failed"),
    }
}

/// Fetch peer list via HTTPS and process any discovered peers.
async fn http_fetch_peers(
    fb: &HttpFallback,
    our_pub_key: &[u8; 32],
    state: &SharedState,
    identity: &Identity,
    socket: &Arc<UdpSocket>,
    config_path: &std::path::Path,
) {
    let url = format!("{}/api/v1/node/peers", fb.api_url);
    let token = fb.auth_token.read().await.clone();
    let resp = match fb.client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            warn!(status = %r.status(), "HTTP peer list rejected by coordination server");
            return;
        }
        Err(e) => {
            warn!(error = %e, "HTTP peer list request failed");
            return;
        }
    };

    let entries: Vec<HttpPeerEntry> = match resp.json().await {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "failed to parse HTTP peer list");
            return;
        }
    };

    let mut changed = false;
    let mut seen_keys: Vec<[u8; 32]> = Vec::new();

    for entry in &entries {
        let pub_key_bytes = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &entry.public_key,
        ) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_key_bytes);

        if pub_key == *our_pub_key {
            continue;
        }
        seen_keys.push(pub_key);

        let virtual_ip: Ipv4Addr = match entry.virtual_ip.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let endpoint: SocketAddr = match entry.endpoint.as_deref().and_then(|s| s.parse().ok()) {
            Some(ep) => ep,
            None => continue,
        };
        let lan_endpoint: Option<SocketAddr> = entry.lan_endpoint.as_deref()
            .and_then(|s| s.parse().ok());

        let discovered = DiscoveredPeer { public_key: pub_key, virtual_ip, endpoint, lan_endpoint };
        let was_new = process_discovered_peer(state, identity, socket, &discovered).await;
        if was_new {
            changed = true;
        }
    }

    if remove_unlisted_peers(state, &seen_keys).await {
        changed = true;
    }

    if changed {
        rewrite_config_peers(config_path, state).await;
    }
}

/// Build an `HttpFallback` from optional config values. Returns `None` if either field is absent.
pub(crate) fn build_http_fallback(
    api_url: Option<String>,
    auth_token: Option<Arc<RwLock<String>>>,
) -> Option<HttpFallback> {
    let api_url = api_url?;
    let auth_token = auth_token?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    Some(HttpFallback { client, api_url, auth_token })
}

/// Remove discovered peers the server no longer lists. Static peers stay.
/// Returns true if anything was removed.
async fn remove_unlisted_peers(state: &SharedState, listed: &[[u8; 32]]) -> bool {
    let stale: Vec<[u8; 32]> = state
        .peers
        .read()
        .await
        .values()
        .filter(|p| !p.static_peer && !listed.contains(&p.public_key))
        .map(|p| p.public_key)
        .collect();
    for key in &stale {
        state.remove_peer(key).await;
        let pub_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
        info!(public_key = %pub_key_b64, "removed stale peer");
    }
    !stale.is_empty()
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
            if remove_unlisted_peers(state, &server_keys).await {
                changed = true;
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

/// Read from the coord channel until a complete peer list arrives (a legacy
/// 0x32 or a fully reassembled chunked list). Returns None if the channel closed.
async fn recv_peer_list(
    coord_rx: &mut mpsc::Receiver<RoutedPacket>,
    assembler: &mut PeerListAssembler,
) -> Option<Vec<u8>> {
    while let Some(pkt) = coord_rx.recv().await {
        if let Some(list) = assembler.push(&pkt.data) {
            return Some(list);
        }
        // Not (yet) a complete peer list — could be a chunk or a late NAT response
        debug!(msg_type = format!("0x{:02x}", pkt.data.first().copied().unwrap_or(0)), "coord packet did not complete a peer list");
    }
    None
}

/// Choose the best endpoint for a discovered peer.
/// If the peer shares our public IP (same NAT), prefer the LAN endpoint.
fn select_endpoint(discovered: &DiscoveredPeer, our_public_ip: Option<IpAddr>) -> SocketAddr {
    if let (Some(our_ip), Some(lan_ep)) = (our_public_ip, discovered.lan_endpoint) {
        if discovered.endpoint.ip() == our_ip {
            debug!(
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
/// Returns true if the peer was newly added or its endpoint changed.
///
/// Never blocks on hole punching: a full punch sequence runs in the background
/// for new/changed endpoints, and known peers get a single probe to keep the
/// NAT mapping open.
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

    if let Some(ref existing_peer) = existing {
        let old_endpoint = existing_peer.endpoint;
        state
            .set_peer_endpoint(&discovered.public_key, effective_endpoint)
            .await;
        // Treat an endpoint change as a state change so the config file gets rewritten.
        is_new = old_endpoint != Some(effective_endpoint);
    } else if !discovered.virtual_ip.is_unspecified() {
        // New peer with a valid virtual IP — add to state
        let allowed_ip: ipnet::Ipv4Net = format!("{}/32", discovered.virtual_ip)
            .parse()
            .expect("valid /32 net");

        state
            .add_peer(crate::state::PeerInfo::new(
                discovered.public_key,
                Some(effective_endpoint),
                discovered.virtual_ip,
                vec![allowed_ip],
            ))
            .await;

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

    if effective_endpoint.port() == 0 || effective_endpoint.ip().is_unspecified() {
        return is_new;
    }

    let our_key = identity.public_key_bytes();
    if is_new {
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Err(e) = hole_punch::punch_hole(&socket, effective_endpoint, &our_key).await {
                warn!(error = %e, "hole punch failed");
            }
        });
    } else if let Err(e) = hole_punch::send_probe(socket, effective_endpoint, &our_key).await {
        debug!(error = %e, "keepalive probe failed");
    }

    is_new
}

/// Rewrite the `[[peers]]` entries of the config file from current SharedState.
///
/// Everything else in the file (other sections, comments, formatting) is kept.
/// Static peers (`static = true`) are kept as written; discovered peers are
/// replaced. The file is written atomically and never world-readable — it
/// holds the private key.
async fn rewrite_config_peers(config_path: &std::path::Path, state: &SharedState) {
    let existing = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to read config file for rewrite");
            return;
        }
    };

    let peers: Vec<crate::state::PeerInfo> = state
        .peers
        .read()
        .await
        .values()
        .filter(|p| !p.static_peer)
        .cloned()
        .collect();

    let new_config = match render_config_peers(&existing, &peers) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to update config file peers");
            return;
        }
    };

    let path = config_path.to_path_buf();
    let count = peers.len();
    let result = tokio::task::spawn_blocking(move || {
        crate::util::write_private(&path, new_config.as_bytes())
    })
    .await;
    match result {
        Ok(Ok(())) => info!(path = %config_path.display(), peers = count, "rewrote config peers section"),
        Ok(Err(e)) => warn!(error = %e, "failed to rewrite config file"),
        Err(e) => warn!(error = %e, "config rewrite task failed"),
    }
}

/// Pure part of `rewrite_config_peers`: replace discovered `[[peers]]` in
/// `existing` with `peers`, keeping static peers and everything else.
fn render_config_peers(existing: &str, peers: &[crate::state::PeerInfo]) -> Result<String> {
    use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

    let mut doc: DocumentMut = existing.parse()?;

    let mut out = ArrayOfTables::new();
    if let Some(old) = doc.get("peers").and_then(Item::as_array_of_tables) {
        for t in old.iter() {
            if t.get("static").and_then(Item::as_bool).unwrap_or(false) {
                out.push(t.clone());
            }
        }
    }

    for peer in peers {
        let pub_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            peer.public_key,
        );
        let mut t = Table::new();
        t["public_key"] = value(pub_key_b64);
        let mut allowed = Array::new();
        allowed.push(format!("{}/32", peer.virtual_ip));
        t["allowed_ips"] = value(allowed);
        if let Some(ep) = peer.endpoint {
            t["endpoint"] = value(ep.to_string());
        }
        out.push(t);
    }

    doc.remove("peers");
    if !out.is_empty() {
        doc.insert("peers", Item::ArrayOfTables(out));
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: u8) -> Vec<u8> {
        let mut e = vec![key; 32];
        e.extend_from_slice(&[10, 0, 0, key, 0x04, 1, 2, 3, 4, 0, 5, 0, 0, 0, 0, 0, 0]);
        e
    }

    fn chunk(id: u16, idx: u8, total: u8, keys: &[u8]) -> Vec<u8> {
        let mut d = vec![proto::PEER_LIST_CHUNK];
        d.extend_from_slice(&id.to_be_bytes());
        d.extend_from_slice(&[idx, total]);
        d.extend_from_slice(&(keys.len() as u16).to_be_bytes());
        for k in keys {
            d.extend(entry(*k));
        }
        d
    }

    #[test]
    fn assembler_waits_for_all_chunks_in_any_order() {
        let mut a = PeerListAssembler::default();
        assert!(a.push(&chunk(7, 1, 2, &[3])).is_none());
        let list = a.push(&chunk(7, 0, 2, &[1, 2])).expect("complete");
        let peers = parse_peer_list(&list).unwrap();
        let keys: Vec<u8> = peers.iter().map(|p| p.public_key[0]).collect();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn assembler_keeps_lists_apart_and_passes_legacy_through() {
        let mut a = PeerListAssembler::default();
        assert!(a.push(&chunk(1, 0, 2, &[1])).is_none());
        assert!(a.push(&chunk(2, 0, 2, &[9])).is_none());
        assert!(a.push(&chunk(1, 1, 2, &[2])).is_some());
        assert!(a.push(&[proto::PEER_LIST_RESP, 0, 0]).is_some());
        assert!(a.push(&[0x11, 4, 1, 2, 3, 4, 0, 1]).is_none());
        assert!(a.push(&chunk(3, 5, 2, &[1])).is_none(), "idx out of range");
    }

    #[test]
    fn config_rewrite_keeps_other_sections_and_static_peers() {
        let existing = r#"# my node
[node]
private_key = "k"

[[peers]]
public_key = "static-one"
allowed_ips = ["192.168.50.0/24"]
static = true

[[peers]]
public_key = "old-discovered"
allowed_ips = ["10.0.0.9/32"]

[peer_api]
enabled = true
"#;
        let peer = crate::state::PeerInfo::new(
            [1; 32],
            Some("1.2.3.4:51820".parse().unwrap()),
            "10.0.0.2".parse().unwrap(),
            vec![],
        );
        let out = render_config_peers(existing, &[peer]).unwrap();
        assert!(out.contains("# my node"));
        assert!(out.contains("[peer_api]\nenabled = true"));
        assert!(out.contains("static-one"));
        assert!(!out.contains("old-discovered"));
        assert!(out.contains("10.0.0.2/32") && out.contains("1.2.3.4:51820"));
        let parsed: toml::Table = out.parse().unwrap();
        assert_eq!(parsed["peers"].as_array().unwrap().len(), 2);
    }
}
