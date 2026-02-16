use crate::crypto::transport;
use crate::net::udp::normalize_addr;
use crate::state::{RoutedPacket, SharedState};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Extract L4 (transport layer) info from an IPv4 packet.
/// Returns (IP protocol number, source port, destination port).
/// TCP=6, UDP=17. Returns None for non-TCP/UDP or if packet is too short.
fn extract_l4_info(packet: &[u8]) -> Option<(u8, u16, u16)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    let protocol = packet[9];
    // Only extract ports for TCP (6) and UDP (17)
    if protocol != 6 && protocol != 17 {
        return None;
    }
    if packet.len() < ihl + 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    Some((protocol, src_port, dst_port))
}

/// Convert IP protocol number to name.
fn protocol_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}

/// Extract the destination IPv4 address from a raw IP packet.
fn extract_dest_ip(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// Extract the source IPv4 address from a raw IP packet.
fn extract_src_ip(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

/// Task: handle outbound packets from TUN.
///
/// Pipeline: TUN read → route lookup → wrap → UDP send
pub async fn outbound_router_task(
    state: SharedState,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    udp_tx: mpsc::Sender<RoutedPacket>,
) {
    while let Some(packet) = tun_rx.recv().await {
        let dest_ip = match extract_dest_ip(&packet) {
            Some(ip) => ip,
            None => {
                trace!("dropping non-IPv4 outbound packet");
                continue;
            }
        };

        // Look up which peer owns this destination
        let peer_key = match state.lookup_route(dest_ip).await {
            Some(key) => key,
            None => {
                trace!(%dest_ip, "no route for destination, dropping");
                continue;
            }
        };

        // Get peer info for endpoint
        let peer = match state.get_peer(&peer_key).await {
            Some(p) => p,
            None => {
                warn!("peer in route table but not in peer table");
                continue;
            }
        };

        let endpoint = match peer.endpoint {
            Some(ep) => ep,
            None => {
                debug!(%dest_ip, "peer has no known endpoint, dropping");
                continue;
            }
        };

        // Outbound ACL check: only for TCP/UDP, ICMP passes through
        if let Some((proto, _src_port, dst_port)) = extract_l4_info(&packet) {
            let proto_name = protocol_name(proto);
            if !state.check_outbound_acl(&peer_key, dst_port, proto_name).await {
                trace!(%dest_ip, dst_port, proto_name, "outbound ACL denied, dropping");
                continue;
            }
        }

        // Wrap the packet with type byte and send
        let wrapped = transport::wrap_packet(&packet);
        let len = packet.len() as u64;
        let routed = RoutedPacket {
            data: wrapped,
            peer_endpoint: endpoint,
        };
        if udp_tx.send(routed).await.is_err() {
            break;
        }
        state.add_tx_bytes(&peer_key, len).await;
    }
}

/// Task: handle inbound packets from UDP.
///
/// Pipeline: UDP recv → unwrap → route verify → TUN write
pub async fn inbound_router_task(
    state: SharedState,
    mut udp_rx: mpsc::Receiver<RoutedPacket>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) {
    while let Some(packet) = udp_rx.recv().await {
        let data = &packet.data;

        if data.is_empty() {
            continue;
        }

        if transport::is_data_packet(data) {
            handle_data_packet(&state, data, packet.peer_endpoint, &tun_tx).await;
        } else {
            debug!(packet_type = data[0], "unknown packet type, ignoring");
        }
    }
}

async fn handle_data_packet(
    state: &SharedState,
    data: &[u8],
    src: std::net::SocketAddr,
    tun_tx: &mpsc::Sender<Vec<u8>>,
) {
    let plaintext = match transport::unwrap_packet(data) {
        Some(p) => p,
        None => {
            debug!(%src, "invalid data packet");
            return;
        }
    };

    // Normalize src in case it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    let src = normalize_addr(src);

    // Find which peer sent this based on the source endpoint
    let peer_key = {
        let peers = state.peers.read().await;
        match peers.values().find(|p| p.endpoint == Some(src)) {
            Some(p) => p.public_key,
            None => {
                debug!(%src, "data packet from unknown endpoint");
                return;
            }
        }
    };

    let len = plaintext.len() as u64;

    // Verify source IP is in allowed_ips
    if let Some(src_ip) = extract_src_ip(plaintext) {
        if let Some(peer) = state.get_peer(&peer_key).await {
            let allowed = peer
                .allowed_ips
                .iter()
                .any(|net| net.contains(&src_ip));
            if !allowed {
                warn!(%src_ip, "packet source IP not in allowed_ips, dropping");
                return;
            }
        }

        // Inbound ACL check: only for TCP/UDP, ICMP passes through
        if let Some((proto, _src_port, dst_port)) = extract_l4_info(plaintext) {
            let proto_name = protocol_name(proto);
            if !state.check_inbound_acl(src_ip, dst_port, proto_name).await {
                trace!(%src_ip, dst_port, proto_name, "inbound ACL denied, dropping");
                return;
            }
        }
    }

    if tun_tx.send(plaintext.to_vec()).await.is_err() {
        return;
    }
    state.add_rx_bytes(&peer_key, len).await;
}
