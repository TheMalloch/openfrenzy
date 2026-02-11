use crate::crypto::{handshake, transport};
use crate::state::{RoutedPacket, SharedState};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

/// Extract the destination IPv4 address from a raw IP packet.
fn extract_dest_ip(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    // IPv4: version+IHL at byte 0, dest IP at bytes 16..20
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
/// Pipeline: TUN read → route lookup → crypto encrypt → UDP send
pub async fn outbound_router_task(
    state: SharedState,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    udp_tx: mpsc::Sender<RoutedPacket>,
) {
    // Per-peer nonce counters (keyed by peer public key)
    let mut nonce_counters: std::collections::HashMap<[u8; 32], transport::NonceCounter> =
        std::collections::HashMap::new();

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

        // Get peer info for endpoint and session key
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

        let session_key = match peer.session_key {
            Some(k) => k,
            None => {
                debug!(%dest_ip, "no session key for peer, dropping (handshake needed)");
                continue;
            }
        };

        // Encrypt the packet
        let counter = nonce_counters
            .entry(peer_key)
            .or_insert_with(transport::NonceCounter::new);
        let nonce = counter.next();

        match transport::encrypt_packet(&session_key, nonce, &packet) {
            Ok(encrypted) => {
                let len = packet.len() as u64;
                let routed = RoutedPacket {
                    data: encrypted,
                    peer_endpoint: endpoint,
                };
                if udp_tx.send(routed).await.is_err() {
                    break;
                }
                state.add_tx_bytes(&peer_key, len).await;
            }
            Err(e) => {
                error!(error = %e, "encryption failed");
            }
        }
    }
}

/// Task: handle inbound packets from UDP.
///
/// Pipeline: UDP recv → crypto decrypt / handshake → route verify → TUN write
pub async fn inbound_router_task(
    state: SharedState,
    identity: std::sync::Arc<handshake::Identity>,
    mut udp_rx: mpsc::Receiver<RoutedPacket>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    udp_tx: mpsc::Sender<RoutedPacket>,
) {
    while let Some(packet) = udp_rx.recv().await {
        let data = &packet.data;

        if data.is_empty() {
            continue;
        }

        // Dispatch based on packet type
        if transport::is_handshake_packet(data) {
            handle_handshake(&state, &identity, data, packet.peer_endpoint, &udp_tx).await;
        } else if transport::is_data_packet(data) {
            handle_data_packet(&state, data, packet.peer_endpoint, &tun_tx).await;
        } else {
            debug!(packet_type = data[0], "unknown packet type, ignoring");
        }
    }
}

async fn handle_handshake(
    state: &SharedState,
    identity: &handshake::Identity,
    data: &[u8],
    src: std::net::SocketAddr,
    udp_tx: &mpsc::Sender<RoutedPacket>,
) {
    match handshake::parse_handshake(data) {
        Ok((handshake::HandshakeType::Initiation, peer_static_pub, peer_ephemeral_pub)) => {
            debug!(%src, "received handshake initiation");

            // Compute shared secret using our static key + their ephemeral
            let session_key = handshake::respond_handshake(identity, &peer_ephemeral_pub);

            // Update peer state
            state.set_peer_endpoint(&peer_static_pub, src).await;
            state.set_session_key(&peer_static_pub, session_key).await;

            // Send response so initiator knows we completed the handshake.
            // Include our static pub key for identity; ephemeral is zeroed since
            // both sides already derived the session key from the initiation.
            let response = handshake::build_handshake_response(
                &identity.public_key_bytes(),
                &[0u8; 32],
            );

            let _ = udp_tx
                .send(RoutedPacket {
                    data: response,
                    peer_endpoint: src,
                })
                .await;
        }
        Ok((handshake::HandshakeType::Response, peer_static_pub, _peer_ephemeral_pub)) => {
            debug!(%src, "received handshake response");

            // Don't recompute session key — we already derived and stored it
            // when we initiated the handshake. Just confirm the peer's endpoint.
            state.set_peer_endpoint(&peer_static_pub, src).await;
        }
        Err(e) => {
            warn!(error = %e, %src, "failed to parse handshake");
        }
    }
}

async fn handle_data_packet(
    state: &SharedState,
    data: &[u8],
    src: std::net::SocketAddr,
    tun_tx: &mpsc::Sender<Vec<u8>>,
) {
    // We need to find which peer sent this based on the source endpoint
    let peers = state.peers.read().await;
    let peer = peers
        .values()
        .find(|p| p.endpoint == Some(src));

    let (peer_key, session_key) = match peer {
        Some(p) => match p.session_key {
            Some(sk) => (p.public_key, sk),
            None => {
                debug!(%src, "data packet from peer with no session key");
                return;
            }
        },
        None => {
            debug!(%src, "data packet from unknown endpoint");
            return;
        }
    };
    drop(peers);

    match transport::decrypt_packet(&session_key, data) {
        Ok(plaintext) => {
            let len = plaintext.len() as u64;

            // Verify source IP is in allowed_ips
            if let Some(src_ip) = extract_src_ip(&plaintext) {
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
            }

            if tun_tx.send(plaintext).await.is_err() {
                return;
            }
            state.add_rx_bytes(&peer_key, len).await;
        }
        Err(e) => {
            debug!(error = %e, %src, "decryption failed");
        }
    }
}
