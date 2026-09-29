use crate::state::RoutedPacket;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

/// Convert IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4.
/// Leaves everything else unchanged.
pub fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

/// Bind a UDP socket, trying ports from `listen_port` up to `listen_port + 10`.
/// Returns the socket and the port it actually bound to.
pub async fn bind_udp(listen_port: u16) -> Result<(UdpSocket, u16)> {
    for port in listen_port..=listen_port.saturating_add(10) {
        let addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                if port != listen_port {
                    info!(%addr, configured_port = listen_port, "UDP socket bound (configured port was in use)");
                } else {
                    info!(%addr, "UDP socket bound");
                }
                return Ok((socket, port));
            }
            Err(e) => {
                debug!(port, error = %e, "port unavailable, trying next");
            }
        }
    }
    anyhow::bail!(
        "could not bind UDP socket on ports {listen_port}–{}",
        listen_port.saturating_add(10)
    )
}

/// Task: read datagrams from UDP socket, dispatch by packet type.
///
/// - `0x04` (data packets) → `data_tx` (to inbound router)
/// - `0x11`, `0x32`, `0x34` (coord protocol responses) → `coord_tx` (to discovery task),
///   only when they come from `coord_addr` (normalized; unset = drop)
/// - everything else → log and drop
pub async fn udp_reader_task(
    socket: Arc<UdpSocket>,
    data_tx: mpsc::Sender<RoutedPacket>,
    coord_tx: mpsc::Sender<RoutedPacket>,
    coord_addr: Arc<std::sync::OnceLock<SocketAddr>>,
) {
    // Max UDP payload: large peer lists must not be silently truncated.
    let mut buf = vec![0u8; 65536];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, raw_src)) => {
                if n == 0 {
                    continue;
                }
                let src_addr = normalize_addr(raw_src);
                let first = buf[0];

                match first {
                    // Data packet
                    0x04 => {
                        debug!(bytes = n, %src_addr, "UDP recv data");
                        let packet = RoutedPacket {
                            data: buf[..n].to_vec(),
                            peer_endpoint: src_addr,
                        };
                        if data_tx.send(packet).await.is_err() {
                            info!("UDP reader data channel closed, shutting down");
                            break;
                        }
                    }
                    // Coord protocol responses: NAT detect resp (0x11), peer list
                    // resp (0x32), chunked peer list (0x34)
                    0x11 | 0x32 | 0x34 => {
                        // Anyone can send to our port; only the coordinator may
                        // drive NAT detection or rewrite our peer table.
                        if coord_addr.get() != Some(&src_addr) {
                            trace!(%src_addr, msg_type = format!("0x{:02x}", first), "coord packet from non-coord source, dropping");
                            continue;
                        }
                        debug!(bytes = n, %src_addr, msg_type = format!("0x{:02x}", first), "UDP recv coord");
                        let packet = RoutedPacket {
                            data: buf[..n].to_vec(),
                            peer_endpoint: src_addr,
                        };
                        // Never block the data plane on a busy discovery task.
                        match coord_tx.try_send(packet) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("coord channel full, dropping coord packet");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                debug!("coord channel closed, dropping coord packet");
                            }
                        }
                    }
                    // Hole punch probe — log and drop
                    0x20 => {
                        debug!(bytes = n, %src_addr, "hole punch probe received, dropping");
                    }
                    _ => {
                        trace!(bytes = n, %src_addr, msg_type = format!("0x{:02x}", first), "unknown packet type, dropping");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "UDP recv error");
                continue;
            }
        }
    }
}

/// Task: receive encrypted packets from outbound pipeline, send via UDP.
pub async fn udp_writer_task(socket: Arc<UdpSocket>, mut rx: mpsc::Receiver<RoutedPacket>) {
    while let Some(packet) = rx.recv().await {
        debug!(bytes = packet.data.len(), dest = %packet.peer_endpoint, "UDP send");
        if let Err(e) = socket.send_to(&packet.data, packet.peer_endpoint).await {
            error!(error = %e, dest = %packet.peer_endpoint, "UDP send error");
        }
    }
    info!("UDP writer channel closed, shutting down");
}
