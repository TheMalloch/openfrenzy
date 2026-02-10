use crate::state::RoutedPacket;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Bind a UDP socket, trying ports from `listen_port` up to `listen_port + 10`.
/// Returns the socket and the port it actually bound to.
pub async fn bind_udp(listen_port: u16) -> Result<(UdpSocket, u16)> {
    for port in listen_port..=listen_port.saturating_add(10) {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
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

/// Task: read datagrams from UDP socket, forward to inbound pipeline with source address.
pub async fn udp_reader_task(socket: Arc<UdpSocket>, tx: mpsc::Sender<RoutedPacket>) {
    let mut buf = vec![0u8; 2048]; // Larger than MTU to handle any overhead

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                debug!(bytes = n, %src_addr, "UDP recv");
                let packet = RoutedPacket {
                    data: buf[..n].to_vec(),
                    peer_endpoint: src_addr,
                };
                if tx.send(packet).await.is_err() {
                    info!("UDP reader channel closed, shutting down");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "UDP recv error");
                // Transient errors are common with UDP, continue
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
