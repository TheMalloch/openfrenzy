use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

/// Detected NAT type from STUN-like probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — public IP matches socket address.
    None,
    /// Endpoint-independent mapping (full cone / restricted cone).
    /// Hole punching will work.
    EndpointIndependent,
    /// Endpoint-dependent mapping (symmetric NAT).
    /// Hole punching unreliable, needs relay.
    EndpointDependent,
    /// Could not determine NAT type.
    Unknown,
}

/// Result of NAT detection: our publicly visible endpoint and NAT type.
#[derive(Debug, Clone)]
pub struct NatDetection {
    pub nat_type: NatType,
    pub public_endpoint: Option<SocketAddr>,
}

/// Detect our NAT type by querying the coordination server.
///
/// Sends a STUN-like probe: the server echoes back our observed endpoint.
/// If the observed endpoint matches our local socket, we're not behind NAT.
pub async fn detect_nat(
    socket: &Arc<UdpSocket>,
    coord_server: &SocketAddr,
) -> Result<NatDetection> {
    // Send probe packet: [0x10] = NAT detection request
    let probe = [0x10u8];
    socket
        .send_to(&probe, coord_server)
        .await
        .context("sending NAT probe")?;

    // Wait for response: [0x11][type: 1][ip: 4|16][port: 2]
    let mut buf = [0u8; 32];
    let result = timeout(Duration::from_secs(5), async {
        loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            if src == *coord_server && n >= 8 && buf[0] == 0x11 {
                return Ok::<_, anyhow::Error>(n);
            }
        }
    })
    .await;

    match result {
        Ok(Ok(n)) if n >= 8 => {
            let public_endpoint = match buf[1] {
                0x04 if n >= 8 => {
                    let ip = std::net::Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5]);
                    let port = u16::from_be_bytes([buf[6], buf[7]]);
                    SocketAddr::new(std::net::IpAddr::V4(ip), port)
                }
                0x06 if n >= 20 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[2..18]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([buf[18], buf[19]]);
                    SocketAddr::new(std::net::IpAddr::V6(ip), port)
                }
                _ => {
                    warn!(addr_type = buf[1], "unknown address type in NAT detection response");
                    return Ok(NatDetection {
                        nat_type: NatType::Unknown,
                        public_endpoint: None,
                    });
                }
            };

            let local_addr = socket.local_addr()?;
            let nat_type = if local_addr.ip().is_unspecified() {
                // Can't compare 0.0.0.0 directly, assume some NAT
                NatType::EndpointIndependent
            } else if local_addr == public_endpoint {
                NatType::None
            } else {
                NatType::EndpointIndependent
            };

            info!(%public_endpoint, ?nat_type, "NAT detection complete");
            Ok(NatDetection {
                nat_type,
                public_endpoint: Some(public_endpoint),
            })
        }
        _ => {
            warn!("NAT detection failed or timed out");
            Ok(NatDetection {
                nat_type: NatType::Unknown,
                public_endpoint: None,
            })
        }
    }
}

/// Attempt UDP hole punching to a peer's reported public endpoint.
///
/// Sends several probe packets to open NAT mappings. The peer should be
/// doing the same simultaneously for the symmetric open to succeed.
pub async fn punch_hole(
    socket: &Arc<UdpSocket>,
    peer_endpoint: SocketAddr,
    our_public_key: &[u8; 32],
) -> Result<()> {
    // Hole punch probe: [0x20][our_public_key: 32 bytes]
    let mut probe = Vec::with_capacity(33);
    probe.push(0x20);
    probe.extend_from_slice(our_public_key);

    // Send multiple probes with increasing delays
    for i in 0..5 {
        debug!(attempt = i, %peer_endpoint, "sending hole punch probe");
        socket
            .send_to(&probe, peer_endpoint)
            .await
            .with_context(|| format!("hole punch probe {i}"))?;
        tokio::time::sleep(Duration::from_millis(200 * (i + 1) as u64)).await;
    }

    info!(%peer_endpoint, "hole punch probes sent");
    Ok(())
}
