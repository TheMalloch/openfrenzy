use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Create and configure a TUN device, returning the async device handle.
pub fn create_tun_device(
    name: &str,
    virtual_ip: ipnet::Ipv4Net,
) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(virtual_ip.addr())
        .netmask(virtual_ip.netmask())
        .mtu(1420) // Leave room for encryption overhead
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)
        .with_context(|| format!("creating TUN device {name} with IP {virtual_ip}"))?;

    info!(name, %virtual_ip, "TUN device created");
    Ok(dev)
}

/// Task: read packets from the TUN device and forward them to the outbound pipeline.
pub async fn tun_reader_task(
    mut dev: tokio::io::ReadHalf<tun::AsyncDevice>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 1500];

    loop {
        match dev.read(&mut buf).await {
            Ok(0) => {
                warn!("TUN device returned 0 bytes, closing reader");
                break;
            }
            Ok(n) => {
                debug!(bytes = n, "TUN read packet");
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    info!("TUN reader channel closed, shutting down");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "TUN read error");
                break;
            }
        }
    }
}

/// Task: receive decrypted packets from the inbound pipeline and write them to the TUN device.
pub async fn tun_writer_task(
    mut dev: tokio::io::WriteHalf<tun::AsyncDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(packet) = rx.recv().await {
        debug!(bytes = packet.len(), "TUN write packet");
        if let Err(e) = dev.write_all(&packet).await {
            error!(error = %e, "TUN write error");
            break;
        }
    }
    info!("TUN writer channel closed, shutting down");
}
