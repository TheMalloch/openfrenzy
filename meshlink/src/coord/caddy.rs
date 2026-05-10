use super::db::NodeRecord;
use anyhow::{Context, Result};
use tracing::{info, warn};

/// Generate a Caddyfile fragment that reverse-proxies each port in every
/// active peer's port range.
///
/// Each port `P` in `[port_range_start .. port_range_start + port_range_size)`
/// gets a server block:
///
/// ```text
/// external_domain:P {
///     reverse_proxy virtual_ip:P
/// }
/// ```
///
/// **Note:** Standard Caddy HTTP reverse proxy works for HTTP services only.
/// For raw TCP port forwarding (non-HTTP), the `caddy-l4` plugin is required.
pub fn generate_caddyfile(peers: &[NodeRecord], external_domain: &str) -> String {
    let mut out = String::new();

    for node in peers {
        // Skip deregistered/stale nodes or nodes without a port range
        if matches!(node.status.as_str(), "deregistered" | "stale") {
            continue;
        }
        let (range_start, range_size) = match (node.port_range_start, node.port_range_size) {
            (Some(s), Some(z)) if z > 0 => (s as u16, z as u16),
            _ => continue,
        };

        // Extract bare IP from "10.0.0.1/24" format
        let vip = node.virtual_ip.split('/').next().unwrap_or(&node.virtual_ip);

        let name = node
            .node_name
            .as_deref()
            .unwrap_or(&node.node_id[..8.min(node.node_id.len())]);

        out.push_str(&format!("# node: {name} ({vip})\n"));

        for port in range_start..range_start.saturating_add(range_size) {
            out.push_str(&format!(
                "{external_domain}:{port} {{\n    reverse_proxy {vip}:{port}\n}}\n"
            ));
        }
        out.push('\n');
    }

    out
}

/// Write `content` to `config_path` then reload Caddy.
///
/// Reload strategy:
/// 1. POST the new config to the Caddy admin API (`POST /load`).
/// 2. If that fails (e.g. Caddy not running), fall back to `systemctl reload caddy`.
pub async fn write_and_reload(config_path: &str, admin_api: &str, content: &str) -> Result<()> {
    // Write config file
    std::fs::write(config_path, content)
        .with_context(|| format!("writing Caddy config to {config_path}"))?;
    info!(path = config_path, "Caddy config written");

    // Try admin API reload first
    let load_url = format!("{}/load", admin_api.trim_end_matches('/'));
    let client = reqwest::Client::new();
    match client
        .post(&load_url)
        .header("Content-Type", "text/caddyfile")
        .body(content.to_string())
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("Caddy reloaded via admin API");
            return Ok(());
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %body, "Caddy admin API reload failed, trying systemctl");
        }
        Err(e) => {
            warn!(error = %e, "Caddy admin API unreachable, trying systemctl");
        }
    }

    // Fallback: systemctl reload caddy
    let status = tokio::process::Command::new("systemctl")
        .args(["reload", "caddy"])
        .status()
        .await
        .context("running systemctl reload caddy")?;

    if status.success() {
        info!("Caddy reloaded via systemctl");
    } else {
        warn!(exit_code = ?status.code(), "systemctl reload caddy failed");
    }

    Ok(())
}
