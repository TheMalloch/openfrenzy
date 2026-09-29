use super::db::{Db, NodeRecord};
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

        // Names are validated at registration, but rows written before that
        // check existed may still hold newlines or braces — strip anything
        // that could break out of the comment.
        let name: String = node
            .node_name
            .as_deref()
            .unwrap_or(&node.node_id[..8.min(node.node_id.len())])
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(64)
            .collect();

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

/// Fetch all nodes from `db`, regenerate the Caddyfile, and reload Caddy.
pub async fn regen_from_db(
    db: &Db,
    config_path: &str,
    admin_api: &str,
    external_domain: &str,
) -> Result<()> {
    let nodes = db.list_all_nodes().await.context("listing nodes for Caddy regen")?;
    let content = generate_caddyfile(&nodes, external_domain);
    write_and_reload(config_path, admin_api, &content).await
}

/// Write `content` to `config_path` then reload Caddy.
///
/// `config_path` is a *fragment* imported by the main Caddyfile, so it must
/// never be POSTed to the admin API's `/load` on its own — that replaces the
/// entire running config with just the fragment. Instead the main Caddyfile
/// (`Caddyfile` next to the fragment) is reloaded as a whole:
/// 1. `caddy reload --config <main> --address <admin_api>`
/// 2. If that fails (e.g. `caddy` not on PATH), `systemctl reload caddy`.
pub async fn write_and_reload(config_path: &str, admin_api: &str, content: &str) -> Result<()> {
    crate::util::write_atomic(std::path::Path::new(config_path), content.as_bytes(), 0o644)
        .with_context(|| format!("writing Caddy config to {config_path}"))?;
    info!(path = config_path, "Caddy config written");

    let main_config = std::path::Path::new(config_path).with_file_name("Caddyfile");
    let address = admin_api
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    match tokio::process::Command::new("caddy")
        .arg("reload")
        .arg("--config")
        .arg(&main_config)
        .args(["--adapter", "caddyfile", "--address", address])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            info!(config = %main_config.display(), "Caddy reloaded");
            return Ok(());
        }
        Ok(out) => {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "caddy reload failed, trying systemctl"
            );
        }
        Err(e) => {
            warn!(error = %e, "could not run caddy, trying systemctl");
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn node(name: &str) -> NodeRecord {
        NodeRecord {
            node_id: "0123456789abcdef".into(),
            node_name: Some(name.into()),
            public_key: vec![0; 32],
            private_key_encrypted: vec![],
            virtual_ip: "10.0.0.2/24".into(),
            auth_token: "t".into(),
            status: "active".into(),
            endpoint: None,
            ipv6_endpoint: None,
            lan_endpoint: None,
            listen_port: 51820,
            last_heartbeat: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            port_range_start: Some(20000),
            port_range_size: Some(1),
        }
    }

    #[test]
    fn malicious_name_cannot_inject_directives() {
        let out = generate_caddyfile(&[node("x\n:80 {\n file_server\n}\n#")], "example.com");
        assert!(!out.contains("file_server\n"), "injected: {out}");
        assert_eq!(out.matches('{').count(), 1, "{out}");
        assert!(out.starts_with("# node: x80file_server (10.0.0.2)\n"), "{out}");
    }
}
