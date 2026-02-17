use super::db::NodeRecord;
use base64::Engine;

/// Generate a TOML config string for a node, including its identity and all active peers.
pub fn generate_config(
    node: &NodeRecord,
    peers: &[NodeRecord],
    coord_server: &str,
) -> String {
    let private_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(&node.private_key_encrypted);
    let virtual_ip = &node.virtual_ip;

    let mut config = format!(
        r#"[node]
private_key = "{private_key_b64}"
listen_port = {listen_port}
virtual_ip = "{virtual_ip}"
tun_name = "meshlink0"

[coordination]
server = "{coord_server}"
"#,
        listen_port = node.listen_port,
    );

    for peer in peers {
        if peer.node_id == node.node_id {
            continue;
        }
        let peer_pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(&peer.public_key);
        // Extract just the IP address without prefix for the /32 allowed_ip
        let peer_ip = peer.virtual_ip.split('/').next().unwrap_or(&peer.virtual_ip);

        config.push_str(&format!(
            r#"
[[peers]]
public_key = "{peer_pub_b64}"
allowed_ips = ["{peer_ip}/32"]
"#,
        ));

        if let Some(ref ep) = peer.endpoint {
            config.push_str(&format!("endpoint = \"{ep}\"\n"));
        }
        if let Some(ref ep6) = peer.ipv6_endpoint {
            config.push_str(&format!("ipv6_endpoint = \"{ep6}\"\n"));
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_node(id: &str, ip: &str, pub_key: &[u8], priv_key: &[u8]) -> NodeRecord {
        NodeRecord {
            node_id: id.to_string(),
            node_name: Some(id.to_string()),
            public_key: pub_key.to_vec(),
            private_key_encrypted: priv_key.to_vec(),
            virtual_ip: ip.to_string(),
            auth_token: "token".to_string(),
            status: "active".to_string(),
            endpoint: None,
            ipv6_endpoint: None,
            listen_port: 51820,
            last_heartbeat: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_generate_config_basic() {
        let node = make_node("node1", "10.0.0.1/24", &[1u8; 32], &[2u8; 32]);
        let peer = make_node("node2", "10.0.0.2/24", &[3u8; 32], &[4u8; 32]);

        let config =
            generate_config(&node, &[node.clone(), peer.clone()], "coord.example.com:4000");

        assert!(config.contains("[node]"));
        assert!(config.contains("private_key ="));
        assert!(config.contains("10.0.0.1/24"));
        assert!(config.contains("[coordination]"));
        assert!(config.contains("coord.example.com:4000"));
        assert!(config.contains("[[peers]]"));
        assert!(config.contains("10.0.0.2/32"));
        // Should not include self as peer
        assert_eq!(config.matches("[[peers]]").count(), 1);
    }

    #[test]
    fn test_generate_config_with_endpoint() {
        let node = make_node("node1", "10.0.0.1/24", &[1u8; 32], &[2u8; 32]);
        let mut peer = make_node("node2", "10.0.0.2/24", &[3u8; 32], &[4u8; 32]);
        peer.endpoint = Some("1.2.3.4:51820".to_string());

        let config = generate_config(&node, &[peer], "coord.example.com:4000");

        assert!(config.contains("endpoint = \"1.2.3.4:51820\""));
    }

    #[test]
    fn test_generate_config_is_valid_toml() {
        let node = make_node("node1", "10.0.0.1/24", &[1u8; 32], &[2u8; 32]);
        let peer = make_node("node2", "10.0.0.2/24", &[3u8; 32], &[4u8; 32]);

        let config = generate_config(&node, &[peer], "coord.example.com:4000");

        // Verify it parses as valid TOML
        let parsed: toml::Value = toml::from_str(&config).expect("config should be valid TOML");
        assert!(parsed.get("node").is_some());
        assert!(parsed.get("coordination").is_some());
        assert!(parsed.get("peers").is_some());
    }
}
