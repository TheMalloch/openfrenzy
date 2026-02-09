use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub coordination: CoordinationConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub private_key: String,
    pub listen_port: u16,
    pub virtual_ip: Ipv4Net,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
}

fn default_tun_name() -> String {
    "meshlink0".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CoordinationConfig {
    pub server: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Net>,
    pub endpoint: Option<SocketAddr>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path:?}"))?;
        let config: Config =
            toml::from_str(&contents).with_context(|| format!("parsing config {path:?}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        // Validate private key is valid base64
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.node.private_key,
        )
        .context("node.private_key is not valid base64")?;

        // Validate peer public keys
        for (i, peer) in self.peers.iter().enumerate() {
            let key_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &peer.public_key,
            )
            .with_context(|| format!("peers[{i}].public_key is not valid base64"))?;
            if key_bytes.len() != 32 {
                anyhow::bail!("peers[{i}].public_key must be 32 bytes, got {}", key_bytes.len());
            }
        }

        Ok(())
    }
}
