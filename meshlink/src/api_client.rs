use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Response from POST /api/v1/register
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    pub node_id: String,
    /// Absent in BYOK mode (peer supplied its own public key).
    pub private_key: Option<String>,
    pub public_key: String,
    pub virtual_ip: String,
    pub config_toml: String,
    pub auth_token: String,
    #[serde(default)]
    pub port_range_start: u16,
    #[serde(default)]
    pub port_range_size: u16,
}

/// HTTP client for the MeshLink coordination server REST API.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Serialize)]
struct RegisterRequest {
    invite_code: String,
    node_name: Option<String>,
    /// Base64-encoded X25519 public key for BYOK registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
}

impl ApiClient {
    /// Create a new API client.
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Register a new node with an invite code.
    ///
    /// Pass `public_key` (base64-encoded X25519) to use BYOK mode; the coordinator will
    /// not generate or store a private key and `response.private_key` will be `None`.
    pub async fn register(
        &self,
        invite_code: &str,
        node_name: Option<&str>,
        public_key: Option<&str>,
    ) -> Result<RegistrationResponse> {
        let url = format!("{}/api/v1/register", self.base_url);
        let body = RegisterRequest {
            invite_code: invite_code.to_string(),
            node_name: node_name.map(|s| s.to_string()),
            public_key: public_key.map(|s| s.to_string()),
        };

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("sending register request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("registration failed ({}): {}", status, text);
        }

        resp.json()
            .await
            .context("parsing registration response")
    }
}
