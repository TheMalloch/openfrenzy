use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Response from POST /api/v1/register
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    pub node_id: String,
    pub private_key: String,
    pub public_key: String,
    pub virtual_ip: String,
    pub config_toml: String,
    pub auth_token: String,
}

/// Response from POST /api/v1/node/:id/heartbeat
#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub peers_changed: bool,
}

/// HTTP client for the MeshLink coordination server REST API.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
}

#[derive(Serialize)]
struct RegisterRequest {
    invite_code: String,
    node_name: Option<String>,
}

impl ApiClient {
    /// Create a new API client.
    pub fn new(base_url: &str, auth_token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token,
        }
    }

    /// Register a new node with an invite code.
    pub async fn register(
        &self,
        invite_code: &str,
        node_name: Option<&str>,
    ) -> Result<RegistrationResponse> {
        let url = format!("{}/api/v1/register", self.base_url);
        let body = RegisterRequest {
            invite_code: invite_code.to_string(),
            node_name: node_name.map(|s| s.to_string()),
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

    /// Fetch the current TOML config for a node.
    pub async fn fetch_config(&self, node_id: &str) -> Result<String> {
        let url = format!("{}/api/v1/node/{}/config", self.base_url, node_id);
        let token = self.auth_token.as_deref().context("no auth token set")?;

        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .context("sending config request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("config fetch failed ({}): {}", status, text);
        }

        resp.text().await.context("reading config response")
    }

    /// Send a heartbeat for a node. Returns whether peers have changed.
    pub async fn heartbeat(&self, node_id: &str) -> Result<HeartbeatResponse> {
        let url = format!("{}/api/v1/node/{}/heartbeat", self.base_url, node_id);
        let token = self.auth_token.as_deref().context("no auth token set")?;

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .context("sending heartbeat")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("heartbeat failed ({}): {}", status, text);
        }

        resp.json().await.context("parsing heartbeat response")
    }

    /// Unregister (deregister) a node.
    pub async fn unregister(&self, node_id: &str) -> Result<()> {
        let url = format!("{}/api/v1/node/{}", self.base_url, node_id);
        let token = self.auth_token.as_deref().context("no auth token set")?;

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .context("sending unregister request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("unregister failed ({}): {}", status, text);
        }

        Ok(())
    }
}
