use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const DEFAULT_CREDENTIALS_PATH: &str = "/etc/meshlink/credentials.json";

/// Stored credentials from a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub server: String,
    pub node_id: String,
    pub auth_token: String,
}

impl Credentials {
    /// Save credentials to the default path.
    pub fn save(&self) -> Result<()> {
        self.save_to(Path::new(DEFAULT_CREDENTIALS_PATH))
    }

    /// Save credentials to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {:?}", parent))?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing credentials")?;
        std::fs::write(path, json).with_context(|| format!("writing credentials to {:?}", path))?;
        Ok(())
    }

    /// Load credentials from the default path.
    pub fn load() -> Result<Self> {
        Self::load_from(Path::new(DEFAULT_CREDENTIALS_PATH))
    }

    /// Load credentials from a specific path.
    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading credentials from {:?}", path))?;
        let creds: Credentials =
            serde_json::from_str(&contents).context("parsing credentials")?;
        Ok(creds)
    }

    /// Check if credentials exist at the default path.
    pub fn exists() -> bool {
        Path::new(DEFAULT_CREDENTIALS_PATH).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_save_and_load() {
        let dir = std::env::temp_dir().join("meshlink_test_creds");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");

        let creds = Credentials {
            server: "http://localhost:4001".to_string(),
            node_id: "test-node-123".to_string(),
            auth_token: "secret-token-456".to_string(),
        };

        creds.save_to(&path).unwrap();
        let loaded = Credentials::load_from(&path).unwrap();

        assert_eq!(loaded.server, "http://localhost:4001");
        assert_eq!(loaded.node_id, "test-node-123");
        assert_eq!(loaded.auth_token, "secret-token-456");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_invalid_json() {
        let dir = std::env::temp_dir().join("meshlink_test_creds_invalid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");

        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"not json").unwrap();

        let result = Credentials::load_from(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file() {
        let path = std::env::temp_dir().join("meshlink_nonexistent_creds.json");
        let result = Credentials::load_from(&path);
        assert!(result.is_err());
    }
}
