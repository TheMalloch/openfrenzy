use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Stored credentials from a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub server: String,
    pub node_id: String,
    pub auth_token: String,
}

impl Credentials {
    /// Return the credentials file path within a config directory.
    pub fn path_in(config_dir: &Path) -> PathBuf {
        config_dir.join("credentials.json")
    }

    /// Save credentials to the given config directory.
    pub fn save(&self, config_dir: &Path) -> Result<()> {
        self.save_to(&Self::path_in(config_dir))
    }

    /// Save credentials to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow::anyhow!(
                        "Permission denied creating {:?}\n\n\
                         Hint: Run 'sudo meshlink setup' first to configure directory permissions.",
                        parent
                    )
                } else {
                    anyhow::Error::new(e).context(format!("creating directory {:?}", parent))
                }
            })?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing credentials")?;
        crate::util::write_atomic(path, json.as_bytes(), 0o600).map_err(|e| {
            let e = match e.downcast::<std::io::Error>() {
                Ok(io) => io,
                Err(other) => return other.context(format!("writing credentials to {:?}", path)),
            };
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!(
                    "Permission denied writing {:?}\n\n\
                     Hint: Run 'sudo meshlink setup' first to configure directory permissions.",
                    path
                )
            } else {
                anyhow::Error::new(e).context(format!("writing credentials to {:?}", path))
            }
        })?;
        Ok(())
    }

    /// Load credentials from the given config directory.
    pub fn load(config_dir: &Path) -> Result<Self> {
        Self::load_from(&Self::path_in(config_dir))
    }

    /// Load credentials from a specific path.
    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading credentials from {:?}", path))?;
        let creds: Credentials =
            serde_json::from_str(&contents).context("parsing credentials")?;
        Ok(creds)
    }

    /// Check if credentials exist in the given config directory.
    pub fn exists(config_dir: &Path) -> bool {
        Self::path_in(config_dir).exists()
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
