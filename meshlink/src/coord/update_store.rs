use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs;

/// Stores update binaries on disk, keyed by update record ID.
#[derive(Clone)]
pub struct UpdateStore {
    base_dir: PathBuf,
}

impl UpdateStore {
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_dir)
            .with_context(|| format!("creating update store at {:?}", base_dir))?;
        Ok(Self { base_dir })
    }

    fn path_for(&self, id: i64) -> PathBuf {
        self.base_dir.join(format!("{id}.bin"))
    }

    pub async fn store(&self, id: i64, data: &[u8]) -> Result<()> {
        let path = self.path_for(id);
        fs::write(&path, data)
            .await
            .with_context(|| format!("writing update binary to {:?}", path))
    }

    pub async fn load(&self, id: i64) -> Result<Vec<u8>> {
        let path = self.path_for(id);
        fs::read(&path)
            .await
            .with_context(|| format!("reading update binary from {:?}", path))
    }
}
