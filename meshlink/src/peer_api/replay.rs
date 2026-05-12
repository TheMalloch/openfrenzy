use anyhow::{bail, Result};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOW: u64 = 30;

pub struct NonceStore {
    seen: HashMap<String, u64>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self { seen: HashMap::new() }
    }

    /// Accept (timestamp_secs, nonce) or reject if replayed / outside ±30 s window.
    pub fn check(&mut self, ts: u64, nonce: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let diff = if ts > now { ts - now } else { now - ts };
        if diff > WINDOW {
            bail!("timestamp outside ±30 s window");
        }
        if self.seen.contains_key(nonce) {
            bail!("nonce already used");
        }
        self.seen.insert(nonce.to_string(), ts);
        Ok(())
    }

    pub fn prune(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.seen.retain(|_, ts| now.saturating_sub(*ts) <= WINDOW * 2);
    }
}
