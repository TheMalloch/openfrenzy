use anyhow::{Context, Result};
use x25519_dalek::{PublicKey, StaticSecret};

/// Our node's long-term identity keypair (used for peer identification).
pub struct Identity {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    /// Create identity from a base64-encoded 32-byte private key.
    pub fn from_base64(private_key_b64: &str) -> Result<Self> {
        let key_bytes: [u8; 32] = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            private_key_b64,
        )
        .context("decoding private key base64")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("private key must be 32 bytes, got {}", v.len()))?;

        let secret = StaticSecret::from(key_bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Generate a new random identity.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return our public key as bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}
