use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

/// Ed25519 PKCS8 DER prefix (16 bytes before the 32-byte private key seed).
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

/// Ed25519 SPKI DER prefix (12 bytes before the 32-byte public key).
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// JWT claims for access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: String,
}

/// Holds the signing/verification material and key metadata.
#[derive(Clone)]
pub struct JwtState {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    pub key_id: String,
    pub public_key_bytes: Vec<u8>,
}

impl JwtState {
    /// Create a new JwtState from raw Ed25519 key material.
    fn from_raw(key_id: String, private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<Self> {
        // Build PKCS8 DER for EncodingKey
        let mut pkcs8_der = Vec::with_capacity(48);
        pkcs8_der.extend_from_slice(&PKCS8_PREFIX);
        pkcs8_der.extend_from_slice(private_key);

        // Build SPKI DER for DecodingKey
        let mut spki_der = Vec::with_capacity(44);
        spki_der.extend_from_slice(&SPKI_PREFIX);
        spki_der.extend_from_slice(public_key);

        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let decoding_key = DecodingKey::from_ed_der(&spki_der);

        Ok(Self {
            encoding_key,
            decoding_key,
            key_id,
            public_key_bytes: public_key.to_vec(),
        })
    }

    /// Create an access token JWT for the given user.
    pub fn create_access_token(
        &self,
        user_id: &str,
        username: &str,
        issuer: &str,
    ) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            iat: now,
            exp: now + 900, // 15 minutes
            iss: issuer.to_string(),
            token_type: "access".to_string(),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key).context("encoding JWT")
    }

    /// Validate an access token and return the claims.
    pub fn validate_access_token(&self, token: &str, issuer: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iss"]);

        let token_data =
            decode::<Claims>(token, &self.decoding_key, &validation).context("decoding JWT")?;

        if token_data.claims.token_type != "access" {
            anyhow::bail!("invalid token type");
        }

        Ok(token_data.claims)
    }
}

/// Hash a refresh token string with SHA-256 and return the hex digest.
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        })
}

/// Initialize the JWT signing key.
/// Loads the active key from the DB, or generates a new one if none exists.
pub async fn init_signing_key(pool: &PgPool) -> Result<JwtState> {
    // Try to load existing active key
    let row = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT key_id, private_key, public_key FROM signing_keys WHERE active = TRUE ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("loading signing key")?;

    if let Some((key_id, private_key, public_key)) = row {
        info!(key_id = %key_id, "loaded existing signing key");
        let priv_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid private key length in DB"))?;
        let pub_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length in DB"))?;
        return JwtState::from_raw(key_id, &priv_bytes, &pub_bytes);
    }

    // Generate new Ed25519 keypair
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();
    let key_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO signing_keys (key_id, algorithm, private_key, public_key) VALUES ($1, 'EdDSA', $2, $3)",
    )
    .bind(&key_id)
    .bind(private_bytes.as_slice())
    .bind(public_bytes.as_slice())
    .execute(pool)
    .await
    .context("persisting signing key")?;

    info!(key_id = %key_id, "generated and stored new signing key");
    JwtState::from_raw(key_id, &private_bytes, &public_bytes)
}
