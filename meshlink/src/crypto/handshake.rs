use anyhow::{Context, Result};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Our node's long-term identity keypair.
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

/// Result of a completed handshake.
pub struct HandshakeResult {
    /// 32-byte shared secret for ChaCha20-Poly1305.
    pub session_key: [u8; 32],
    /// The ephemeral public key we sent (so the peer can derive the same secret).
    pub ephemeral_public: [u8; 32],
}

/// Perform the initiator side of the handshake.
///
/// Protocol:
/// 1. Generate ephemeral X25519 keypair
/// 2. Send our ephemeral public key to the peer
/// 3. Receive peer's ephemeral public key
/// 4. Compute shared secret = ECDH(our_ephemeral_secret, peer_ephemeral_public)
///
/// For initial version, we do a simple 1-RTT exchange. The static keys are used
/// for peer identity verification, the ephemeral keys provide forward secrecy.
pub fn initiate_handshake(peer_static_public: &[u8; 32]) -> HandshakeResult {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let peer_public = PublicKey::from(*peer_static_public);
    let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);

    HandshakeResult {
        session_key: *shared_secret.as_bytes(),
        ephemeral_public: *ephemeral_public.as_bytes(),
    }
}

/// Respond to a handshake: given the initiator's ephemeral public key,
/// compute the shared secret using our static secret.
pub fn respond_handshake(
    our_identity: &Identity,
    peer_ephemeral_public: &[u8; 32],
) -> [u8; 32] {
    let peer_public = PublicKey::from(*peer_ephemeral_public);
    let shared_secret = our_identity.secret.diffie_hellman(&peer_public);
    *shared_secret.as_bytes()
}

/// Handshake message types sent over the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    Initiation = 1,
    Response = 2,
}

/// Wire format for handshake initiation message.
/// [type: 1 byte][sender_static_pub: 32 bytes][ephemeral_pub: 32 bytes]
pub const HANDSHAKE_INIT_SIZE: usize = 1 + 32 + 32;

/// Wire format for handshake response message.
/// [type: 1 byte][responder_static_pub: 32 bytes][ephemeral_pub: 32 bytes]
pub const HANDSHAKE_RESP_SIZE: usize = 1 + 32 + 32;

/// Build a handshake initiation message.
pub fn build_handshake_init(
    sender_static_pub: &[u8; 32],
    ephemeral_pub: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HANDSHAKE_INIT_SIZE);
    msg.push(HandshakeType::Initiation as u8);
    msg.extend_from_slice(sender_static_pub);
    msg.extend_from_slice(ephemeral_pub);
    msg
}

/// Build a handshake response message.
pub fn build_handshake_response(
    responder_static_pub: &[u8; 32],
    ephemeral_pub: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HANDSHAKE_RESP_SIZE);
    msg.push(HandshakeType::Response as u8);
    msg.extend_from_slice(responder_static_pub);
    msg.extend_from_slice(ephemeral_pub);
    msg
}

/// Parse an incoming handshake message. Returns (type, static_pub, ephemeral_pub).
pub fn parse_handshake(data: &[u8]) -> Result<(HandshakeType, [u8; 32], [u8; 32])> {
    anyhow::ensure!(data.len() >= 65, "handshake message too short: {} bytes", data.len());

    let msg_type = match data[0] {
        1 => HandshakeType::Initiation,
        2 => HandshakeType::Response,
        t => anyhow::bail!("unknown handshake type: {t}"),
    };

    let mut static_pub = [0u8; 32];
    static_pub.copy_from_slice(&data[1..33]);

    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&data[33..65]);

    Ok((msg_type, static_pub, ephemeral_pub))
}
