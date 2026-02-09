use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Overhead added by encryption: 12-byte nonce + 16-byte Poly1305 tag.
pub const CRYPTO_OVERHEAD: usize = 12 + 16;

/// Maximum plaintext payload we'll encrypt (MTU - IP header room).
pub const MAX_PLAINTEXT: usize = 1500;

/// Wire format for a data packet:
/// [type: 1 byte = 0x04][nonce: 12 bytes][ciphertext + tag: N + 16 bytes]
pub const DATA_PACKET_TYPE: u8 = 0x04;

/// Encrypt a plaintext packet using the session key and a counter-based nonce.
///
/// Returns the full wire packet: [type][nonce][ciphertext+tag]
pub fn encrypt_packet(session_key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(session_key)
        .map_err(|e| anyhow::anyhow!("creating cipher: {e}"))?;

    // Build 12-byte nonce: 4 bytes zero padding + 8 bytes counter (little-endian)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut packet = Vec::with_capacity(1 + 12 + ciphertext.len());
    packet.push(DATA_PACKET_TYPE);
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

/// Decrypt a wire data packet. Expects format: [type][nonce: 12][ciphertext+tag].
///
/// Returns the plaintext payload.
pub fn decrypt_packet(session_key: &[u8; 32], packet: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        packet.len() >= 1 + 12 + 16,
        "data packet too short: {} bytes",
        packet.len()
    );
    anyhow::ensure!(
        packet[0] == DATA_PACKET_TYPE,
        "not a data packet: type=0x{:02x}",
        packet[0]
    );

    let cipher = ChaCha20Poly1305::new_from_slice(session_key)
        .map_err(|e| anyhow::anyhow!("creating cipher: {e}"))?;

    let nonce = Nonce::from_slice(&packet[1..13]);
    let ciphertext = &packet[13..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    Ok(plaintext)
}

/// Counter-based nonce generator for a single peer session.
/// Each direction (send/recv) should have its own counter.
pub struct NonceCounter {
    counter: u64,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn next(&mut self) -> u64 {
        let c = self.counter;
        self.counter += 1;
        c
    }
}

/// Check if a received packet is a data packet (vs handshake).
pub fn is_data_packet(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == DATA_PACKET_TYPE
}

/// Check if a received packet is a handshake packet.
pub fn is_handshake_packet(data: &[u8]) -> bool {
    !data.is_empty() && (data[0] == 1 || data[0] == 2)
}
