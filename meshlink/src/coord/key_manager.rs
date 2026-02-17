use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a new X25519 keypair and return (private_key_bytes, public_key_bytes).
pub fn generate_node_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_produces_valid_keys() {
        let (private_key, public_key) = generate_node_keypair();
        // Keys should not be all zeros
        assert_ne!(private_key, [0u8; 32]);
        assert_ne!(public_key, [0u8; 32]);
        // Private and public should differ
        assert_ne!(private_key, public_key);
    }

    #[test]
    fn test_generate_keypair_unique() {
        let (priv1, pub1) = generate_node_keypair();
        let (priv2, pub2) = generate_node_keypair();
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_keypair_derivation_consistent() {
        let (private_key, public_key) = generate_node_keypair();
        // Re-derive public from private and verify it matches
        let secret = StaticSecret::from(private_key);
        let derived_public = PublicKey::from(&secret);
        assert_eq!(*derived_public.as_bytes(), public_key);
    }
}
