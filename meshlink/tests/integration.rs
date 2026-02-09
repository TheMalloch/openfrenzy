use std::net::SocketAddr;

/// Helper: generate a test config TOML string.
fn test_config(
    private_key: &str,
    port: u16,
    virtual_ip: &str,
    tun_name: &str,
    peer_pub: &str,
    peer_allowed: &str,
) -> String {
    format!(
        r#"
[node]
private_key = "{private_key}"
listen_port = {port}
virtual_ip = "{virtual_ip}"
tun_name = "{tun_name}"

[coordination]
server = "127.0.0.1:4000"

[[peers]]
public_key = "{peer_pub}"
allowed_ips = ["{peer_allowed}"]
"#
    )
}

// ---- Crypto: key generation and handshake ----

#[test]
fn test_keygen_identity() {
    let id = meshlink::crypto::handshake::Identity::generate();
    let pub_key = id.public_key_bytes();
    assert_eq!(pub_key.len(), 32);
    // Public key should not be all zeros
    assert!(pub_key.iter().any(|&b| b != 0));
}

#[test]
fn test_identity_from_base64_roundtrip() {
    let id = meshlink::crypto::handshake::Identity::generate();
    let priv_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        id.secret.as_bytes(),
    );
    let restored = meshlink::crypto::handshake::Identity::from_base64(&priv_b64).unwrap();
    assert_eq!(id.public_key_bytes(), restored.public_key_bytes());
}

#[test]
fn test_handshake_shared_secret() {
    // Simulate: Node A initiates handshake to Node B
    let node_a = meshlink::crypto::handshake::Identity::generate();
    let node_b = meshlink::crypto::handshake::Identity::generate();

    // A initiates: uses B's static public key
    let a_result = meshlink::crypto::handshake::initiate_handshake(&node_b.public_key_bytes());

    // B responds: uses A's ephemeral public key
    let b_session_key =
        meshlink::crypto::handshake::respond_handshake(&node_b, &a_result.ephemeral_public);

    // Both should derive the same shared secret
    assert_eq!(a_result.session_key, b_session_key);
}

#[test]
fn test_handshake_wire_format() {
    let id = meshlink::crypto::handshake::Identity::generate();
    let result = meshlink::crypto::handshake::initiate_handshake(&id.public_key_bytes());

    let msg = meshlink::crypto::handshake::build_handshake_init(
        &id.public_key_bytes(),
        &result.ephemeral_public,
    );

    assert_eq!(msg.len(), meshlink::crypto::handshake::HANDSHAKE_INIT_SIZE);
    assert_eq!(msg[0], 1); // Initiation type

    // Parse it back
    let (msg_type, static_pub, ephemeral_pub) =
        meshlink::crypto::handshake::parse_handshake(&msg).unwrap();

    assert_eq!(
        msg_type,
        meshlink::crypto::handshake::HandshakeType::Initiation
    );
    assert_eq!(static_pub, id.public_key_bytes());
    assert_eq!(ephemeral_pub, result.ephemeral_public);
}

#[test]
fn test_handshake_response_wire_format() {
    let id = meshlink::crypto::handshake::Identity::generate();
    let result = meshlink::crypto::handshake::initiate_handshake(&id.public_key_bytes());

    let msg = meshlink::crypto::handshake::build_handshake_response(
        &id.public_key_bytes(),
        &result.ephemeral_public,
    );

    assert_eq!(msg.len(), meshlink::crypto::handshake::HANDSHAKE_RESP_SIZE);
    assert_eq!(msg[0], 2); // Response type

    let (msg_type, _, _) = meshlink::crypto::handshake::parse_handshake(&msg).unwrap();
    assert_eq!(
        msg_type,
        meshlink::crypto::handshake::HandshakeType::Response
    );
}

#[test]
fn test_parse_handshake_too_short() {
    let result = meshlink::crypto::handshake::parse_handshake(&[1, 2, 3]);
    assert!(result.is_err());
}

// ---- Crypto: transport encryption ----

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [42u8; 32];
    let plaintext = b"Hello, MeshLink!";

    let encrypted =
        meshlink::crypto::transport::encrypt_packet(&key, 0, plaintext).unwrap();

    // Should be larger than plaintext (type + nonce + tag)
    assert!(encrypted.len() > plaintext.len());
    assert_eq!(encrypted[0], meshlink::crypto::transport::DATA_PACKET_TYPE);

    let decrypted = meshlink::crypto::transport::decrypt_packet(&key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_different_nonces_different_ciphertext() {
    let key = [42u8; 32];
    let plaintext = b"same data";

    let enc1 = meshlink::crypto::transport::encrypt_packet(&key, 0, plaintext).unwrap();
    let enc2 = meshlink::crypto::transport::encrypt_packet(&key, 1, plaintext).unwrap();

    // Different nonces should produce different ciphertext
    assert_ne!(enc1, enc2);

    // Both should decrypt correctly
    let dec1 = meshlink::crypto::transport::decrypt_packet(&key, &enc1).unwrap();
    let dec2 = meshlink::crypto::transport::decrypt_packet(&key, &enc2).unwrap();
    assert_eq!(dec1, plaintext);
    assert_eq!(dec2, plaintext);
}

#[test]
fn test_decrypt_wrong_key_fails() {
    let key1 = [42u8; 32];
    let key2 = [99u8; 32];
    let plaintext = b"secret message";

    let encrypted = meshlink::crypto::transport::encrypt_packet(&key1, 0, plaintext).unwrap();
    let result = meshlink::crypto::transport::decrypt_packet(&key2, &encrypted);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_tampered_data_fails() {
    let key = [42u8; 32];
    let plaintext = b"important data";

    let mut encrypted =
        meshlink::crypto::transport::encrypt_packet(&key, 0, plaintext).unwrap();

    // Tamper with ciphertext
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0xFF;

    let result = meshlink::crypto::transport::decrypt_packet(&key, &encrypted);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_too_short_fails() {
    let key = [42u8; 32];
    let result = meshlink::crypto::transport::decrypt_packet(&key, &[0x04, 0, 0]);
    assert!(result.is_err());
}

#[test]
fn test_packet_type_detection() {
    assert!(meshlink::crypto::transport::is_data_packet(&[0x04, 1, 2, 3]));
    assert!(!meshlink::crypto::transport::is_data_packet(&[0x01, 1, 2]));
    assert!(meshlink::crypto::transport::is_handshake_packet(&[0x01]));
    assert!(meshlink::crypto::transport::is_handshake_packet(&[0x02]));
    assert!(!meshlink::crypto::transport::is_handshake_packet(&[0x04]));
    assert!(!meshlink::crypto::transport::is_data_packet(&[]));
    assert!(!meshlink::crypto::transport::is_handshake_packet(&[]));
}

#[test]
fn test_nonce_counter() {
    let mut counter = meshlink::crypto::transport::NonceCounter::new();
    assert_eq!(counter.next(), 0);
    assert_eq!(counter.next(), 1);
    assert_eq!(counter.next(), 2);
}

// ---- Full handshake + encrypted tunnel simulation ----

#[test]
fn test_full_handshake_then_data_exchange() {
    let node_a = meshlink::crypto::handshake::Identity::generate();
    let node_b = meshlink::crypto::handshake::Identity::generate();

    // Step 1: A initiates handshake
    let a_hs = meshlink::crypto::handshake::initiate_handshake(&node_b.public_key_bytes());
    let init_msg = meshlink::crypto::handshake::build_handshake_init(
        &node_a.public_key_bytes(),
        &a_hs.ephemeral_public,
    );

    // Step 2: B receives initiation, derives session key
    let (_, _sender_pub, ephemeral_pub) =
        meshlink::crypto::handshake::parse_handshake(&init_msg).unwrap();
    let b_session_key =
        meshlink::crypto::handshake::respond_handshake(&node_b, &ephemeral_pub);

    // Both have same session key
    let a_session_key = a_hs.session_key;
    assert_eq!(a_session_key, b_session_key);

    // Step 3: A sends encrypted data to B
    let payload = b"ping from A";
    let mut a_counter = meshlink::crypto::transport::NonceCounter::new();
    let encrypted =
        meshlink::crypto::transport::encrypt_packet(&a_session_key, a_counter.next(), payload)
            .unwrap();

    // B decrypts
    let decrypted =
        meshlink::crypto::transport::decrypt_packet(&b_session_key, &encrypted).unwrap();
    assert_eq!(decrypted, payload);

    // Step 4: B sends encrypted data to A
    let reply = b"pong from B";
    let mut b_counter = meshlink::crypto::transport::NonceCounter::new();
    let encrypted =
        meshlink::crypto::transport::encrypt_packet(&b_session_key, b_counter.next(), reply)
            .unwrap();

    let decrypted =
        meshlink::crypto::transport::decrypt_packet(&a_session_key, &encrypted).unwrap();
    assert_eq!(decrypted, reply);
}

// ---- Config parsing ----

#[test]
fn test_config_parse_valid() {
    let id_a = meshlink::crypto::handshake::Identity::generate();
    let id_b = meshlink::crypto::handshake::Identity::generate();

    let priv_a = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        id_a.secret.as_bytes(),
    );
    let pub_b = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        id_b.public.as_bytes(),
    );

    let toml_str = test_config(&priv_a, 51820, "10.0.0.1/24", "meshlink0", &pub_b, "10.0.0.2/32");

    let tmp = std::env::temp_dir().join("meshlink-test-config.toml");
    std::fs::write(&tmp, &toml_str).unwrap();

    let config = meshlink::config::Config::load(&tmp).unwrap();
    assert_eq!(config.node.listen_port, 51820);
    assert_eq!(config.node.tun_name, "meshlink0");
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.coordination.server, "127.0.0.1:4000");

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn test_config_invalid_key() {
    let toml_str = r#"
[node]
private_key = "not_valid_base64!!!"
listen_port = 51820
virtual_ip = "10.0.0.1/24"

[coordination]
server = "127.0.0.1:4000"
"#;

    let tmp = std::env::temp_dir().join("meshlink-test-config-bad.toml");
    std::fs::write(&tmp, toml_str).unwrap();

    let result = meshlink::config::Config::load(&tmp);
    assert!(result.is_err());

    std::fs::remove_file(&tmp).ok();
}

// ---- State management ----

#[tokio::test]
async fn test_state_add_peer_and_lookup() {
    let state = meshlink::state::SharedState::new();

    let pub_key = [1u8; 32];
    let virtual_ip: std::net::Ipv4Addr = "10.0.0.2".parse().unwrap();

    state
        .add_peer(meshlink::state::PeerInfo {
            public_key: pub_key,
            endpoint: Some("1.2.3.4:51820".parse().unwrap()),
            virtual_ip,
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            session_key: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        })
        .await;

    // Route lookup
    let found = state.lookup_route(virtual_ip).await;
    assert_eq!(found, Some(pub_key));

    // Unknown IP
    let not_found = state.lookup_route("10.0.0.99".parse().unwrap()).await;
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_state_session_key_and_stats() {
    let state = meshlink::state::SharedState::new();

    let pub_key = [2u8; 32];
    state
        .add_peer(meshlink::state::PeerInfo {
            public_key: pub_key,
            endpoint: None,
            virtual_ip: "10.0.0.3".parse().unwrap(),
            allowed_ips: vec!["10.0.0.3/32".parse().unwrap()],
            session_key: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        })
        .await;

    // No session key initially
    let peer = state.get_peer(&pub_key).await.unwrap();
    assert!(peer.session_key.is_none());

    // Set session key
    let session_key = [42u8; 32];
    state.set_session_key(&pub_key, session_key).await;
    let peer = state.get_peer(&pub_key).await.unwrap();
    assert_eq!(peer.session_key, Some(session_key));
    assert!(peer.last_handshake.is_some());

    // Update endpoint
    let ep: SocketAddr = "5.6.7.8:12345".parse().unwrap();
    state.set_peer_endpoint(&pub_key, ep).await;
    let peer = state.get_peer(&pub_key).await.unwrap();
    assert_eq!(peer.endpoint, Some(ep));

    // Stats
    state.add_tx_bytes(&pub_key, 100).await;
    state.add_rx_bytes(&pub_key, 200).await;
    let peer = state.get_peer(&pub_key).await.unwrap();
    assert_eq!(peer.tx_bytes, 100);
    assert_eq!(peer.rx_bytes, 200);
}

#[tokio::test]
async fn test_pipeline_channels() {
    let channels = meshlink::state::PipelineChannels::new(16);

    // Test tun -> router channel
    channels
        .tun_to_router_tx
        .send(vec![1, 2, 3])
        .await
        .unwrap();

    // Test router -> udp channel
    channels
        .router_to_udp_tx
        .send(meshlink::state::RoutedPacket {
            data: vec![4, 5, 6],
            peer_endpoint: "1.2.3.4:1234".parse().unwrap(),
        })
        .await
        .unwrap();
}

// ---- Coord server protocol ----

#[tokio::test]
async fn test_coord_server_nat_detect() {
    // Start a mock coord server
    let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let client_sock = std::sync::Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    );
    let client_addr = client_sock.local_addr().unwrap();

    // Spawn mock server that responds to NAT detect
    let server_handle = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (n, src) = server_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x10); // NAT detect request

        // Respond with client's observed address
        let mut resp = vec![0x11u8];
        if let std::net::IpAddr::V4(ip) = src.ip() {
            resp.extend_from_slice(&ip.octets());
        }
        resp.extend_from_slice(&src.port().to_be_bytes());
        server_sock.send_to(&resp, src).await.unwrap();
    });

    let result =
        meshlink::net::hole_punch::detect_nat(&client_sock, &server_addr).await;
    assert!(result.is_ok());

    let detection = result.unwrap();
    assert!(detection.public_endpoint.is_some());
    let ep = detection.public_endpoint.unwrap();
    assert_eq!(ep.port(), client_addr.port());

    server_handle.await.unwrap();
}

// ---- Large payload encryption ----

#[test]
fn test_encrypt_large_payload() {
    let key = [7u8; 32];
    // Simulate a full MTU-sized packet
    let payload = vec![0xABu8; 1420];

    let encrypted =
        meshlink::crypto::transport::encrypt_packet(&key, 0, &payload).unwrap();
    let decrypted =
        meshlink::crypto::transport::decrypt_packet(&key, &encrypted).unwrap();
    assert_eq!(decrypted, payload);
}

#[test]
fn test_encrypt_empty_payload() {
    let key = [7u8; 32];
    let payload = b"";

    let encrypted =
        meshlink::crypto::transport::encrypt_packet(&key, 0, payload).unwrap();
    let decrypted =
        meshlink::crypto::transport::decrypt_packet(&key, &encrypted).unwrap();
    assert_eq!(decrypted, payload);
}
