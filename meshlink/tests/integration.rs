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

// ---- Crypto: key generation ----

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

// ---- Transport: wrap/unwrap ----

#[test]
fn test_wrap_unwrap_roundtrip() {
    let plaintext = b"Hello, MeshLink!";
    let wrapped = meshlink::crypto::transport::wrap_packet(plaintext);

    assert_eq!(wrapped[0], meshlink::crypto::transport::DATA_PACKET_TYPE);
    assert_eq!(wrapped.len(), 1 + plaintext.len());

    let unwrapped = meshlink::crypto::transport::unwrap_packet(&wrapped).unwrap();
    assert_eq!(unwrapped, plaintext);
}

#[test]
fn test_wrap_large_payload() {
    let payload = vec![0xABu8; 1420];
    let wrapped = meshlink::crypto::transport::wrap_packet(&payload);
    let unwrapped = meshlink::crypto::transport::unwrap_packet(&wrapped).unwrap();
    assert_eq!(unwrapped, &payload[..]);
}

#[test]
fn test_unwrap_invalid_type() {
    // Wrong type byte
    let result = meshlink::crypto::transport::unwrap_packet(&[0x01, 1, 2, 3]);
    assert!(result.is_none());
}

#[test]
fn test_unwrap_too_short() {
    // Just the type byte, no payload
    let result = meshlink::crypto::transport::unwrap_packet(&[0x04]);
    assert!(result.is_none());

    let result = meshlink::crypto::transport::unwrap_packet(&[]);
    assert!(result.is_none());
}

#[test]
fn test_packet_type_detection() {
    assert!(meshlink::crypto::transport::is_data_packet(&[0x04, 1, 2, 3]));
    assert!(!meshlink::crypto::transport::is_data_packet(&[0x01, 1, 2]));
    assert!(!meshlink::crypto::transport::is_data_packet(&[]));
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
async fn test_state_endpoint_and_stats() {
    let state = meshlink::state::SharedState::new();

    let pub_key = [2u8; 32];
    state
        .add_peer(meshlink::state::PeerInfo {
            public_key: pub_key,
            endpoint: None,
            virtual_ip: "10.0.0.3".parse().unwrap(),
            allowed_ips: vec!["10.0.0.3/32".parse().unwrap()],
            tx_bytes: 0,
            rx_bytes: 0,
        })
        .await;

    // No endpoint initially
    let peer = state.get_peer(&pub_key).await.unwrap();
    assert!(peer.endpoint.is_none());

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
        let (_n, src) = server_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x10); // NAT detect request

        // Respond with client's observed address: [0x11][addr_type][ip...][port]
        let mut resp = vec![0x11u8];
        match src.ip() {
            std::net::IpAddr::V4(ip) => {
                resp.push(0x04);
                resp.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                resp.push(0x06);
                resp.extend_from_slice(&ip.octets());
            }
        }
        resp.extend_from_slice(&src.port().to_be_bytes());
        server_sock.send_to(&resp, src).await.unwrap();
    });

    let (coord_tx, mut coord_rx) = tokio::sync::mpsc::channel::<meshlink::state::RoutedPacket>(16);

    // Spawn a task to forward the server response to coord_rx
    let fwd_sock = client_sock.clone();
    let fwd_handle = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        if let Ok((n, src)) = fwd_sock.recv_from(&mut buf).await {
            let _ = coord_tx.send(meshlink::state::RoutedPacket {
                data: buf[..n].to_vec(),
                peer_endpoint: src,
            }).await;
        }
    });

    let result =
        meshlink::net::hole_punch::detect_nat(&client_sock, &server_addr, &mut coord_rx).await;
    assert!(result.is_ok());

    let detection = result.unwrap();
    assert!(detection.public_endpoint.is_some());
    let ep = detection.public_endpoint.unwrap();
    assert_eq!(ep.port(), client_addr.port());

    fwd_handle.abort();

    server_handle.await.unwrap();
}
