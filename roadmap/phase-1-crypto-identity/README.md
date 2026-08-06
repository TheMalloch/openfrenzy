# Phase 1 — Cryptographic identity and encrypted data plane

**Goal:** peer identity comes from an authenticated Noise session, not from the
UDP source address. Encryption falls out of this.

**Estimate:** ~3-4 weeks
**Requires:** Phase 0 complete
**This is the phase that matters.** Everything else is supporting work.

---

## Why this is one change, not two

"Add encryption" and "fix identity spoofing" look like separate tasks. They are
not. If packets are encrypted but peers are still identified by source address,
an attacker who spoofs an address is still treated as that peer — they just
can't read the payload, which is not the property you wanted. Conversely you
cannot authenticate identity on a UDP datagram without a MAC, and once you have
a MAC you have most of an AEAD.

So: **the AEAD tag is the identity proof.** One mechanism, one phase.

## Current state

### The good news
`meshlink/src/state.rs` is already shaped correctly. `PeerInfo` is keyed by
`PeerPublicKey = [u8; 32]`, and the route table is `Ipv4Addr -> PeerPublicKey`.
Identity degrades to "address" in exactly one place. This is a much smaller
blast radius than the codebase size suggests.

### The hole
`meshlink/src/router/mod.rs:133-142`:

```rust
let peer_key = {
    let peers = state.peers.read().await;
    match peers.values().find(|p| p.endpoint == Some(src)) {
        Some(p) => p.public_key,
        None => { debug!(%src, "data packet from unknown endpoint"); return; }
    }
};
```

Identity is whoever last registered from this address. The `allowed_ips` check
that follows (line 147-158) validates the packet's inner source IP against the
*claimed* peer's allowed ranges — so it constrains an attacker to impersonating
one specific peer at a time, and nothing more.

### The stub
`meshlink/src/crypto/transport.rs`, in full, is 24 lines:

```rust
pub const DATA_PACKET_TYPE: u8 = 0x04;
pub fn wrap_packet(plaintext: &[u8]) -> Vec<u8>   // pushes 0x04, appends payload
pub fn unwrap_packet(packet: &[u8]) -> Option<&[u8]>  // strips 0x04
pub fn is_data_packet(data: &[u8]) -> bool
```

`meshlink/src/crypto/handshake.rs` is misleadingly named — it performs no
handshake. It is an `Identity` struct wrapping an X25519 `StaticSecret` with
`from_base64`, `generate`, and `public_key_bytes`. Useful; keep it; rename it.

`meshlink/src/crypto/mod.rs` exports only `handshake` and `transport`.

## Design

### Handshake: Noise_IK via `snow`

```
Noise_IK:
  -> e, es, s, ss
  <- e, ee, se
```

`IK` because the initiator already knows the responder's static public key — the
coordination server distributes it in the peer list. This is the same pattern
WireGuard uses. Properties: mutual authentication, forward secrecy, and the
initiator's identity is encrypted to the responder.

Cipher suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.

### Wire format

Replace the single type byte:

```
0x01  handshake init      [0x01][sender_session_id:4][noise msg 1]
0x02  handshake response  [0x02][sender_session_id:4][receiver_session_id:4][noise msg 2]
0x03  reserved (rekey)
0x04  transport           [0x04][receiver_session_id:4][counter:8][ciphertext][tag:16]
```

`0x04` is deliberately kept as the transport type so the coordination protocol
types (`0x10`, `0x11`, `0x30`-`0x33`) stay untouched — Phase 2 handles those.

Counter is the Noise nonce, sent explicitly so the receiver can handle
reordering. 64-bit, never reused within a session.

### New module layout

```
meshlink/src/crypto/
  mod.rs        — exports
  identity.rs   — renamed from handshake.rs; unchanged content
  noise.rs      — NEW: Noise_IK handshake state machine
  session.rs    — NEW: Session, SessionManager, replay window
  transport.rs  — REWRITTEN: real framing, encrypt/decrypt
```

### `Session`

```rust
pub struct Session {
    pub peer_static: PeerPublicKey,   // proven, from the completed handshake
    pub local_id: u32,                // what we tell the peer to send us
    pub remote_id: u32,               // what we put on packets we send
    transport: snow::TransportState,
    send_counter: u64,
    replay: ReplayWindow,
    established: Instant,
    last_recv: Instant,
}
```

`SessionManager` holds `HashMap<u32, Session>` keyed by `local_id` for the
inbound hot path, plus `HashMap<PeerPublicKey, u32>` for outbound lookup.

**Put it behind its own `Arc`, not inside `SharedState`.** `SharedState` is
already the highest-betweenness node in the codebase; adding sessions to it makes
the coupling worse. Pass a `SessionManager` handle to the router tasks
alongside `SharedState`.

### Replay window

Sliding bitmap, WireGuard-style. 128 packets is a good default. Reject counters
below the window, reject already-seen counters inside it, advance on new highs.

## Tasks

Sequenced. Each is independently testable.

### 1.1 — Add dependencies, rename identity
- `snow = "0.9"` (check for a newer version at implementation time).
- `git mv crypto/handshake.rs crypto/identity.rs`; update `crypto/mod.rs` and
  the ~4 call sites. Pure rename, no behaviour change, own commit.

### 1.2 — Replay window
- `crypto/session.rs`: `ReplayWindow` with `check_and_update(counter) -> bool`.
- Unit tests first: in-order accept, duplicate reject, far-past reject,
  far-future advance, wraparound at the window edge.
- This is self-contained and pure; write it before anything touches the network.

### 1.3 — Noise handshake
- `crypto/noise.rs`: build initiator and responder from `snow::Builder` using
  the local `Identity`'s static secret and the peer's known static public key.
- Serialize/parse handshake messages into the `0x01`/`0x02` frames above.
- Test: two in-memory instances complete a handshake and derive matching
  transport keys.

### 1.4 — Session and manager
- `Session::encrypt(plaintext) -> Vec<u8>` and
  `Session::decrypt(counter, ciphertext) -> Option<Vec<u8>>`.
- `SessionManager` with lookup by `local_id` and by peer static key.
- Session ID allocation must be random, not sequential.

### 1.5 — Rewrite `crypto/transport.rs`
- Real framing per the wire format above. Parse and build all four types.
- Keep `is_data_packet` semantics for the router's dispatch, extended to
  recognise handshake types.

### 1.6 — Outbound path (`router/mod.rs::outbound_router_task`)
- After route lookup, get or create the session for that peer.
- No session → start a handshake, queue the packet (bounded queue, drop oldest),
  send on completion.
- Session exists → `session.encrypt()`, frame, send.

### 1.7 — Inbound path (`router/mod.rs::handle_data_packet`) — **the security fix**
Replace the endpoint-matching block entirely:

```
1. parse frame, extract receiver_session_id and counter
2. look up session by id            -> unknown id: drop
3. replay.check_and_update(counter) -> replayed: drop
4. session.decrypt()                -> AEAD failure: drop
5. peer_key = session.peer_static   <- PROVEN, not claimed
6. NOW check allowed_ips against peer_key   <- meaningful for the first time
7. write to TUN
```

Also route `0x01`/`0x02` frames to the handshake handler rather than dropping
them as "unknown packet type".

### 1.8 — Endpoint roaming
Once step 5 yields a proven identity, a packet arriving from a new source
address for an established session is a legitimate NAT rebind. Authenticate
first, then update `peer.endpoint` from the packet source.

Today this behaviour would be a vulnerability. After 1.7 it is a feature, and
it is the payoff that makes the rewrite worth the effort: peers survive network
changes without waiting for a coordination-server round trip.

### 1.9 — Rekey and expiry
- Rekey after N messages (e.g. 2^48, far below nonce exhaustion) or T seconds
  (e.g. 120s, WireGuard's REKEY_AFTER_TIME).
- Expire sessions with no receive activity; drop them from the manager.
- Prune loop, reusing the pattern already in `peer_api/auth.rs::RateLimiter::prune`.

### 1.10 — Handshake DoS resistance
Handshakes are expensive; an unauthenticated peer can force them. At minimum:
rate-limit handshake initiations per source IP, and cap concurrent
half-open handshakes. A cookie-reply mechanism is the thorough answer — note it
in the backlog if you defer it, do not silently skip it.

## Acceptance criteria

- [ ] Two nodes complete a Noise_IK handshake and pass traffic.
- [ ] `tcpdump` on the wire shows no plaintext IP headers inside the payload.
- [ ] A packet with a valid session id but a corrupted tag is dropped.
- [ ] A replayed packet is dropped.
- [ ] **Spoof test:** a third machine sending a well-formed `0x04` frame from a
      peer's address, without session keys, is dropped. This is the test that
      proves the phase.
- [ ] A peer whose source address changes mid-session keeps working without
      re-registering (roaming).
- [ ] Sessions rekey under sustained traffic without dropping packets.
- [ ] `allowed_ips` enforcement is applied against the decrypted session
      identity, never against a claimed one.
- [ ] Throughput measured and recorded here. Note it even if it regressed —
      a number in this file is worth more than an assumption.
- [ ] Integration tests in `meshlink/tests/integration.rs` cover handshake,
      replay, and tamper rejection.

## Out of scope

- **Coordination protocol auth** (`0x30`-`0x33`). Phase 2. The mesh is
  meaningfully secure after Phase 1 even with `REGISTER` still open: the worst an
  attacker can do is deny service, not read or inject traffic.
- **Removing server-side key generation.** Phase 2. Phase 1 must work with
  whatever key the node currently has.
- **Splitting `SharedState`.** Add `SessionManager` alongside it; do not
  restructure. Revisit after this lands, when the real shape is visible.
- **Post-quantum anything.**
- **IPv6 inside the tunnel.** `extract_dest_ip` is IPv4-only today; keep it that
  way for now and note it in the backlog.

## References

- Noise spec, IK pattern: https://noiseprotocol.org/noise.html#interactive-handshake-patterns
- `snow` crate: https://docs.rs/snow
- WireGuard whitepaper (session/rekey/cookie design worth copying):
  https://www.wireguard.com/papers/wireguard.pdf

## Notes

Add findings here as you go.
