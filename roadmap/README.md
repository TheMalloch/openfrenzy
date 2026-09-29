# OpenFrenzy / MeshLink Roadmap

One folder per phase. Each phase folder is self-contained: a session can open it
cold, with no prior context, and have everything needed to do the work.

Read this file first, then open exactly one phase folder and stay in it.

| Phase | Folder | Focus | Est. |
|---|---|---|---|
| 0 | [`phase-0-scope-split/`](phase-0-scope-split/) | Cut non-mesh features out of core | ~1 week |
| 1 | [`phase-1-crypto-identity/`](phase-1-crypto-identity/) | Noise_IK sessions; identity from crypto, not IP | ~3-4 weeks |
| 2 | [`phase-2-coordination-auth/`](phase-2-coordination-auth/) | Authenticate REGISTER/KEEPALIVE; nodes self-generate keys | ~1-2 weeks |
| 3 | [`phase-3-usability/`](phase-3-usability/) | Make it usable without reading GUIDE.md | ~2 weeks |
| — | [`backlog.md`](backlog.md) | Known issues deliberately not scheduled | — |

## Why this project needs a reset

The mesh grew past the point where one person can hold it in their head, and the
security work that matters was never done. Concretely, as of the audit that
produced this roadmap:

1. **The data plane is plaintext.** `meshlink/src/crypto/transport.rs` is 24
   lines; `wrap_packet` prepends the byte `0x04`. `x25519-dalek` is a dependency
   but there is no `diffie_hellman` call anywhere in the tree and no AEAD crate
   at all. Keypairs are used purely as names.

2. **Peer identity is the UDP source address.** `meshlink/src/router/mod.rs:135`
   attributes inbound packets via
   `peers.values().find(|p| p.endpoint == Some(src))`. Spoof a source address and
   you are that peer. The `allowed_ips` check on line 149 then validates against
   the identity you claimed, so it protects nothing.

3. **`REGISTER` is unauthenticated.** `meshlink/src/coord/udp_handler.rs:297`
   takes a 35-byte UDP packet, reads bytes 1..33 as a public key, and
   unconditionally overwrites that peer's endpoint in the peer map and the
   database, then broadcasts the new peer list mesh-wide. No signature, no proof
   of key ownership, no invite. Anyone who learns a node's public key can
   redirect its traffic with one packet.

4. **The coordination server holds every node's private key.** Server-side
   keypair generation is the default path (`coord/api.rs:338`), and
   `meshlink/src/coord/db.rs::setup_tables` stores it as `private_key_encrypted BYTEA NOT
   NULL` — which is not encrypted; `coord/api.rs:388` writes raw bytes.

These are **one problem, not four**. Encrypting packets while still identifying
peers by source address buys nothing. The AEAD session *is* the identity
mechanism. So the unit of work is "replace address-based identity with
cryptographic identity", and encryption falls out of it.

## Scale

8.8k lines of Rust across two binaries. Largest files:

```
1127  meshlink/src/coord/api.rs
 860  mldeploy/src/main.rs
 706  meshlink/src/main.rs
 678  meshlink/src/discovery/mod.rs
 503  meshlink/src/coord/mod.rs
 503  meshlink/src/coord/db.rs
 501  meshlink/src/coord/udp_handler.rs
```

Size is not the real problem; scope is. A LAN mesh tool has acquired a Caddy
reverse-proxy config generator, a port-range allocator, a peer port scanner, a
binary update store with self-update, an admin HTML UI, and a second deployment
binary. Each is defensible alone. Together they are why the codebase stopped
being holdable, and why the security work feels unapproachable — the review
surface is four products wide.

## Ordering, and why not to reorder

The temptation is to do Phase 2 first, because the unauthenticated `REGISTER` is
the scariest single finding. Resist it.

After Phase 1, an attacker who rebinds an endpoint still cannot decrypt or inject
anything — they can only cause a denial of service. **Phase 1 downgrades Phase
2's bug from full MITM to nuisance.** Doing Phase 2 first means designing the
coordination auth twice: once before Noise sessions exist, once after.

Phase 0 comes first not because refactoring is virtuous but because you cannot
safely rewrite the trust model of a codebase you cannot fully see.

Phase 3 comes last because every UX decision made now would need revisiting once
the trust model changes.

## Decisions already made

Locked in. Do not relitigate inside a phase session without changing this file.

- **Crypto: Noise_IK via the `snow` crate.** Same handshake pattern WireGuard
  uses. Mutual auth, forward secrecy, identity hiding, from an audited
  implementation. We write the session/rekey state machine, not the primitives.
  Fits the existing X25519 static identities directly.
- **Nodes self-generate keypairs.** The private key never leaves the machine.
  Server compromise stops implying traffic compromise.
- **Non-mesh features split into a separate `meshops` repo**, talking to the
  coordination server over its public HTTP API.

## Status

- [ ] Phase 0 — Scope split
- [ ] Phase 1 — Cryptographic identity and encrypted data plane
- [ ] Phase 2 — Authenticated coordination
- [ ] Phase 3 — Usability

## Working agreement for phase sessions

- Open one phase folder. Do not work across phases in one session.
- Every phase folder has a `README.md` with objective, current state (with
  `file:line` references), tasks, acceptance criteria, and an explicit
  "out of scope" list. The out-of-scope list is what keeps the session bounded.
- Add findings and working notes as extra files inside the phase folder.
- Tick the box above when a phase's acceptance criteria all pass.
