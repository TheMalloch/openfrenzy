# Phase 2 — Authenticated coordination

**Goal:** close the unauthenticated `REGISTER` hole, and stop the coordination
server from ever holding a node's private key.

**Estimate:** ~1-2 weeks
**Requires:** Phase 1 complete

---

## Why this comes after Phase 1

The unauthenticated `REGISTER` is the scariest single finding in the audit, so
the instinct is to fix it first. Don't.

Before Phase 1, an attacker who rebinds a peer's endpoint gets a full
man-in-the-middle: they receive that peer's traffic in plaintext. After Phase 1,
the same attack yields only ciphertext they cannot decrypt and cannot forge a
session for — the impact drops to denial of service.

So Phase 1 turns this from critical to moderate, and doing Phase 2 first would
mean designing the coordination auth twice: once against a plaintext transport,
once against Noise sessions.

## Current state

### The hole
`meshlink/src/coord/udp_handler.rs:297` — `handle_register`:

```rust
if data.len() < 35 { return; }
let mut public_key = [0u8; 32];
public_key.copy_from_slice(&data[1..33]);
let listen_port = u16::from_be_bytes([data[33], data[34]]);
```

...and then, with no further checks, it inserts into the peer map with
`endpoint: src`, calls `database.update_endpoint_by_pubkey(...)`, and if the
peer is new, `broadcast_peer_list(...)` to the whole mesh.

There is no proof that the sender holds the private key for the public key it
presented. Invite codes gate the **HTTP** enrollment path only; the UDP path has
no gate at all. `handle_keepalive` (line 426) has the same shape.

### The trust problem
`coord/api.rs:338` generates the node's keypair server-side by default, and
`coord/api.rs:388` stores the private key via
`private_key_opt.map(|k| k.to_vec())` into
`migrations/001_init.sql:5`'s `private_key_encrypted BYTEA NOT NULL`.

**The column name is wrong** — the bytes are stored raw, not encrypted.

`GUIDE.md:313` documents server-side generation as a feature. After Phase 1 this
becomes the weakest link: traffic is encrypted, but the server can decrypt all of
it and impersonate any node.

### The good news: BYOK already exists
`coord/api.rs:315` already branches on a client-supplied `public_key`:

```rust
let (private_key_opt, public_key): (Option<[u8; 32]>, [u8; 32]) =
    if let Some(ref pk_b64) = req.public_key { ... (None, arr) }
    else { let (priv_key, pub_key) = key_manager::generate_node_keypair(); (Some(priv_key), pub_key) };
```

`coord/config_generator.rs:15` already handles the empty-private-key case, and
`api_client.rs:52` already plumbs the parameter. It is reachable today only via
a manual `--public-key` flag on `meshlink up` (`main.rs:54`), so nobody uses it.

**This phase flips the default and deletes the other branch.** It is not new
construction.

## Design

### Message authentication

Two options, cheapest first:

**(a) Bearer token.** The server issues a random 32-byte token at HTTP
enrollment; UDP messages carry it. Stops the anonymous rebind. But it is a
bearer token on a plaintext UDP path — sniffable, and replayable until rotated.

**(b) Signature — recommended.** Sign each coordination message with the node's
key. The server verifies against the enrolled public key.

```
0x30 REGISTER  [0x30][pubkey:32][timestamp:8][listen_port:2][lan_ips...][sig:64]
0x33 KEEPALIVE [0x33][pubkey:32][timestamp:8][sig:64]
```

Reject timestamps outside ±30s to bound replay. Signature covers the entire
message before the signature field.

X25519 keys cannot sign directly. Either derive an Ed25519 signing key alongside
the X25519 identity from the same seed, or — cleaner, and reuses Phase 1's work
— run the whole coordination channel through a Noise session with the server,
making the server just another Noise peer. **Decide this at implementation
time and record the decision in this file.** The Noise-channel option is more
work but removes a whole parallel crypto path.

### Enrollment

Public key only, always:

```
sudo meshlink up --server ... --invite CODE --name laptop
  1. generate X25519 keypair locally (crypto/identity.rs::Identity::generate)
  2. POST /api/v1/register { invite, name, public_key }   <- no private key
  3. server returns { node_id, virtual_ip, auth_token, peers[] }
  4. write private key to /etc/meshlink/config.toml, 0600
```

## Tasks

### 2.1 — Make BYOK the only enrollment path
- `main.rs`: generate an identity locally before registering; always send the
  public key. Remove the `--public-key` flag's special-case role (it may stay as
  a way to supply an existing key).
- `coord/api.rs:315`: delete the `else` branch that calls
  `key_manager::generate_node_keypair()`. Registration without a `public_key`
  becomes a 400.
- Delete `coord/key_manager.rs` and its export from `coord/mod.rs`.
- `coord/api.rs:161,423-450`: remove `private_key` from the registration
  response type and its base64 encoding.
- `coord/config_generator.rs`: the private-key line is now always omitted —
  simplify, don't just leave the branch dead.

### 2.2 — Drop private keys from the schema
- Migration: `ALTER TABLE nodes DROP COLUMN private_key_encrypted;`
- Ship a migration that **zeroes the column before dropping it**, so the bytes
  do not survive in table bloat or in a backup taken mid-upgrade.
- Existing deployments: nodes enrolled under the old scheme keep working (the
  server just forgets their private key, which it should never have had).
  Document that operators should re-enrol nodes to rotate keys that the server
  has seen. Those keys must be considered compromised.

### 2.3 — Sign coordination messages
- Extend the `0x30`/`0x33` wire formats as above.
- `coord/udp_handler.rs::handle_register`: look up the enrolled public key,
  verify the signature and the timestamp, reject on failure. Only then touch the
  peer map or the database.
- Same for `handle_keepalive`.
- `handle_peer_list_req` (`0x31`) should also be authenticated — the peer list
  is not public information.

### 2.4 — Version the protocol
Adding fields to `0x30`/`0x33` breaks old nodes. Add a version byte or use new
message types (`0x34`/`0x35`) and support both for one release. Decide, and
write it here — an unversioned flag day will hurt.

### 2.5 — Update the docs
- `GUIDE.md:313` — the "server generates keypairs" note becomes false. Replace
  it with the stronger, now-true statement: the server never sees a private key.
- `readme.md` — "encryption planned" is no longer accurate after Phase 1;
  document the real security model across both phases.

## Acceptance criteria

- [ ] A `REGISTER` with a valid public key but an invalid signature is rejected,
      and the peer map and database are unchanged.
- [ ] A replayed `REGISTER` captured from the wire is rejected on timestamp.
- [ ] **Rebind test:** a third machine cannot change an enrolled peer's endpoint.
      This is the test that proves the phase.
- [ ] `grep -rn "generate_node_keypair" meshlink/src` returns nothing.
- [ ] The `nodes` table has no private key column.
- [ ] A fresh enrollment writes a private key that exists only on the node.
- [ ] Old and new nodes interoperate for one release, or the flag day is
      documented in GUIDE.md.
- [ ] `GUIDE.md` and `readme.md` describe the actual security model.

## Out of scope

- **Coordination server HA / multi-server.** Separate problem.
- **Revocation beyond the existing peer disable endpoints.**
- **Encrypting the coordination channel's metadata** (who is talking to whom).
  The server necessarily knows the peer list. Note it as a known property, not
  a bug.
- **Re-doing Phase 1's data plane.** If a Phase 1 defect surfaces here, log it in
  the Phase 1 notes and fix it there.

## Notes

Add findings here as you go.
