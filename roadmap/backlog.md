# Backlog

Known issues deliberately **not** scheduled into a phase. Each has a reason for
being deferred. Revisit after Phase 3.

---

## `allowed_ips` subnet routes silently do not work

`meshlink/src/state.rs:131-150`, `add_peer`:

```rust
for net in &info.allowed_ips {
    routes.insert(net.addr(), pub_key);
}
```

Only the network address of each `allowed_ips` entry is inserted into the route
table. For a `/32` that is correct. For a `/24`, only `x.x.x.0` gets a route —
every other address in the range has no route and `outbound_router_task` drops
the packet at `router/mod.rs:53` (`outbound_target` returns `None`).

Either restrict `allowed_ips` to `/32` and validate at config load, or replace
the `HashMap<Ipv4Addr, PeerPublicKey>` with a longest-prefix-match trie.

**Scheduled as a decision in Phase 0 task 0.6**, because Phase 1 builds session
lookup next to this table. The implementation may land later; the decision must
not.

---

## `SharedState` is the top coupling point

Betweenness centrality 0.248 — the highest in the codebase. It bridges UDP
transport, peer API auth, CLI control, and discovery.

The struct itself (`state.rs`) is clean and well-documented. The problem is how
many subsystems reach into it. Phase 1 makes it worse by adding sessions —
which is why Phase 1 explicitly says to put `SessionManager` behind its own
`Arc` rather than inside `SharedState`.

Deferred because the right split (`PeerTable` / `RouteTable` / `SessionTable`)
is only visible once sessions exist. Pre-refactoring it would be guessing.

---

## `peer_api` security is on the wrong plane

`peer_api/` has mTLS (`tls.rs`), constant-time token comparison
(`util.rs:44`, shared with the coordinator), and per-IP rate limiting with
lockout and pruning (`auth.rs:19-58`). This is real, careful security
engineering. (A replay/nonce store existed but was never called; it was
removed.)

It is all on the node's management HTTP API. None of it was on the data plane.

After Phase 1 the question worth asking is whether `peer_api` still needs its own
TLS and token stack, or whether it should simply bind to the mesh interface and
inherit Noise's authentication. That would delete a lot of code.

Deferred because it is an optimisation that only becomes available after Phase 1.

---

## Handshake DoS / cookie replies

Phase 1 task 1.10 covers rate limiting and capping half-open handshakes. The
thorough answer is WireGuard's cookie-reply mechanism, which lets a loaded
responder defer proof-of-work to the initiator without keeping state.

Deferred as a hardening pass. If Phase 1 ships without it, record that here
explicitly rather than letting it be forgotten.

---

## IPv4-only inside the tunnel

`router/mod.rs::extract_dest_ip` and `extract_src_ip` both check
`version != 4` and drop anything else. IPv6 inside the tunnel is unsupported.

IPv6 *endpoints* are partly supported — `coord/udp_handler.rs` stores
`ipv6_endpoint` separately and advertises a peer's IPv4 endpoint in
preference, and `normalize_addr` handles IPv4-mapped addresses. Nodes still
skip peers whose only endpoint is IPv6 (`discovery/mod.rs`,
`process_discovered_peer`). The tunnelled payload is v4-only.

Deferred: this is a feature, not a security issue, and it touches the same code
Phase 1 rewrites. Doing both at once makes the security diff harder to review.

---

## `private_key_encrypted` column name

`meshlink/src/coord/db.rs::setup_tables` declares `private_key_encrypted BYTEA NOT NULL`, but
`coord/api.rs:413` writes `private_key_opt.map(|k| k.to_vec())` — raw, unencrypted
key bytes. The name suggests a protection that does not exist.

**Resolved by Phase 2 task 2.2**, which drops the column entirely. Listed here so
that if Phase 2 slips, the misleading name is not mistaken for a safeguard.

---

## Coordination server metadata visibility

The coordination server necessarily knows the full peer list, every node's
public key, and every node's endpoint. After Phase 2 it cannot read traffic, but
it still knows the shape of the mesh.

This is an inherent property of a centralised coordinator, not a bug. Recorded
so it is a documented property rather than an unexamined assumption. Changing it
means a fundamentally different discovery design.

---

## Residual risks after the review-findings fixes (`fix/review-findings`)

Mitigations that landed before Phase 1/2 and are **not** the real fix:

- **`PEER_LIST_REQ` is bound to the registering address, not authenticated.**
  `coord/udp_handler.rs::handle_peer_list_req` only answers a key whose last
  `REGISTER`/`KEEPALIVE` came from the same source address. Since `REGISTER` is
  still unauthenticated, anyone who knows a node's public key can register it
  from their own address and then read the peer list. Phase 2 closes this.
- **Nodes accept coordinator packets by source address.** `net/udp.rs` only
  passes `0x11`/`0x32`/`0x34` from the resolved coordinator address. An
  on-path or source-spoofing attacker can still forge them. Phase 2 should sign
  or MAC coordinator messages.
- **`peer_api` has no replay protection.** The unused `NonceStore` was removed
  rather than wired in. Reconsider together with "`peer_api` security is on the
  wrong plane" above.
- **`X-Forwarded-For` is trusted only from loopback.** A reverse proxy on
  another host is not supported; that would need a `trusted_proxies` setting.
- **Port ranges and virtual IPs are never reclaimed.** Both stay reserved for
  every node row, including disabled ones, because nodes are never deleted.
  A node delete (or explicit release) API is needed before the pools run out.
- **Caddy reload assumes `/etc/caddy/Caddyfile` imports the fragment.** The
  main config is taken to be `Caddyfile` next to `caddy.config_path`.
