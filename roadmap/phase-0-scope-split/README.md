# Phase 0 — Scope split

**Goal:** shrink the core to the part that actually carries traffic, so Phase 1
is auditable by one person.

**Estimate:** ~1 week
**Blocks:** Phase 1 (do not start Phase 1 before this lands)

---

## Why

Core meshlink is 8.8k lines across two binaries, and `coord/api.rs` alone is
1127 lines serving 21 routes — of which registration and peer-list are the only
ones the mesh needs. Phase 1 rewrites the trust model. You cannot safely rewrite
a trust model across a surface you cannot read in one sitting.

This is not a cleanup for its own sake. The measurable output is
**security-review surface**, and the target is roughly halving it.

## Current state

Workspace (`Cargo.toml`) has two members: `meshlink`, `mldeploy`.

`meshlink/src/coord/mod.rs` exports 11 submodules:

```
admin_html  api  caddy  config_generator  db  ip_allocator
key_manager  port_allocator  scanner  udp_handler  update_store
```

Of these, the mesh itself needs: `api` (partially), `config_generator`, `db`,
`ip_allocator`, `udp_handler`. The rest are adjacent products.

`coord/api.rs` routes, classified:

```
KEEP (mesh):
  POST   /api/v1/register
  POST   /api/v1/node/keepalive
  GET    /api/v1/node/peers
  PATCH  /api/v1/node/token
  POST   /api/v1/admin/invite
  GET    /api/v1/admin/invites
  DELETE /api/v1/admin/invites/{code}
  GET    /api/v1/admin/peers
  GET    /api/v1/admin/peers/{id}
  POST   /api/v1/admin/peers/{id}/disable
  POST   /api/v1/admin/peers/{id}/enable

MOVE (meshops):
  POST   /api/v1/update
  GET    /api/v1/update/latest
  GET    /api/v1/update/latest/binary
  GET    /api/v1/admin/updates
  GET    /api/v1/admin/services
  GET    /api/v1/admin/stream        (SSE, feeds the admin UI)
  GET    /admin  and  /admin/        (admin_ui)
```

**`mldeploy` is already standalone.** `mldeploy/Cargo.toml` has no dependency on
the `meshlink` crate — it talks HTTP only. Moving it out is a `git mv` plus a
workspace edit, not a refactor.

## Tasks

### 0.1 — Extract `mldeploy` to its own repo
- New repo `meshops`, `mldeploy` as its first binary.
- Remove `"mldeploy"` from `Cargo.toml` workspace members.
- It consumes the coordination server's HTTP API; it already does this, so no
  code changes should be needed beyond the move.
- Verify it still builds standalone before deleting from this tree.

### 0.2 — Move the update/self-update subsystem
- `meshlink/src/coord/update_store.rs` → meshops.
- Remove routes `/api/v1/update*` and `/api/v1/admin/updates` from
  `coord/api.rs`, plus their handlers (`publish_update`, `get_latest_update`,
  `download_latest_binary`, `list_updates`).
- Drop `update_store` from `coord/mod.rs`.
- The `updates` table can stay in the schema for now; migrating it out is a
  separate concern from removing the code path.

### 0.3 — Move the admin UI
- `meshlink/src/coord/admin_html.rs` (431 lines) → meshops, as a static asset or
  a small separate service.
- Remove routes `/admin`, `/admin/`, `/api/v1/admin/services`,
  `/api/v1/admin/stream` and their handlers.
- The `admin/peers` and `admin/invites` JSON endpoints **stay** — they are the
  API the moved UI will call.

### 0.4 — Move Caddy integration
- `meshlink/src/coord/caddy.rs` → meshops.
- Drop `caddy` from `coord/mod.rs` and `CaddyConfig` from
  `coord/mod.rs`'s config structs.
- Note: `caddy.rs` has a `regen_from_db` path — meshops will need read access to
  the coordination DB, or better, drive it from `GET /api/v1/admin/peers`.
  Prefer the API; do not give meshops a second DB connection if avoidable.

### 0.5 — Move the port scanner
- `meshlink/src/coord/scanner.rs` → meshops.
- `coord/port_allocator.rs` is a judgement call: if port ranges are only ever
  used by the Caddy/service-exposure feature, it moves too. If the mesh itself
  allocates ports, it stays. **Check before moving** — grep for
  `PortAllocator` usage in `api.rs` and `db.rs`.

### 0.6 — Decide the `allowed_ips` routing model
Not a move, but it belongs here because it changes a data structure Phase 1
touches. See [`backlog.md`](../backlog.md) for the bug detail.

`state.rs:66` inserts only `net.addr()` per `allowed_ips` entry, so a `/24`
route only matches its network address. Either:
- **(a)** restrict `allowed_ips` to `/32`, validate it at config load, document
  it — simplest, matches how the mesh is actually used; or
- **(b)** replace the `HashMap<Ipv4Addr, PeerPublicKey>` route table with a
  longest-prefix-match structure.

Pick one and write the decision into this file. Phase 1 will build session
lookup next to this table, so it should not be in flux.

## Acceptance criteria

- [ ] `cargo build --release` succeeds for `meshlink` alone; workspace has one member.
- [ ] `cargo test` passes; no test references a moved module.
- [ ] `meshops` builds and runs standalone in its own repo.
- [ ] `meshlink/src/coord/mod.rs` exports 6 or fewer submodules.
- [ ] `coord/api.rs` is under 700 lines.
- [ ] Total core Rust LOC under ~5k (`find meshlink -name '*.rs' | xargs wc -l`).
- [ ] A node can still enrol with `meshlink up --server ... --invite ...` and
      reach another node. **Test this on two real machines before calling the
      phase done** — the acceptance criterion is a working mesh, not a clean build.
- [ ] GUIDE.md and readme.md updated: no references to moved features.
- [ ] Decision 0.6 recorded in this file.

## Out of scope

Do not do these here, however tempting:

- **Any crypto work.** That is Phase 1. Not one line of `crypto/`.
- **Splitting `SharedState`.** It is the top betweenness node and it will get
  worse in Phase 1, but the right split is only visible after sessions exist.
  See backlog.
- **Touching the enrollment trust model.** Server-side key generation stays
  exactly as-is until Phase 2. Moving code and changing behaviour in the same
  pass makes the diff unreviewable.
- **Rewriting `discovery/mod.rs`** (678 lines). It is big but it is mesh-core,
  and Phase 1 rewrites much of it anyway.
- **Reformatting or renaming** beyond what the moves require.

## Notes

Add findings here as you go.
