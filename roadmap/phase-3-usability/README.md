# Phase 3 — Usability

**Goal:** a competent Linux user gets two machines meshed without reading
GUIDE.md.

**Estimate:** ~2 weeks
**Requires:** Phase 2 complete

---

## Why this comes last

Not because it matters least — "not easy to use" was half the reason for this
reset. Because every UX decision made before Phase 2 would need revisiting.

Enrollment changes in Phase 2 (nodes self-generate keys). Status output changes
in Phase 1 (there are now sessions and handshake states to show). Designing the
CLI around today's model means designing it twice.

## Current state

`GUIDE.md` is ~460 lines across ten numbered sections. A first-time user must
read most of it: database creation, `coord.toml` (with the easy-to-miss
`external_address`), Caddy, invite creation, port opening, node registration —
before two machines can ping each other.

`meshlink/src/main.rs` is 745 lines and mixes CLI dispatch, daemonization,
registration, and the daemon runtime.

What already exists and is good:
- `main.rs::wrap_permission_error` — the right instinct, applied in one place.
- `state.rs` tracks per-peer traffic (`PeerStats`), which `status` underuses.
- `cli/mod.rs` has a unix-socket control channel at `/run/meshlink/meshlink.sock`
  (`/var/run/meshlink.sock` outside systemd).

## Tasks

### 3.1 — `meshlink up` with no arguments
On a machine with no config, it should print what it needs and how to get it,
not fail with a clap parse error or a missing-file error. Something like:

```
No configuration found at /etc/meshlink/config.toml

To join an existing mesh, you need an invite code from its coordinator:
    sudo meshlink up --server https://coord.example.com --invite <CODE>

To start your own mesh, see:  meshlink cs --help
```

### 3.2 — `meshlink status` as the primary diagnostic
Model it on `wg show` — the one command that tells you what is wrong:

```
interface: meshlink0
  public key: rTx9…kQ2
  virtual ip: 10.0.0.1/24
  listen port: 51820
  coordinator: coord.example.com:4000  (connected, last sync 4s ago)

peer: nB7k…9xR   node-b
  endpoint: 203.0.113.42:51820
  allowed ips: 10.0.0.2/32
  handshake: 38 seconds ago
  transfer: 1.42 MiB received, 890 KiB sent

peer: pQ2m…4vT   node-c
  endpoint: (unknown)
  allowed ips: 10.0.0.3/32
  handshake: never
  ! no endpoint from coordinator — peer may be offline
```

The last line is the point. Most support questions are "why can't I ping X",
and the answer is almost always visible in per-peer handshake state.

Requires Phase 1: "handshake: never" is only meaningful once handshakes exist.

### 3.3 — Coordinator setup in one command
Today: create the database and user, write `coord.toml` (setting
`external_address`), configure Caddy, run `db-setup`, create an invite, open
two firewall ports, start.

Target: `meshlink cs init` does the reachable parts and prints exactly what it
cannot do itself (firewall rules, DNS), then prints the first invite code and
the exact `meshlink up` line to run on a node. Copy-paste to a working mesh.

### 3.4 — Error messages that name the fix
Audit every `anyhow::bail!` and `.context(...)` in the tree. Each should say what
went wrong *and* what to do. Extend the `wrap_permission_error` pattern:

- TUN creation denied → suggest `setcap cap_net_admin+ep` (already in the
  GUIDE.md Notes, should be in the error).
- Coordinator started without `external_address` → nodes are told to use
  `0.0.0.0:4000`. It logs an error (`coord/mod.rs`) but still starts and hands
  out the dead address; it should refuse to start instead.
- Coordinator unreachable → show the resolved address and the port, and whether
  it was DNS, connection refused, or timeout.
- Invite rejected → distinguish expired, exhausted, and unknown.

### 3.5 — Trim `main.rs`
745 lines mixing four responsibilities. Split CLI dispatch, enrollment, and
daemon runtime. Do this *driven by* the UX changes above, not as a separate
refactor — otherwise it will not converge.

### 3.6 — Rewrite the docs around the happy path
- `readme.md`: what it is, the security model as it actually stands after Phases
  1-2, and a five-line quick start.
- `GUIDE.md`: sections 2 and 3 (node setup, quick example) are the happy path
  and go first. Static configuration (section 7), the peer API (§6) and
  `mldeploy` (§8) are appendices.
- Delete instructions the tooling now handles itself.

### 3.7 — Installer
`install.sh` is the single installer (it writes the `meshlink-peer` /
`meshlink-coord` units itself). It does not install `mldeploy` or its
auto-update unit (`systemd/mldeploy-autoupdate.service`). The installer should
detect the platform, install the binaries, and stop. Enrollment is
`meshlink up`'s job, not the installer's.

## Acceptance criteria

- [ ] A user with a fresh VPS and two machines gets a working mesh using only
      `readme.md`'s quick start. **Test with someone who has not seen the
      project.** Watching where they get stuck is the whole point of this phase.
- [ ] `meshlink up` with no config prints actionable guidance, exit code 1.
- [ ] `meshlink status` shows per-peer handshake age, endpoint, and transfer.
- [ ] `meshlink cs init` takes a fresh Postgres to a running coordinator with a
      printed invite and a ready-to-paste node command.
- [ ] Every error path names a next action.
- [ ] `readme.md` quick start is under 20 lines.
- [ ] `main.rs` is under 300 lines.

## Out of scope

- **GUI or web dashboard.** The admin UI moved to meshops in Phase 0; leave it.
- **Windows or macOS support.** Linux-only stays a stated constraint.
- **Packaging** (deb/rpm/AUR). Worth doing, but after the CLI stabilises.
- **Mobile clients.**
- **Changing the security model** to make something more convenient. If a
  usability fix requires weakening Phases 1-2, it does not ship — write it in
  the backlog instead.

## Notes

Add findings here as you go.
