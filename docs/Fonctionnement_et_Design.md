# Meshlink — Architecture technique détaillée

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Interface TUN — capture de paquets](#2-interface-tun--capture-de-paquets)
3. [Pipeline de paquets — canaux Tokio](#3-pipeline-de-paquets--canaux-tokio)
4. [Routage — outbound et inbound](#4-routage--outbound-et-inbound)
5. [Transport UDP — enveloppe de paquet](#5-transport-udp--enveloppe-de-paquet)
6. [Serveur de coordination — protocole UDP](#6-serveur-de-coordination--protocole-udp)
7. [Découverte de pairs — discovery_task](#7-découverte-de-pairs--discovery_task)
8. [NAT detection et Hole Punching](#8-nat-detection-et-hole-punching)
9. [Allocation d'IP virtuelle](#9-allocation-dip-virtuelle)
10. [Base de données PostgreSQL — sqlx](#10-base-de-données-postgresql--sqlx)
11. [Système d'invitations](#11-système-dinvitations)
12. [Intégration Caddy + Allocation de ports](#12-intégration-caddy--allocation-de-ports)
13. [Démonisation et signaux Unix](#13-démonisation-et-signaux-unix)
14. [Identité — X25519](#14-identité--x25519)
15. [État partagé — SharedState](#15-état-partagé--sharedstate)

---

## 1. Vue d'ensemble

Meshlink est un **VPN mesh pair-à-pair** écrit en Rust. Chaque nœud est un binaire unique (`meshlink`) qui embarque optionnellement un serveur de coordination (`meshlink cs start`). Les nœuds envoient du trafic IP brut encapsulé en UDP directement de pair à pair, sans passer par un relay central une fois la connexion établie.

```
[OS kernel] ──TUN──> [meshlink] ──UDP──> [peer meshlink]
                        ↑ UDP
                  [coord server]   (register / peer-list / keepalive)
```

**Stack technique :**
- `tokio` : runtime async, canaux mpsc, timers — [docs.rs/tokio](https://docs.rs/tokio)
- `tun` crate : interface réseau virtuelle Linux/macOS — [docs.rs/tun](https://docs.rs/tun)
- `sqlx` : requêtes PostgreSQL async et compile-time — [docs.rs/sqlx](https://docs.rs/sqlx)
- `axum` : HTTP API REST pour l'admin — [docs.rs/axum](https://docs.rs/axum)
- `x25519-dalek` : clés publiques/privées Diffie-Hellman — [docs.rs/x25519-dalek](https://docs.rs/x25519-dalek)
- `clap` : CLI derive macros — [docs.rs/clap](https://docs.rs/clap)

---

## 2. Interface TUN — capture de paquets

**Fichier :** `meshlink/src/tun/mod.rs`

Une interface TUN est un périphérique réseau virtuel en espace utilisateur. Le kernel y envoie les paquets IP à destination de l'IP virtuelle du nœud, et meshlink les lit comme un simple descripteur de fichier.

```rust
// tun/mod.rs:14
let mut config = tun::Configuration::default();
config
    .tun_name(name)
    .address(virtual_ip.addr())
    .netmask(virtual_ip.netmask())
    .mtu(1420)   // 1500 - 80 bytes overhead (UDP/IP + type byte)
    .up();
```

Le MTU de **1420** est choisi pour laisser de la place à l'encapsulation UDP (20 bytes IP + 8 bytes UDP + 1 byte type = 29 bytes) sans fragmentation. C'est la même valeur que WireGuard par défaut.

> **Référence :** RFC 4459 — MTU and Fragmentation Issues with In-the-Network Tunneling.
> **Discussion :** [WireGuard MTU considerations](https://www.wireguard.com/known-limitations/)

Le device est ouvert en mode async via `tun::create_as_async()`, puis splitté en lecture/écriture avec `tokio::io::split` afin d'alimenter deux tâches indépendantes sans contention de lock :

```rust
// main.rs:511
let (tun_read, tun_write) = tokio::io::split(tun_dev);
```

**`tun_reader_task`** lit en boucle avec `dev.read(&mut buf)` (buffer 1500 bytes) et forward chaque paquet sur le canal `tun_to_router_tx`.

**`tun_writer_task`** reçoit des paquets décapsulés depuis `router_to_tun_rx` et les écrit avec `dev.write_all()`, injectant ainsi le trafic entrant dans le kernel.

> **Linux TUN/TAP :** [kernel.org — tuntap.txt](https://www.kernel.org/doc/html/latest/networking/tuntap.html)

---

## 3. Pipeline de paquets — canaux Tokio

**Fichier :** `meshlink/src/state.rs:114`

Pour éviter tout mutex sur le chemin critique des paquets, meshlink utilise des **canaux `mpsc` unidirectionnels** entre les tâches. Chaque canal a un buffer de 256 entrées (backpressure intégrée — `send().await` bloque si plein).

```
TUN reader ──[tun_to_router_tx]──> outbound router ──[router_to_udp_tx]──> UDP writer
                                                                              ↓ socket
UDP reader ──[udp_to_router_tx]──> inbound router ──[router_to_tun_tx]──> TUN writer
               ↓ coord packets
           [coord_tx/coord_rx]──> discovery_task
```

```rust
// state.rs:134
pub fn new(buffer_size: usize) -> Self {
    let (tun_to_router_tx, tun_to_router_rx) = mpsc::channel(buffer_size);
    let (router_to_udp_tx, router_to_udp_rx) = mpsc::channel(buffer_size);
    // ...
}
```

> **Référence :** Tokio mpsc — [tokio.rs/docs/channels](https://docs.rs/tokio/latest/tokio/sync/mpsc/index.html)
> **Pattern :** "Actor model" en Rust async — [Alice Ryhl — Actors with Tokio](https://ryhl.io/blog/actors-with-tokio/)

Le canal `coord_tx/coord_rx` (capacité 64) sert de file séparée pour les messages de contrôle venant du serveur de coordination (réponses NAT `0x11`, listes de pairs `0x32`). Le `udp_reader_task` dispatche sur ce canal selon le type de message :

```rust
// net/udp.rs — les paquets coord (0x10-0x33) partent sur coord_tx
// les paquets data (0x04) partent sur udp_to_router_tx
```

---

## 4. Routage — outbound et inbound

**Fichier :** `meshlink/src/router/mod.rs`

### Outbound (TUN → UDP)

```rust
// router/mod.rs:43
pub async fn outbound_router_task(...) {
    while let Some(packet) = tun_rx.recv().await {
        let dest_ip = extract_dest_ip(&packet); // octets [16..20] du header IPv4
        let peer_key = state.lookup_route(dest_ip).await; // HashMap<Ipv4Addr, PubKey>
        let endpoint = peer.endpoint; // SocketAddr UDP réel du pair
        let wrapped = transport::wrap_packet(&packet); // préfixe 0x04
        udp_tx.send(RoutedPacket { data: wrapped, peer_endpoint: endpoint }).await;
    }
}
```

L'extraction de l'IP destination lit directement les octets 16-19 du header IPv4 (offset fixe, version vérifiée) :

```rust
fn extract_dest_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 { return None; }
    if packet[0] >> 4 != 4 { return None; } // version IPv4
    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}
```

> **RFC 791 :** Format du header IPv4 — offset 16 = Destination Address.

### Inbound (UDP → TUN)

```rust
// router/mod.rs:95
pub async fn inbound_router_task(...) {
    while let Some(packet) = udp_rx.recv().await {
        if transport::is_data_packet(&packet.data) {
            handle_data_packet(&state, &packet.data, packet.peer_endpoint, &tun_tx).await;
        }
    }
}
```

L'inbound effectue une **vérification `allowed_ips`** : l'IP source du paquet IP décapsulé doit appartenir aux plages autorisées pour ce pair. C'est la même logique que WireGuard — un pair ne peut pas usurper une IP qui n'est pas la sienne :

```rust
// router/mod.rs:147
let allowed = peer.allowed_ips.iter().any(|net| net.contains(&src_ip));
if !allowed {
    warn!("packet source IP not in allowed_ips, dropping");
    return;
}
```

> **WireGuard conceptual overview :** [wireguard.com/papers/wireguard.pdf](https://www.wireguard.com/papers/wireguard.pdf) — section "Cryptokey Routing"

---

## 5. Transport UDP — enveloppe de paquet

**Fichier :** `meshlink/src/crypto/transport.rs`

Le format de transport actuel est minimal : un seul octet de type `0x04` est préfixé au paquet IP brut. Il n'y a **pas de chiffrement** pour l'instant.

```rust
pub const DATA_PACKET_TYPE: u8 = 0x04;

pub fn wrap_packet(plaintext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + plaintext.len());
    packet.push(DATA_PACKET_TYPE);
    packet.extend_from_slice(plaintext);
    packet
}

pub fn unwrap_packet(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() >= 2 && packet[0] == DATA_PACKET_TYPE {
        Some(&packet[1..])
    } else {
        None
    }
}
```

L'octet `0x04` sert à distinguer les paquets data des paquets de contrôle du protocole de coordination (`0x10`-`0x33`), car tout transite sur le même socket UDP.

**Évolution prévue :** chiffrement symétrique (ChaCha20-Poly1305) après un handshake X25519 ECDH — les clés `x25519-dalek` sont déjà en place dans `crypto/handshake.rs`.

> **Référence chiffrement :** [RFC 8439 — ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
> **x25519-dalek :** [docs.rs/x25519-dalek](https://docs.rs/x25519-dalek)

---

## 6. Serveur de coordination — protocole UDP

**Fichier :** `meshlink/src/coord/udp_handler.rs`

Le serveur de coordination maintient un **registre en mémoire** (`PeerMap = Arc<Mutex<HashMap<[u8;32], RegisteredPeer>>>`) et une source de vérité persistante en PostgreSQL.

### Protocole wire (binaire, big-endian)

| Opcode | Direction | Contenu |
|--------|-----------|---------|
| `0x10` | Peer → Coord | NAT detect request (1 byte) |
| `0x11` | Coord → Peer | NAT detect response: `[type:1][ip:4\|16][port:2]` |
| `0x30` | Peer → Coord | Register: `[pubkey:32][port:2][lan_count:1][lan_ips:n*4]` |
| `0x31` | Peer → Coord | Peer list request: `[pubkey:32]` |
| `0x32` | Coord → Peer | Peer list response: `[count:2]([pubkey:32][vip:4][type:1][ip:4\|16][port:2][lan_ip:4][lan_port:2])*` |
| `0x33` | Peer → Coord | Keepalive: `[pubkey:32][lan_count:1][lan_ips:n*4]` |

### Boucle principale

La boucle du serveur utilise `tokio::select!` pour multiplexer la réception UDP et le nettoyage périodique des pairs stales :

```rust
// udp_handler.rs:63
loop {
    tokio::select! {
        result = socket.recv_from(&mut buf) => { handle_message(...).await; }
        _ = cleanup_interval.tick() => {
            map.retain(|_, p| p.last_seen > cutoff); // supprime les pairs stales
        }
    }
}
```

> **tokio::select! :** [docs.rs/tokio/latest/tokio/macro.select.html](https://docs.rs/tokio/latest/tokio/macro.select.html)

### Broadcast server-push

Quand un nouveau pair s'enregistre, le serveur **pousse immédiatement** une liste de pairs mise à jour à tous les pairs connectés, sans attendre leur prochain `PEER_LIST_REQ` :

```rust
// udp_handler.rs:384
if is_new {
    broadcast_peer_list(socket, peers, database).await;
}
```

`broadcast_peer_list` construit une réponse **personnalisée par pair** (excluant le destinataire de sa propre liste) et l'envoie à chaque endpoint connu :

```rust
// udp_handler.rs:138
for (requester_key, endpoint) in &endpoints {
    let resp = build_peer_list_response(requester_key, &db_nodes, peers).await;
    socket.send_to(&resp, endpoint).await;
}
```

La réponse préfère l'endpoint UDP live (en mémoire) sur l'endpoint persisté en base, pour tenir compte des changements de port NAT récents.

> **Discussion :** Push vs pull pour la découverte de pairs — [tailscale.com/blog/how-tailscale-works](https://tailscale.com/blog/how-tailscale-works/)

---

## 7. Découverte de pairs — discovery_task

**Fichier :** `meshlink/src/discovery/mod.rs`

La tâche de découverte tourne en boucle infinie avec trois timers indépendants gérés par `tokio::select!` :

| Timer | Intervalle | Action |
|-------|-----------|--------|
| `discovery_interval` | 30 s | Envoie `0x31`, attend `0x32` avec timeout 5 s |
| `keepalive_interval` | 25 s | Envoie `0x33` pour maintenir l'entrée UDP sur le coord |
| `reregister_interval` | 5 min | Re-envoie `0x30` + re-détecte le NAT |

À la réception d'une liste de pairs, `process_peer_list_data` :
1. **Ajoute** les nouveaux pairs à `SharedState`
2. **Supprime** les pairs absents de la liste (ils ont été marqués stales)
3. **Réécrit** la section `[[peers]]` du fichier de config TOML

La réécriture du fichier config (`rewrite_config_peers`) est une stratégie simple : on conserve tout ce qui précède le premier `[[peers]]` et on réécrit toutes les entrées depuis l'état mémoire. Elle est **idempotente** et tolérante aux formats variés.

```rust
// discovery/mod.rs:467
let peers_start = existing.find("\n[[peers]]")
    .map(|i| i + 1)
    .unwrap_or(existing.len());
let mut new_config = existing[..peers_start].to_string();
for peer in peers.values() {
    new_config.push_str(&format!("\n[[peers]]\npublic_key = \"{}\"\n...", pub_key_b64));
}
```

### Sélection d'endpoint (same-NAT)

Si deux pairs partagent la même IP publique (derrière le même NAT), le pair cible est inaccessible via son endpoint public — les paquets boucleraient à l'intérieur du NAT sans sortir. Meshlink détecte ce cas et utilise le LAN endpoint à la place :

```rust
// discovery/mod.rs:361
fn select_endpoint(discovered: &DiscoveredPeer, our_public_ip: Option<IpAddr>) -> SocketAddr {
    if let (Some(our_ip), Some(lan_ep)) = (our_public_ip, discovered.lan_endpoint) {
        if discovered.endpoint.ip() == our_ip {
            return lan_ep; // même NAT → LAN direct
        }
    }
    discovered.endpoint
}
```

> **Référence same-NAT :** [RFC 4787 — Network Address Translation Behavioral Requirements](https://datatracker.ietf.org/doc/html/rfc4787)
> **Hairpin NAT :** [en.wikipedia.org/wiki/Hairpinning](https://en.wikipedia.org/wiki/Hairpinning)

---

## 8. NAT detection et Hole Punching

**Fichier :** `meshlink/src/net/hole_punch.rs`

### NAT Detection (STUN-like)

Meshlink envoie un paquet `0x10` au serveur de coordination. Le serveur répond `0x11` avec l'IP et le port tels qu'il les voit (l'adresse publique après NAT). C'est le principe de base de STUN (RFC 8489) sans la complexité de ses extensions.

```rust
// hole_punch.rs:41
let probe = [0x10u8];
socket.send_to(&probe, coord_server).await;
// attente de la réponse 0x11 avec timeout 5s
```

La réponse `0x11` encode l'adresse en format binaire compact (type byte `0x04`=IPv4 ou `0x06`=IPv6 puis l'adresse et le port).

> **STUN :** [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)
> **Comparaison avec STUN :** meshlink implémente uniquement le "binding request" — pas de CHANGE-REQUEST ni de XOR-MAPPED-ADDRESS.

### UDP Hole Punching

Pour traverser le NAT, meshlink envoie 5 sondes espacées à l'endpoint public du pair. Ces sondes ouvrent des "trous" dans le NAT des deux côtés :

```rust
// hole_punch.rs:126
for i in 0..5 {
    socket.send_to(&probe, peer_endpoint).await;
    tokio::time::sleep(Duration::from_millis(200 * (i + 1))).await;
}
```

Le délai croissant (200ms, 400ms, 600ms...) compense la latence réseau et les paquets perdus. Les deux pairs doivent effectuer ce punch simultanément — c'est le serveur qui les y incite en leur envoyant la liste de pairs au même moment via le broadcast `0x32`.

> **UDP hole punching :** [RFC 5128 — State of Peer-to-Peer Communication across NATs](https://datatracker.ietf.org/doc/html/rfc5128)
> **Article de référence :** [Bryan Ford, Pyda Srisuresh, Dan Kegel — Peer-to-Peer Communication Across NATs](https://bford.info/pub/net/p2pnat/)

**Limitation connue :** le hole punching échoue avec les NATs symétriques (ports différents pour chaque destination). Dans ce cas, un relay (TURN) serait nécessaire. Meshlink ne l'implémente pas encore.

---

## 9. Allocation d'IP virtuelle

**Fichier :** `meshlink/src/coord/ip_allocator.rs`

L'allocateur linéaire itère de `.1` à `host_count` dans le CIDR configuré et retourne la première IP non déjà allouée :

```rust
// ip_allocator.rs:74
for i in 1..=host_count {
    let candidate = Ipv4Addr::from(net_u32 + i);
    if !allocated_addrs.contains(&candidate) {
        return Ok(format!("{}/{}", candidate, self.prefix_len));
    }
}
```

La liste `allocated` est lue depuis la base de données avant chaque allocation — pas de compteur en mémoire, donc pas de problème de désynchronisation après redémarrage.

L'option `override_ip` permet d'assigner une IP spécifique (pour les migrations ou tests) avec validation que l'IP est dans le réseau et non déjà prise.

---

## 10. Base de données PostgreSQL — sqlx

**Fichier :** `meshlink/src/coord/db.rs`

### Contrainte sqlx : une requête par appel

`sqlx` refuse de compiler des requêtes multi-statements dans un seul `query()`. Chaque `ALTER TABLE`, `CREATE TABLE`, `DROP TABLE` doit être une requête séparée :

```rust
// db.rs:68 — chaque statement est un appel sqlx distinct
sqlx::query("CREATE TABLE IF NOT EXISTS nodes (...)").execute(&self.pool).await?;
sqlx::query("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS port_range_start INT").execute(&self.pool).await?;
sqlx::query("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS port_range_size INT").execute(&self.pool).await?;
```

> **Issue sqlx :** [github.com/launchbadge/sqlx/issues/1151](https://github.com/launchbadge/sqlx/issues/1151) — "Multiple statements in a single query() are not supported"
> **Docs :** [sqlx — Query API](https://docs.rs/sqlx/latest/sqlx/fn.query.html)

### Schéma de la table `nodes`

```sql
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT,
    public_key BYTEA NOT NULL UNIQUE,
    private_key_encrypted BYTEA NOT NULL,
    virtual_ip TEXT NOT NULL UNIQUE,
    auth_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'registered'
        CHECK(status IN ('registered','active','stale','deregistered')),
    endpoint TEXT,
    ipv6_endpoint TEXT,
    lan_endpoint TEXT,
    listen_port INT NOT NULL DEFAULT 51820,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    port_range_start INT,
    port_range_size INT
);
```

Les colonnes `port_range_start` et `port_range_size` ont été ajoutées via migration `ALTER TABLE IF NOT EXISTS` — c'est le mécanisme de migration sans outil externe (pas de diesel-migrations ni de refinery).

### Endpoint live vs DB

Le serveur maintient deux vues du même pair :
- **En mémoire** (`PeerMap`) : endpoint UDP actuel, mis à jour à chaque paquet reçu — source of truth pour le broadcast
- **En DB** (`nodes.endpoint`) : endpoint persisté, utilisé pour la génération de config TOML et la liste admin

---

## 11. Système d'invitations

**Fichiers :** `coord/api.rs`, `coord/db.rs`

Un pair ne peut rejoindre le réseau qu'avec un **code d'invitation** valide. Les invitations supportent :
- `max_uses` : 0 = illimité, N = quota
- `expires_at` : timestamp d'expiration
- `use_count` : compteur incrémenté à chaque utilisation

La validation vérifie les deux conditions d'épuisement :

```rust
// logique dans api.rs
let expired = invite.expires_at < Utc::now();
let exhausted = invite.max_uses > 0 && invite.use_count >= invite.max_uses;
if expired || exhausted { return Err(/* 403 */); }
```

À l'utilisation, `use_count` est incrémenté en base dans la même transaction que la création du nœud, pour éviter les race conditions.

**CLI :**
```bash
meshlink cs create-invite --multi-use --max-uses 5 --expires-hours 48
```

**HTTP API :**
```http
POST /api/v1/admin/invite
Authorization: Bearer <admin_token>
{"max_uses": 5, "expires_in_hours": 48}
```

---

## 12. Intégration Caddy + Allocation de ports

**Fichiers :** `coord/caddy.rs`, `coord/port_allocator.rs`

### Allocation de plages de ports

Chaque nœud reçoit un bloc de ports UDP contigus `[base + n*block_size .. base + n*block_size + block_size - 1]`. L'allocateur cherche le premier slot libre :

```rust
// port_allocator.rs
pub struct PortAllocator { base: u16, block_size: u16 }
// slot 0 → [base .. base+block_size-1]
// slot 1 → [base+block_size .. base+2*block_size-1]
```

Les plages allouées sont récupérées depuis la DB (`allocated_port_ranges()`) à chaque allocation pour éviter les conflits après redémarrage.

### Génération Caddyfile

Caddy est utilisé comme reverse proxy TLS devant l'API HTTP des nœuds. Meshlink génère dynamiquement le Caddyfile et le recharge via l'API admin Caddy :

```rust
// caddy.rs
pub fn generate_caddyfile(peers: &[NodeRecord], domain: &str) -> String {
    // Pour chaque nœud avec port_range_start défini :
    // {node_id}.{domain} { reverse_proxy {endpoint}:{http_port} }
}

pub async fn write_and_reload(path: &str, admin_api: &str, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    // POST http://localhost:2019/load (Caddy admin API)
    // fallback: systemctl reload caddy
}
```

> **Caddy Admin API :** [caddyserver.com/docs/api](https://caddyserver.com/docs/api)
> **Limitation :** Caddy ne proxifie que TCP/HTTP — le trafic UDP de coordination doit aller directement (pas via Caddy).

---

## 13. Démonisation et signaux Unix

**Fichier :** `meshlink/src/main.rs`

Meshlink utilise la crate `daemonize` pour se forker en arrière-plan :

```rust
// main.rs:115
let daemonize = daemonize::Daemonize::new()
    .pid_file(&pid_path)       // /var/run/meshlink.pid
    .chown_pid_file(true)
    .stdout(log_file)           // redirige stdout → /var/log/meshlink.log
    .stderr(log_file_err);
daemonize.start()?;
```

**Pourquoi initialiser `tracing` après le fork ?** Le fork POSIX clone le processus au niveau OS. Si `tracing-subscriber` est initialisé avant le fork, le processus enfant hériterait d'handles potentiellement corrompus. La règle est : initialiser les ressources async/IO après le fork.

> **Fork et threads :** [pubs.opengroup.org — fork after threads](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html)

**Tokio runtime post-fork :** le runtime Tokio est multi-thread par défaut. Meshlink utilise `new_current_thread()` pour éviter les problèmes de threads orphelins après fork :

```rust
// main.rs:140
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
```

> **Tokio et fork :** [docs.rs/tokio — Builder](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html) — "Do not fork after starting a multi-threaded runtime."

### Arrêt propre

`meshlink down` envoie `SIGTERM` au PID lu dans le PID file. Le daemon intercepte `SIGTERM` via `tokio::signal::unix::signal(SignalKind::terminate())` et annule toutes les tâches via `.abort()` :

```rust
// main.rs:617
tokio::select! {
    _ = sigterm.recv() => { info!("received SIGTERM"); }
    result = tokio::signal::ctrl_c() => { /* Ctrl+C en foreground */ }
}
// abort toutes les tâches, supprime socket CLI et PID file
```

---

## 14. Identité — X25519

**Fichier :** `meshlink/src/crypto/handshake.rs`

Chaque nœud possède une paire de clés X25519 (Diffie-Hellman sur courbe 25519). La clé publique sert d'**identifiant unique** du pair dans tous les messages du protocole de coordination.

```rust
// handshake.rs — Identity::from_base64 charge la clé privée depuis la config
// identity.public_key_bytes() → [u8; 32]
```

La clé publique est encodée en base64 pour le stockage config/DB/affichage, et utilisée en binaire brut dans les messages UDP (32 bytes fixes).

> **X25519-dalek :** [docs.rs/x25519-dalek](https://docs.rs/x25519-dalek)
> **RFC 7748 :** [Elliptic Curves for Diffie-Hellman Key Agreement](https://datatracker.ietf.org/doc/html/rfc7748)

La clé privée générée par `meshlink genkey` ou `meshlink cs keygen` est stockée en base64 dans la config TOML. La DB stocke la clé privée chiffrée (`private_key_encrypted BYTEA`) — le chiffrement côté serveur n'est pas encore implémenté (stockage brut encodé pour l'instant).

---

## 15. État partagé — SharedState

**Fichier :** `meshlink/src/state.rs`

`SharedState` est le cœur de la coordination entre tâches. Il utilise `Arc<RwLock<...>>` car les tables sont **read-heavy** (lookup à chaque paquet) et **write-rare** (modification uniquement lors de l'ajout/suppression de pairs) :

```rust
pub struct SharedState {
    pub peers:  Arc<RwLock<HashMap<PeerPublicKey, PeerInfo>>>,  // pubkey → info
    pub routes: Arc<RwLock<HashMap<Ipv4Addr, PeerPublicKey>>>,  // vip → pubkey
    pub our_public_ip: Arc<RwLock<Option<IpAddr>>>,
}
```

La **double table** (peers + routes) permet un lookup O(1) dans les deux directions sans scan linéaire :
- Outbound : `routes[dest_vip]` → pubkey → `peers[pubkey]` → endpoint
- Inbound : scan linéaire sur `peers.values()` par endpoint source (acceptable : peu de pairs)

`RwLock` de Tokio est un rwlock async — il ne bloque pas le thread, il suspend la tâche en attendant le verrou.

> **Tokio RwLock :** [docs.rs/tokio/latest/tokio/sync/struct.RwLock.html](https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html)
> **Pattern Arc<RwLock<T>> :** [Rust Book — Shared-State Concurrency](https://doc.rust-lang.org/book/ch16-03-shared-state.html)

L'`Arc` (Atomic Reference Counted) permet de cloner `SharedState` pour le passer à chaque tâche sans copie des données — toutes les tâches partagent le **même** pointeur vers les mêmes `RwLock`.

---

*Document généré à partir du code source de `meshlink/` — mai 2026.*
