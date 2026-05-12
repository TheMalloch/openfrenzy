use crate::coord::db::Db;
use chrono::{DateTime, Utc};
use futures::future::join_all;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, RwLock, Semaphore};
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

/// One port's liveness status.
#[derive(Debug, Clone, Serialize)]
pub struct PortStatus {
    pub port: u16,
    pub up: bool,
}

/// Snapshot for a single peer.
#[derive(Debug, Clone, Serialize)]
pub struct PeerSnapshot {
    pub node_id: String,
    pub node_name: Option<String>,
    pub virtual_ip: String,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub endpoint: Option<String>,
    pub ports: Vec<PortStatus>,
    pub scanned_at: DateTime<Utc>,
}

/// Shared scan state: node_id → latest snapshot.
pub type ScanState = Arc<RwLock<HashMap<String, PeerSnapshot>>>;

/// Broadcast channel that carries full JSON snapshots on every scan.
pub type SseTx = broadcast::Sender<String>;

/// Probe a single TCP port. Returns true if a connection was accepted.
async fn probe(ip: &str, port: u16) -> bool {
    let addr = format!("{ip}:{port}");
    timeout(Duration::from_secs(2), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Background task: scans all active peers every `interval_secs` seconds.
/// Requires the coord server to have layer-3 reachability to the mesh virtual
/// IPs (i.e. it should also run `meshlink up` as a peer). If unreachable,
/// all ports will report `up: false`.
pub async fn run(db: Db, state: ScanState, tx: SseTx, interval_secs: u64) {
    // Max simultaneous TCP probes — prevents hammering the network.
    let sem = Arc::new(Semaphore::new(64));
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        let peers = match db.list_active_nodes().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "scanner: failed to list active peers");
                continue;
            }
        };

        let mut peer_futures = Vec::new();

        for peer in peers {
            let bare_ip = peer
                .virtual_ip
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();

            if bare_ip.is_empty() {
                continue;
            }

            let (range_start, range_size) = match (peer.port_range_start, peer.port_range_size) {
                (Some(s), Some(z)) if z > 0 => (s as u16, z as u16),
                _ => (0, 0),
            };

            let sem = sem.clone();

            peer_futures.push(async move {
                let mut port_futures = Vec::new();

                for port in range_start..range_start.saturating_add(range_size) {
                    let ip = bare_ip.clone();
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    port_futures.push(async move {
                        let up = probe(&ip, port).await;
                        drop(permit);
                        PortStatus { port, up }
                    });
                }

                let ports = join_all(port_futures).await;
                debug!(
                    node_id = %peer.node_id,
                    up = ports.iter().filter(|p| p.up).count(),
                    total = ports.len(),
                    "scan complete"
                );

                PeerSnapshot {
                    node_id: peer.node_id,
                    node_name: peer.node_name,
                    virtual_ip: peer.virtual_ip,
                    status: peer.status,
                    last_heartbeat: peer.last_heartbeat,
                    endpoint: peer.endpoint,
                    ports,
                    scanned_at: Utc::now(),
                }
            });
        }

        let snapshots = join_all(peer_futures).await;
        let count = snapshots.len();

        let new_state: HashMap<String, PeerSnapshot> = snapshots
            .into_iter()
            .map(|s| (s.node_id.clone(), s))
            .collect();

        *state.write().await = new_state.clone();

        let payload: Vec<&PeerSnapshot> = new_state.values().collect();
        if let Ok(json) = serde_json::to_string(&payload) {
            let _ = tx.send(json);
        }

        info!(peers = count, "service scan complete");
    }
}
