use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    Read,
    Write,
}

struct Entry {
    count: u32,
    since: Instant,
}

pub struct RateLimiter {
    map: HashMap<IpAddr, Entry>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn is_locked(&self, ip: IpAddr) -> bool {
        match self.map.get(&ip) {
            Some(e) => e.count >= MAX_FAILURES && e.since.elapsed() < LOCKOUT,
            None => false,
        }
    }

    pub fn failure(&mut self, ip: IpAddr) {
        let e = self.map.entry(ip).or_insert(Entry { count: 0, since: Instant::now() });
        if e.count >= MAX_FAILURES && e.since.elapsed() >= LOCKOUT {
            e.count = 1;
            e.since = Instant::now();
        } else {
            if e.count == 0 {
                e.since = Instant::now();
            }
            e.count += 1;
        }
    }

    pub fn success(&mut self, ip: IpAddr) {
        self.map.remove(&ip);
    }

    pub fn prune(&mut self) {
        self.map.retain(|_, e| {
            e.count < MAX_FAILURES || e.since.elapsed() < LOCKOUT * 2
        });
    }
}

/// Constant-time token comparison — avoids timing side channels.
pub fn token_eq(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        let _ = b.ct_eq(b); // keep timing uniform
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

pub fn audit(ip: IpAddr, method: &str, path: &str, ok: bool, note: &str) {
    if ok {
        tracing::info!(
            target: "peer_api::audit",
            %ip, method, path, note, "allow"
        );
    } else {
        tracing::warn!(
            target: "peer_api::audit",
            %ip, method, path, note, "deny"
        );
    }
}
