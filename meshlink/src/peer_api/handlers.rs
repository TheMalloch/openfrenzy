use super::auth::{self, Scope};
use super::html::PEER_PAGE;
use super::{PeerAddr, PeerApiState};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::Json;
use serde::Serialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

// --- Auth helper ---

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

async fn check_auth(
    state: &PeerApiState,
    ip: IpAddr,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    scope: Scope,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Source IP CIDR check
    if let Some(cidr) = &state.bind_cidr {
        let allowed = match cidr {
            ipnet::IpNet::V4(net) => match ip {
                IpAddr::V4(v4) => net.contains(&v4),
                _ => false,
            },
            ipnet::IpNet::V6(net) => match ip {
                IpAddr::V6(v6) => net.contains(&v6),
                _ => false,
            },
        };
        if !allowed {
            auth::audit(ip, method, path, false, "source IP not in allowed CIDR");
            return Err((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))));
        }
    }

    {
        let rl = state.rate_limiter.lock().await;
        if rl.is_locked(ip) {
            auth::audit(ip, method, path, false, "rate limited");
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many requests"}))));
        }
    }

    let provided = match bearer(headers) {
        Some(t) => t,
        None => {
            state.rate_limiter.lock().await.failure(ip);
            auth::audit(ip, method, path, false, "missing token");
            return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "missing Authorization"}))));
        }
    };

    let write_tok = state.write_token.read().await;
    if auth::token_eq(&provided, &write_tok) {
        drop(write_tok);
        state.rate_limiter.lock().await.success(ip);
        auth::audit(ip, method, path, true, "write-token");
        return Ok(());
    }
    drop(write_tok);

    if scope == Scope::Read {
        if let Some(rt) = &state.read_token {
            if auth::token_eq(&provided, rt) {
                state.rate_limiter.lock().await.success(ip);
                auth::audit(ip, method, path, true, "read-token");
                return Ok(());
            }
        }
    }

    state.rate_limiter.lock().await.failure(ip);
    auth::audit(ip, method, path, false, "invalid token");
    Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid token"}))))
}

// --- Handlers ---

pub async fn index() -> Html<&'static str> {
    Html(PEER_PAGE)
}

/// GET /api/status
pub async fn get_status(
    State(state): State<Arc<PeerApiState>>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, ip, &headers, "GET", "/api/status", Scope::Read).await {
        return e.into_response();
    }

    let peers = state.shared_state.peers.read().await;
    let uptime = state.start_time.elapsed().as_secs();
    let creds = state.credentials.read().await;

    Json(json!({
        "node_id": creds.node_id,
        "virtual_ip": state.virtual_ip.to_string(),
        "uptime_secs": uptime,
        "peer_count": peers.len(),
        "coord_server": creds.server,
    }))
    .into_response()
}

/// GET /api/peers
pub async fn get_peers(
    State(state): State<Arc<PeerApiState>>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, ip, &headers, "GET", "/api/peers", Scope::Read).await {
        return e.into_response();
    }

    #[derive(Serialize)]
    struct PeerInfo {
        virtual_ip: String,
        status: String,
        endpoint: Option<String>,
        tx_bytes: u64,
        rx_bytes: u64,
    }

    let peers = state.shared_state.peers.read().await;
    let list: Vec<PeerInfo> = peers
        .values()
        .map(|p| PeerInfo {
            virtual_ip: p.virtual_ip.to_string(),
            status: if p.endpoint.is_some() { "active" } else { "pending" }.to_string(),
            endpoint: p.endpoint.map(|a| a.to_string()),
            tx_bytes: p.tx_bytes,
            rx_bytes: p.rx_bytes,
        })
        .collect();

    Json(list).into_response()
}

/// GET /api/config
pub async fn get_config(
    State(state): State<Arc<PeerApiState>>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, ip, &headers, "GET", "/api/config", Scope::Read).await {
        return e.into_response();
    }

    let creds = state.credentials.read().await;
    Json(json!({
        "node_id": creds.node_id,
        "virtual_ip": state.virtual_ip.to_string(),
        "coord_server": creds.server,
        "peer_api_port": state.port,
        "tls_enabled": state.tls_enabled,
        "mtls_enabled": state.mtls_enabled,
    }))
    .into_response()
}

/// POST /api/token/rotate  (write scope only)
pub async fn rotate_token(
    State(state): State<Arc<PeerApiState>>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, ip, &headers, "POST", "/api/token/rotate", Scope::Write).await {
        return e.into_response();
    }

    let new_token = uuid::Uuid::new_v4().to_string();

    let (coord_url, old_token) = {
        let creds = state.credentials.read().await;
        (creds.server.clone(), creds.auth_token.clone())
    };

    let resp = state
        .coord_client
        .patch(format!("{coord_url}/api/v1/node/token"))
        .bearer_auth(&old_token)
        .json(&json!({"new_token": new_token}))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            warn!(status = %r.status(), "coord server rejected token rotation");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "coord server rejected rotation"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "failed to reach coord server for token rotation");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "could not reach coord server"})),
            )
                .into_response();
        }
    }

    {
        let mut creds = state.credentials.write().await;
        creds.auth_token = new_token.clone();
        if let Err(e) = creds.save_to(&state.credentials_path) {
            warn!(error = %e, "failed to persist rotated credentials");
        }
    }

    *state.write_token.write().await = new_token.clone();

    let node_id = state.credentials.read().await.node_id.clone();
    tracing::info!(%node_id, %ip, "auth token rotated");

    Json(json!({"new_token": new_token})).into_response()
}
