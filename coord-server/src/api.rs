use crate::config_generator;
use crate::db::{Db, NodeRecord};
use crate::ip_allocator::IpAllocator;
use crate::key_manager;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

/// Shared application state for API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub ip_allocator: IpAllocator,
    pub coord_server_addr: String,
}

/// Build the Axum router with all API routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        .route("/api/v1/node/{id}/config", get(get_config))
        .route("/api/v1/node/{id}/heartbeat", post(heartbeat))
        .route("/api/v1/node/{id}", delete(deregister))
        .route("/api/v1/admin/invite", post(create_invite))
        .with_state(state)
}

// --- Request / Response types ---

#[derive(Deserialize)]
struct RegisterRequest {
    invite_code: String,
    node_name: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    node_id: String,
    private_key: String,
    public_key: String,
    virtual_ip: String,
    config_toml: String,
    auth_token: String,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    peers_changed: bool,
}

#[derive(Serialize)]
struct InviteResponse {
    code: String,
    expires_at: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> impl IntoResponse {
    (status, Json(ErrorResponse { error: msg.into() }))
}

/// Extract and validate the Bearer token from the Authorization header.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Validate that the auth token matches the node's stored token.
async fn validate_auth(db: &Db, node_id: &str, headers: &HeaderMap) -> Result<NodeRecord, (StatusCode, Json<ErrorResponse>)> {
    let token = extract_token(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "missing Authorization header".into() }))
    })?;

    let node = db.get_node(node_id).await.map_err(|e| {
        warn!(error = %e, "database error looking up node");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".into() }))
    })?;

    let node = node.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "node not found".into() }))
    })?;

    if node.auth_token != token {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid token".into() })));
    }

    if node.status == "deregistered" {
        return Err((StatusCode::GONE, Json(ErrorResponse { error: "node has been deregistered".into() })));
    }

    Ok(node)
}

// --- Handlers ---

/// POST /api/v1/register
/// Register a new node with an invite code.
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Validate invite
    let invite = match state.db.get_invite(&req.invite_code).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid invite code").into_response(),
        Err(e) => {
            warn!(error = %e, "database error checking invite");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if invite.used_at.is_some() {
        return error_response(StatusCode::BAD_REQUEST, "invite code already used").into_response();
    }

    if invite.expires_at < Utc::now() {
        return error_response(StatusCode::BAD_REQUEST, "invite code expired").into_response();
    }

    // Generate keypair
    let (private_key, public_key) = key_manager::generate_node_keypair();

    // Allocate IP
    let allocated = match state.db.allocated_ips().await {
        Ok(ips) => ips,
        Err(e) => {
            warn!(error = %e, "failed to list allocated IPs");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let virtual_ip = match state.ip_allocator.allocate(&allocated) {
        Ok(ip) => ip,
        Err(e) => {
            warn!(error = %e, "IP allocation failed");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "no IPs available").into_response();
        }
    };

    // Generate IDs and tokens
    let node_id = Uuid::new_v4().to_string();
    let auth_token = Uuid::new_v4().to_string();

    let now = Utc::now();
    let node_record = NodeRecord {
        node_id: node_id.clone(),
        node_name: req.node_name.clone(),
        public_key: public_key.to_vec(),
        private_key_encrypted: private_key.to_vec(),
        virtual_ip: virtual_ip.clone(),
        auth_token: auth_token.clone(),
        status: "registered".to_string(),
        endpoint: None,
        listen_port: 51820,
        last_heartbeat: None,
        created_at: now,
        updated_at: now,
    };

    // Insert node
    if let Err(e) = state.db.insert_node(&node_record).await {
        warn!(error = %e, "failed to insert node");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    // Mark invite as used
    if let Err(e) = state.db.use_invite(&req.invite_code, &node_id).await {
        warn!(error = %e, "failed to mark invite as used");
    }

    // Generate config
    let active_nodes = state.db.list_active_nodes().await.unwrap_or_default();
    let config_toml = config_generator::generate_config(
        &node_record,
        &active_nodes,
        &state.coord_server_addr,
    );

    let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    info!(node_id = %node_id, virtual_ip = %virtual_ip, "node registered");

    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            node_id,
            private_key: private_key_b64,
            public_key: public_key_b64,
            virtual_ip,
            config_toml,
            auth_token,
        }),
    )
        .into_response()
}

/// GET /api/v1/node/:id/config
/// Fetch the current TOML config for a node.
async fn get_config(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let node = match validate_auth(&state.db, &node_id, &headers).await {
        Ok(n) => n,
        Err(resp) => return resp.into_response(),
    };

    let active_nodes = match state.db.list_active_nodes().await {
        Ok(nodes) => nodes,
        Err(e) => {
            warn!(error = %e, "failed to list nodes");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let config = config_generator::generate_config(&node, &active_nodes, &state.coord_server_addr);
    (StatusCode::OK, config).into_response()
}

/// POST /api/v1/node/:id/heartbeat
/// Update the node's last_seen timestamp.
async fn heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let node = match validate_auth(&state.db, &node_id, &headers).await {
        Ok(n) => n,
        Err(resp) => return resp.into_response(),
    };

    let last_update = node.updated_at;

    if let Err(e) = state.db.update_heartbeat(&node_id, None).await {
        warn!(error = %e, "failed to update heartbeat");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    let peers_changed = state
        .db
        .peers_updated_since(last_update)
        .await
        .unwrap_or(false);

    Json(HeartbeatResponse { peers_changed }).into_response()
}

/// DELETE /api/v1/node/:id
/// Deregister a node, releasing its IP.
async fn deregister(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    if let Err(e) = state.db.update_node_status(&node_id, "deregistered").await {
        warn!(error = %e, "failed to deregister node");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(node_id = %node_id, "node deregistered");
    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/v1/admin/invite
/// Create a new invite code (basic admin endpoint).
async fn create_invite(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(24);

    if let Err(e) = state.db.create_invite(&code, expires_at).await {
        warn!(error = %e, "failed to create invite");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(code = %code, "invite created");

    (
        StatusCode::CREATED,
        Json(InviteResponse {
            code,
            expires_at: expires_at.to_rfc3339(),
        }),
    )
        .into_response()
}
