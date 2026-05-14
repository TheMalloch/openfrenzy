use super::config_generator;
use super::db::{Db, NodeRecord};
use super::ip_allocator::IpAllocator;
use super::key_manager;
use super::update_store::UpdateStore;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tracing::{info, warn};
use uuid::Uuid;

/// Shared application state for API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub ip_allocator: IpAllocator,
    pub coord_server_addr: String,
    pub admin_token: Option<String>,
    pub default_listen_port: u16,
    pub update_store: UpdateStore,
}

/// Build the Axum router with all API routes.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        // Peer token rotation (authenticated with current peer token)
        .route("/api/v1/node/token", patch(rotate_peer_token))
        // Update distribution (admin or peer token)
        .route("/api/v1/update", post(publish_update))
        .route("/api/v1/update/latest", get(get_latest_update))
        .route("/api/v1/update/latest/binary", get(download_latest_binary))
        // Admin-only update history
        .route("/api/v1/admin/updates", get(list_updates))
        .with_state(state)
}

/// Start the HTTP API server.
#[allow(clippy::too_many_arguments)]
pub async fn run_http_server(
    port: u16,
    bind_address: String,
    db: Db,
    ip_allocator: IpAllocator,
    coord_server_addr: String,
    admin_token: Option<String>,
    default_listen_port: u16,
    update_store: UpdateStore,
) {
    let state = AppState {
        db,
        ip_allocator,
        coord_server_addr,
        admin_token,
        default_listen_port,
        update_store,
    };

    let app = router(state);
    let addr: SocketAddr = format!("{bind_address}:{port}").parse().expect("valid listen address");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind HTTP listener");
    info!(%addr, "HTTP API server starting");

    if let Err(e) = axum::serve(listener, app).await {
        warn!(error = %e, "HTTP server error");
    }
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

/// Validate the admin token from the Authorization header.
fn validate_admin_token(
    admin_token: &Option<String>,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let configured = admin_token.as_ref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "admin API disabled".into(),
            }),
        )
    })?;

    let provided = extract_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing Authorization header".into(),
            }),
        )
    })?;

    if provided != *configured {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid admin token".into(),
            }),
        ));
    }

    Ok(())
}

// --- Handlers ---

/// POST /api/v1/register
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Validate invite
    let invite = match state.db.get_invite(&req.invite_code).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid invite code").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error checking invite");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    // Check if invite has been fully consumed (max_uses > 0 means limited)
    if invite.max_uses > 0 && invite.use_count >= invite.max_uses {
        return error_response(StatusCode::BAD_REQUEST, "invite code fully used").into_response();
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
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    let virtual_ip = match state.ip_allocator.allocate(&allocated, None) {
        Ok(ip) => ip,
        Err(e) => {
            warn!(error = %e, "IP allocation failed");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "no IPs available")
                .into_response();
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
        ipv6_endpoint: None,
        lan_endpoint: None,
        listen_port: state.default_listen_port as i32,
        last_heartbeat: None,
        created_at: now,
        updated_at: now,
    };

    // Insert node
    if let Err(e) = state.db.insert_node(&node_record).await {
        warn!(error = ?e, "failed to insert node");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    // Increment invite use count
    if let Err(e) = state.db.increment_invite_use(&req.invite_code, &node_id).await {
        warn!(error = %e, "failed to increment invite use count");
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

// ---------------------------------------------------------------------------
// Peer token rotation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RotateTokenRequest {
    new_token: String,
}

/// PATCH /api/v1/node/token
/// The peer authenticates with its current token, sends a new one in the body.
async fn rotate_peer_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RotateTokenRequest>,
) -> impl IntoResponse {
    let provided = match extract_token(&headers) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization").into_response(),
    };

    let node_id = match state.db.validate_peer_token(&provided).await {
        Ok(Some(id)) => id,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "invalid token").into_response(),
        Err(e) => {
            warn!(error = %e, "db error validating token for rotation");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if req.new_token.len() < 16 {
        return error_response(StatusCode::BAD_REQUEST, "new_token too short").into_response();
    }

    if let Err(e) = state.db.rotate_node_token(&node_id, &req.new_token).await {
        warn!(error = %e, "failed to rotate token");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(%node_id, "peer token rotated");
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Update distribution
// ---------------------------------------------------------------------------

/// Resolve the caller's identity from the Authorization header.
/// Accepts an admin token (returns "admin") or a peer auth_token (returns node_id).
/// Returns Err with an HTTP response on failure.
async fn resolve_caller(
    admin_token: &Option<String>,
    db: &Db,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let provided = extract_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing Authorization header".into(),
            }),
        )
    })?;

    // Admin token wins immediately.
    if let Some(admin) = admin_token {
        if provided == *admin {
            return Ok("admin".to_string());
        }
    }

    // Try peer token.
    match db.validate_peer_token(&provided).await {
        Ok(Some(node_id)) => Ok(node_id),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid token".into(),
            }),
        )),
        Err(e) => {
            warn!(error = %e, "db error validating peer token");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "internal error".into(),
                }),
            ))
        }
    }
}

#[derive(Serialize)]
struct UpdateMeta {
    id: i64,
    description: String,
    binary_hash: String,
    binary_size: i64,
    uploaded_by: String,
    uploaded_at: chrono::DateTime<Utc>,
}

impl From<super::db::UpdateRecord> for UpdateMeta {
    fn from(r: super::db::UpdateRecord) -> Self {
        Self {
            id: r.id,
            description: r.description,
            binary_hash: r.binary_hash,
            binary_size: r.binary_size,
            uploaded_by: r.uploaded_by,
            uploaded_at: r.uploaded_at,
        }
    }
}

/// POST /api/v1/update
/// Upload a new binary update. Body = raw binary bytes.
/// Required headers:
///   Authorization: Bearer <admin_token or peer_auth_token>
///   X-Update-Description: <non-empty description>
async fn publish_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let caller = match resolve_caller(&state.admin_token, &state.db, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp.into_response(),
    };

    let description = match headers
        .get("x-update-description")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
    {
        Some(d) if !d.is_empty() => d,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "X-Update-Description header is required and must not be empty",
            )
            .into_response()
        }
    };

    if body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "binary body must not be empty")
            .into_response();
    }

    let hash = format!("{:x}", Sha256::digest(&body));
    let size = body.len() as i64;

    let id = match state.db.insert_update(&description, &hash, size, &caller).await {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "failed to insert update record");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    if let Err(e) = state.update_store.store(id, &body).await {
        warn!(error = %e, "failed to store update binary");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to store binary")
            .into_response();
    }

    info!(id, %caller, bytes = size, "update published");

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "binary_hash": hash,
            "binary_size": size,
            "uploaded_by": caller,
            "description": description,
        })),
    )
        .into_response()
}

/// GET /api/v1/update/latest
/// Return metadata for the most recently published update.
async fn get_latest_update(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = resolve_caller(&state.admin_token, &state.db, &headers).await {
        return resp.into_response();
    }

    match state.db.get_latest_update().await {
        Ok(Some(rec)) => Json(UpdateMeta::from(rec)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "no updates available").into_response(),
        Err(e) => {
            warn!(error = %e, "failed to fetch latest update");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/update/latest/binary
/// Download the binary of the most recently published update.
async fn download_latest_binary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = resolve_caller(&state.admin_token, &state.db, &headers).await {
        return resp.into_response();
    }

    let rec = match state.db.get_latest_update().await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "no updates available").into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to fetch latest update");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    match state.update_store.load(rec.id).await {
        Ok(data) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("x-update-id", &rec.id.to_string()),
                ("x-binary-hash", &rec.binary_hash),
            ],
            data,
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, id = rec.id, "failed to load update binary");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "binary not found").into_response()
        }
    }
}

/// GET /api/v1/admin/updates
/// List all published updates (admin only).
async fn list_updates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.list_updates().await {
        Ok(recs) => {
            let metas: Vec<UpdateMeta> = recs.into_iter().map(UpdateMeta::from).collect();
            Json(metas).into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to list updates");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}


