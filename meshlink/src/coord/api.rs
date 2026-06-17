use super::admin_html::ADMIN_PAGE;
use super::caddy;
use super::config_generator;
use super::db::{Db, NodeRecord};
use super::ip_allocator::IpAllocator;
use super::key_manager;
use super::port_allocator::PortAllocator;
use super::scanner::{ScanState, SseTx};
use super::udp_handler::{self, PeerMap};
use super::update_store::UpdateStore;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};
use uuid::Uuid;

/// Shared application state for API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub ip_allocator: IpAllocator,
    pub port_allocator: PortAllocator,
    pub coord_server_addr: String,
    pub coord_api_url: Option<String>,
    pub admin_token: Option<String>,
    pub default_listen_port: u16,
    pub default_expiry_hours: i64,
    pub default_max_uses: i32,
    pub udp_socket: Arc<UdpSocket>,
    pub peer_map: PeerMap,
    pub caddy_config_path: String,
    pub caddy_admin_api: String,
    pub caddy_external_domain: String,
    pub update_store: UpdateStore,
    pub scan_state: ScanState,
    pub sse_tx: SseTx,
}

/// Build the Axum router with all API routes.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        .route("/api/v1/admin/invite", post(create_invite))
        // Admin peer endpoints
        .route("/api/v1/admin/peers", get(list_peers))
        .route("/api/v1/admin/peers/{id}", get(show_peer))
        .route("/api/v1/admin/peers/{id}/disable", post(disable_peer))
        .route("/api/v1/admin/peers/{id}/enable", post(enable_peer))
        // Admin invite endpoints
        .route("/api/v1/admin/invites", get(list_invites))
        .route("/api/v1/admin/invites/{code}", delete(revoke_invite))
        // Peer node endpoints (authenticated with peer token)
        .route("/api/v1/node/token", patch(rotate_peer_token))
        .route("/api/v1/node/keepalive", post(http_keepalive))
        .route("/api/v1/node/peers", get(http_peer_list))
        // Update distribution (admin or peer token)
        .route("/api/v1/update", post(publish_update))
        .route("/api/v1/update/latest", get(get_latest_update))
        .route("/api/v1/update/latest/binary", get(download_latest_binary))
        // Admin-only update history
        .route("/api/v1/admin/updates", get(list_updates))
        // Service discovery + admin UI
        .route("/api/v1/admin/services", get(get_services))
        .route("/api/v1/admin/stream", get(sse_stream))
        .route("/admin", get(admin_ui))
        .route("/admin/", get(admin_ui))
        .with_state(state)
}

/// Start the HTTP API server.
#[allow(clippy::too_many_arguments)]
pub async fn run_http_server(
    port: u16,
    bind_address: String,
    db: Db,
    ip_allocator: IpAllocator,
    port_allocator: PortAllocator,
    coord_server_addr: String,
    coord_api_url: Option<String>,
    admin_token: Option<String>,
    default_listen_port: u16,
    default_expiry_hours: i64,
    default_max_uses: i32,
    udp_socket: Arc<UdpSocket>,
    peer_map: PeerMap,
    caddy_config_path: String,
    caddy_admin_api: String,
    caddy_external_domain: String,
    update_store: UpdateStore,
    scan_state: ScanState,
    sse_tx: SseTx,
) {
    let state = AppState {
        db,
        ip_allocator,
        port_allocator,
        coord_server_addr,
        coord_api_url,
        admin_token,
        default_listen_port,
        default_expiry_hours,
        default_max_uses,
        udp_socket,
        peer_map,
        caddy_config_path,
        caddy_admin_api,
        caddy_external_domain,
        update_store,
        scan_state,
        sse_tx,
    };

    let app = router(state);
    let addr: SocketAddr = format!("{bind_address}:{port}").parse().expect("valid listen address");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind HTTP listener");
    info!(%addr, "HTTP API server starting");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        warn!(error = %e, "HTTP server error");
    }
}

// --- Request / Response types ---

#[derive(Deserialize)]
struct RegisterRequest {
    invite_code: String,
    node_name: Option<String>,
    /// Base64-encoded X25519 public key. When supplied, the coordinator skips key
    /// generation and never stores or returns a private key (BYOK mode).
    public_key: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    node_id: String,
    /// Absent when the peer supplied its own public key (BYOK mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    public_key: String,
    virtual_ip: String,
    config_toml: String,
    auth_token: String,
    port_range_start: u16,
    port_range_size: u16,
}

/// Public node summary (omits private_key_encrypted).
#[derive(Serialize)]
pub struct NodeSummary {
    pub node_id: String,
    pub node_name: Option<String>,
    pub public_key: String,
    pub virtual_ip: String,
    pub status: String,
    pub endpoint: Option<String>,
    pub ipv6_endpoint: Option<String>,
    pub lan_endpoint: Option<String>,
    pub listen_port: i32,
    pub last_heartbeat: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub port_range_start: Option<i32>,
    pub port_range_size: Option<i32>,
}

impl From<NodeRecord> for NodeSummary {
    fn from(n: NodeRecord) -> Self {
        Self {
            node_id: n.node_id,
            node_name: n.node_name,
            public_key: base64::engine::general_purpose::STANDARD.encode(&n.public_key),
            virtual_ip: n.virtual_ip,
            status: n.status,
            endpoint: n.endpoint,
            ipv6_endpoint: n.ipv6_endpoint,
            lan_endpoint: n.lan_endpoint,
            listen_port: n.listen_port,
            last_heartbeat: n.last_heartbeat,
            created_at: n.created_at,
            updated_at: n.updated_at,
            port_range_start: n.port_range_start,
            port_range_size: n.port_range_size,
        }
    }
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

// --- Helpers ---

/// Regenerate Caddy config from DB and reload.
async fn regen_caddy(state: &AppState) {
    if let Err(e) = caddy::regen_from_db(
        &state.db,
        &state.caddy_config_path,
        &state.caddy_admin_api,
        &state.caddy_external_domain,
    )
    .await
    {
        warn!(error = %e, "Caddy regen failed");
    }
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

    // Resolve keypair: BYOK (peer supplies public key) or coordinator-generated.
    let (private_key_opt, public_key): (Option<[u8; 32]>, [u8; 32]) =
        if let Some(ref pk_b64) = req.public_key {
            let decoded = match base64::engine::general_purpose::STANDARD.decode(pk_b64) {
                Ok(b) => b,
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid public_key: not valid base64",
                    )
                    .into_response()
                }
            };
            if decoded.len() != 32 {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid public_key: must be 32 bytes",
                )
                .into_response();
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            (None, arr)
        } else {
            let (priv_key, pub_key) = key_manager::generate_node_keypair();
            (Some(priv_key), pub_key)
        };

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

    // Allocate port range
    let allocated_ports = match state.db.allocated_port_ranges().await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to list allocated port ranges");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };
    let (port_start, port_size) = match state.port_allocator.allocate(&allocated_ports) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "port range allocation failed");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "no port ranges available")
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
        private_key_encrypted: private_key_opt.map(|k| k.to_vec()).unwrap_or_default(),
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
        port_range_start: Some(port_start as i32),
        port_range_size: Some(port_size as i32),
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
        state.coord_api_url.as_deref(),
    );

    let private_key_b64 = node_record
        .private_key_encrypted
        .is_empty()
        .then(|| None)
        .unwrap_or_else(|| {
            Some(
                base64::engine::general_purpose::STANDARD
                    .encode(&node_record.private_key_encrypted),
            )
        });
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    info!(
        node_id = %node_id,
        virtual_ip = %virtual_ip,
        port_range_start = port_start,
        port_range_size = port_size,
        "node registered"
    );

    // Regen Caddy config after registration
    regen_caddy(&state).await;

    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            node_id,
            private_key: private_key_b64,
            public_key: public_key_b64,
            virtual_ip,
            config_toml,
            auth_token,
            port_range_start: port_start,
            port_range_size: port_size,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct CreateInviteRequest {
    max_uses: Option<i32>,
    expires_in_hours: Option<i64>,
}

/// POST /api/v1/admin/invite
async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<CreateInviteRequest>>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    let req = body.map(|Json(r)| r).unwrap_or(CreateInviteRequest {
        max_uses: None,
        expires_in_hours: None,
    });
    let max_uses = req.max_uses.unwrap_or(state.default_max_uses);
    let expires_in_hours = req.expires_in_hours.unwrap_or(state.default_expiry_hours);

    let code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(expires_in_hours);

    if let Err(e) = state.db.create_invite(&code, expires_at, max_uses).await {
        warn!(error = %e, "failed to create invite");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(code = %code, max_uses, "invite created");

    (
        StatusCode::CREATED,
        Json(InviteResponse {
            code,
            expires_at: expires_at.to_rfc3339(),
        }),
    )
        .into_response()
}

/// GET /api/v1/admin/peers
async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.list_all_nodes().await {
        Ok(nodes) => {
            let summaries: Vec<NodeSummary> = nodes.into_iter().map(NodeSummary::from).collect();
            Json(summaries).into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to list nodes");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/admin/peers/:id
async fn show_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.get_node(&id).await {
        Ok(Some(node)) => Json(NodeSummary::from(node)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "node not found").into_response(),
        Err(e) => {
            warn!(error = %e, "failed to get node");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// POST /api/v1/admin/peers/:id/disable
async fn disable_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.set_node_status(&id, "deregistered").await {
        Ok(()) => {
            info!(node_id = %id, "peer disabled");
            regen_caddy(&state).await;
            udp_handler::broadcast_peer_list(&state.udp_socket, &state.peer_map, &state.db).await;
            StatusCode::OK.into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to disable peer");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// POST /api/v1/admin/peers/:id/enable
async fn enable_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.set_node_status(&id, "registered").await {
        Ok(()) => {
            info!(node_id = %id, "peer enabled");
            regen_caddy(&state).await;
            udp_handler::broadcast_peer_list(&state.udp_socket, &state.peer_map, &state.db).await;
            StatusCode::OK.into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to enable peer");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/admin/invites
async fn list_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.list_all_invites().await {
        Ok(invites) => Json(invites).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to list invites");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// DELETE /api/v1/admin/invites/:code
async fn revoke_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state.db.revoke_invite(&code).await {
        Ok(true) => {
            info!(code = %code, "invite revoked");
            StatusCode::OK.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "invite not found").into_response(),
        Err(e) => {
            warn!(error = %e, "failed to revoke invite");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
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

// ---------------------------------------------------------------------------
// Admin UI + service discovery
// ---------------------------------------------------------------------------

/// GET /admin — serve the brutalist admin page (no server-side auth; the page
/// handles auth client-side and sends the token with every API request).
async fn admin_ui() -> Html<&'static str> {
    Html(ADMIN_PAGE)
}

/// GET /api/v1/admin/services — current scan snapshot (admin token required).
async fn get_services(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    let snap = state.scan_state.read().await;
    let list: Vec<&super::scanner::PeerSnapshot> = snap.values().collect();
    Json(list).into_response()
}

/// GET /api/v1/admin/stream?token=<admin_token>
/// SSE stream: broadcasts a full peer snapshot JSON array on every scan.
/// Token is passed as a query param because EventSource does not support headers.
/// The server validates it independently — no link to any cookie or session.
async fn sse_stream(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();

    // Server-side auth: validate admin token independently.
    let is_valid = state
        .admin_token
        .as_ref()
        .map(|t| *t == token)
        .unwrap_or(false);

    if !is_valid {
        return (
            StatusCode::UNAUTHORIZED,
            [("content-type", "text/plain")],
            "invalid token",
        )
            .into_response();
    }

    // Send current snapshot immediately so the page renders without waiting
    // for the next scan cycle.
    let initial = {
        let snap = state.scan_state.read().await;
        let list: Vec<&super::scanner::PeerSnapshot> = snap.values().collect();
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".into())
    };

    let rx = state.sse_tx.subscribe();
    let stream = tokio_stream::once(Ok::<Event, std::convert::Infallible>(
        Event::default().data(initial),
    ))
    .chain(
        BroadcastStream::new(rx).map(|msg| {
            Ok::<Event, std::convert::Infallible>(match msg {
                Ok(data) => Event::default().data(data),
                Err(_) => Event::default().comment("lagged"),
            })
        }),
    );

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ---------------------------------------------------------------------------
// HTTP fallback: keepalive + peer list for nodes that can't reach UDP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HttpKeepaliveRequest {
    listen_port: u16,
    #[serde(default)]
    lan_ips: Vec<String>,
}

#[derive(Serialize)]
struct HttpPeerEntry {
    public_key: String,
    virtual_ip: String,
    endpoint: Option<String>,
    lan_endpoint: Option<String>,
}

/// Extract the real client IP: prefer X-Real-IP / X-Forwarded-For (set by Caddy),
/// fall back to the direct TCP connection address.
fn real_ip(headers: &HeaderMap, conn: SocketAddr) -> IpAddr {
    if let Some(v) = headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return v;
    }
    conn.ip()
}

/// POST /api/v1/node/keepalive
/// Lets a node send a heartbeat via HTTPS when UDP is unreachable.
async fn http_keepalive(
    State(state): State<AppState>,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HttpKeepaliveRequest>,
) -> impl IntoResponse {
    let token = match extract_token(&headers) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization").into_response(),
    };

    let node_id = match state.db.validate_peer_token(&token).await {
        Ok(Some(id)) => id,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "invalid token").into_response(),
        Err(e) => {
            warn!(error = %e, "db error in http_keepalive");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let node = match state.db.get_node(&node_id).await {
        Ok(Some(n)) => n,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "invalid token").into_response(),
        Err(e) => {
            warn!(error = %e, "db error fetching node in http_keepalive");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let ip = real_ip(&headers, conn);
    let endpoint = SocketAddr::new(ip, req.listen_port);
    let lan_ip = req.lan_ips.first()
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());

    // Update in-memory peer map
    if node.public_key.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&node.public_key);
        let mut map = state.peer_map.lock().await;
        let entry = map.entry(key).or_insert_with(|| udp_handler::RegisteredPeer {
            public_key: key,
            endpoint,
            listen_port: req.listen_port,
            last_seen: Instant::now(),
            virtual_ip: node.virtual_ip.split('/').next().and_then(|s| s.parse().ok()),
            lan_ip,
        });
        entry.last_seen = Instant::now();
        entry.endpoint = endpoint;
        entry.lan_ip = lan_ip;
    }

    // Update DB heartbeat + endpoint
    if let Err(e) = state.db.update_heartbeat(&node_id, Some(&endpoint.to_string())).await {
        warn!(error = %e, "failed to update heartbeat in http_keepalive");
    }

    StatusCode::OK.into_response()
}

/// GET /api/v1/node/peers
/// Returns the active peer list as JSON; used by nodes falling back from UDP.
async fn http_peer_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_token(&headers) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization").into_response(),
    };

    let node_id = match state.db.validate_peer_token(&token).await {
        Ok(Some(id)) => id,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "invalid token").into_response(),
        Err(e) => {
            warn!(error = %e, "db error in http_peer_list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let peers = match state.db.list_active_nodes().await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to list peers for http_peer_list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let map = state.peer_map.lock().await;
    let entries: Vec<HttpPeerEntry> = peers
        .into_iter()
        .filter(|p| p.node_id != node_id)
        .map(|p| {
            let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(&p.public_key);
            let virtual_ip = p.virtual_ip.split('/').next().unwrap_or(&p.virtual_ip).to_string();

            // Prefer live endpoint from peer_map (most recent), fall back to DB
            let (endpoint, lan_endpoint) = if p.public_key.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&p.public_key);
                let ep = map.get(&key)
                    .map(|r| r.endpoint.to_string())
                    .or(p.endpoint.clone());
                let lan_ep = map.get(&key)
                    .and_then(|r| r.lan_ip.map(|ip| format!("{}:{}", ip, p.listen_port)));
                (ep, lan_ep)
            } else {
                (p.endpoint.clone(), p.lan_endpoint.clone())
            };

            HttpPeerEntry { public_key: pub_key_b64, virtual_ip, endpoint, lan_endpoint }
        })
        .collect();

    Json(entries).into_response()
}
