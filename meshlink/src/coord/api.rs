use super::caddy;
use super::config_generator;
use super::db::{Db, NodeRecord};
use super::ip_allocator::IpAllocator;
use super::key_manager;
use super::port_allocator::PortAllocator;
use super::udp_handler::{self, PeerMap};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};
use uuid::Uuid;

/// Shared application state for API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub ip_allocator: IpAllocator,
    pub port_allocator: PortAllocator,
    pub coord_server_addr: String,
    pub admin_token: Option<String>,
    pub default_listen_port: u16,
    pub default_expiry_hours: i64,
    pub default_max_uses: i32,
    pub udp_socket: Arc<UdpSocket>,
    pub peer_map: PeerMap,
    pub caddy_config_path: String,
    pub caddy_admin_api: String,
    pub caddy_external_domain: String,
}

/// Build the Axum router with all API routes.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        .route("/api/v1/admin/invite", post(create_invite))
        // Admin peer endpoints
        .route("/api/v1/admin/peers", get(list_peers))
        .route("/api/v1/admin/peers/:id", get(show_peer))
        .route("/api/v1/admin/peers/:id/disable", post(disable_peer))
        .route("/api/v1/admin/peers/:id/enable", post(enable_peer))
        // Admin invite endpoints
        .route("/api/v1/admin/invites", get(list_invites))
        .route("/api/v1/admin/invites/:code", delete(revoke_invite))
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
    admin_token: Option<String>,
    default_listen_port: u16,
    default_expiry_hours: i64,
    default_max_uses: i32,
    udp_socket: Arc<UdpSocket>,
    peer_map: PeerMap,
    caddy_config_path: String,
    caddy_admin_api: String,
    caddy_external_domain: String,
) {
    let state = AppState {
        db,
        ip_allocator,
        port_allocator,
        coord_server_addr,
        admin_token,
        default_listen_port,
        default_expiry_hours,
        default_max_uses,
        udp_socket,
        peer_map,
        caddy_config_path,
        caddy_admin_api,
        caddy_external_domain,
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
    match state.db.list_all_nodes().await {
        Ok(nodes) => {
            let content = caddy::generate_caddyfile(&nodes, &state.caddy_external_domain);
            if let Err(e) = caddy::write_and_reload(
                &state.caddy_config_path,
                &state.caddy_admin_api,
                &content,
            )
            .await
            {
                warn!(error = %e, "Caddy regen failed");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to query nodes for Caddy regen");
        }
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
    );

    let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
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

