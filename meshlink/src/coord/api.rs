use super::config_generator;
use super::db::{Db, NodeRecord};
use super::ip_allocator::IpAllocator;
use super::key_manager;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
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
}

/// Build the Axum router with minimal API routes.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        .route("/api/v1/admin/invite", post(create_invite))
        .with_state(state)
}

/// Start the HTTP API server.
pub async fn run_http_server(
    port: u16,
    db: Db,
    ip_allocator: IpAllocator,
    coord_server_addr: String,
    admin_token: Option<String>,
) {
    let state = AppState {
        db,
        ip_allocator,
        coord_server_addr,
        admin_token,
    };

    let app = router(state);
    let addr: SocketAddr = format!("[::]:{port}").parse().expect("valid listen address");
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

#[derive(Deserialize)]
struct CreateInviteRequest {
    #[serde(default = "default_max_uses")]
    max_uses: i32,
    #[serde(default = "default_expires_hours")]
    expires_in_hours: i64,
}

fn default_max_uses() -> i32 { 1 }
fn default_expires_hours() -> i64 { 24 }

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
        max_uses: 1,
        expires_in_hours: 24,
    });

    let code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(req.expires_in_hours);

    if let Err(e) = state.db.create_invite(&code, expires_at, req.max_uses).await {
        warn!(error = %e, "failed to create invite");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(code = %code, max_uses = req.max_uses, "invite created");

    (
        StatusCode::CREATED,
        Json(InviteResponse {
            code,
            expires_at: expires_at.to_rfc3339(),
        }),
    )
        .into_response()
}
