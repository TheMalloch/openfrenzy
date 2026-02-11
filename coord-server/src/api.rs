use crate::config_generator;
use crate::db::{AccessRuleRecord, Db, NodeRecord, RefreshTokenRecord, ServiceRecord, UserRecord};
use crate::ip_allocator::IpAllocator;
use crate::jwt::{self, JwtState};
use crate::key_manager;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
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
    pub jwt: JwtState,
}

/// Build the Axum router with all API routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/register", post(register))
        .route("/api/v1/node/{id}/config", get(get_config))
        .route("/api/v1/node/{id}/heartbeat", post(heartbeat))
        .route("/api/v1/node/{id}", delete(deregister))
        .route("/api/v1/admin/invite", post(create_invite))
        // Service management (peer auth)
        .route("/api/v1/node/{id}/services", post(create_service))
        .route("/api/v1/node/{id}/services", get(list_services))
        .route("/api/v1/node/{id}/services/{svc_id}", delete(delete_service))
        .route("/api/v1/node/{id}/services/{svc_id}/rules", post(create_peer_rule))
        .route("/api/v1/node/{id}/services/{svc_id}/rules", get(list_rules))
        .route("/api/v1/node/{id}/services/{svc_id}/rules/{rule_id}", delete(delete_rule))
        // Admin override endpoints
        .route("/api/v1/admin/services/{svc_id}/rules", post(admin_create_rule))
        .route("/api/v1/admin/services/{svc_id}/rules/{rule_id}", delete(admin_delete_rule))
        // User management (admin)
        .route("/api/v1/admin/user-invite", post(create_user_invite))
        .route("/api/v1/admin/users/{user_id}/approve", post(approve_user))
        .route("/api/v1/admin/users", get(list_users))
        // Auth endpoints
        .route("/api/v1/auth/register", post(register_user))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/userinfo", get(userinfo))
        // JWKS
        .route("/api/v1/.well-known/jwks.json", get(jwks))
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

#[derive(Deserialize)]
struct CreateServiceRequest {
    name: String,
    port: u16,
    #[serde(default = "default_protocol")]
    protocol: String,
}

fn default_protocol() -> String {
    "tcp".into()
}

#[derive(Deserialize)]
struct CreateRuleRequest {
    target_peer_id: String,
    #[serde(default = "default_allow")]
    rule_type: String,
}

fn default_allow() -> String {
    "allow".into()
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

/// Validate the admin token from the Authorization header.
fn validate_admin_token(
    admin_token: &Option<String>,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let configured = admin_token.as_ref().ok_or_else(|| {
        (StatusCode::FORBIDDEN, Json(ErrorResponse { error: "admin API disabled".into() }))
    })?;

    let provided = extract_token(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "missing Authorization header".into() }))
    })?;

    if provided != *configured {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid admin token".into() })));
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

    // Generate config (fresh node, no ACL rules yet)
    let active_nodes = state.db.list_active_nodes().await.unwrap_or_default();
    let config_toml = config_generator::generate_config(
        &node_record,
        &active_nodes,
        &state.coord_server_addr,
        &[],
        &[],
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

    let outbound_acl = state.db.resolve_acl_for_peer(&node_id).await.unwrap_or_default();
    let inbound_acl = state.db.resolve_inbound_acl_for_owner(&node_id).await.unwrap_or_default();

    let config = config_generator::generate_config(
        &node,
        &active_nodes,
        &state.coord_server_addr,
        &outbound_acl,
        &inbound_acl,
    );
    (StatusCode::OK, config).into_response()
}

/// POST /api/v1/node/:id/heartbeat
async fn heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let node = match validate_auth(&state.db, &node_id, &headers).await {
        Ok(n) => n,
        Err(resp) => return resp.into_response(),
    };

    let last_update = node.updated_at;

    // Extract the real client IP from proxy headers, falling back to ConnectInfo.
    let client_ip = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    // Build the endpoint from the client's real IP and the node's configured listen port.
    let endpoint_str = if client_ip.contains(':') {
        format!("[{}]:{}", client_ip, node.listen_port)
    } else {
        format!("{}:{}", client_ip, node.listen_port)
    };

    if let Err(e) = state.db.update_heartbeat(&node_id, Some(&endpoint_str)).await {
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

// --- Service management handlers (peer auth) ---

/// POST /api/v1/node/:id/services
async fn create_service(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateServiceRequest>,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    if !matches!(req.protocol.as_str(), "tcp" | "udp" | "both") {
        return error_response(StatusCode::BAD_REQUEST, "protocol must be tcp, udp, or both").into_response();
    }

    if req.port == 0 {
        return error_response(StatusCode::BAD_REQUEST, "port must be 1-65535").into_response();
    }

    let service = ServiceRecord {
        id: Uuid::new_v4().to_string(),
        peer_id: node_id.clone(),
        name: req.name,
        port: req.port as i32,
        protocol: req.protocol,
        created_at: Utc::now(),
    };

    if let Err(e) = state.db.insert_service(&service).await {
        warn!(error = %e, "failed to create service");
        return error_response(StatusCode::CONFLICT, "service already exists for this port/protocol").into_response();
    }

    info!(service_id = %service.id, node_id = %node_id, "service created");
    (StatusCode::CREATED, Json(service)).into_response()
}

/// GET /api/v1/node/:id/services
async fn list_services(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    match state.db.list_services_for_peer(&node_id).await {
        Ok(services) => Json(services).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to list services");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// DELETE /api/v1/node/:id/services/:svc_id
async fn delete_service(
    State(state): State<AppState>,
    Path((node_id, svc_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    // Verify service ownership
    let service = match state.db.get_service(&svc_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "service not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if service.peer_id != node_id {
        return error_response(StatusCode::FORBIDDEN, "not your service").into_response();
    }

    if let Err(e) = state.db.delete_service(&svc_id).await {
        warn!(error = %e, "failed to delete service");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(service_id = %svc_id, "service deleted");
    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/v1/node/:id/services/:svc_id/rules
async fn create_peer_rule(
    State(state): State<AppState>,
    Path((node_id, svc_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    // Verify service ownership
    let service = match state.db.get_service(&svc_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "service not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if service.peer_id != node_id {
        return error_response(StatusCode::FORBIDDEN, "not your service").into_response();
    }

    if !matches!(req.rule_type.as_str(), "allow" | "deny") {
        return error_response(StatusCode::BAD_REQUEST, "rule_type must be allow or deny").into_response();
    }

    // Verify target peer exists and is active
    match state.db.get_node(&req.target_peer_id).await {
        Ok(Some(n)) if n.status != "deregistered" => {}
        Ok(Some(_)) => return error_response(StatusCode::BAD_REQUEST, "target peer is deregistered").into_response(),
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "target peer not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    let rule = AccessRuleRecord {
        id: Uuid::new_v4().to_string(),
        service_id: svc_id,
        target_peer_id: req.target_peer_id,
        granted_by: "owner".into(),
        rule_type: req.rule_type,
        created_at: Utc::now(),
    };

    if let Err(e) = state.db.upsert_access_rule(&rule).await {
        warn!(error = %e, "failed to create rule");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(rule_id = %rule.id, "peer rule created");
    (StatusCode::CREATED, Json(rule)).into_response()
}

/// GET /api/v1/node/:id/services/:svc_id/rules
async fn list_rules(
    State(state): State<AppState>,
    Path((node_id, svc_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    // Verify service ownership
    let service = match state.db.get_service(&svc_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "service not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if service.peer_id != node_id {
        return error_response(StatusCode::FORBIDDEN, "not your service").into_response();
    }

    match state.db.list_rules_for_service(&svc_id).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to list rules");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// DELETE /api/v1/node/:id/services/:svc_id/rules/:rule_id
async fn delete_rule(
    State(state): State<AppState>,
    Path((node_id, svc_id, rule_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_auth(&state.db, &node_id, &headers).await {
        return resp.into_response();
    }

    // Verify service ownership
    let service = match state.db.get_service(&svc_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "service not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if service.peer_id != node_id {
        return error_response(StatusCode::FORBIDDEN, "not your service").into_response();
    }

    // Verify rule exists and is owner-granted (peers can't delete admin rules)
    let rule = match state.db.get_access_rule(&rule_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "rule not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if rule.service_id != svc_id {
        return error_response(StatusCode::NOT_FOUND, "rule not found for this service").into_response();
    }

    if rule.granted_by != "owner" {
        return error_response(StatusCode::FORBIDDEN, "cannot delete admin rules").into_response();
    }

    if let Err(e) = state.db.delete_access_rule(&rule_id).await {
        warn!(error = %e, "failed to delete rule");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(rule_id = %rule_id, "rule deleted");
    StatusCode::NO_CONTENT.into_response()
}

// --- Admin override handlers ---

/// POST /api/v1/admin/services/:svc_id/rules
async fn admin_create_rule(
    State(state): State<AppState>,
    Path(svc_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    // Verify service exists
    if let Ok(None) | Err(_) = state.db.get_service(&svc_id).await {
        return error_response(StatusCode::NOT_FOUND, "service not found").into_response();
    }

    if !matches!(req.rule_type.as_str(), "allow" | "deny") {
        return error_response(StatusCode::BAD_REQUEST, "rule_type must be allow or deny").into_response();
    }

    // Verify target peer exists
    match state.db.get_node(&req.target_peer_id).await {
        Ok(Some(_)) => {}
        _ => return error_response(StatusCode::BAD_REQUEST, "target peer not found").into_response(),
    }

    let rule = AccessRuleRecord {
        id: Uuid::new_v4().to_string(),
        service_id: svc_id,
        target_peer_id: req.target_peer_id,
        granted_by: "admin".into(),
        rule_type: req.rule_type,
        created_at: Utc::now(),
    };

    if let Err(e) = state.db.upsert_access_rule(&rule).await {
        warn!(error = %e, "failed to create admin rule");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(rule_id = %rule.id, "admin rule created");
    (StatusCode::CREATED, Json(rule)).into_response()
}

/// DELETE /api/v1/admin/services/:svc_id/rules/:rule_id
async fn admin_delete_rule(
    State(state): State<AppState>,
    Path((svc_id, rule_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    // Verify rule exists and belongs to this service
    let rule = match state.db.get_access_rule(&rule_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "rule not found").into_response(),
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if rule.service_id != svc_id {
        return error_response(StatusCode::NOT_FOUND, "rule not found for this service").into_response();
    }

    if let Err(e) = state.db.delete_access_rule(&rule_id).await {
        warn!(error = %e, "failed to delete admin rule");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(rule_id = %rule_id, "admin rule deleted");
    StatusCode::NO_CONTENT.into_response()
}

// --- User auth request/response types ---

#[derive(Deserialize)]
struct RegisterUserRequest {
    invite_code: String,
    username: String,
    password: String,
    display_name: Option<String>,
}

#[derive(Serialize)]
struct RegisterUserResponse {
    user_id: String,
    username: String,
    status: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize)]
struct RefreshResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct UserInfoResponse {
    user_id: String,
    username: String,
    display_name: Option<String>,
    status: String,
}

#[derive(Serialize)]
struct UserInviteResponse {
    code: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct ListUsersQuery {
    status: Option<String>,
}

#[derive(Serialize)]
struct UserListEntry {
    user_id: String,
    username: String,
    display_name: Option<String>,
    status: String,
    created_at: String,
}

// --- User/Auth handlers ---

/// POST /api/v1/admin/user-invite
async fn create_user_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    let code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(24);

    if let Err(e) = state.db.create_user_invite(&code, expires_at).await {
        warn!(error = %e, "failed to create user invite");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(code = %code, "user invite created");
    (
        StatusCode::CREATED,
        Json(UserInviteResponse {
            code,
            expires_at: expires_at.to_rfc3339(),
        }),
    )
        .into_response()
}

/// POST /api/v1/auth/register
async fn register_user(
    State(state): State<AppState>,
    Json(req): Json<RegisterUserRequest>,
) -> impl IntoResponse {
    // Validate invite
    let invite = match state.db.get_user_invite(&req.invite_code).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid invite code").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error checking user invite");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    if invite.used_at.is_some() {
        return error_response(StatusCode::BAD_REQUEST, "invite code already used").into_response();
    }
    if invite.expires_at < Utc::now() {
        return error_response(StatusCode::BAD_REQUEST, "invite code expired").into_response();
    }

    // Validate username
    if req.username.len() < 3 || req.username.len() > 64 {
        return error_response(StatusCode::BAD_REQUEST, "username must be 3-64 characters")
            .into_response();
    }
    if !req
        .username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "username may only contain alphanumeric, underscore, or hyphen",
        )
        .into_response();
    }

    // Validate password
    if req.password.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "password must be at least 8 characters")
            .into_response();
    }

    // Check username uniqueness
    match state.db.get_user_by_username(&req.username).await {
        Ok(Some(_)) => {
            return error_response(StatusCode::CONFLICT, "username already taken").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error checking username");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
        Ok(None) => {}
    }

    // Hash password
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let password_hash = match Argon2::default().hash_password(req.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!(error = %e, "failed to hash password");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    let now = Utc::now();
    let user_id = Uuid::new_v4().to_string();

    let user = UserRecord {
        user_id: user_id.clone(),
        username: req.username.clone(),
        password_hash,
        display_name: req.display_name,
        status: "pending".into(),
        created_at: now,
        updated_at: now,
    };

    if let Err(e) = state.db.insert_user(&user).await {
        warn!(error = %e, "failed to insert user");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    // Mark invite as used
    if let Err(e) = state.db.use_user_invite(&req.invite_code, &user_id).await {
        warn!(error = %e, "failed to mark user invite as used");
    }

    info!(user_id = %user_id, username = %req.username, "user registered (pending approval)");
    (
        StatusCode::CREATED,
        Json(RegisterUserResponse {
            user_id,
            username: req.username,
            status: "pending".into(),
        }),
    )
        .into_response()
}

/// POST /api/v1/admin/users/{user_id}/approve
async fn approve_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    let user = match state.db.get_user(&user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "user not found").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    if user.status != "pending" {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("user status is '{}', expected 'pending'", user.status),
        )
        .into_response();
    }

    if let Err(e) = state.db.update_user_status(&user_id, "active").await {
        warn!(error = %e, "failed to approve user");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(user_id = %user_id, "user approved");
    StatusCode::NO_CONTENT.into_response()
}

/// GET /api/v1/admin/users
async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListUsersQuery>,
) -> impl IntoResponse {
    if let Err(resp) = validate_admin_token(&state.admin_token, &headers) {
        return resp.into_response();
    }

    match state
        .db
        .list_users(query.status.as_deref())
        .await
    {
        Ok(users) => {
            let entries: Vec<UserListEntry> = users
                .into_iter()
                .map(|u| UserListEntry {
                    user_id: u.user_id,
                    username: u.username,
                    display_name: u.display_name,
                    status: u.status,
                    created_at: u.created_at.to_rfc3339(),
                })
                .collect();
            Json(entries).into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to list users");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// POST /api/v1/auth/login
async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let user = match state.db.get_user_by_username(&req.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error during login");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    // Verify password
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response()
        }
    };

    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return error_response(StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    // Check user status
    if user.status != "active" {
        return error_response(
            StatusCode::FORBIDDEN,
            format!("account is {}", user.status),
        )
        .into_response();
    }

    // Create access token
    let access_token = match state
        .jwt
        .create_access_token(&user.user_id, &user.username, &state.coord_server_addr)
    {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "failed to create access token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    // Create refresh token
    let raw_refresh = Uuid::new_v4().to_string();
    let token_hash = jwt::hash_refresh_token(&raw_refresh);
    let now = Utc::now();

    let refresh_record = RefreshTokenRecord {
        token_id: Uuid::new_v4().to_string(),
        user_id: user.user_id.clone(),
        token_hash,
        expires_at: now + chrono::Duration::days(7),
        created_at: now,
        revoked_at: None,
    };

    if let Err(e) = state.db.insert_refresh_token(&refresh_record).await {
        warn!(error = %e, "failed to store refresh token");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    info!(user_id = %user.user_id, "user logged in");
    Json(LoginResponse {
        access_token,
        refresh_token: raw_refresh,
        token_type: "Bearer".into(),
        expires_in: 900,
    })
    .into_response()
}

/// POST /api/v1/auth/refresh
async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> impl IntoResponse {
    let token_hash = jwt::hash_refresh_token(&req.refresh_token);

    let stored = match state.db.get_refresh_token_by_hash(&token_hash).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "invalid refresh token")
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error during refresh");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    if stored.expires_at < Utc::now() {
        // Revoke the expired token
        let _ = state.db.revoke_refresh_token(&stored.token_id).await;
        return error_response(StatusCode::UNAUTHORIZED, "refresh token expired").into_response();
    }

    // Look up user
    let user = match state.db.get_user(&stored.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "user not found").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error during refresh");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    if user.status != "active" {
        return error_response(
            StatusCode::FORBIDDEN,
            format!("account is {}", user.status),
        )
        .into_response();
    }

    // Create new access token
    let access_token = match state
        .jwt
        .create_access_token(&user.user_id, &user.username, &state.coord_server_addr)
    {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "failed to create access token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    Json(RefreshResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 900,
    })
    .into_response()
}

/// GET /api/v1/auth/userinfo
async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_token(&headers) {
        Some(t) => t,
        None => {
            return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header")
                .into_response()
        }
    };

    let claims = match state
        .jwt
        .validate_access_token(&token, &state.coord_server_addr)
    {
        Ok(c) => c,
        Err(_) => {
            return error_response(StatusCode::UNAUTHORIZED, "invalid or expired token")
                .into_response()
        }
    };

    let user = match state.db.get_user(&claims.sub).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "user not found").into_response()
        }
        Err(e) => {
            warn!(error = %e, "database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };

    Json(UserInfoResponse {
        user_id: user.user_id,
        username: user.username,
        display_name: user.display_name,
        status: user.status,
    })
    .into_response()
}

/// GET /api/v1/.well-known/jwks.json
async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&state.jwt.public_key_bytes);

    let jwk = serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": state.jwt.key_id,
            "x": pub_key_b64,
        }]
    });

    Json(jwk).into_response()
}
