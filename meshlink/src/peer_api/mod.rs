pub mod auth;
pub mod handlers;
pub mod html;
pub mod replay;
pub mod tls;

use crate::config::PeerApiConfig;
use crate::credentials::Credentials;
use crate::state::SharedState;
use anyhow::{Context, Result};
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use auth::RateLimiter;
use replay::NonceStore;

// --- State ---

/// Peer IP injected by the accept loop as a request extension (can't be spoofed by client).
#[derive(Clone, Copy)]
pub struct PeerAddr(pub IpAddr);

pub struct PeerApiState {
    pub shared_state: SharedState,
    pub credentials: Arc<RwLock<Credentials>>,
    pub write_token: Arc<RwLock<String>>,
    pub read_token: Option<String>,
    pub bind_cidr: Option<ipnet::IpNet>,
    pub credentials_path: PathBuf,
    pub coord_client: reqwest::Client,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub nonce_store: Arc<Mutex<NonceStore>>,
    pub virtual_ip: Ipv4Addr,
    pub start_time: Instant,
    pub port: u16,
    pub tls_enabled: bool,
    pub mtls_enabled: bool,
}

// --- Router ---

fn router(state: Arc<PeerApiState>) -> Router {
    Router::new()
        .route("/", get(handlers::index))
        .route("/api/status", get(handlers::get_status))
        .route("/api/peers", get(handlers::get_peers))
        .route("/api/config", get(handlers::get_config))
        .route("/api/token/rotate", post(handlers::rotate_token))
        .layer(middleware::from_fn(inject_default_peer_addr))
        .with_state(state)
}

/// Fallback middleware: if no PeerAddr extension was set by the accept loop
/// (non-TLS plain axum::serve path), extract it from ConnectInfo.
async fn inject_default_peer_addr(mut req: Request, next: Next) -> Response {
    if req.extensions().get::<PeerAddr>().is_none() {
        use axum::extract::ConnectInfo;
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        req.extensions_mut().insert(PeerAddr(ip));
    }
    next.run(req).await
}

// --- Entry point ---

pub async fn run(
    config: PeerApiConfig,
    shared_state: SharedState,
    virtual_ip: Ipv4Addr,
    creds_path: PathBuf,
    _coord_url: String,
) -> Result<()> {
    let creds = Credentials::load(creds_path.parent().unwrap_or(std::path::Path::new(".")))
        .context("loading credentials for peer API")?;

    let write_token = creds.auth_token.clone();

    let bind_cidr: Option<ipnet::IpNet> = config
        .bind_cidr
        .as_deref()
        .map(|s| s.parse().context("parsing bind_cidr"))
        .transpose()?;

    let state = Arc::new(PeerApiState {
        shared_state,
        credentials: Arc::new(RwLock::new(creds)),
        write_token: Arc::new(RwLock::new(write_token)),
        read_token: config.read_token.clone(),
        bind_cidr,
        credentials_path: creds_path,
        coord_client: reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // coord may use self-signed
            .build()
            .context("building HTTP client")?,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        nonce_store: Arc::new(Mutex::new(NonceStore::new())),
        virtual_ip,
        start_time: Instant::now(),
        port: config.port,
        tls_enabled: config.tls_enabled,
        mtls_enabled: config.mtls_enabled,
    });

    let app = router(state);

    let bind_addr = SocketAddr::from((virtual_ip, config.port));

    if config.tls_enabled {
        // Install ring crypto provider (idempotent — ignore error if already installed).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (certs, key) = if config.tls_cert.is_some() && config.tls_key.is_some() {
            tls::from_files(
                config.tls_cert.as_deref().unwrap(),
                config.tls_key.as_deref().unwrap(),
            )?
        } else {
            tls::self_signed(vec![virtual_ip.to_string(), "localhost".to_string()])?
        };

        let mtls_ca = if config.mtls_enabled { config.mtls_ca.as_deref() } else { None };
        let srv_cfg = tls::server_config(certs, key, mtls_ca)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(srv_cfg);

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("binding peer API TLS listener on {bind_addr}"))?;

        if config.mtls_enabled {
            info!(%bind_addr, "peer API (TLS + mTLS) listening");
        } else {
            info!(%bind_addr, "peer API (TLS) listening");
        }

        serve_tls(listener, app, acceptor).await
    } else {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("binding peer API listener on {bind_addr}"))?;
        info!(%bind_addr, "peer API listening");

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("peer API server error")
    }
}

async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;

    let conn_builder = ConnBuilder::new(TokioExecutor::new());

    loop {
        let (tcp, peer_addr) = listener.accept().await.context("TLS accept")?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        let conn_builder = conn_builder.clone();
        let peer_ip = peer_addr.ip();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "TLS handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(PeerAddr(peer_ip));
                let app = app.clone();
                async move {
                    use tower::ServiceExt;
                    app.oneshot(req).await
                }
            });

            if let Err(e) = conn_builder.serve_connection(io, svc).await {
                tracing::debug!(error = %e, "peer API connection error");
            }
        });
    }
}
