use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::process::Command as Proc;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Coord server types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NodeSummary {
    node_id: String,
    node_name: Option<String>,
    virtual_ip: String,
    status: String,
    last_heartbeat: Option<DateTime<Utc>>,
}

impl NodeSummary {
    fn display_name(&self) -> String {
        self.node_name
            .clone()
            .unwrap_or_else(|| self.node_id[..8].to_string())
    }

    fn bare_ip(&self) -> &str {
        self.virtual_ip.split('/').next().unwrap_or(&self.virtual_ip)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateMeta {
    id: i64,
    description: String,
    binary_hash: String,
    binary_size: i64,
    uploaded_by: String,
    uploaded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Stored credentials (mirrors meshlink credentials.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Credentials {
    server: String,
    #[allow(dead_code)]
    node_id: String,
    auth_token: String,
}

impl Credentials {
    fn load(path: &PathBuf) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading credentials from {}", path.display()))?;
        serde_json::from_str(&data).context("parsing credentials")
    }

    fn try_load_default() -> Option<Self> {
        let path = PathBuf::from("/etc/meshlink/credentials.json");
        Self::load(&path).ok()
    }
}

// ---------------------------------------------------------------------------
// Coord API client
// ---------------------------------------------------------------------------

struct CoordClient {
    client: Client,
    base_url: String,
    /// Bearer token — either admin token or peer auth_token.
    token: String,
}

impl CoordClient {
    fn new(base_url: &str, token: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    async fn list_peers(&self) -> Result<Vec<NodeSummary>> {
        let url = format!("{}/api/v1/admin/peers", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("fetching peer list")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("coord server {status}: {body}");
        }
        resp.json().await.context("parsing peer list")
    }

    async fn push_update(&self, binary: Vec<u8>, description: &str) -> Result<UpdateMeta> {
        let url = format!("{}/api/v1/update", self.base_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .header("x-update-description", description)
            .header("content-type", "application/octet-stream")
            .body(binary)
            .send()
            .await
            .context("uploading update")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("coord server {status}: {body}");
        }
        resp.json().await.context("parsing upload response")
    }

    async fn latest_update(&self) -> Result<Option<UpdateMeta>> {
        let url = format!("{}/api/v1/update/latest", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("fetching latest update metadata")?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("coord server {status}: {body}");
        }
        Ok(Some(resp.json().await.context("parsing update metadata")?))
    }

    async fn download_latest(&self) -> Result<Vec<u8>> {
        let url = format!("{}/api/v1/update/latest/binary", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("downloading update binary")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("coord server {status}: {body}");
        }
        Ok(resp.bytes().await.context("reading binary body")?.to_vec())
    }
}

// ---------------------------------------------------------------------------
// SSH / SCP helpers
// ---------------------------------------------------------------------------

struct SshOpts {
    user: String,
    key: Option<PathBuf>,
    port: u16,
}

impl SshOpts {
    fn common_flags(&self) -> Vec<String> {
        let mut flags = vec![
            "-o".into(), "StrictHostKeyChecking=no".into(),
            "-o".into(), "ConnectTimeout=10".into(),
            "-p".into(), self.port.to_string(),
        ];
        if let Some(k) = &self.key {
            flags.push("-i".into());
            flags.push(k.display().to_string());
        }
        flags
    }
}

async fn scp_push(opts: &SshOpts, local: &PathBuf, peer_ip: &str, remote: &str) -> Result<()> {
    let dest = format!("{}@{}:{}", opts.user, peer_ip, remote);
    let mut cmd = Proc::new("scp");
    cmd.args(opts.common_flags()).arg(local).arg(&dest);
    let out = cmd.output().await.context("launching scp")?;
    if !out.status.success() {
        anyhow::bail!("scp failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

async fn ssh_run(opts: &SshOpts, peer_ip: &str, command: &str) -> Result<String> {
    let target = format!("{}@{}", opts.user, peer_ip);
    let mut cmd = Proc::new("ssh");
    cmd.args(opts.common_flags()).arg(&target).arg(command);
    let out = cmd.output().await.context("launching ssh")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        anyhow::bail!("{}", stderr.trim());
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

// ---------------------------------------------------------------------------
// Peer filtering
// ---------------------------------------------------------------------------

fn filter_peers(peers: Vec<NodeSummary>, filter: Option<&str>) -> Vec<NodeSummary> {
    peers
        .into_iter()
        .filter(|p| p.status == "active" || p.status == "registered")
        .filter(|p| {
            filter
                .map(|f| {
                    p.node_name.as_deref().unwrap_or("").contains(f)
                        || p.node_id.contains(f)
                        || p.virtual_ip.contains(f)
                })
                .unwrap_or(true)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Result tracking
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PeerResult {
    name: String,
    ip: String,
    outcome: Result<String>,
}

// ---------------------------------------------------------------------------
// SHA256 of a file
// ---------------------------------------------------------------------------

fn sha256_file(path: &PathBuf) -> Result<String> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Deploy and distribute apps across a MeshLink mesh network.
#[derive(Parser)]
#[command(name = "mldeploy", version, about)]
struct Cli {
    /// Coordination server base URL (e.g. http://coord.example.com:4001).
    #[arg(long, env = "MESHLINK_SERVER")]
    server: Option<String>,

    /// Admin bearer token (required for push/run/self-update/peers).
    #[arg(long, env = "MESHLINK_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Peer auth token (used for push-update/check-update/auto-update).
    /// Auto-loaded from /etc/meshlink/credentials.json if not provided.
    #[arg(long, env = "MESHLINK_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// SSH user on peer nodes.
    #[arg(long, default_value = "root", env = "MLDEPLOY_SSH_USER")]
    ssh_user: String,

    /// Path to SSH private key (default: ssh-agent / ~/.ssh/id_*).
    #[arg(long, env = "MLDEPLOY_SSH_KEY")]
    ssh_key: Option<PathBuf>,

    /// SSH port on peer nodes.
    #[arg(long, default_value_t = 22, env = "MLDEPLOY_SSH_PORT")]
    ssh_port: u16,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy a local file to all peers, optionally running a command after.
    Push {
        local: PathBuf,
        remote: String,
        #[arg(long, short = 'r')]
        run: Option<String>,
        #[arg(long, short = 'f')]
        filter: Option<String>,
    },

    /// Run a shell command on all peers.
    Run {
        command: String,
        #[arg(long, short = 'f')]
        filter: Option<String>,
    },

    /// List active peers registered with the mesh.
    Peers,

    /// Push this binary to all peers, replacing their mldeploy in-place.
    SelfUpdate {
        #[arg(long, default_value = "/usr/local/bin/mldeploy")]
        dest: String,
        #[arg(long, short = 'r')]
        run: Option<String>,
        #[arg(long, short = 'f')]
        filter: Option<String>,
    },

    /// Upload the current binary to the coord server as a new update.
    /// Any peer with a valid auth token can then auto-apply it.
    PushUpdate {
        /// Human-readable description of what changed (required).
        #[arg(long, short = 'd')]
        description: String,
    },

    /// Check whether the coord server has an update newer than this binary.
    CheckUpdate,

    /// Poll the coord server and self-apply updates automatically.
    AutoUpdate {
        /// Seconds between polls.
        #[arg(long, default_value_t = 300)]
        interval: u64,

        /// Destination path to replace on self-update.
        #[arg(long, default_value = "/usr/local/bin/mldeploy")]
        dest: String,

        /// Shell command to run after a successful update.
        #[arg(long, short = 'r')]
        post_cmd: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mldeploy=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // Load credentials from file if no explicit tokens given.
    let file_creds = Credentials::try_load_default();

    // Resolve server URL: CLI > credentials file > error.
    let server = cli
        .server
        .clone()
        .or_else(|| file_creds.as_ref().map(|c| c.server.clone()));

    // Resolve the token to use for admin operations (peer list, etc.).
    let admin_token = cli.admin_token.clone();

    // Resolve the token to use for update operations (admin OR peer auth).
    let update_token = cli
        .auth_token
        .clone()
        .or_else(|| file_creds.as_ref().map(|c| c.auth_token.clone()))
        .or_else(|| cli.admin_token.clone());

    let ssh = SshOpts {
        user: cli.ssh_user.clone(),
        key: cli.ssh_key.clone(),
        port: cli.ssh_port,
    };

    match cli.command {
        Cmd::Peers => {
            let coord = admin_coord(&server, &admin_token)?;
            cmd_peers(&coord).await
        }
        Cmd::Push { local, remote, run, filter } => {
            let coord = admin_coord(&server, &admin_token)?;
            cmd_push(&coord, &ssh, &local, &remote, run.as_deref(), filter.as_deref()).await
        }
        Cmd::Run { command, filter } => {
            let coord = admin_coord(&server, &admin_token)?;
            cmd_run(&coord, &ssh, &command, filter.as_deref()).await
        }
        Cmd::SelfUpdate { dest, run, filter } => {
            let coord = admin_coord(&server, &admin_token)?;
            cmd_self_update(&coord, &ssh, &dest, run.as_deref(), filter.as_deref()).await
        }
        Cmd::PushUpdate { description } => {
            let coord = update_coord(&server, &update_token)?;
            cmd_push_update(&coord, &description).await
        }
        Cmd::CheckUpdate => {
            let coord = update_coord(&server, &update_token)?;
            cmd_check_update(&coord).await
        }
        Cmd::AutoUpdate { interval, dest, post_cmd } => {
            let coord = update_coord(&server, &update_token)?;
            cmd_auto_update(&coord, interval, &dest, post_cmd.as_deref()).await
        }
    }
}

fn admin_coord(server: &Option<String>, token: &Option<String>) -> Result<CoordClient> {
    let s = server
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--server is required (or set MESHLINK_SERVER)"))?;
    let t = token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--admin-token is required for this command"))?;
    Ok(CoordClient::new(s, t))
}

fn update_coord(server: &Option<String>, token: &Option<String>) -> Result<CoordClient> {
    let s = server.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "--server is required (or set MESHLINK_SERVER, or have /etc/meshlink/credentials.json)"
        )
    })?;
    let t = token.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "a token is required: use --auth-token, --admin-token, \
             or ensure /etc/meshlink/credentials.json exists"
        )
    })?;
    Ok(CoordClient::new(s, t))
}

// ---------------------------------------------------------------------------
// Admin commands
// ---------------------------------------------------------------------------

async fn cmd_peers(coord: &CoordClient) -> Result<()> {
    let peers = coord.list_peers().await?;
    if peers.is_empty() {
        println!("No peers registered.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<16}  {:<12}  {}",
        "ID", "NAME", "VIRTUAL IP", "STATUS", "LAST SEEN"
    );
    println!("{}", "-".repeat(100));

    for p in &peers {
        let last_seen = p
            .last_heartbeat
            .map(|t| {
                let ago = Utc::now().signed_duration_since(t);
                if ago.num_seconds() < 60 {
                    format!("{}s ago", ago.num_seconds())
                } else if ago.num_minutes() < 60 {
                    format!("{}m ago", ago.num_minutes())
                } else {
                    format!("{}h ago", ago.num_hours())
                }
            })
            .unwrap_or_else(|| "never".to_string());

        println!(
            "{:<36}  {:<20}  {:<16}  {:<12}  {}",
            p.node_id,
            p.node_name.as_deref().unwrap_or("-"),
            p.bare_ip(),
            p.status,
            last_seen,
        );
    }
    Ok(())
}

async fn cmd_push(
    coord: &CoordClient,
    ssh: &SshOpts,
    local: &PathBuf,
    remote: &str,
    run_cmd: Option<&str>,
    filter: Option<&str>,
) -> Result<()> {
    if !local.exists() {
        anyhow::bail!("local file does not exist: {}", local.display());
    }

    let peers = filter_peers(coord.list_peers().await?, filter);
    if peers.is_empty() {
        warn!("No active peers matched. Nothing to deploy.");
        return Ok(());
    }

    info!(
        "Deploying {} → {} on {} peer(s){}",
        local.display(),
        remote,
        peers.len(),
        run_cmd.map(|c| format!(", then: {c}")).unwrap_or_default(),
    );

    let local = std::sync::Arc::new(local.clone());
    let remote = std::sync::Arc::new(remote.to_string());
    let run_cmd = run_cmd.map(|s| std::sync::Arc::new(s.to_string()));
    let mut handles = Vec::new();

    for peer in peers {
        let local = local.clone();
        let remote = remote.clone();
        let run_cmd = run_cmd.clone();
        let opts = make_ssh(ssh);
        let name = peer.display_name();
        let ip = peer.bare_ip().to_string();

        handles.push(tokio::spawn(async move {
            let outcome: Result<String> = async {
                scp_push(&opts, &local, &ip, &remote).await?;
                if let Some(cmd) = &run_cmd {
                    let out = ssh_run(&opts, &ip, cmd).await?;
                    Ok(out.trim().to_string())
                } else {
                    Ok("copied".to_string())
                }
            }
            .await;
            PeerResult { name, ip, outcome }
        }));
    }

    let results = join_all(handles).await;
    print_results(&results);
    require_all_ok(&results)
}

async fn cmd_run(
    coord: &CoordClient,
    ssh: &SshOpts,
    command: &str,
    filter: Option<&str>,
) -> Result<()> {
    let peers = filter_peers(coord.list_peers().await?, filter);
    if peers.is_empty() {
        warn!("No active peers matched.");
        return Ok(());
    }

    info!("Running `{command}` on {} peer(s)", peers.len());

    let command = std::sync::Arc::new(command.to_string());
    let mut handles = Vec::new();

    for peer in peers {
        let command = command.clone();
        let opts = make_ssh(ssh);
        let name = peer.display_name();
        let ip = peer.bare_ip().to_string();

        handles.push(tokio::spawn(async move {
            let outcome = ssh_run(&opts, &ip, &command).await;
            PeerResult { name, ip, outcome }
        }));
    }

    let results = join_all(handles).await;
    print_results(&results);
    require_all_ok(&results)
}

async fn cmd_self_update(
    coord: &CoordClient,
    ssh: &SshOpts,
    dest: &str,
    run_cmd: Option<&str>,
    filter: Option<&str>,
) -> Result<()> {
    let self_path = std::fs::read_link("/proc/self/exe").context("resolving /proc/self/exe")?;
    if self_path.to_string_lossy().contains("(deleted)") {
        anyhow::bail!("running binary appears deleted — copy it to a permanent path first");
    }

    let binary_size = std::fs::metadata(&self_path)
        .with_context(|| format!("stat {}", self_path.display()))?
        .len();

    let peers = filter_peers(coord.list_peers().await?, filter);
    if peers.is_empty() {
        warn!("No active peers matched.");
        return Ok(());
    }

    info!(
        "Self-update: {} ({} bytes) → {} on {} peer(s){}",
        self_path.display(),
        binary_size,
        dest,
        peers.len(),
        run_cmd.map(|c| format!(", then: {c}")).unwrap_or_default(),
    );

    let self_path = std::sync::Arc::new(self_path);
    let dest = std::sync::Arc::new(dest.to_string());
    let run_cmd = run_cmd.map(|s| std::sync::Arc::new(s.to_string()));
    let mut handles = Vec::new();

    for peer in peers {
        let self_path = self_path.clone();
        let dest = dest.clone();
        let run_cmd = run_cmd.clone();
        let opts = make_ssh(ssh);
        let name = peer.display_name();
        let ip = peer.bare_ip().to_string();

        handles.push(tokio::spawn(async move {
            let outcome: Result<String> = async {
                let tmp = format!("{}.new.{}", dest, std::process::id());
                scp_push(&opts, &self_path, &ip, &tmp).await?;
                ssh_run(&opts, &ip, &format!("chmod +x {tmp} && mv {tmp} {dest}")).await?;
                if let Some(cmd) = &run_cmd {
                    let out = ssh_run(&opts, &ip, cmd).await?;
                    Ok(out.trim().to_string())
                } else {
                    Ok("updated".to_string())
                }
            }
            .await;
            PeerResult { name, ip, outcome }
        }));
    }

    let results = join_all(handles).await;
    print_results(&results);
    require_all_ok(&results)
}

// ---------------------------------------------------------------------------
// Update distribution commands
// ---------------------------------------------------------------------------

async fn cmd_push_update(coord: &CoordClient, description: &str) -> Result<()> {
    let self_path = std::fs::read_link("/proc/self/exe").context("resolving /proc/self/exe")?;
    if self_path.to_string_lossy().contains("(deleted)") {
        anyhow::bail!("running binary appears deleted — copy it to a permanent path first");
    }

    let binary = std::fs::read(&self_path)
        .with_context(|| format!("reading {}", self_path.display()))?;
    let hash = format!("{:x}", Sha256::digest(&binary));

    info!(
        path = %self_path.display(),
        bytes = binary.len(),
        "uploading update to coord server"
    );

    let meta = coord.push_update(binary, description).await?;

    println!("Update published:");
    println!("  ID:          {}", meta.id);
    println!("  Description: {}", meta.description);
    println!("  Hash:        {}", meta.binary_hash);
    println!("  Size:        {} bytes", meta.binary_size);
    println!("  Uploaded by: {}", meta.uploaded_by);

    // Sanity check: verify the server stored it correctly.
    if meta.binary_hash != hash {
        warn!(
            local = %hash,
            remote = %meta.binary_hash,
            "hash mismatch after upload"
        );
    }

    Ok(())
}

async fn cmd_check_update(coord: &CoordClient) -> Result<()> {
    let self_path = std::fs::read_link("/proc/self/exe").context("resolving /proc/self/exe")?;
    let current_hash = sha256_file(&self_path)?;

    let meta = match coord.latest_update().await? {
        Some(m) => m,
        None => {
            println!("No updates available on the coord server.");
            return Ok(());
        }
    };

    println!("Latest update on server:");
    println!("  ID:          {}", meta.id);
    println!("  Description: {}", meta.description);
    println!("  Hash:        {}", meta.binary_hash);
    println!("  Size:        {} bytes", meta.binary_size);
    println!("  Uploaded by: {}", meta.uploaded_by);
    println!("  Uploaded at: {}", meta.uploaded_at);

    if meta.binary_hash == current_hash {
        println!("\nThis peer is already up to date.");
    } else {
        println!("\nAn update is available. Run `mldeploy auto-update` to apply.");
    }

    Ok(())
}

async fn cmd_auto_update(
    coord: &CoordClient,
    interval_secs: u64,
    dest: &str,
    post_cmd: Option<&str>,
) -> Result<()> {
    info!(interval = interval_secs, "auto-update daemon started");

    loop {
        match try_apply_update(coord, dest, post_cmd).await {
            Ok(true) => info!("update applied successfully"),
            Ok(false) => info!("already up to date"),
            Err(e) => warn!(error = %e, "update check failed"),
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}

/// Check for and atomically apply an update if a newer binary is available.
/// Returns true if an update was applied, false if already current.
async fn try_apply_update(
    coord: &CoordClient,
    dest: &str,
    post_cmd: Option<&str>,
) -> Result<bool> {
    let self_path = std::fs::read_link("/proc/self/exe").context("resolving /proc/self/exe")?;
    let current_hash = sha256_file(&self_path)?;

    let meta = match coord.latest_update().await? {
        Some(m) => m,
        None => return Ok(false),
    };

    if meta.binary_hash == current_hash {
        return Ok(false);
    }

    info!(
        id = meta.id,
        description = %meta.description,
        "new update available — downloading"
    );

    let data = coord.download_latest().await?;
    let downloaded_hash = format!("{:x}", Sha256::digest(&data));

    if downloaded_hash != meta.binary_hash {
        anyhow::bail!(
            "hash mismatch: expected {} got {}",
            meta.binary_hash,
            downloaded_hash
        );
    }

    // Write to a temp file next to dest, then atomic rename.
    let tmp = format!("{dest}.new.{}", std::process::id());
    tokio::fs::write(&tmp, &data)
        .await
        .with_context(|| format!("writing to {tmp}"))?;

    // Set executable bit.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .context("setting executable bit")?;

    // Atomic replace.
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("replacing {dest} with {tmp}"))?;

    info!(dest, "binary replaced atomically");

    if let Some(cmd) = post_cmd {
        info!(cmd, "running post-update command");
        let out = Proc::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
            .context("running post-update command")?;
        if !out.status.success() {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "post-update command failed"
            );
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn make_ssh(opts: &SshOpts) -> SshOpts {
    SshOpts {
        user: opts.user.clone(),
        key: opts.key.clone(),
        port: opts.port,
    }
}

async fn join_all(handles: Vec<tokio::task::JoinHandle<PeerResult>>) -> Vec<PeerResult> {
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(e) => error!("task panicked: {e}"),
        }
    }
    results
}

fn print_results(results: &[PeerResult]) {
    println!();
    for r in results {
        match &r.outcome {
            Ok(msg) => {
                let detail = if msg.is_empty() { String::new() } else { format!(": {msg}") };
                println!("  \u{2713} {} ({}){}", r.name, r.ip, detail);
            }
            Err(e) => println!("  \u{2717} {} ({}): {}", r.name, r.ip, e),
        }
    }
    println!();
}

fn require_all_ok(results: &[PeerResult]) -> Result<()> {
    let failures = results.iter().filter(|r| r.outcome.is_err()).count();
    if failures > 0 {
        anyhow::bail!("{failures} peer(s) failed");
    }
    Ok(())
}
