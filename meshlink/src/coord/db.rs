use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;

/// A node record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_name: Option<String>,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub virtual_ip: String,
    pub auth_token: String,
    pub status: String,
    pub endpoint: Option<String>,
    pub ipv6_endpoint: Option<String>,
    pub listen_port: i32,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An invite record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InviteRecord {
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by_node_id: Option<String>,
    pub max_uses: i32,
    pub use_count: i32,
}

/// Database handle wrapping a PostgreSQL connection pool.
#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
}

impl Db {
    /// Connect to the database and return a Db handle.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .context("connecting to PostgreSQL")?;
        info!("connected to PostgreSQL");
        Ok(Self { pool })
    }

    /// Create all required tables (idempotent).
    pub async fn setup_tables(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                node_name TEXT,
                public_key BYTEA NOT NULL UNIQUE,
                private_key_encrypted BYTEA NOT NULL,
                virtual_ip TEXT NOT NULL UNIQUE,
                auth_token TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'registered'
                    CHECK(status IN ('registered','active','stale','deregistered')),
                endpoint TEXT,
                ipv6_endpoint TEXT,
                listen_port INTEGER NOT NULL DEFAULT 51820,
                last_heartbeat TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await
        .context("creating nodes table")?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                used_by_node_id TEXT REFERENCES nodes(node_id),
                max_uses INTEGER NOT NULL DEFAULT 1,
                use_count INTEGER NOT NULL DEFAULT 0
            )"#,
        )
        .execute(&self.pool)
        .await
        .context("creating invites table")?;

        // Migrate existing tables: add columns if missing
        sqlx::query("ALTER TABLE invites ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1")
            .execute(&self.pool)
            .await
            .context("migrating invites: max_uses")?;
        sqlx::query("ALTER TABLE invites ADD COLUMN IF NOT EXISTS use_count INTEGER NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await
            .context("migrating invites: use_count")?;
        sqlx::query("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS ipv6_endpoint TEXT")
            .execute(&self.pool)
            .await
            .context("migrating nodes: ipv6_endpoint")?;

        info!("database tables created");
        Ok(())
    }

    /// Drop all tables (destructive!).
    pub async fn drop_all_tables(&self) -> Result<()> {
        sqlx::query("DROP TABLE IF EXISTS invites CASCADE")
            .execute(&self.pool)
            .await
            .context("dropping invites table")?;
        sqlx::query("DROP TABLE IF EXISTS nodes CASCADE")
            .execute(&self.pool)
            .await
            .context("dropping nodes table")?;
        info!("all tables dropped");
        Ok(())
    }

    // --- Node operations ---

    /// Insert a new node record.
    pub async fn insert_node(&self, node: &NodeRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO nodes (node_id, node_name, public_key, private_key_encrypted,
               virtual_ip, auth_token, status, endpoint, ipv6_endpoint, listen_port,
               last_heartbeat, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
        )
        .bind(&node.node_id)
        .bind(&node.node_name)
        .bind(&node.public_key)
        .bind(&node.private_key_encrypted)
        .bind(&node.virtual_ip)
        .bind(&node.auth_token)
        .bind(&node.status)
        .bind(&node.endpoint)
        .bind(&node.ipv6_endpoint)
        .bind(node.listen_port)
        .bind(node.last_heartbeat)
        .bind(node.created_at)
        .bind(node.updated_at)
        .execute(&self.pool)
        .await
        .context("inserting node")?;
        Ok(())
    }

    /// Get a node by its ID.
    pub async fn get_node(&self, node_id: &str) -> Result<Option<NodeRecord>> {
        let node = sqlx::query_as::<_, NodeRecord>("SELECT * FROM nodes WHERE node_id = $1")
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await
            .context("fetching node")?;
        Ok(node)
    }

    /// Get a node by its public key.
    pub async fn get_node_by_pubkey(&self, public_key: &[u8]) -> Result<Option<NodeRecord>> {
        let node = sqlx::query_as::<_, NodeRecord>("SELECT * FROM nodes WHERE public_key = $1")
            .bind(public_key)
            .fetch_optional(&self.pool)
            .await
            .context("fetching node by pubkey")?;
        Ok(node)
    }

    /// Update a node's status.
    pub async fn update_node_status(&self, node_id: &str, status: &str) -> Result<()> {
        sqlx::query("UPDATE nodes SET status = $1, updated_at = NOW() WHERE node_id = $2")
            .bind(status)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .context("updating node status")?;
        Ok(())
    }

    /// Update a node's last heartbeat timestamp and optionally its endpoint.
    pub async fn update_heartbeat(
        &self,
        node_id: &str,
        endpoint: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE nodes SET last_heartbeat = NOW(), updated_at = NOW(),
               status = 'active', endpoint = COALESCE($1, endpoint)
               WHERE node_id = $2"#,
        )
        .bind(endpoint)
        .bind(node_id)
        .execute(&self.pool)
        .await
        .context("updating heartbeat")?;
        Ok(())
    }

    /// List all active nodes (status = 'registered' or 'active').
    pub async fn list_active_nodes(&self) -> Result<Vec<NodeRecord>> {
        let nodes = sqlx::query_as::<_, NodeRecord>(
            "SELECT * FROM nodes WHERE status IN ('registered', 'active') ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing active nodes")?;
        Ok(nodes)
    }

    /// Mark nodes as stale if they haven't sent a heartbeat in the given duration.
    pub async fn mark_stale_nodes(&self, stale_seconds: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"UPDATE nodes SET status = 'stale', updated_at = NOW()
               WHERE status = 'active'
               AND last_heartbeat < NOW() - INTERVAL '1 second' * $1"#,
        )
        .bind(stale_seconds)
        .execute(&self.pool)
        .await
        .context("marking stale nodes")?;
        Ok(result.rows_affected())
    }

    /// Update a node's endpoint and heartbeat by its public key (used by UDP registration).
    pub async fn update_endpoint_by_pubkey(
        &self,
        public_key: &[u8],
        endpoint: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"UPDATE nodes SET endpoint = $1, last_heartbeat = NOW(), updated_at = NOW(),
               status = 'active'
               WHERE public_key = $2 AND status IN ('registered', 'active')"#,
        )
        .bind(endpoint)
        .bind(public_key)
        .execute(&self.pool)
        .await
        .context("updating endpoint by public key")?;
        Ok(result.rows_affected() > 0)
    }

    /// Update a node's IPv6 endpoint by its public key.
    pub async fn update_ipv6_endpoint_by_pubkey(
        &self,
        public_key: &[u8],
        ipv6_endpoint: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"UPDATE nodes SET ipv6_endpoint = $1, updated_at = NOW()
               WHERE public_key = $2 AND status IN ('registered', 'active')"#,
        )
        .bind(ipv6_endpoint)
        .bind(public_key)
        .execute(&self.pool)
        .await
        .context("updating IPv6 endpoint by public key")?;
        Ok(result.rows_affected() > 0)
    }

    // --- Invite operations ---

    /// Create a new invite code with a maximum number of uses (0 = unlimited).
    pub async fn create_invite(&self, code: &str, expires_at: DateTime<Utc>, max_uses: i32) -> Result<()> {
        sqlx::query("INSERT INTO invites (code, expires_at, max_uses) VALUES ($1, $2, $3)")
            .bind(code)
            .bind(expires_at)
            .bind(max_uses)
            .execute(&self.pool)
            .await
            .context("creating invite")?;
        Ok(())
    }

    /// Get an invite by code.
    pub async fn get_invite(&self, code: &str) -> Result<Option<InviteRecord>> {
        let invite = sqlx::query_as::<_, InviteRecord>("SELECT * FROM invites WHERE code = $1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .context("fetching invite")?;
        Ok(invite)
    }

    /// Increment the use count of an invite. Sets used_at on first use.
    pub async fn increment_invite_use(&self, code: &str, node_id: &str) -> Result<()> {
        sqlx::query(
            r#"UPDATE invites SET
               use_count = use_count + 1,
               used_at = COALESCE(used_at, NOW()),
               used_by_node_id = $1
               WHERE code = $2"#,
        )
        .bind(node_id)
        .bind(code)
        .execute(&self.pool)
        .await
        .context("incrementing invite use")?;
        Ok(())
    }

    // --- IP allocation helper ---

    /// Get all virtual IPs currently allocated to active/registered nodes.
    pub async fn allocated_ips(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT virtual_ip FROM nodes WHERE status IN ('registered', 'active')",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing allocated IPs")?;
        Ok(rows.into_iter().map(|(ip,)| ip).collect())
    }
}
