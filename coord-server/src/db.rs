use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
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
    pub listen_port: i32,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A service record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServiceRecord {
    pub id: String,
    pub peer_id: String,
    pub name: String,
    pub port: i32,
    pub protocol: String,
    pub created_at: DateTime<Utc>,
}

/// An access rule record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AccessRuleRecord {
    pub id: String,
    pub service_id: String,
    pub target_peer_id: String,
    pub granted_by: String,
    pub rule_type: String,
    pub created_at: DateTime<Utc>,
}

/// Flattened ACL entry for config generation.
#[derive(Debug, Clone)]
pub struct AclEntry {
    pub peer_virtual_ip: String,
    pub port: i32,
    pub protocol: String,
    pub action: String,
}

/// An invite record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InviteRecord {
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by_node_id: Option<String>,
}

/// A user record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserRecord {
    pub user_id: String,
    pub username: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A user invite record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserInviteRecord {
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by_user_id: Option<String>,
}

/// A refresh token record from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshTokenRecord {
    pub token_id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
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

    /// Run embedded migrations.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("running migrations")?;
        info!("database migrations complete");
        Ok(())
    }

    // --- Node operations ---

    /// Insert a new node record.
    pub async fn insert_node(&self, node: &NodeRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO nodes (node_id, node_name, public_key, private_key_encrypted,
               virtual_ip, auth_token, status, endpoint, listen_port, last_heartbeat,
               created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
        )
        .bind(&node.node_id)
        .bind(&node.node_name)
        .bind(&node.public_key)
        .bind(&node.private_key_encrypted)
        .bind(&node.virtual_ip)
        .bind(&node.auth_token)
        .bind(&node.status)
        .bind(&node.endpoint)
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

    /// Get the count of the last heartbeat update to detect peer changes.
    /// Returns the max updated_at among active nodes.
    pub async fn peers_updated_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM nodes WHERE status IN ('registered', 'active') AND updated_at > $1",
        )
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .context("checking peer updates")?;
        Ok(row.0 > 0)
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

    // --- Invite operations ---

    /// Create a new invite code.
    pub async fn create_invite(&self, code: &str, expires_at: DateTime<Utc>) -> Result<()> {
        sqlx::query("INSERT INTO invites (code, expires_at) VALUES ($1, $2)")
            .bind(code)
            .bind(expires_at)
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

    /// Mark an invite as used by a specific node.
    pub async fn use_invite(&self, code: &str, node_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE invites SET used_at = NOW(), used_by_node_id = $1 WHERE code = $2",
        )
        .bind(node_id)
        .bind(code)
        .execute(&self.pool)
        .await
        .context("using invite")?;
        Ok(())
    }

    // --- IP allocation helper ---

    // --- Service operations ---

    pub async fn insert_service(&self, service: &ServiceRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO services (id, peer_id, name, port, protocol, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(&service.id)
        .bind(&service.peer_id)
        .bind(&service.name)
        .bind(service.port)
        .bind(&service.protocol)
        .bind(service.created_at)
        .execute(&self.pool)
        .await
        .context("inserting service")?;
        Ok(())
    }

    pub async fn get_service(&self, service_id: &str) -> Result<Option<ServiceRecord>> {
        let svc = sqlx::query_as::<_, ServiceRecord>("SELECT * FROM services WHERE id = $1")
            .bind(service_id)
            .fetch_optional(&self.pool)
            .await
            .context("fetching service")?;
        Ok(svc)
    }

    pub async fn list_services_for_peer(&self, peer_id: &str) -> Result<Vec<ServiceRecord>> {
        let services = sqlx::query_as::<_, ServiceRecord>(
            "SELECT * FROM services WHERE peer_id = $1 ORDER BY created_at",
        )
        .bind(peer_id)
        .fetch_all(&self.pool)
        .await
        .context("listing services for peer")?;
        Ok(services)
    }

    pub async fn delete_service(&self, service_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM services WHERE id = $1")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .context("deleting service")?;
        Ok(result.rows_affected() > 0)
    }

    // --- Access rule operations ---

    pub async fn upsert_access_rule(&self, rule: &AccessRuleRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO access_rules (id, service_id, target_peer_id, granted_by, rule_type, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (service_id, target_peer_id, granted_by)
               DO UPDATE SET rule_type = EXCLUDED.rule_type"#,
        )
        .bind(&rule.id)
        .bind(&rule.service_id)
        .bind(&rule.target_peer_id)
        .bind(&rule.granted_by)
        .bind(&rule.rule_type)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await
        .context("upserting access rule")?;
        Ok(())
    }

    pub async fn delete_access_rule(&self, rule_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM access_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&self.pool)
            .await
            .context("deleting access rule")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_access_rule(&self, rule_id: &str) -> Result<Option<AccessRuleRecord>> {
        let rule = sqlx::query_as::<_, AccessRuleRecord>(
            "SELECT * FROM access_rules WHERE id = $1",
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching access rule")?;
        Ok(rule)
    }

    pub async fn list_rules_for_service(&self, service_id: &str) -> Result<Vec<AccessRuleRecord>> {
        let rules = sqlx::query_as::<_, AccessRuleRecord>(
            "SELECT * FROM access_rules WHERE service_id = $1 ORDER BY created_at",
        )
        .bind(service_id)
        .fetch_all(&self.pool)
        .await
        .context("listing rules for service")?;
        Ok(rules)
    }

    /// Compute outbound ACL: "what services can this peer reach?"
    /// Priority: admin deny > admin allow > owner deny > owner allow > default-deny.
    /// Returns only effective "allow" entries.
    pub async fn resolve_acl_for_peer(&self, requesting_peer_id: &str) -> Result<Vec<AclEntry>> {
        // Get all rules targeting this peer, joined with service + node info
        let rows = sqlx::query_as::<_, AclRuleRow>(
            r#"SELECT s.port, s.protocol, n.virtual_ip as peer_virtual_ip,
                      ar.granted_by, ar.rule_type
               FROM access_rules ar
               JOIN services s ON ar.service_id = s.id
               JOIN nodes n ON s.peer_id = n.node_id
               WHERE ar.target_peer_id = $1
                 AND n.status IN ('registered', 'active')
               ORDER BY s.id"#,
        )
        .bind(requesting_peer_id)
        .fetch_all(&self.pool)
        .await
        .context("resolving ACL for peer")?;

        Ok(resolve_rules(rows))
    }

    /// Compute inbound ACL: "who can reach this peer's services?"
    /// Same priority logic, queried from the service-owner perspective.
    pub async fn resolve_inbound_acl_for_owner(&self, owner_peer_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclRuleRow>(
            r#"SELECT s.port, s.protocol, n.virtual_ip as peer_virtual_ip,
                      ar.granted_by, ar.rule_type
               FROM access_rules ar
               JOIN services s ON ar.service_id = s.id
               JOIN nodes n ON ar.target_peer_id = n.node_id
               WHERE s.peer_id = $1
                 AND n.status IN ('registered', 'active')
               ORDER BY s.id"#,
        )
        .bind(owner_peer_id)
        .fetch_all(&self.pool)
        .await
        .context("resolving inbound ACL for owner")?;

        Ok(resolve_rules(rows))
    }

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

    // --- User invite operations ---

    pub async fn create_user_invite(&self, code: &str, expires_at: DateTime<Utc>) -> Result<()> {
        sqlx::query("INSERT INTO user_invites (code, expires_at) VALUES ($1, $2)")
            .bind(code)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .context("creating user invite")?;
        Ok(())
    }

    pub async fn get_user_invite(&self, code: &str) -> Result<Option<UserInviteRecord>> {
        let invite =
            sqlx::query_as::<_, UserInviteRecord>("SELECT * FROM user_invites WHERE code = $1")
                .bind(code)
                .fetch_optional(&self.pool)
                .await
                .context("fetching user invite")?;
        Ok(invite)
    }

    pub async fn use_user_invite(&self, code: &str, user_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE user_invites SET used_at = NOW(), used_by_user_id = $1 WHERE code = $2",
        )
        .bind(user_id)
        .bind(code)
        .execute(&self.pool)
        .await
        .context("using user invite")?;
        Ok(())
    }

    // --- User operations ---

    pub async fn insert_user(&self, user: &UserRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO users (user_id, username, password_hash, display_name, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(&user.user_id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.display_name)
        .bind(&user.status)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .context("inserting user")?;
        Ok(())
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<UserRecord>> {
        let user = sqlx::query_as::<_, UserRecord>("SELECT * FROM users WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .context("fetching user")?;
        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        let user = sqlx::query_as::<_, UserRecord>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .context("fetching user by username")?;
        Ok(user)
    }

    pub async fn update_user_status(&self, user_id: &str, status: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET status = $1, updated_at = NOW() WHERE user_id = $2",
        )
        .bind(status)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("updating user status")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_users(&self, status_filter: Option<&str>) -> Result<Vec<UserRecord>> {
        let users = if let Some(status) = status_filter {
            sqlx::query_as::<_, UserRecord>(
                "SELECT * FROM users WHERE status = $1 ORDER BY created_at",
            )
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, UserRecord>("SELECT * FROM users ORDER BY created_at")
                .fetch_all(&self.pool)
                .await
        }
        .context("listing users")?;
        Ok(users)
    }

    // --- Refresh token operations ---

    pub async fn insert_refresh_token(&self, token: &RefreshTokenRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO refresh_tokens (token_id, user_id, token_hash, expires_at, created_at)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&token.token_id)
        .bind(&token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .context("inserting refresh token")?;
        Ok(())
    }

    pub async fn get_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>> {
        let token = sqlx::query_as::<_, RefreshTokenRecord>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .context("fetching refresh token")?;
        Ok(token)
    }

    pub async fn revoke_refresh_token(&self, token_id: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .context("revoking refresh token")?;
        Ok(())
    }

    pub async fn revoke_all_user_refresh_tokens(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("revoking all user refresh tokens")?;
        Ok(())
    }
}

/// Internal row type for ACL resolution queries.
#[derive(sqlx::FromRow)]
struct AclRuleRow {
    port: i32,
    protocol: String,
    peer_virtual_ip: String,
    granted_by: String,
    rule_type: String,
}

/// Resolve priority: admin deny > admin allow > owner deny > owner allow > default-deny.
/// Returns only effective "allow" entries.
fn resolve_rules(rows: Vec<AclRuleRow>) -> Vec<AclEntry> {
    // Group by (peer_ip, port, protocol)
    let mut groups: HashMap<(String, i32, String), Vec<&AclRuleRow>> = HashMap::new();
    for row in &rows {
        // For "both" protocol services, emit separate entries for tcp and udp
        let protocols: Vec<String> = if row.protocol == "both" {
            vec!["tcp".into(), "udp".into()]
        } else {
            vec![row.protocol.clone()]
        };
        for proto in protocols {
            groups
                .entry((row.peer_virtual_ip.clone(), row.port, proto))
                .or_default()
                .push(row);
        }
    }

    let mut entries = Vec::new();
    for ((ip, port, protocol), rules) in groups {
        // Check admin rules first (highest priority)
        let admin_deny = rules.iter().any(|r| r.granted_by == "admin" && r.rule_type == "deny");
        if admin_deny {
            continue; // admin deny wins, skip this entry
        }
        let admin_allow = rules.iter().any(|r| r.granted_by == "admin" && r.rule_type == "allow");
        if admin_allow {
            entries.push(AclEntry {
                peer_virtual_ip: ip,
                port,
                protocol,
                action: "allow".into(),
            });
            continue;
        }
        // Then owner rules
        let owner_deny = rules.iter().any(|r| r.granted_by == "owner" && r.rule_type == "deny");
        if owner_deny {
            continue;
        }
        let owner_allow = rules.iter().any(|r| r.granted_by == "owner" && r.rule_type == "allow");
        if owner_allow {
            entries.push(AclEntry {
                peer_virtual_ip: ip,
                port,
                protocol,
                action: "allow".into(),
            });
        }
        // default: deny (no entry emitted)
    }

    entries
}
