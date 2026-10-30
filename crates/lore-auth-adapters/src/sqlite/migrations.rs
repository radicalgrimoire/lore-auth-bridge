//! Schema migrations and schema-version validation for the SQLite store.
//! This module owns migration SQL and migration version bookkeeping.

use super::{Result, Store, new_id, unix_now};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, TransactionBehavior},
};

const BASELINE_VERSION: &str = "phase2b_baseline_20260702";
const GROUP_GROUPS_VERSION: &str = "phase3_group_groups_20260702";
const ADMIN_AUDIT_VERSION: &str = "phase4_admin_audit_20260702";
const GROUP_NETWORK_CIDRS_VERSION: &str = "phase5_group_network_cidrs_20261020";
const SERVICE_ACCOUNTS_VERSION: &str = "phase6_service_accounts_20261021";
const REMOVE_EXISTING_GROUP_NESTS_VERSION: &str = "phase7_remove_existing_group_nests_20261030";
const MAINTENANCE_VERSION: &str = "phase8_maintenance_20261030";

const BASELINE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT,
  primary_email TEXT,
  primary_email_normalized TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_primary_email
ON users(primary_email_normalized)
WHERE primary_email_normalized IS NOT NULL AND status <> 'deleted';

CREATE TABLE IF NOT EXISTS external_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  subject_strategy TEXT NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name TEXT,
  picture_url TEXT,
  hosted_domain TEXT,
  status TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  UNIQUE(provider_id, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_user
ON external_identities(user_id);

CREATE TABLE IF NOT EXISTS identity_invitations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  email TEXT,
  email_normalized TEXT,
  binding_policy TEXT NOT NULL,
  status TEXT NOT NULL,
  accepted_identity_id TEXT REFERENCES external_identities(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  accepted_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_invitations_pending_email
ON identity_invitations(provider_id, issuer, email_normalized)
WHERE status = 'pending' AND email_normalized IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identity_invitations_user
ON identity_invitations(user_id);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

CREATE TABLE IF NOT EXISTS repositories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  remote_url TEXT NOT NULL DEFAULT '',
  lore_repository_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_by_source TEXT NOT NULL DEFAULT 'manual',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (subject_type, subject_id, repository_id, role)
);

CREATE INDEX IF NOT EXISTS idx_grants_repo ON grants(repository_id);
CREATE INDEX IF NOT EXISTS idx_grants_subject ON grants(subject_type, subject_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  session_code_hash TEXT NOT NULL UNIQUE,
  client_state_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  login_url_nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_status ON auth_sessions(status);

CREATE TABLE IF NOT EXISTS login_transactions (
  id TEXT PRIMARY KEY,
  state_hash TEXT NOT NULL UNIQUE,
  provider_id TEXT NOT NULL,
  nonce TEXT,
  login_url_nonce TEXT,
  return_path TEXT,
  private_state BLOB,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_login_transactions_provider ON login_transactions(provider_id);
CREATE INDEX IF NOT EXISTS idx_login_transactions_expires ON login_transactions(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS csrf_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_csrf_tokens_session ON csrf_tokens(session_id);

CREATE TABLE IF NOT EXISTS device_authorizations (
  id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  requested_remote_url TEXT NOT NULL,
  requested_repository_id TEXT REFERENCES repositories(id),
  approved_user_id TEXT REFERENCES users(id),
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_device_authorizations_status
ON device_authorizations(status);

CREATE TABLE IF NOT EXISTS issued_tokens (
  jti TEXT PRIMARY KEY,
  token_kind TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  service_account_id TEXT,
  repository_id TEXT REFERENCES repositories(id),
  lore_resource_id TEXT,
  role TEXT NOT NULL DEFAULT '',
  kid TEXT NOT NULL,
  audience_json TEXT NOT NULL DEFAULT '[]',
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_issued_tokens_kind ON issued_tokens(token_kind);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_user ON issued_tokens(user_id);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL,
  public_jwk_json TEXT NOT NULL,
  private_key_path TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  not_before INTEGER,
  retired_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata_json TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at);
"#;

const GROUP_GROUPS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS group_groups (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  member_group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, member_group_id)
);

CREATE INDEX IF NOT EXISTS idx_group_groups_member ON group_groups(member_group_id);
"#;

const ADMIN_AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admin_audit (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);
"#;

const GROUP_NETWORK_CIDRS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS group_network_cidrs (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  cidr TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, cidr)
);

CREATE INDEX IF NOT EXISTS idx_group_network_cidrs_group
ON group_network_cidrs(group_id);
"#;

const SERVICE_ACCOUNTS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS service_accounts (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  rotated_at INTEGER NOT NULL
);
"#;

const MAINTENANCE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS maintenance_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  enabled_at INTEGER NOT NULL,
  wait_minutes INTEGER NOT NULL CHECK (wait_minutes > 0)
);
INSERT OR IGNORE INTO maintenance_settings (id, enabled, enabled_at, wait_minutes)
VALUES (1, 0, 0, 15);
"#;

impl Store {
    pub async fn migrate(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch(BASELINE_SCHEMA)?;
                conn.execute_batch(GROUP_GROUPS_SCHEMA)?;
                conn.execute_batch(ADMIN_AUDIT_SCHEMA)?;
                conn.execute_batch(GROUP_NETWORK_CIDRS_SCHEMA)?;
                conn.execute_batch(SERVICE_ACCOUNTS_SCHEMA)?;
                conn.execute_batch(MAINTENANCE_SCHEMA)?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![BASELINE_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![GROUP_GROUPS_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![ADMIN_AUDIT_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![GROUP_NETWORK_CIDRS_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![SERVICE_ACCOUNTS_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![MAINTENANCE_VERSION, unix_now()],
                )?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let applied = tx.query_row(
                    "SELECT 1 FROM schema_migrations WHERE version = ?1",
                    params![REMOVE_EXISTING_GROUP_NESTS_VERSION],
                    |_| Ok(()),
                ).optional()?.is_some();
                if !applied {
                    let edges = {
                        let mut stmt = tx.prepare(
                            "SELECT group_id, member_group_id FROM group_groups ORDER BY group_id, member_group_id"
                        )?;
                        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
                        rows.collect::<rusqlite::Result<Vec<_>>>()?
                    };
                    for (parent, member) in &edges {
                        tx.execute(
                            "INSERT INTO admin_audit (id, actor, action, object_type, object_id, detail, created_at)
                             VALUES (?1, 'migration', 'group.nest.remove', 'group', ?2, ?3, ?4)",
                            params![new_id(), parent, format!("member_group={member}"), unix_now()],
                        )?;
                    }
                    tx.execute("DELETE FROM group_groups", [])?;
                    tx.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![REMOVE_EXISTING_GROUP_NESTS_VERSION, unix_now()],
                    )?;
                }
                tx.commit()?;
                Ok::<(), rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    pub async fn validate_schema(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                for expected in [
                    BASELINE_VERSION,
                    GROUP_GROUPS_VERSION,
                    ADMIN_AUDIT_VERSION,
                    GROUP_NETWORK_CIDRS_VERSION,
                    SERVICE_ACCOUNTS_VERSION,
                    REMOVE_EXISTING_GROUP_NESTS_VERSION,
                    MAINTENANCE_VERSION,
                ] {
                    let version = conn
                        .query_row(
                            "SELECT version FROM schema_migrations WHERE version = ?1",
                            params![expected],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    if version.is_none() {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }
                Ok::<(), rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }
}
