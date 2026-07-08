use std::fs;
use std::path::{Path, PathBuf};

use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::util::{now_text, random_token};

#[derive(Clone)]
pub struct Store {
    db_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct LoginState {
    pub id: String,
    pub return_to: String,
}

#[derive(Clone, Debug)]
pub struct GatewaySession {
    pub id: String,
    pub auth_session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub email: Option<String>,
    pub amr: Vec<String>,
    pub access_expires_at: String,
    pub session_expires_at: String,
}

pub struct NewSession {
    pub auth_session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub email: Option<String>,
    pub amr: Vec<String>,
    pub access_expires_at: String,
    pub session_ttl_seconds: i64,
}

pub enum RefreshUpdate {
    Updated(GatewaySession),
    Current(GatewaySession),
    MissingOrRevoked,
}

impl Store {
    pub fn initialize(path: &Path) -> rusqlite::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }

        let connection = Connection::open(path)?;
        let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if version < 1 {
            connection.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS gateway_sessions (
                    id TEXT PRIMARY KEY,
                    auth_session_id TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    email TEXT,
                    amr_json TEXT NOT NULL,
                    access_expires_at TEXT NOT NULL,
                    session_expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    refresh_generation INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_gateway_sessions_expiry
                    ON gateway_sessions(session_expires_at, revoked_at);

                CREATE TABLE IF NOT EXISTS login_states (
                    id TEXT PRIMARY KEY,
                    return_to TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_login_states_expiry
                    ON login_states(expires_at, consumed_at);

                PRAGMA user_version = 1;
                "#,
            )?;
        }

        Ok(())
    }

    pub fn new(path: PathBuf) -> Self {
        Self { db_path: path }
    }

    fn connection(&self) -> rusqlite::Result<Connection> {
        let connection = Connection::open(&self.db_path)?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
        Ok(connection)
    }

    pub fn create_login_state(
        &self,
        return_to: &str,
        ttl_seconds: i64,
    ) -> rusqlite::Result<LoginState> {
        self.prune()?;
        let connection = self.connection()?;
        let id = random_token(32);
        let now = now_text();
        let expires_at = (Utc::now() + Duration::seconds(ttl_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        connection.execute(
            "INSERT INTO login_states (id, return_to, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, return_to, expires_at, now],
        )?;
        Ok(LoginState {
            id,
            return_to: return_to.to_string(),
        })
    }

    pub fn consume_login_state(&self, id: &str) -> rusqlite::Result<Option<LoginState>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let now = now_text();
        let state = tx
            .query_row(
                "SELECT id, return_to FROM login_states WHERE id = ?1 AND consumed_at IS NULL AND expires_at > ?2 LIMIT 1",
                params![id, now],
                |row| Ok(LoginState { id: row.get(0)?, return_to: row.get(1)? }),
            )
            .optional()?;

        if state.is_some() {
            tx.execute(
                "UPDATE login_states SET consumed_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
        }
        tx.commit()?;
        Ok(state)
    }

    pub fn create_session(&self, input: NewSession) -> rusqlite::Result<GatewaySession> {
        self.prune()?;
        let connection = self.connection()?;
        let id = random_token(32);
        let now = now_text();
        let session_expires_at = (Utc::now() + Duration::seconds(input.session_ttl_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let amr_json = serde_json::to_string(&input.amr).map_err(to_sql_error)?;

        connection.execute(
            "INSERT INTO gateway_sessions
             (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json, access_expires_at, session_expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                id,
                input.auth_session_id,
                input.access_token,
                input.refresh_token,
                input.user_id,
                input.email,
                amr_json,
                input.access_expires_at,
                session_expires_at,
                now,
            ],
        )?;

        self.get_session(&id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn get_session(&self, id: &str) -> rusqlite::Result<Option<GatewaySession>> {
        let connection = self.connection()?;
        let now = now_text();
        connection
            .query_row(
                "SELECT id, auth_session_id, access_token, refresh_token, user_id, email, amr_json, access_expires_at, session_expires_at
                 FROM gateway_sessions
                 WHERE id = ?1 AND revoked_at IS NULL AND session_expires_at > ?2
                 LIMIT 1",
                params![id, now],
                row_to_session,
            )
            .optional()
    }

    pub fn revoke_session(&self, id: &str) -> rusqlite::Result<()> {
        let connection = self.connection()?;
        let now = now_text();
        connection.execute(
            "UPDATE gateway_sessions SET revoked_at = ?1, updated_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![now, id],
        )?;
        Ok(())
    }

    pub fn update_after_refresh(
        &self,
        original: &GatewaySession,
        next_access_token: &str,
        next_refresh_token: &str,
        next_user_id: &str,
        next_email: Option<&str>,
        next_amr: &[String],
        next_access_expires_at: &str,
    ) -> rusqlite::Result<RefreshUpdate> {
        let connection = self.connection()?;
        let now = now_text();
        let amr_json = serde_json::to_string(next_amr).map_err(to_sql_error)?;
        let changed = connection.execute(
            "UPDATE gateway_sessions
             SET access_token = ?1,
                 refresh_token = ?2,
                 user_id = ?3,
                 email = ?4,
                 amr_json = ?5,
                 access_expires_at = ?6,
                 refresh_generation = refresh_generation + 1,
                 updated_at = ?7
             WHERE id = ?8
               AND refresh_token = ?9
               AND revoked_at IS NULL
               AND session_expires_at > ?7",
            params![
                next_access_token,
                next_refresh_token,
                next_user_id,
                next_email,
                amr_json,
                next_access_expires_at,
                now,
                original.id,
                original.refresh_token,
            ],
        )?;

        if changed == 1 {
            return Ok(RefreshUpdate::Updated(
                self.get_session(&original.id)?
                    .ok_or(rusqlite::Error::QueryReturnedNoRows)?,
            ));
        }

        if let Some(current) = self.get_session(&original.id)? {
            if current.refresh_token != original.refresh_token
                || current.access_expires_at > original.access_expires_at
            {
                return Ok(RefreshUpdate::Current(current));
            }
        }

        Ok(RefreshUpdate::MissingOrRevoked)
    }

    pub fn prune(&self) -> rusqlite::Result<()> {
        let connection = self.connection()?;
        let now = now_text();
        connection.execute(
            "DELETE FROM login_states WHERE expires_at <= ?1 OR consumed_at IS NOT NULL",
            params![now],
        )?;
        connection.execute(
            "DELETE FROM gateway_sessions WHERE session_expires_at <= ?1 OR revoked_at IS NOT NULL",
            params![now],
        )?;
        Ok(())
    }
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<GatewaySession> {
    let amr_json: String = row.get(6)?;
    let amr = serde_json::from_str(&amr_json).map_err(to_sql_error)?;
    Ok(GatewaySession {
        id: row.get(0)?,
        auth_session_id: row.get(1)?,
        access_token: row.get(2)?,
        refresh_token: row.get(3)?,
        user_id: row.get(4)?,
        email: row.get(5)?,
        amr,
        access_expires_at: row.get(7)?,
        session_expires_at: row.get(8)?,
    })
}

fn to_sql_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, SecondsFormat, Utc};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn login_state_is_durable_and_one_time() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("gateway.sqlite");
        Store::initialize(&path).expect("database initializes");
        let store = Store::new(path);

        let state = store
            .create_login_state("/protected", 300)
            .expect("state creates");

        assert_eq!(
            store
                .consume_login_state(&state.id)
                .expect("state consumes")
                .expect("state exists")
                .return_to,
            "/protected"
        );
        assert!(store
            .consume_login_state(&state.id)
            .expect("second consume succeeds")
            .is_none());
    }

    #[test]
    fn revoke_removes_session_from_active_reads() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("gateway.sqlite");
        Store::initialize(&path).expect("database initializes");
        let store = Store::new(path);
        let session = store
            .create_session(new_session("refresh-1", 900))
            .expect("session creates");

        store.revoke_session(&session.id).expect("session revokes");

        assert!(store
            .get_session(&session.id)
            .expect("session read")
            .is_none());
    }

    #[test]
    fn refresh_update_uses_compare_and_swap() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("gateway.sqlite");
        Store::initialize(&path).expect("database initializes");
        let store = Store::new(path);
        let original = store
            .create_session(new_session("refresh-1", 10))
            .expect("session creates");

        let first = store
            .update_after_refresh(
                &original,
                "access-2",
                "refresh-2",
                "user-1",
                Some("allowed@example.com"),
                &["webauthn".to_string()],
                &future_text(900),
            )
            .expect("refresh updates");
        let updated = match first {
            RefreshUpdate::Updated(session) => session,
            _ => panic!("first refresh should update"),
        };

        let second = store
            .update_after_refresh(
                &original,
                "access-3",
                "refresh-3",
                "user-1",
                Some("allowed@example.com"),
                &["webauthn".to_string()],
                &future_text(1200),
            )
            .expect("second refresh resolves");

        match second {
            RefreshUpdate::Current(current) => assert_eq!(current.refresh_token, "refresh-2"),
            _ => panic!("stale refresh should return current session"),
        }

        store.revoke_session(&updated.id).expect("session revokes");
        let after_revoke = store
            .update_after_refresh(
                &updated,
                "access-4",
                "refresh-4",
                "user-1",
                Some("allowed@example.com"),
                &["webauthn".to_string()],
                &future_text(1200),
            )
            .expect("revoked refresh resolves");
        assert!(matches!(after_revoke, RefreshUpdate::MissingOrRevoked));
    }

    fn new_session(refresh_token: &str, access_ttl_seconds: i64) -> NewSession {
        NewSession {
            auth_session_id: "auth-session-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: refresh_token.to_string(),
            user_id: "user-1".to_string(),
            email: Some("allowed@example.com".to_string()),
            amr: vec!["webauthn".to_string()],
            access_expires_at: future_text(access_ttl_seconds),
            session_ttl_seconds: 3600,
        }
    }

    fn future_text(seconds: i64) -> String {
        (Utc::now() + Duration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}
