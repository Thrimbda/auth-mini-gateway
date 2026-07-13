use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::util::{format_time, parse_time, random_token, Clock, SystemClock};

pub const SCHEMA_VERSION: i64 = 2;
pub const COMPAT_DENY_AT: &str = "1970-01-01T00:00:00.000Z";
const LEGACY_ABSOLUTE_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone)]
pub struct Store {
    db_path: PathBuf,
    clock: Arc<dyn Clock>,
}

#[derive(Clone)]
pub struct LoginState {
    pub id: String,
    pub return_to: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum IdentityState {
    Ready,
    Pending,
}

impl IdentityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Pending => "pending",
        }
    }
}

#[derive(Clone)]
pub struct GatewaySession {
    pub id: String,
    pub auth_session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub email: Option<String>,
    pub amr: Vec<String>,
    pub access_expires_at: DateTime<Utc>,
    pub session_expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub last_touched_at: DateTime<Utc>,
    pub identity_state: IdentityState,
    pub identity_pending_since: Option<DateTime<Utc>>,
    pub refresh_generation: i64,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl GatewaySession {
    pub fn observed_version(&self) -> ObservedVersion {
        ObservedVersion {
            generation: self.refresh_generation,
            identity_state: self.identity_state,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ObservedVersion {
    pub generation: i64,
    pub identity_state: IdentityState,
}

pub struct NewSession {
    pub auth_session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub email: Option<String>,
    pub amr: Vec<String>,
    pub access_expires_at: DateTime<Utc>,
    pub idle_ttl_seconds: i64,
    pub absolute_ttl_seconds: i64,
}

pub struct PendingTokens<'a> {
    pub access_token: &'a str,
    pub refresh_token: &'a str,
    pub user_id: &'a str,
    pub amr: &'a [String],
    pub access_expires_at: DateTime<Utc>,
}

// The active variant intentionally owns the row so callers can finish without
// retaining a SQLite connection or performing a second read.
#[allow(clippy::large_enum_variant)]
pub enum SessionLookup {
    Active(GatewaySession),
    Inactive,
}

pub enum CasResult {
    Updated(GatewaySession),
    Current(GatewaySession),
    Inactive,
}

pub enum TouchResult {
    NotDue(GatewaySession),
    Advanced(GatewaySession),
    Lost,
}

impl Store {
    pub fn initialize(path: &Path) -> rusqlite::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(to_sql_failure)?;
            }
        }

        let mut connection = Connection::open(path)?;
        let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
        migrate(&mut connection)
    }

    pub fn new(path: PathBuf) -> Self {
        Self::with_clock(path, Arc::new(SystemClock))
    }

    pub fn with_clock(path: PathBuf, clock: Arc<dyn Clock>) -> Self {
        Self {
            db_path: path,
            clock,
        }
    }

    fn connection(&self) -> rusqlite::Result<Connection> {
        let connection = Connection::open(&self.db_path)?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
        Ok(connection)
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    pub fn create_login_state(
        &self,
        return_to: &str,
        ttl_seconds: i64,
    ) -> rusqlite::Result<LoginState> {
        self.prune()?;
        let connection = self.connection()?;
        let id = random_token(32);
        let now = self.clock.now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        connection.execute(
            "INSERT INTO login_states (id, return_to, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, return_to, format_time(expires_at), format_time(now)],
        )?;
        Ok(LoginState {
            id,
            return_to: return_to.to_string(),
            expires_at,
        })
    }

    pub fn consume_login_state(&self, id: &str) -> rusqlite::Result<Option<LoginState>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let now = self.clock.now();
        let now_text = format_time(now);
        let raw = tx
            .query_row(
                "SELECT id, return_to, expires_at FROM login_states WHERE id = ?1 AND consumed_at IS NULL AND expires_at > ?2 LIMIT 1",
                params![id, now_text],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .optional()?;
        let state = raw
            .map(|(id, return_to, expires_at)| {
                Ok::<LoginState, rusqlite::Error>(LoginState {
                    id,
                    return_to,
                    expires_at: parse_db_time(&expires_at)?,
                })
            })
            .transpose()?;

        if state.is_some() {
            tx.execute(
                "UPDATE login_states SET consumed_at = ?1 WHERE id = ?2",
                params![format_time(now), id],
            )?;
        }
        tx.commit()?;
        Ok(state)
    }

    pub fn create_session(&self, input: NewSession) -> rusqlite::Result<GatewaySession> {
        self.prune()?;
        let connection = self.connection()?;
        let id = random_token(32);
        let now = self.clock.now();
        let absolute_expires_at = now + Duration::seconds(input.absolute_ttl_seconds);
        let idle_expires_at = std::cmp::min(
            now + Duration::seconds(input.idle_ttl_seconds),
            absolute_expires_at,
        );
        let amr_json = serde_json::to_string(&input.amr).map_err(to_sql_failure)?;
        let now_text = format_time(now);
        let idle_text = format_time(idle_expires_at);

        connection.execute(
            "INSERT INTO gateway_sessions
             (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
              access_expires_at, session_expires_at, revoked_at, refresh_generation,
              created_at, updated_at, idle_expires_at, absolute_expires_at, last_touched_at,
              identity_state, identity_pending_since)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, 0, ?10, ?10, ?9, ?11, ?10, 'ready', NULL)",
            params![
                id,
                input.auth_session_id,
                input.access_token,
                input.refresh_token,
                input.user_id,
                input.email,
                amr_json,
                format_time(input.access_expires_at),
                idle_text,
                now_text,
                format_time(absolute_expires_at),
            ],
        )?;

        match self.lookup_session_at(&id, now)? {
            SessionLookup::Active(session) => Ok(session),
            SessionLookup::Inactive => Err(rusqlite::Error::QueryReturnedNoRows),
        }
    }

    pub fn lookup_session(&self, id: &str) -> rusqlite::Result<SessionLookup> {
        self.lookup_session_at(id, self.clock.now())
    }

    pub fn lookup_session_at(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<SessionLookup> {
        let connection = self.connection()?;
        let session = connection
            .query_row(SESSION_SELECT, params![id], row_to_session)
            .optional()?;
        Ok(match session {
            Some(session) if is_active(&session, now) => SessionLookup::Active(session),
            _ => SessionLookup::Inactive,
        })
    }

    pub fn logout_access_snapshot(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.connection()?
            .query_row(
                "SELECT access_token FROM gateway_sessions WHERE id = ?1 AND revoked_at IS NULL",
                params![id],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn revoke_session(&self, id: &str) -> rusqlite::Result<bool> {
        let connection = self.connection()?;
        let now = format_time(self.clock.now());
        Ok(connection.execute(
            "UPDATE gateway_sessions SET revoked_at = ?1, updated_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![now, id],
        )? == 1)
    }

    pub fn conditional_revoke(&self, expected: &GatewaySession) -> rusqlite::Result<bool> {
        let connection = self.connection()?;
        let now = self.clock.now();
        let now_text = format_time(now);
        Ok(connection.execute(
            "UPDATE gateway_sessions
             SET revoked_at = ?1, updated_at = ?1
             WHERE id = ?2 AND refresh_generation = ?3 AND refresh_token = ?4
               AND identity_state = ?5 AND revoked_at IS NULL
               AND idle_expires_at > ?1 AND absolute_expires_at > ?1",
            params![
                now_text,
                expected.id,
                expected.refresh_generation,
                expected.refresh_token,
                expected.identity_state.as_str(),
            ],
        )? == 1)
    }

    pub fn persist_pending(
        &self,
        original: &GatewaySession,
        next: PendingTokens<'_>,
    ) -> rusqlite::Result<CasResult> {
        let connection = self.connection()?;
        let now = self.clock.now();
        let now_text = format_time(now);
        let amr_json = serde_json::to_string(next.amr).map_err(to_sql_failure)?;
        let changed = connection.execute(
            "UPDATE gateway_sessions
             SET access_token = ?1, refresh_token = ?2, user_id = ?3, amr_json = ?4,
                 access_expires_at = ?5, refresh_generation = refresh_generation + 1,
                 identity_state = 'pending', identity_pending_since = ?6,
                 session_expires_at = ?7, updated_at = ?6
             WHERE id = ?8 AND refresh_generation = ?9 AND refresh_token = ?10
               AND identity_state = ?11 AND revoked_at IS NULL
               AND idle_expires_at > ?6 AND absolute_expires_at > ?6",
            params![
                next.access_token,
                next.refresh_token,
                next.user_id,
                amr_json,
                format_time(next.access_expires_at),
                now_text,
                COMPAT_DENY_AT,
                original.id,
                original.refresh_generation,
                original.refresh_token,
                original.identity_state.as_str(),
            ],
        )?;
        self.resolve_cas(&original.id, now, changed)
    }

    pub fn finalize_pending(
        &self,
        pending: &GatewaySession,
        email: Option<&str>,
    ) -> rusqlite::Result<CasResult> {
        let connection = self.connection()?;
        let now = self.clock.now();
        let now_text = format_time(now);
        let changed = connection.execute(
            "UPDATE gateway_sessions
             SET email = ?1, identity_state = 'ready', identity_pending_since = NULL,
                 session_expires_at = idle_expires_at, updated_at = ?2
             WHERE id = ?3 AND refresh_generation = ?4 AND identity_state = 'pending'
               AND user_id = ?5 AND revoked_at IS NULL
               AND idle_expires_at > ?2 AND absolute_expires_at > ?2",
            params![
                email,
                now_text,
                pending.id,
                pending.refresh_generation,
                pending.user_id,
            ],
        )?;
        self.resolve_cas(&pending.id, now, changed)
    }

    pub fn touch_ready(
        &self,
        original: &GatewaySession,
        idle_ttl_seconds: i64,
        touch_interval_seconds: i64,
    ) -> rusqlite::Result<TouchResult> {
        let now = self.clock.now();
        if original.identity_state != IdentityState::Ready || !is_active(original, now) {
            return Ok(TouchResult::Lost);
        }
        if now.signed_duration_since(original.last_touched_at)
            < Duration::seconds(touch_interval_seconds)
        {
            return Ok(TouchResult::NotDue(original.clone()));
        }
        let candidate = std::cmp::min(
            now + Duration::seconds(idle_ttl_seconds),
            original.absolute_expires_at,
        );
        if candidate <= original.idle_expires_at {
            return Ok(TouchResult::NotDue(original.clone()));
        }

        let connection = self.connection()?;
        let now_text = format_time(now);
        let candidate_text = format_time(candidate);
        let changed = connection.execute(
            "UPDATE gateway_sessions
             SET idle_expires_at = ?1, session_expires_at = ?1,
                 last_touched_at = ?2, updated_at = ?2
             WHERE id = ?3 AND refresh_generation = ?4 AND identity_state = 'ready'
               AND revoked_at IS NULL AND idle_expires_at = ?5
               AND idle_expires_at > ?2 AND absolute_expires_at > ?2",
            params![
                candidate_text,
                now_text,
                original.id,
                original.refresh_generation,
                format_time(original.idle_expires_at),
            ],
        )?;
        if changed != 1 {
            return Ok(TouchResult::Lost);
        }
        match self.lookup_session_at(&original.id, now)? {
            SessionLookup::Active(session) => Ok(TouchResult::Advanced(session)),
            SessionLookup::Inactive => Ok(TouchResult::Lost),
        }
    }

    pub fn prune(&self) -> rusqlite::Result<()> {
        let connection = self.connection()?;
        let now = format_time(self.clock.now());
        connection.execute(
            "DELETE FROM login_states WHERE expires_at <= ?1 OR consumed_at IS NOT NULL",
            params![now],
        )?;
        connection.execute(
            "DELETE FROM gateway_sessions
             WHERE revoked_at IS NOT NULL OR idle_expires_at <= ?1 OR absolute_expires_at <= ?1",
            params![now],
        )?;
        Ok(())
    }

    fn resolve_cas(
        &self,
        id: &str,
        now: DateTime<Utc>,
        changed: usize,
    ) -> rusqlite::Result<CasResult> {
        match self.lookup_session_at(id, now)? {
            SessionLookup::Active(session) if changed == 1 => Ok(CasResult::Updated(session)),
            SessionLookup::Active(session) => Ok(CasResult::Current(session)),
            SessionLookup::Inactive => Ok(CasResult::Inactive),
        }
    }
}

fn migrate(connection: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(invalid_data("database schema is newer than this binary"));
    }

    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if version == 0 {
        tx.execute_batch(V1_SCHEMA)?;
    }
    if version < 2 {
        tx.execute_batch(
            r#"
            ALTER TABLE gateway_sessions ADD COLUMN idle_expires_at TEXT;
            ALTER TABLE gateway_sessions ADD COLUMN absolute_expires_at TEXT;
            ALTER TABLE gateway_sessions ADD COLUMN last_touched_at TEXT;
            ALTER TABLE gateway_sessions ADD COLUMN identity_state TEXT;
            ALTER TABLE gateway_sessions ADD COLUMN identity_pending_since TEXT;
            "#,
        )?;
        backfill_v1_rows(&tx)?;
    }
    repair_legacy_null_rows(&tx)?;
    tx.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_gateway_sessions_v2_expiry
            ON gateway_sessions(idle_expires_at, absolute_expires_at, revoked_at);
        PRAGMA user_version = 2;
        "#,
    )?;
    tx.commit()?;
    eprintln!("event=schema_migration from={version} to={SCHEMA_VERSION} outcome=ready");
    Ok(())
}

fn backfill_v1_rows(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let rows = {
        let mut statement = tx.prepare(
            "SELECT id, created_at, session_expires_at FROM gateway_sessions ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (id, created_raw, old_raw) in rows {
        let created = parse_db_time(&created_raw)?;
        let old = parse_db_time(&old_raw)?;
        let absolute = std::cmp::min(
            old,
            created
                .checked_add_signed(Duration::seconds(LEGACY_ABSOLUTE_TTL_SECONDS))
                .ok_or_else(|| invalid_data("legacy absolute deadline overflow"))?,
        );
        let idle = std::cmp::min(old, absolute);
        tx.execute(
            "UPDATE gateway_sessions
             SET idle_expires_at = ?1, absolute_expires_at = ?2, last_touched_at = ?3,
                 identity_state = 'ready', identity_pending_since = NULL,
                 session_expires_at = ?1
             WHERE id = ?4",
            params![
                format_time(idle),
                format_time(absolute),
                format_time(created),
                id,
            ],
        )?;
    }
    Ok(())
}

fn repair_legacy_null_rows(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let rows = {
        let mut statement = tx.prepare(
            "SELECT id, created_at, session_expires_at
             FROM gateway_sessions
             WHERE idle_expires_at IS NULL AND absolute_expires_at IS NULL
               AND last_touched_at IS NULL AND identity_state IS NULL
               AND identity_pending_since IS NULL
             ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (id, created_raw, old_raw) in rows {
        let created = parse_db_time(&created_raw)?;
        let old = parse_db_time(&old_raw)?;
        let absolute = std::cmp::min(
            old,
            created
                .checked_add_signed(Duration::seconds(LEGACY_ABSOLUTE_TTL_SECONDS))
                .ok_or_else(|| invalid_data("legacy absolute deadline overflow"))?,
        );
        let idle = std::cmp::min(old, absolute);
        tx.execute(
            "UPDATE gateway_sessions
             SET idle_expires_at = ?1, absolute_expires_at = ?2, last_touched_at = ?3,
                 identity_state = 'ready', session_expires_at = ?1
             WHERE id = ?4",
            params![
                format_time(idle),
                format_time(absolute),
                format_time(created),
                id,
            ],
        )?;
    }
    Ok(())
}

const V1_SCHEMA: &str = r#"
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
"#;

const SESSION_SELECT: &str =
    "SELECT id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
            access_expires_at, session_expires_at, idle_expires_at, absolute_expires_at,
            last_touched_at, identity_state, identity_pending_since, refresh_generation, revoked_at
     FROM gateway_sessions WHERE id = ?1 LIMIT 1";

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<GatewaySession> {
    let amr_json: String = row.get(6)?;
    let amr = serde_json::from_str(&amr_json).map_err(to_sql_failure)?;
    let state_raw: String = row.get(12)?;
    let identity_state = match state_raw.as_str() {
        "ready" => IdentityState::Ready,
        "pending" => IdentityState::Pending,
        _ => return Err(invalid_data("unknown identity state")),
    };
    let session = GatewaySession {
        id: row.get(0)?,
        auth_session_id: row.get(1)?,
        access_token: row.get(2)?,
        refresh_token: row.get(3)?,
        user_id: row.get(4)?,
        email: row.get(5)?,
        amr,
        access_expires_at: parse_db_time(&row.get::<_, String>(7)?)?,
        session_expires_at: parse_db_time(&row.get::<_, String>(8)?)?,
        idle_expires_at: parse_db_time(&row.get::<_, String>(9)?)?,
        absolute_expires_at: parse_db_time(&row.get::<_, String>(10)?)?,
        last_touched_at: parse_db_time(&row.get::<_, String>(11)?)?,
        identity_state,
        identity_pending_since: row
            .get::<_, Option<String>>(13)?
            .map(|value| parse_db_time(&value))
            .transpose()?,
        refresh_generation: row.get(14)?,
        revoked_at: row
            .get::<_, Option<String>>(15)?
            .map(|value| parse_db_time(&value))
            .transpose()?,
    };
    validate_session_invariants(&session)?;
    Ok(session)
}

fn validate_session_invariants(session: &GatewaySession) -> rusqlite::Result<()> {
    if session.idle_expires_at > session.absolute_expires_at || session.refresh_generation < 0 {
        return Err(invalid_data("invalid session deadline or generation"));
    }
    match session.identity_state {
        IdentityState::Ready
            if session.identity_pending_since.is_none()
                && session.session_expires_at == session.idle_expires_at =>
        {
            Ok(())
        }
        IdentityState::Pending
            if session.identity_pending_since.is_some()
                && format_time(session.session_expires_at) == COMPAT_DENY_AT =>
        {
            Ok(())
        }
        _ => Err(invalid_data("identity state compatibility gate mismatch")),
    }
}

fn is_active(session: &GatewaySession, now: DateTime<Utc>) -> bool {
    session.revoked_at.is_none()
        && now < session.idle_expires_at
        && now < session.absolute_expires_at
}

fn parse_db_time(value: &str) -> rusqlite::Result<DateTime<Utc>> {
    parse_time(value).map_err(to_sql_failure)
}

fn invalid_data(message: &'static str) -> rusqlite::Error {
    to_sql_failure(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn to_sql_failure(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::TimeZone;
    use tempfile::tempdir;

    use crate::util::ManualClock;

    use super::*;

    fn base_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 13, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (tempfile::TempDir, Store, ManualClock) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("gateway.sqlite");
        Store::initialize(&path).expect("database initializes");
        let clock = ManualClock::new(base_time());
        let store = Store::with_clock(path, Arc::new(clock.clone()));
        (dir, store, clock)
    }

    fn new_session() -> NewSession {
        NewSession {
            auth_session_id: "auth-session".to_string(),
            access_token: "test-access".to_string(),
            refresh_token: "test-refresh".to_string(),
            user_id: "user".to_string(),
            email: Some("allowed@example.com".to_string()),
            amr: vec!["test".to_string()],
            access_expires_at: base_time() + Duration::hours(2),
            idle_ttl_seconds: 7 * 24 * 60 * 60,
            absolute_ttl_seconds: 30 * 24 * 60 * 60,
        }
    }

    #[test]
    fn login_state_is_durable_one_time_and_uses_controlled_time() {
        let (_dir, store, clock) = setup();
        let state = store
            .create_login_state("/protected", 600)
            .expect("state creates");
        assert_eq!(state.expires_at, base_time() + Duration::minutes(10));
        clock.set(base_time() + Duration::minutes(9));
        assert!(store
            .consume_login_state(&state.id)
            .expect("consume")
            .is_some());
        assert!(store
            .consume_login_state(&state.id)
            .expect("second consume")
            .is_none());
    }

    #[test]
    fn exact_idle_and_absolute_boundaries_are_inactive() {
        let (_dir, store, clock) = setup();
        let session = store.create_session(new_session()).expect("session");
        clock.set(session.idle_expires_at - Duration::milliseconds(1));
        assert!(matches!(
            store.lookup_session(&session.id).expect("lookup"),
            SessionLookup::Active(_)
        ));
        clock.set(session.idle_expires_at);
        assert!(matches!(
            store.lookup_session(&session.id).expect("lookup"),
            SessionLookup::Inactive
        ));

        clock.set(base_time());
        let mut absolute_limited = new_session();
        absolute_limited.idle_ttl_seconds = 40 * 24 * 60 * 60;
        let absolute_limited = store
            .create_session(absolute_limited)
            .expect("absolute-limited session");
        assert_eq!(
            absolute_limited.idle_expires_at,
            absolute_limited.absolute_expires_at
        );
        clock.set(absolute_limited.absolute_expires_at - Duration::milliseconds(1));
        assert!(matches!(
            store.lookup_session(&absolute_limited.id).expect("lookup"),
            SessionLookup::Active(_)
        ));
        clock.set(absolute_limited.absolute_expires_at);
        assert!(matches!(
            store.lookup_session(&absolute_limited.id).expect("lookup"),
            SessionLookup::Inactive
        ));
    }

    #[test]
    fn touch_is_merged_at_exact_interval_and_capped_by_absolute() {
        let (_dir, store, clock) = setup();
        let session = store.create_session(new_session()).expect("session");
        clock.set(base_time() + Duration::milliseconds(3_599_999));
        assert!(matches!(
            store.touch_ready(&session, 604_800, 3_600).expect("touch"),
            TouchResult::NotDue(_)
        ));
        clock.set(base_time() + Duration::seconds(3_600));
        let advanced = match store.touch_ready(&session, 604_800, 3_600).expect("touch") {
            TouchResult::Advanced(session) => session,
            _ => panic!("touch should advance"),
        };
        assert_eq!(
            advanced.idle_expires_at,
            base_time() + Duration::days(7) + Duration::hours(1)
        );

        let connection = store.connection().expect("connection");
        connection
            .execute(
                "UPDATE gateway_sessions SET idle_expires_at = ?1, session_expires_at = ?1,
                 absolute_expires_at = ?2, last_touched_at = ?3 WHERE id = ?4",
                params![
                    format_time(base_time() + Duration::days(29) + Duration::hours(1)),
                    format_time(base_time() + Duration::days(30)),
                    format_time(base_time() + Duration::days(28)),
                    advanced.id,
                ],
            )
            .expect("fixture update");
        clock.set(base_time() + Duration::days(29));
        let current = match store.lookup_session(&advanced.id).expect("lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("active"),
        };
        let capped = match store.touch_ready(&current, 604_800, 3_600).expect("touch") {
            TouchResult::Advanced(session) => session,
            _ => panic!("touch should cap"),
        };
        assert_eq!(capped.idle_expires_at, capped.absolute_expires_at);
    }

    #[test]
    fn refresh_persists_pending_before_identity_and_logout_cannot_be_finalized() {
        let (_dir, store, _clock) = setup();
        let session = store.create_session(new_session()).expect("session");
        let pending = match store
            .persist_pending(
                &session,
                PendingTokens {
                    access_token: "next-access",
                    refresh_token: "next-refresh",
                    user_id: &session.user_id,
                    amr: &session.amr,
                    access_expires_at: base_time() + Duration::hours(3),
                },
            )
            .expect("persist pending")
        {
            CasResult::Updated(session) => session,
            _ => panic!("pending update"),
        };
        assert_eq!(pending.identity_state, IdentityState::Pending);
        assert_eq!(format_time(pending.session_expires_at), COMPAT_DENY_AT);
        store.revoke_session(&pending.id).expect("revoke");
        assert!(matches!(
            store
                .finalize_pending(&pending, Some("new@example.com"))
                .expect("finalize"),
            CasResult::Inactive
        ));
    }

    #[test]
    fn authoritative_prune_does_not_delete_pending_for_compatibility_epoch() {
        let (_dir, store, _clock) = setup();
        let session = store.create_session(new_session()).expect("session");
        let pending = match store
            .persist_pending(
                &session,
                PendingTokens {
                    access_token: "next-access",
                    refresh_token: "next-refresh",
                    user_id: &session.user_id,
                    amr: &session.amr,
                    access_expires_at: base_time() + Duration::hours(3),
                },
            )
            .expect("persist pending")
        {
            CasResult::Updated(session) => session,
            _ => panic!("pending update"),
        };
        store.prune().expect("prune");
        assert!(matches!(
            store.lookup_session(&pending.id).expect("lookup"),
            SessionLookup::Active(session) if session.identity_state == IdentityState::Pending
        ));
    }

    #[test]
    fn pending_expiry_cannot_be_finalized_or_resurrected() {
        let (_dir, store, clock) = setup();
        let session = store.create_session(new_session()).expect("session");
        let pending = match store
            .persist_pending(
                &session,
                PendingTokens {
                    access_token: "next-access",
                    refresh_token: "next-refresh",
                    user_id: &session.user_id,
                    amr: &session.amr,
                    access_expires_at: base_time() + Duration::hours(3),
                },
            )
            .expect("persist pending")
        {
            CasResult::Updated(session) => session,
            _ => panic!("pending update"),
        };
        clock.set(pending.idle_expires_at);
        assert!(matches!(
            store
                .finalize_pending(&pending, Some("fresh@example.com"))
                .expect("finalize"),
            CasResult::Inactive
        ));
        assert!(matches!(
            store.lookup_session(&pending.id).expect("lookup"),
            SessionLookup::Inactive
        ));
    }

    #[test]
    fn migration_is_additive_and_never_extends_legacy_deadline() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("v1.sqlite");
        let connection = Connection::open(&path).expect("open");
        connection.execute_batch(V1_SCHEMA).expect("v1 schema");
        connection
            .execute(
                "INSERT INTO gateway_sessions
                 (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
                  access_expires_at, session_expires_at, created_at, updated_at)
                 VALUES ('legacy', 'sid', 'access', 'refresh', 'user', NULL, '[]', ?1, ?2, ?3, ?3)",
                params![
                    format_time(base_time() + Duration::hours(1)),
                    format_time(base_time() + Duration::hours(8)),
                    format_time(base_time()),
                ],
            )
            .expect("legacy row");
        connection
            .execute_batch("PRAGMA user_version = 1;")
            .expect("v1");
        drop(connection);

        Store::initialize(&path).expect("migrate");
        let store = Store::with_clock(path, Arc::new(ManualClock::new(base_time())));
        let session = match store.lookup_session("legacy").expect("lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("legacy active"),
        };
        let old = base_time() + Duration::hours(8);
        assert!(session.idle_expires_at <= session.absolute_expires_at);
        assert!(session.absolute_expires_at <= old);
        assert_eq!(session.session_expires_at, session.idle_expires_at);
    }

    #[test]
    fn legacy_all_null_v2_row_is_repaired_without_extension() {
        let (dir, _store, _clock) = setup();
        let path = dir.path().join("gateway.sqlite");
        let connection = Connection::open(&path).expect("open");
        connection
            .execute(
                "INSERT INTO gateway_sessions
                 (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
                  access_expires_at, session_expires_at, created_at, updated_at)
                 VALUES ('old-write', 'sid', 'access', 'refresh', 'user', NULL, '[]', ?1, ?2, ?3, ?3)",
                params![
                    format_time(base_time() + Duration::hours(1)),
                    format_time(base_time() + Duration::hours(8)),
                    format_time(base_time()),
                ],
            )
            .expect("old insert");
        drop(connection);
        Store::initialize(&path).expect("repair");
        let store = Store::with_clock(path, Arc::new(ManualClock::new(base_time())));
        let repaired = match store.lookup_session("old-write").expect("lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("repaired active"),
        };
        assert_eq!(repaired.identity_state, IdentityState::Ready);
        assert!(repaired.absolute_expires_at <= base_time() + Duration::hours(8));
    }

    #[test]
    fn future_schema_version_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("future.sqlite");
        let connection = Connection::open(&path).expect("open");
        connection
            .execute_batch("PRAGMA user_version = 3;")
            .expect("future version");
        drop(connection);
        assert!(Store::initialize(&path).is_err());
    }

    #[test]
    fn malformed_v1_timestamp_rolls_back_entire_migration() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("invalid.sqlite");
        let connection = Connection::open(&path).expect("open");
        connection.execute_batch(V1_SCHEMA).expect("v1 schema");
        connection
            .execute(
                "INSERT INTO gateway_sessions
                 (id, auth_session_id, access_token, refresh_token, user_id, amr_json,
                  access_expires_at, session_expires_at, created_at, updated_at)
                 VALUES ('bad', 'sid', 'access', 'refresh', 'user', '[]', 'bad', 'bad', 'bad', 'bad')",
                [],
            )
            .expect("fixture");
        connection
            .execute_batch("PRAGMA user_version = 1;")
            .expect("v1");
        drop(connection);
        assert!(Store::initialize(&path).is_err());
        let connection = Connection::open(&path).expect("reopen");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, 1);
        let has_v2_column = connection
            .prepare("SELECT idle_expires_at FROM gateway_sessions")
            .is_ok();
        assert!(!has_v2_column);
    }
}
