//! Deterministic schema-v2 Ready session materialization for black-box gateways.

use crate::linux::{clock_ns, utc_rfc3339, ClockKind};
use crate::seal::sha256_hex;
use crate::{Error, Result, ResultContext};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};

pub const SESSION_SCHEMA: &str = "amg-http2-perf/ready-session/v1";
pub const SESSION_ID: &str = "bench-session-000000000000000000000001";
pub const USER_ID: &str = "bench-user";
pub const USER_EMAIL: &str = "bench-user@example.invalid";
pub const AUTH_SESSION_ID: &str = "bench-auth-session";
pub const COOKIE_SECRET: &str = "amg-benchmark-synthetic-cookie-secret-v1-fixed";
pub const ACCESS_TOKEN: &str = "amg-benchmark-synthetic-access-token-v1";
pub const REFRESH_TOKEN: &str = "amg-benchmark-synthetic-refresh-token-v1";
pub const SESSION_TTL_SECONDS: u64 = 604_800;
pub const ABSOLUTE_TTL_SECONDS: u64 = 2_592_000;
pub const TOUCH_INTERVAL_SECONDS: u64 = 604_800;
pub const REFRESH_SKEW_SECONDS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadySessionEvidence {
    pub schema: String,
    pub sqlite_user_version: u32,
    pub journal_mode: String,
    pub database_sha256: String,
    pub session_id_sha256: String,
    pub cookie_value_sha256: String,
    pub cookie_secret_sha256: String,
    pub access_token_sha256: String,
    pub refresh_token_sha256: String,
    pub user_id: String,
    pub email: String,
    pub identity_state: String,
    pub created_at: String,
    pub access_expires_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub last_touched_at: String,
    pub session_ttl_seconds: u64,
    pub absolute_ttl_seconds: u64,
    pub touch_interval_seconds: u64,
    #[serde(
        default = "default_refresh_skew_seconds",
        skip_serializing_if = "is_default_refresh_skew_seconds"
    )]
    pub refresh_skew_seconds: u64,
    pub predicates: ReadyPredicates,
}

const fn default_refresh_skew_seconds() -> u64 {
    REFRESH_SKEW_SECONDS
}

const fn is_default_refresh_skew_seconds(value: &u64) -> bool {
    *value == REFRESH_SKEW_SECONDS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyPredicates {
    pub ready: bool,
    pub active: bool,
    pub access_refresh_due: bool,
    pub touch_due: bool,
}

/// Secret-bearing runtime values. This type intentionally cannot be serialized.
#[derive(Debug, Clone)]
pub struct ReadySessionRuntime {
    pub database_path: PathBuf,
    pub cookie_value: String,
    pub cookie_header: String,
    pub evidence: ReadySessionEvidence,
}

pub fn create_ready_session(path: &Path) -> Result<ReadySessionRuntime> {
    let realtime_ns = clock_ns(ClockKind::Realtime)?;
    create_ready_session_at(path, realtime_ns / 1_000_000_000)
}

pub fn create_ready_session_at(path: &Path, unix_seconds: u64) -> Result<ReadySessionRuntime> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::new(format!(
            "session database path already exists: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("database path has no parent"))?;
    fs::create_dir_all(parent)?;
    set_mode(parent, 0o700)?;
    let created_at = utc_rfc3339(unix_seconds)?;
    let access_expires_at = utc_rfc3339(
        unix_seconds
            .checked_add(SESSION_TTL_SECONDS)
            .ok_or_else(|| Error::new("access deadline overflow"))?,
    )?;
    let idle_expires_at = access_expires_at.clone();
    let absolute_expires_at = utc_rfc3339(
        unix_seconds
            .checked_add(ABSOLUTE_TTL_SECONDS)
            .ok_or_else(|| Error::new("absolute deadline overflow"))?,
    )?;
    {
        let connection = Connection::open(path).context("create Ready-session SQLite database")?;
        set_mode(path, 0o600)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .context("enable Ready-session WAL")?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(Error::new("SQLite did not enter WAL mode"));
        }
        connection
            .execute_batch(SCHEMA_V2)
            .context("create schema-v2 database")?;
        connection
            .execute(
                "INSERT INTO gateway_sessions
                 (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
                  access_expires_at, session_expires_at, revoked_at, refresh_generation,
                  created_at, updated_at, idle_expires_at, absolute_expires_at, last_touched_at,
                  identity_state, identity_pending_since)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, '[\"benchmark\"]', ?7, ?8, NULL, 0,
                         ?9, ?9, ?8, ?10, ?9, 'ready', NULL)",
                params![
                    SESSION_ID,
                    AUTH_SESSION_ID,
                    ACCESS_TOKEN,
                    REFRESH_TOKEN,
                    USER_ID,
                    USER_EMAIL,
                    access_expires_at,
                    idle_expires_at,
                    created_at,
                    absolute_expires_at,
                ],
            )
            .context("insert deterministic Ready session")?;
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("read SQLite user_version")?;
        if version != 2 {
            return Err(Error::new("Ready-session database is not schema v2"));
        }
        let state: String = connection
            .query_row(
                "SELECT identity_state FROM gateway_sessions WHERE id=?1",
                [SESSION_ID],
                |row| row.get(0),
            )
            .context("verify Ready session")?;
        if state != "ready" {
            return Err(Error::new("Ready-session identity_state is not ready"));
        }
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("checkpoint deterministic Ready-session database")?;
    }
    set_runtime_file_modes(parent)?;
    let cookie_value = sign_cookie_value(SESSION_ID, COOKIE_SECRET)?;
    let database_sha256 = sha256_hex(&fs::read(path)?);
    let mut evidence = ReadySessionEvidence {
        schema: SESSION_SCHEMA.to_owned(),
        sqlite_user_version: 2,
        journal_mode: "wal".to_owned(),
        database_sha256,
        session_id_sha256: sha256_hex(SESSION_ID.as_bytes()),
        cookie_value_sha256: sha256_hex(cookie_value.as_bytes()),
        cookie_secret_sha256: sha256_hex(COOKIE_SECRET.as_bytes()),
        access_token_sha256: sha256_hex(ACCESS_TOKEN.as_bytes()),
        refresh_token_sha256: sha256_hex(REFRESH_TOKEN.as_bytes()),
        user_id: USER_ID.to_owned(),
        email: USER_EMAIL.to_owned(),
        identity_state: "ready".to_owned(),
        created_at: created_at.clone(),
        access_expires_at: access_expires_at.clone(),
        idle_expires_at: idle_expires_at.clone(),
        absolute_expires_at,
        last_touched_at: created_at,
        session_ttl_seconds: SESSION_TTL_SECONDS,
        absolute_ttl_seconds: ABSOLUTE_TTL_SECONDS,
        touch_interval_seconds: TOUCH_INTERVAL_SECONDS,
        refresh_skew_seconds: REFRESH_SKEW_SECONDS,
        predicates: ReadyPredicates {
            ready: false,
            active: false,
            access_refresh_due: true,
            touch_due: true,
        },
    };
    evidence.predicates = ready_predicates_at(&evidence, unix_seconds * 1_000_000_000)?;
    Ok(ReadySessionRuntime {
        database_path: path.to_owned(),
        cookie_header: format!("amg_session={cookie_value}"),
        cookie_value,
        evidence,
    })
}

pub fn ready_predicates_at(
    evidence: &ReadySessionEvidence,
    realtime_ns: u64,
) -> Result<ReadyPredicates> {
    let now = realtime_ns / 1_000_000_000;
    let access_expires = parse_utc_rfc3339_seconds(&evidence.access_expires_at)?;
    let idle_expires = parse_utc_rfc3339_seconds(&evidence.idle_expires_at)?;
    let absolute_expires = parse_utc_rfc3339_seconds(&evidence.absolute_expires_at)?;
    let last_touched = parse_utc_rfc3339_seconds(&evidence.last_touched_at)?;
    let refresh_boundary = now
        .checked_add(evidence.refresh_skew_seconds)
        .ok_or_else(|| Error::new("refresh boundary overflow"))?;
    let touch_elapsed = now.saturating_sub(last_touched);
    let touch_candidate = now
        .checked_add(evidence.session_ttl_seconds)
        .ok_or_else(|| Error::new("touch candidate overflow"))?
        .min(absolute_expires);
    Ok(ReadyPredicates {
        ready: evidence.identity_state == "ready",
        active: now < idle_expires && now < absolute_expires,
        access_refresh_due: access_expires <= refresh_boundary,
        touch_due: touch_elapsed >= evidence.touch_interval_seconds
            && touch_candidate > idle_expires,
    })
}

fn parse_utc_rfc3339_seconds(value: &str) -> Result<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || &bytes[19..24] != b".000Z"
    {
        return Err(Error::new(
            "session UTC field is not exact RFC3339 milliseconds",
        ));
    }
    let parse = |range: std::ops::Range<usize>| -> Result<i64> {
        std::str::from_utf8(&bytes[range])
            .map_err(|_| Error::new("session UTC field is not ASCII"))?
            .parse::<i64>()
            .map_err(|_| Error::new("session UTC field contains a non-decimal component"))
    };
    let year = parse(0..4)?;
    let month = parse(5..7)?;
    let day = parse(8..10)?;
    let hour = parse(11..13)?;
    let minute = parse(14..16)?;
    let second = parse(17..19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(Error::new(
            "session UTC field has an out-of-range component",
        ));
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let unix_days = era * 146_097 + day_of_era - 719_468;
    if unix_days < 0 {
        return Err(Error::new("session UTC field predates the Unix epoch"));
    }
    u64::try_from(unix_days)
        .ok()
        .and_then(|days| days.checked_mul(86_400))
        .and_then(|base| base.checked_add(u64::try_from(hour * 3_600 + minute * 60 + second).ok()?))
        .ok_or_else(|| Error::new("session UTC field overflows Unix seconds"))
}

pub fn sign_cookie_value(value: &str, secret: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::new("HMAC rejected synthetic cookie key"))?;
    mac.update(value.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{value}.{signature}"))
}

pub fn verify_cookie_value(signed: &str, secret: &str) -> Result<String> {
    let (value, signature) = signed
        .rsplit_once('.')
        .ok_or_else(|| Error::new("signed cookie has no separator"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error::new("signed cookie has invalid base64"))?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::new("HMAC rejected synthetic cookie key"))?;
    mac.update(value.as_bytes());
    mac.verify_slice(&decoded)
        .map_err(|_| Error::new("signed cookie HMAC mismatch"))?;
    Ok(value.to_owned())
}

fn set_runtime_file_modes(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_file() {
            set_mode(&entry.path(), 0o600)?;
        } else if metadata.is_dir() {
            set_mode(&entry.path(), 0o700)?;
        } else {
            return Err(Error::new(
                "session runtime namespace contains a link or device",
            ));
        }
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(Error::new("benchmark requires Unix file permissions"))
    }
}

const SCHEMA_V2: &str = r#"
CREATE TABLE gateway_sessions (
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
    updated_at TEXT NOT NULL,
    idle_expires_at TEXT,
    absolute_expires_at TEXT,
    last_touched_at TEXT,
    identity_state TEXT,
    identity_pending_since TEXT
);
CREATE INDEX idx_gateway_sessions_expiry
    ON gateway_sessions(session_expires_at, revoked_at);
CREATE INDEX idx_gateway_sessions_v2_expiry
    ON gateway_sessions(idle_expires_at, absolute_expires_at, revoked_at);
CREATE TABLE login_states (
    id TEXT PRIMARY KEY,
    return_to TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_login_states_expiry ON login_states(expires_at, consumed_at);
PRAGMA user_version = 2;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-scratch")
            .join(format!("session-{name}-{nonce}"));
        fs::create_dir_all(&root).expect("scratch");
        root.join("gateway.sqlite")
    }

    #[test]
    fn cookie_signing_matches_production_contract() {
        let signed =
            sign_cookie_value("session-1", "test-cookie-secret-that-is-long-enough").expect("sign");
        assert!(signed.starts_with("session-1."));
        assert_eq!(
            verify_cookie_value(&signed, "test-cookie-secret-that-is-long-enough").expect("verify"),
            "session-1"
        );
        assert!(verify_cookie_value(&signed, "different-secret-that-is-long-enough").is_err());
    }

    #[test]
    fn creates_exact_schema_v2_ready_row_and_secret_free_evidence() {
        let path = test_path("ready");
        let runtime = create_ready_session_at(&path, 1_774_051_200).expect("session");
        let connection = Connection::open(&path).expect("database");
        let row: (String, String, String, String) = connection
            .query_row(
                "SELECT identity_state,user_id,access_token,refresh_token FROM gateway_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("row");
        assert_eq!(row.0, "ready");
        assert_eq!(row.1, USER_ID);
        assert_eq!(row.2, ACCESS_TOKEN);
        assert_eq!(row.3, REFRESH_TOKEN);
        assert_eq!(
            verify_cookie_value(&runtime.cookie_value, COOKIE_SECRET).unwrap(),
            SESSION_ID
        );
        let evidence = json::canonical_bytes(&runtime.evidence).expect("evidence");
        for secret in [
            COOKIE_SECRET,
            ACCESS_TOKEN,
            REFRESH_TOKEN,
            &runtime.cookie_value,
        ] {
            assert!(!evidence
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
        }
        fs::remove_dir_all(path.parent().unwrap()).expect("cleanup");
    }
}
