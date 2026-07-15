#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Pin the actual pre-lifecycle binary. Using a moving origin/master stops being
# an old-binary test as soon as the lifecycle change is merged.
BASE_REF=${OLD_GATEWAY_REF:-f0519d1}
TMP_DIR=$(mktemp -d)
CURRENT_PID=""
OLD_PID=""

cleanup() {
  set +e
  for pid in "$CURRENT_PID" "$OLD_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1
      wait "$pid" >/dev/null 2>&1
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_gateway() {
  local port=$1
  for _ in $(seq 1 80); do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz" || true)" == "204" ]]; then
      return 0
    fi
    sleep 0.1
  done
  printf 'gateway did not become ready\n' >&2
  return 1
}

stop_pid() {
  local name=$1
  local pid=${!name}
  if [[ -n "$pid" ]]; then
    kill "$pid"
    wait "$pid" >/dev/null 2>&1 || true
    printf -v "$name" '%s' ""
  fi
}

command -v git >/dev/null
command -v cargo >/dev/null
command -v curl >/dev/null
command -v python3 >/dev/null

mkdir "$TMP_DIR/old-source"
git -C "$ROOT_DIR" archive "$BASE_REF" | tar -x -C "$TMP_DIR/old-source"
mkdir -p "$TMP_DIR/old-source/src/bin"
cat >"$TMP_DIR/old-source/src/bin/insert-legacy-row.rs" <<'RS'
use std::path::PathBuf;

use auth_mini_gateway::db::{NewSession, Store};
use chrono::{Duration, SecondsFormat, Utc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args().nth(1).ok_or("missing database path")?);
    let store = Store::new(path);
    store.create_session(NewSession {
        auth_session_id: "legacy-null-sid".to_string(),
        access_token: "legacy-null-access".to_string(),
        refresh_token: "legacy-null-refresh".to_string(),
        user_id: "compat-user".to_string(),
        email: None,
        amr: vec!["fixture".to_string()],
        access_expires_at: (Utc::now() + Duration::hours(1))
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        session_ttl_seconds: 2 * 60 * 60,
    })?;
    Ok(())
}
RS
cargo build --quiet --manifest-path "$ROOT_DIR/Cargo.toml" --bin auth-mini-gateway
cargo build --quiet --manifest-path "$TMP_DIR/old-source/Cargo.toml" --bin auth-mini-gateway --bin insert-legacy-row

CURRENT_BIN="$ROOT_DIR/target/debug/auth-mini-gateway"
OLD_BIN="$TMP_DIR/old-source/target/debug/auth-mini-gateway"
DB="$TMP_DIR/compat.sqlite"
SECRET='compat-test-cookie-secret-at-least-32-chars'
CURRENT_PORT=$(free_port)
OLD_PORT=$(free_port)

env HOST=127.0.0.1 PORT="$CURRENT_PORT" \
  GATEWAY_PUBLIC_BASE_URL="http://127.0.0.1:$CURRENT_PORT" \
  AUTH_MINI_ISSUER=http://127.0.0.1:9 \
  GATEWAY_DB="$DB" GATEWAY_COOKIE_SECRET="$SECRET" COOKIE_SECURE=false \
  ALLOW_USER_IDS=compat-user \
  "$CURRENT_BIN" >"$TMP_DIR/current.log" 2>&1 &
CURRENT_PID=$!
wait_gateway "$CURRENT_PORT"
stop_pid CURRENT_PID

# Use the actual pre-change Store implementation and INSERT statement against
# user_version=2. The additive v2 columns must therefore be NULL until the new
# binary's startup repair runs.
"$TMP_DIR/old-source/target/debug/insert-legacy-row" "$DB"

python3 - "$DB" "$SECRET" "$TMP_DIR/cookies.env" <<'PY'
import base64, datetime, hashlib, hmac, sqlite3, sys

db, secret, output = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc)
fmt = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
future = fmt(now + datetime.timedelta(hours=2))
created = fmt(now)
past = "1970-01-01T00:00:00.000Z"
connection = sqlite3.connect(db)
try:
    common = ("sid", "fixture-access", "fixture-refresh", "compat-user", None, "[]", future)
    connection.execute(
        """INSERT INTO gateway_sessions
        (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
         access_expires_at, session_expires_at, refresh_generation, created_at, updated_at,
         idle_expires_at, absolute_expires_at, last_touched_at, identity_state, identity_pending_since)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 'ready', NULL)""",
        ("ready", *common, future, created, created, future, future, created),
    )
    for session_id in ("pending-logout", "pending-prune"):
        connection.execute(
            """INSERT INTO gateway_sessions
            (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
             access_expires_at, session_expires_at, refresh_generation, created_at, updated_at,
             idle_expires_at, absolute_expires_at, last_touched_at, identity_state, identity_pending_since)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 'pending', ?)""",
            (session_id, *common, past, created, created, future, future, created, created),
        )
    legacy_id = connection.execute(
        "SELECT id FROM gateway_sessions WHERE auth_session_id='legacy-null-sid'"
    ).fetchone()[0]
    connection.commit()
finally:
    connection.close()

def signed(value):
    digest = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"amg_session={value}.{signature}"

with open(output, "w", encoding="utf-8") as handle:
    handle.write("READY='" + signed("ready") + "'\n")
    handle.write("PENDING_LOGOUT='" + signed("pending-logout") + "'\n")
    handle.write("LEGACY_NULL='" + signed(legacy_id) + "'\n")
PY
# The generated values are fixed test-fixture cookies and are never printed.
source "$TMP_DIR/cookies.env"

env HOST=127.0.0.1 PORT="$OLD_PORT" \
  GATEWAY_PUBLIC_BASE_URL="http://127.0.0.1:$OLD_PORT" \
  AUTH_MINI_ISSUER=http://127.0.0.1:9 \
  GATEWAY_DB="$DB" GATEWAY_COOKIE_SECRET="$SECRET" COOKIE_SECURE=false \
  SESSION_TTL_SECONDS=28800 LOGIN_STATE_TTL_SECONDS=300 \
  ALLOW_USER_IDS=compat-user \
  "$OLD_BIN" >"$TMP_DIR/old.log" 2>&1 &
OLD_PID=$!
wait_gateway "$OLD_PORT"

ready_status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $READY" "http://127.0.0.1:$OLD_PORT/auth/check")
pending_status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $PENDING_LOGOUT" "http://127.0.0.1:$OLD_PORT/auth/check")
legacy_null_status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $LEGACY_NULL" "http://127.0.0.1:$OLD_PORT/auth/check")
if [[ "$ready_status" != "204" || "$pending_status" != "401" || "$legacy_null_status" != "204" ]]; then
  printf 'old-binary compatibility read gate failed\n' >&2
  exit 1
fi

curl -sS -o /dev/null -H "Cookie: $PENDING_LOGOUT" "http://127.0.0.1:$OLD_PORT/logout"
python3 - "$DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    row = connection.execute(
        "SELECT revoked_at IS NOT NULL FROM gateway_sessions WHERE id='pending-logout'"
    ).fetchone()
    if row is None or not row[0]:
        raise SystemExit("old binary did not durably revoke Pending")
finally:
    connection.close()
PY
# Creating an old login state invokes the old authoritative prune, which may
# delete Pending through its deliberately past compatibility deadline.
curl -sS -o /dev/null "http://127.0.0.1:$OLD_PORT/login?return_to=%2F"
stop_pid OLD_PID

python3 - "$DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    pruned = connection.execute(
        "SELECT COUNT(*) FROM gateway_sessions WHERE id='pending-prune'"
    ).fetchone()[0]
    if pruned != 0:
        raise SystemExit("old binary did not fail-closed prune Pending")
finally:
    connection.close()
PY

# Starting the new binary again proves the additive schema remains readable
# and no old-binary logout/prune is resurrected.
env HOST=127.0.0.1 PORT="$CURRENT_PORT" \
  GATEWAY_PUBLIC_BASE_URL="http://127.0.0.1:$CURRENT_PORT" \
  AUTH_MINI_ISSUER=http://127.0.0.1:9 \
  GATEWAY_DB="$DB" GATEWAY_COOKIE_SECRET="$SECRET" COOKIE_SECURE=false \
  ALLOW_USER_IDS=compat-user \
  "$CURRENT_BIN" >"$TMP_DIR/current-restart.log" 2>&1 &
CURRENT_PID=$!
wait_gateway "$CURRENT_PORT"

python3 - "$DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    row = connection.execute(
        """SELECT session_expires_at, idle_expires_at, absolute_expires_at,
                  last_touched_at, identity_state, identity_pending_since
           FROM gateway_sessions WHERE auth_session_id='legacy-null-sid'"""
    ).fetchone()
    if row is None or any(value is None for value in row[:5]):
        raise SystemExit("new binary did not repair actual old-binary NULL row")
    if row[0] != row[1] or row[4] != "ready" or row[5] is not None or row[2] > row[0]:
        raise SystemExit("old-binary NULL repair violated compatibility invariants")
finally:
    connection.close()
PY

printf 'Old-binary compatibility E2E passed: Ready/NULL read, Pending deny/logout/prune, NULL repair, safe re-upgrade.\n'
