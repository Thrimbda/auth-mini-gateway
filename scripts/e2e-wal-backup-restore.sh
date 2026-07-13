#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
GATEWAY_PID=""
SECRET='wal-drill-cookie-secret-at-least-32-characters'

cleanup() {
  set +e
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID" >/dev/null 2>&1
    wait "$GATEWAY_PID" >/dev/null 2>&1
  fi
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
  printf 'gateway did not become ready during WAL drill\n' >&2
  return 1
}

start_gateway() {
  local database=$1
  local port=$2
  env HOST=127.0.0.1 PORT="$port" \
    GATEWAY_PUBLIC_BASE_URL="http://127.0.0.1:$port" \
    AUTH_MINI_ISSUER=http://127.0.0.1:9 \
    GATEWAY_DB="$database" GATEWAY_COOKIE_SECRET="$SECRET" COOKIE_SECURE=false \
    ALLOW_USER_IDS=backup-user \
    "$ROOT_DIR/target/debug/auth-mini-gateway" >"$TMP_DIR/gateway.log" 2>&1 &
  GATEWAY_PID=$!
  wait_gateway "$port"
}

stop_gateway() {
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID"
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
    GATEWAY_PID=""
  fi
}

command -v cargo >/dev/null
command -v curl >/dev/null
command -v python3 >/dev/null

cargo build --quiet --manifest-path "$ROOT_DIR/Cargo.toml" --bin auth-mini-gateway

SOURCE_DB="$TMP_DIR/source.sqlite"
BACKUP_DB="$TMP_DIR/backup.sqlite"
RESTORED_DB="$TMP_DIR/restored.sqlite"
PORT=$(free_port)

# Let the real binary create/migrate the source database before the drill.
start_gateway "$SOURCE_DB" "$PORT"
stop_gateway

python3 - "$SOURCE_DB" "$BACKUP_DB" "$RESTORED_DB" "$SECRET" "$TMP_DIR/cookie.env" <<'PY'
import base64, datetime, hashlib, hmac, os, sqlite3, sys

source_path, backup_path, restored_path, secret, cookie_path = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc)
fmt = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
created = fmt(now)
future = fmt(now + datetime.timedelta(hours=2))

# Hold an older read snapshot so the committed fixture remains in WAL frames
# while sqlite3_backup obtains a transactionally consistent latest snapshot.
reader = sqlite3.connect(source_path)
writer = sqlite3.connect(source_path)
try:
    writer.execute("PRAGMA wal_autocheckpoint=0")
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM gateway_sessions").fetchone()
    writer.execute(
        """INSERT INTO gateway_sessions
        (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
         access_expires_at, session_expires_at, revoked_at, refresh_generation,
         created_at, updated_at, idle_expires_at, absolute_expires_at,
         last_touched_at, identity_state, identity_pending_since)
        VALUES ('backup-ready', 'backup-sid', 'fixture-access', 'fixture-refresh',
                'backup-user', NULL, '[]', ?, ?, NULL, 0, ?, ?, ?, ?, ?, 'ready', NULL)""",
        (future, future, created, created, future, future, created),
    )
    writer.commit()
    wal_path = source_path + "-wal"
    if not os.path.exists(wal_path) or os.path.getsize(wal_path) == 0:
        raise SystemExit("fixture was not durably represented in WAL")
    backup = sqlite3.connect(backup_path)
    try:
        writer.backup(backup)
    finally:
        backup.close()
    reader.rollback()

    # Changes after the backup must not appear after restore.
    writer.execute("UPDATE gateway_sessions SET email='post-backup@example.invalid' WHERE id='backup-ready'")
    writer.execute(
        """INSERT INTO gateway_sessions
        (id, auth_session_id, access_token, refresh_token, user_id, email, amr_json,
         access_expires_at, session_expires_at, revoked_at, refresh_generation,
         created_at, updated_at, idle_expires_at, absolute_expires_at,
         last_touched_at, identity_state, identity_pending_since)
        SELECT 'post-backup', auth_session_id, access_token, refresh_token, user_id,
               email, amr_json, access_expires_at, session_expires_at, revoked_at,
               refresh_generation, created_at, updated_at, idle_expires_at,
               absolute_expires_at, last_touched_at, identity_state,
               identity_pending_since
        FROM gateway_sessions WHERE id='backup-ready'"""
    )
    writer.commit()
finally:
    reader.close()
    writer.close()

backup = sqlite3.connect(backup_path)
restored = sqlite3.connect(restored_path)
try:
    backup.backup(restored)
    if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("restored database integrity check failed")
    if restored.execute("PRAGMA user_version").fetchone()[0] != 2:
        raise SystemExit("restored database schema version changed")
    row = restored.execute(
        """SELECT user_id, email, identity_state, session_expires_at=idle_expires_at,
                  revoked_at IS NULL
           FROM gateway_sessions WHERE id='backup-ready'"""
    ).fetchone()
    if row != ("backup-user", None, "ready", 1, 1):
        raise SystemExit("restored Ready fixture does not match backup snapshot")
    if restored.execute("SELECT COUNT(*) FROM gateway_sessions WHERE id='post-backup'").fetchone()[0] != 0:
        raise SystemExit("post-backup mutation appeared in restored database")
finally:
    backup.close()
    restored.close()

digest = hmac.new(secret.encode(), b"backup-ready", hashlib.sha256).digest()
signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
with open(cookie_path, "w", encoding="utf-8") as handle:
    handle.write("COOKIE='amg_session=backup-ready." + signature + "'\n")
PY

# The restored snapshot must be directly usable by the real binary. The
# generated value is a fixed local fixture cookie and is never printed.
source "$TMP_DIR/cookie.env"
start_gateway "$RESTORED_DB" "$PORT"
status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $COOKIE" "http://127.0.0.1:$PORT/auth/check")
if [[ "$status" != "204" ]]; then
  printf 'restored WAL snapshot did not authorize its Ready fixture\n' >&2
  exit 1
fi

printf 'WAL-consistent backup/restore drill passed.\n'
