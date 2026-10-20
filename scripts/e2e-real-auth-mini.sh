#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AUTH_MINI_RUST_DIR=${AUTH_MINI_RUST_DIR:-/tmp/opencode/auth-mini-official-20261005/rust-backend}
AUTH_MINI_EXPECTED_COMMIT=${AUTH_MINI_EXPECTED_COMMIT:-156484e69d00487151a283edf96930fac9bc9cae}
# Optional prebuilt auth-mini server (for example the release binary that will
# be deployed). The pinned checkout is still required for the commit check.
AUTH_MINI_BIN=${AUTH_MINI_BIN:-}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}

ALLOWED_USER_ID="11111111-1111-4111-8111-111111111111"
DENIED_USER_ID="22222222-2222-4222-8222-222222222222"
WRONG_AUDIENCE="status.example"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

need cargo
need curl
need git
need python3

if [[ ! -f "$AUTH_MINI_RUST_DIR/Cargo.toml" ]]; then
  printf 'AUTH_MINI_RUST_DIR must point to auth-mini rust-backend; got %s\n' "$AUTH_MINI_RUST_DIR" >&2
  exit 1
fi

AUTH_MINI_ACTUAL_COMMIT=$(git -C "$AUTH_MINI_RUST_DIR" rev-parse HEAD)
if [[ "$AUTH_MINI_ACTUAL_COMMIT" != "$AUTH_MINI_EXPECTED_COMMIT" ]]; then
  printf 'auth-mini commit mismatch: expected %s, got %s\n' "$AUTH_MINI_EXPECTED_COMMIT" "$AUTH_MINI_ACTUAL_COMMIT" >&2
  exit 1
fi

if ! command -v nginx >/dev/null 2>&1; then
  need docker
fi

mkdir -p "$ROOT_DIR/target"
TMP_DIR=$(mktemp -d "$ROOT_DIR/target/e2e-real-auth-mini.XXXXXX")
AUTH_PID=""
GATEWAY_PID=""
UPSTREAM_PID=""
NGINX_CONTAINER="amg-e2e-nginx-$$"
NGINX_MODE=""

cleanup() {
  set +e
  if [[ -n "$NGINX_MODE" && "$NGINX_MODE" == "local" ]]; then
    nginx -p "$TMP_DIR/nginx" -c "$TMP_DIR/nginx.conf" -s stop >/dev/null 2>&1
  fi
  if [[ -n "$NGINX_MODE" && "$NGINX_MODE" == "docker" ]]; then
    docker rm -f "$NGINX_CONTAINER" >/dev/null 2>&1
  fi
  for pid in "$GATEWAY_PID" "$UPSTREAM_PID" "$AUTH_PID"; do
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

wait_status() {
  local url=$1
  local expected=$2
  local name=$3
  for _ in $(seq 1 80); do
    local status
    status=$(curl --ipv4 -s -o /dev/null -w '%{http_code}' "$url" || true)
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    sleep 0.1
  done
  printf '%s did not become ready at %s with status %s\n' "$name" "$url" "$expected" >&2
  if [[ "$name" == "nginx" && "$NGINX_MODE" == "docker" ]]; then
    docker logs "$NGINX_CONTAINER" >&2 || true
  fi
  return 1
}

json_body() {
  local tokens_file=$1
  local state=$2
  local body_file=$3
  python3 - "$tokens_file" "$state" "$body_file" <<'PY'
import json, sys
tokens_file, state, body_file = sys.argv[1:]
with open(tokens_file, "r", encoding="utf-8") as handle:
    tokens = json.load(handle)
body = {
    "access_token": tokens["access_token"],
    "refresh_token": tokens["refresh_token"],
    "session_id": tokens["session_id"],
    "token_type": tokens.get("token_type", "Bearer"),
    "state": state,
}
with open(body_file, "w", encoding="utf-8") as handle:
    json.dump(body, handle)
PY
}

seed_fixtures() {
  python3 - "$AUTH_DB" "$AUTH_BASE" "$ALLOWED_USER_ID" "$DENIED_USER_ID" <<'PY'
import sqlite3, sys
db_path, issuer, allowed_id, denied_id = sys.argv[1:]
connection = sqlite3.connect(db_path)
try:
    connection.execute("UPDATE app_meta SET issuer = ?, rp_id = 'localhost' WHERE id = 'APP'", (issuer,))
    for user_id, email in [
        (allowed_id, "allowed@example.com"),
        (denied_id, "denied@example.com"),
    ]:
        connection.execute(
            "INSERT OR IGNORE INTO users (id, email, email_verified_at) VALUES (?, ?, '2026-01-01T00:00:00.000Z')",
            (user_id, email),
        )
    connection.commit()
finally:
    connection.close()
PY
}

seed_otp() {
  local email=$1
  local code=$2
  python3 - "$AUTH_DB" "$email" "$code" <<'PY'
import hashlib, sqlite3, sys
db_path, email, code = sys.argv[1:]
connection = sqlite3.connect(db_path)
try:
    connection.execute(
        "INSERT OR REPLACE INTO email_otps (email, code_hash, expires_at, consumed_at) VALUES (?, ?, '9999-01-01T00:00:00.000Z', NULL)",
        (email, hashlib.sha256(code.encode()).hexdigest()),
    )
    connection.commit()
finally:
    connection.close()
PY
}

start_gateway() {
  env \
    HOST=127.0.0.1 \
    PORT="$GATEWAY_PORT" \
    UPSTREAM_URL="${GATEWAY_UPSTREAM_URL:-}" \
    UPSTREAM_PROTOCOL=http1 \
    GATEWAY_PUBLIC_BASE_URL="$PUBLIC_BASE" \
    AUTH_MINI_ISSUER="$AUTH_BASE" \
    AUTH_MINI_PUBLIC_BASE_URL="$AUTH_BASE" \
    GATEWAY_DB="$GATEWAY_DB" \
    GATEWAY_COOKIE_SECRET='e2e-cookie-secret-change-me-32chars' \
    COOKIE_SECURE=false \
    COOKIE_SAME_SITE=lax \
    ALLOW_USER_IDS="$ALLOWED_USER_ID" \
    SESSION_TTL_SECONDS=604800 \
    SESSION_ABSOLUTE_TTL_SECONDS=2592000 \
    SESSION_TOUCH_INTERVAL_SECONDS=3600 \
    LOGIN_STATE_TTL_SECONDS=600 \
    REFRESH_SKEW_SECONDS=60 \
    "$ROOT_DIR/target/debug/auth-mini-gateway" \
    >"$TMP_DIR/gateway.log" 2>&1 &
  GATEWAY_PID=$!
  wait_status "http://127.0.0.1:$GATEWAY_PORT/healthz" 204 gateway
}

start_auth() {
  "$AUTH_MINI_SERVER" --db "$AUTH_DB" --host 127.0.0.1 --port "$AUTH_PORT" >"$TMP_DIR/auth-mini.log" 2>&1 &
  AUTH_PID=$!
  wait_status "$AUTH_BASE/healthz" 200 auth-mini
}

stop_auth() {
  if [[ -n "$AUTH_PID" ]]; then
    kill "$AUTH_PID"
    wait "$AUTH_PID" >/dev/null 2>&1 || true
    AUTH_PID=""
  fi
}

stop_gateway() {
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID"
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
    GATEWAY_PID=""
  fi
}

write_nginx_conf() {
  mkdir -p "$TMP_DIR/nginx/logs"
  cat >"$TMP_DIR/nginx.conf" <<EOF
pid nginx.pid;
error_log /dev/stderr warn;
events {}
http {
  access_log off;

  map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
  }

  upstream gateway { server 127.0.0.1:$GATEWAY_PORT; }
  upstream protected_upstream { server 127.0.0.1:$UPSTREAM_PORT; }

  server {
    listen 127.0.0.1:$NGINX_PORT;
    server_name _;

    location = /healthz { proxy_pass http://gateway/healthz; }
    location = /login {
      proxy_pass http://gateway/login;
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-Proto \$scheme;
    }
    location = /auth/callback { proxy_pass http://gateway/auth/callback; }
    location = /auth/callback/session { proxy_pass http://gateway/auth/callback/session; }
    location = /logout { proxy_pass http://gateway/logout; }

    location = /_auth {
      internal;
      proxy_pass http://gateway/auth/check;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header X-Original-URI \$request_uri;
      proxy_set_header X-Forwarded-Proto \$scheme;
      proxy_set_header X-Forwarded-Host \$host;
      proxy_set_header Cookie \$http_cookie;
    }

    location / {
      auth_request /_auth;
      auth_request_set \$auth_user_id \$upstream_http_x_auth_mini_user_id;
      auth_request_set \$auth_set_cookie \$upstream_http_set_cookie;
      add_header Set-Cookie \$auth_set_cookie always;
      error_page 401 = /__login_redirect;
      error_page 403 = @forbidden;
      error_page 500 = @auth_unavailable;
      proxy_intercept_errors off;

      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection \$connection_upgrade;
      proxy_set_header Host \$host;
      proxy_set_header Cookie "";
      proxy_set_header X-Auth-Mini-User-Id \$auth_user_id;
      proxy_pass http://protected_upstream;
    }

    location = /__login_redirect {
      internal;
      proxy_pass http://gateway/login;
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-Proto \$scheme;
      proxy_set_header X-Original-URI \$request_uri;
      add_header Set-Cookie \$auth_set_cookie always;
    }

    location @forbidden { return 403 "Forbidden\n"; }
    location @auth_unavailable {
      add_header Cache-Control "no-store" always;
      add_header Retry-After "5" always;
      return 503 "Authentication service temporarily unavailable\n";
    }
  }
}
EOF
}

start_nginx() {
  write_nginx_conf
  if command -v nginx >/dev/null 2>&1; then
    nginx -p "$TMP_DIR/nginx" -c "$TMP_DIR/nginx.conf"
    NGINX_MODE=local
  else
    docker run -d --network host \
      -v "$TMP_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
      --name "$NGINX_CONTAINER" \
      "$NGINX_IMAGE" >/dev/null
    NGINX_MODE=docker
  fi
  wait_status "$PUBLIC_BASE/healthz" 204 nginx
}

login_start() {
  local jar=$1
  local headers=$2
  local status
  status=$(curl --ipv4 -sS -o /dev/null -D "$headers" -c "$jar" -w '%{http_code}' "$PUBLIC_BASE/")
  if [[ "$status" != "302" ]]; then
    printf 'expected unauthenticated protected request to redirect, got %s\n' "$status" >&2
    return 1
  fi
  python3 - "$headers" "$PUBLIC_BASE/auth/callback" <<'PY'
import sys, urllib.parse
headers = open(sys.argv[1], encoding="utf-8").read().splitlines()
expected_callback = sys.argv[2]
location = None
for line in headers:
    if line.lower().startswith("location:"):
        location = line.split(":", 1)[1].strip()
        break
if not location:
    raise SystemExit("missing login redirect location")
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie:")]
session = [value for value in cookies if value.lower().startswith("amg_session=")]
state_cookie = [value for value in cookies if value.lower().startswith("amg_login_state=")]
if len(session) != 1 or "max-age=0" not in session[0].lower() or "expires=thu, 01 jan 1970" not in session[0].lower():
    raise SystemExit("missing independent session clear cookie")
if len(state_cookie) != 1 or "expires=" not in state_cookie[0].lower() or "max-age=" in state_cookie[0].lower():
    raise SystemExit("missing absolute-expiry login-state cookie")
parsed = urllib.parse.urlparse(location)
fragment_query = parsed.fragment.split("?", 1)[1] if "?" in parsed.fragment else ""
query = urllib.parse.parse_qs(parsed.query or fragment_query)
redirect_uri = query.get("redirect_uri", [])
if redirect_uri != [expected_callback]:
    raise SystemExit("login redirect_uri mismatch")
audience = query.get("aud", [])
if audience != ["localhost"]:
    raise SystemExit("loopback login must carry aud=localhost exactly once")
state = query.get("state", [None])[0]
if not state:
    raise SystemExit("missing state in login redirect")
print(state)
PY
}

mint_tokens() {
  local email=$1
  local code=$2
  local tokens_file=$3
  local redirect_uri=$4
  local audience=${5:-}
  local audience_field=""
  if [[ -n "$audience" ]]; then
    audience_field=",\"aud\":\"$audience\""
  fi
  curl --ipv4 -fsS \
    -H 'content-type: application/json' \
    --data "{\"email\":\"$email\",\"code\":\"$code\",\"redirect_uri\":\"$redirect_uri\"$audience_field}" \
    "$AUTH_BASE/email/verify" >"$tokens_file"
}

assert_token_claims() {
  local tokens_file=$1
  local expected_sub=$2
  local expected_aud=$3
  python3 - "$tokens_file" "$expected_sub" "$expected_aud" <<'PY'
import base64, json, sys
tokens_file, expected_sub, expected_aud = sys.argv[1:]
with open(tokens_file, "r", encoding="utf-8") as handle:
    token = json.load(handle)["access_token"]
segment = token.split(".")[1]
segment += "=" * (-len(segment) % 4)
claims = json.loads(base64.urlsafe_b64decode(segment.encode()))
ok = claims.get("sub") == expected_sub and claims.get("aud") == expected_aud and claims.get("typ") == "access"
if not ok:
    raise SystemExit("minted token claims mismatch")
PY
}

assert_stored_access_claims() {
  local expected_sub=$1
  local expected_aud=$2
  python3 - "$GATEWAY_DB" "$expected_sub" "$expected_aud" <<'PY'
import base64, json, sqlite3, sys
db_path, expected_sub, expected_aud = sys.argv[1:]
connection = sqlite3.connect(db_path)
try:
    row = connection.execute(
        "SELECT access_token FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1"
    ).fetchone()
finally:
    connection.close()
if not row:
    raise SystemExit("no active gateway session stored")
segment = row[0].split(".")[1]
segment += "=" * (-len(segment) % 4)
claims = json.loads(base64.urlsafe_b64decode(segment.encode()))
if claims.get("sub") != expected_sub or claims.get("aud") != expected_aud:
    raise SystemExit("stored access token claims mismatch")
PY
}

mint_main_site_tokens() {
  local email=$1
  local code=$2
  local tokens_file=$3
  curl --ipv4 -fsS \
    -H 'content-type: application/json' \
    --data "{\"email\":\"$email\",\"code\":\"$code\"}" \
    "$AUTH_BASE/email/verify" >"$tokens_file"
}

mint_multi_audience_tokens() {
  local email=$1
  local code=$2
  local tokens_file=$3
  local redirect_uri=$4
  local audiences_json=$5
  curl --ipv4 -fsS \
    -H 'content-type: application/json' \
    --data "{\"email\":\"$email\",\"code\":\"$code\",\"redirect_uri\":\"$redirect_uri\",\"audiences\":$audiences_json}" \
    "$AUTH_BASE/email/verify" >"$tokens_file"
}

sso_authorize() {
  local main_tokens_file=$1
  local tokens_file=$2
  local redirect_uri=$3
  local audience=$4
  curl --ipv4 -fsS \
    -H 'content-type: application/json' \
    -H "authorization: Bearer $(access_token_of "$main_tokens_file")" \
    --data "{\"redirect_uri\":\"$redirect_uri\",\"aud\":\"$audience\"}" \
    "$AUTH_BASE/session/authorize" >"$tokens_file"
}

access_token_of() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$1"
}

assert_claim_json() {
  local source=$1
  local claim=$2
  local expected=$3
  python3 - "$source" "$claim" "$expected" "$GATEWAY_DB" <<'PY'
import base64, json, sqlite3, sys
source, claim, expected, gateway_db = sys.argv[1:]
if source == "stored":
    connection = sqlite3.connect(gateway_db)
    try:
        row = connection.execute(
            "SELECT access_token FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1"
        ).fetchone()
    finally:
        connection.close()
    if not row:
        raise SystemExit("no active gateway session stored")
    token = row[0]
else:
    with open(source, "r", encoding="utf-8") as handle:
        token = json.load(handle)["access_token"]
segment = token.split(".")[1]
segment += "=" * (-len(segment) % 4)
claims = json.loads(base64.urlsafe_b64decode(segment.encode()))
if claims.get(claim) != json.loads(expected):
    raise SystemExit(f"{claim} claim mismatch")
PY
}

callback_session() {
  local jar=$1
  local tokens_file=$2
  local state=$3
  local expected=$4
  local body_file=$TMP_DIR/callback-body-$(date +%s%N).json
  json_body "$tokens_file" "$state" "$body_file"
  local output=$TMP_DIR/callback-output-$(date +%s%N).txt
  local headers=$TMP_DIR/callback-headers-$(date +%s%N).txt
  local status
  status=$(curl --ipv4 -sS -o "$output" -D "$headers" -b "$jar" -c "$jar" -w '%{http_code}' \
    -H 'content-type: application/json' \
    --data @"$body_file" \
    "$PUBLIC_BASE/auth/callback/session")
  if [[ "$status" != "$expected" ]]; then
    printf 'callback expected %s, got %s\n' "$expected" "$status" >&2
    return 1
  fi
  python3 - "$headers" "$expected" <<'PY'
import sys
headers_path, expected = sys.argv[1:]
headers = open(headers_path, encoding="utf-8").read().splitlines()
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie:")]
sessions = [value for value in cookies if value.lower().startswith("amg_session=")]
if expected == "401":
    if sessions:
        raise SystemExit("rejected callback must not set a session cookie")
elif len(sessions) != 1 or "expires=" not in sessions[0].lower() or "max-age=" in sessions[0].lower():
    raise SystemExit("callback session cookie must use absolute Expires without Max-Age")
PY
}

protected_status() {
  local jar=$1
  local output=$2
  curl --ipv4 -sS -o "$output" -b "$jar" -c "$jar" -w '%{http_code}' "$PUBLIC_BASE/"
}

active_refresh_token() {
  python3 - "$GATEWAY_DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    row = connection.execute(
        "SELECT refresh_token FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1"
    ).fetchone()
    print(row[0] if row else "")
finally:
    connection.close()
PY
}

expire_active_access() {
  python3 - "$GATEWAY_DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    connection.execute(
        "UPDATE gateway_sessions SET access_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = (SELECT id FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1)"
    )
    connection.commit()
finally:
    connection.close()
PY
}

corrupt_active_refresh_and_expire() {
  python3 - "$GATEWAY_DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    connection.execute(
        "UPDATE gateway_sessions SET refresh_token = 'invalid-refresh-token', access_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = (SELECT id FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1)"
    )
    connection.commit()
finally:
    connection.close()
PY
}

active_session_count() {
  python3 - "$GATEWAY_DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    print(connection.execute("SELECT COUNT(*) FROM gateway_sessions WHERE revoked_at IS NULL").fetchone()[0])
finally:
    connection.close()
PY
}

upstream_hits() {
  curl --ipv4 -fsS "http://127.0.0.1:$UPSTREAM_PORT/__hits"
}

force_touch_due() {
  python3 - "$GATEWAY_DB" <<'PY'
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    connection.execute(
        "UPDATE gateway_sessions SET last_touched_at = '2000-01-01T00:00:00.000Z' WHERE id = (SELECT id FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1)"
    )
    connection.commit()
finally:
    connection.close()
PY
}

shorten_active_deadline() {
  python3 - "$GATEWAY_DB" <<'PY'
import datetime, email.utils, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
try:
    now = datetime.datetime.now(datetime.timezone.utc)
    idle = now + datetime.timedelta(seconds=3)
    absolute = now + datetime.timedelta(seconds=4)
    fmt = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    connection.execute(
        """UPDATE gateway_sessions
           SET idle_expires_at=?, session_expires_at=?, absolute_expires_at=?,
               last_touched_at='2000-01-01T00:00:00.000Z'
           WHERE id=(SELECT id FROM gateway_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1)""",
        (fmt(idle), fmt(idle), fmt(absolute)),
    )
    connection.commit()
    print(email.utils.format_datetime(absolute, usegmt=True))
finally:
    connection.close()
PY
}

assert_absolute_renewal() {
  local headers=$1
  python3 - "$headers" <<'PY'
import sys
headers = open(sys.argv[1], encoding="utf-8").read().splitlines()
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie:")]
sessions = [value for value in cookies if value.lower().startswith("amg_session=")]
if len(sessions) != 1 or "expires=" not in sessions[0].lower() or "max-age=" in sessions[0].lower():
    raise SystemExit("missing absolute-only session renewal")
PY
}

websocket_check() {
  local jar=$1
  local port=${2:-$NGINX_PORT}
  local host=${3:-127.0.0.1}
  python3 - "$port" "$host" "$jar" <<'PY'
import base64, os, socket, sys
port = int(sys.argv[1])
host = sys.argv[2]
jar = sys.argv[3]
cookies = []
with open(jar, encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.strip().split("\t")
        if len(parts) >= 7:
            cookies.append(f"{parts[5]}={parts[6]}")
key = base64.b64encode(os.urandom(16)).decode()
request = (
    f"GET /ws HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Cookie: {'; '.join(cookies)}\r\n"
    "\r\n"
).encode()
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise SystemExit("websocket handshake failed")
    lowered = response.lower()
    if b"set-cookie: amg_session=" not in lowered or b"expires=" not in lowered or b"max-age=" in lowered:
        raise SystemExit("websocket handshake did not propagate absolute renewal")
    payload = b"ping"
    mask = b"\x01\x02\x03\x04"
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
    header = sock.recv(2)
    if len(header) != 2 or header[0] & 0x0F != 0x1:
        raise SystemExit("websocket echo did not return a text frame")
    length = header[1] & 0x7F
    echoed = sock.recv(length)
    if echoed != payload:
        raise SystemExit("websocket echo mismatch")
PY
}

AUTH_PORT=$(free_port)
GATEWAY_PORT=$(free_port)
UPSTREAM_PORT=$(free_port)
NGINX_PORT=$(free_port)
AUTH_BASE="http://127.0.0.1:$AUTH_PORT"
PUBLIC_BASE="http://localhost:$NGINX_PORT"
AUTH_DB="$TMP_DIR/auth-mini.sqlite"
GATEWAY_DB="$TMP_DIR/gateway.sqlite"

printf 'Building auth-mini and gateway binaries...\n'
printf 'Pinned auth-mini commit: %s\n' "$AUTH_MINI_ACTUAL_COMMIT"
if [[ -n "$AUTH_MINI_BIN" ]]; then
  AUTH_MINI_SERVER=$AUTH_MINI_BIN
  printf 'Using prebuilt auth-mini server: %s\n' "$AUTH_MINI_SERVER"
else
  CARGO_TARGET_DIR="$ROOT_DIR/target" cargo build --manifest-path "$AUTH_MINI_RUST_DIR/Cargo.toml" --bin auth-mini >/dev/null
  AUTH_MINI_SERVER="$ROOT_DIR/target/debug/auth-mini"
fi
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin auth-mini-gateway --example upstream >/dev/null

start_auth
seed_fixtures

env HOST=127.0.0.1 PORT="$UPSTREAM_PORT" SLOW_RESPONSE_MILLISECONDS=5000 "$ROOT_DIR/target/debug/examples/upstream" >"$TMP_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_status "http://127.0.0.1:$UPSTREAM_PORT/" 200 upstream

start_gateway
start_nginx

printf 'Checking unauthenticated redirect and real audience-bound login callback...\n'
ALLOWED_JAR="$TMP_DIR/allowed-cookies.txt"
state=$(login_start "$ALLOWED_JAR" "$TMP_DIR/login.headers")
seed_otp allowed@example.com 123456
mint_tokens allowed@example.com 123456 "$TMP_DIR/allowed-tokens.json" "$PUBLIC_BASE/auth/callback" localhost
assert_token_claims "$TMP_DIR/allowed-tokens.json" "$ALLOWED_USER_ID" localhost

me_status=$(curl --ipv4 -sS -o /dev/null -w '%{http_code}' \
  -H "authorization: Bearer $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$TMP_DIR/allowed-tokens.json")" \
  "$AUTH_BASE/me")
if [[ "$me_status" != "401" ]]; then
  printf 'expected downstream-audience token to be rejected by /me, got %s\n' "$me_status" >&2
  exit 1
fi

callback_session "$ALLOWED_JAR" "$TMP_DIR/allowed-tokens.json" "$state" 200

body="$TMP_DIR/protected-body.txt"
status=$(protected_status "$ALLOWED_JAR" "$body")
if [[ "$status" != "200" ]] \
  || ! grep -q "user_id=$ALLOWED_USER_ID" "$body" \
  || grep -q 'allowed@example.com' "$body"; then
  printf 'expected authorized protected HTTP response with user-ID-only identity, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking successful HTTP touch propagates an absolute-only renewal...\n'
force_touch_due
curl --ipv4 -sS -o /dev/null -D "$TMP_DIR/touch.headers" -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" "$PUBLIC_BASE/"
assert_absolute_renewal "$TMP_DIR/touch.headers"

printf 'Checking WebSocket proxy after auth_request...\n'
force_touch_due
websocket_check "$ALLOWED_JAR"

printf 'Checking protected upstream 500 is not remapped as auth unavailable...\n'
status=$(curl --ipv4 -sS -o /dev/null -b "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/upstream-500")
if [[ "$status" != "500" ]]; then
  printf 'expected protected upstream 500 to remain 500, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking gateway connection failure maps to 503 without upstream access...\n'
hits_before=$(upstream_hits)
stop_gateway
status=$(curl --ipv4 -sS -o /dev/null -D "$TMP_DIR/gateway-down.headers" -b "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
hits_after=$(upstream_hits)
if [[ "$status" != "503" || "$hits_before" != "$hits_after" ]]; then
  printf 'gateway-down auth isolation failed\n' >&2
  exit 1
fi
python3 - "$TMP_DIR/gateway-down.headers" <<'PY'
import sys
headers = open(sys.argv[1], encoding="utf-8").read().lower()
if "location:" in headers or "set-cookie: amg_session=" in headers:
    raise SystemExit("gateway-down 503 redirected or changed session cookie")
PY
start_gateway

printf 'Checking gateway restart preserves SQLite session...\n'
status=$(protected_status "$ALLOWED_JAR" "$body")
if [[ "$status" != "200" ]]; then
  printf 'expected session to survive gateway restart, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking temporary refresh failure preserves the local session and later recovers...\n'
before_refresh=$(active_refresh_token)
expire_active_access
hits_before=$(upstream_hits)
stop_auth
status=$(curl --ipv4 -sS -o /dev/null -D "$TMP_DIR/auth-down.headers" -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
hits_after=$(upstream_hits)
if [[ "$status" != "503" || "$hits_before" != "$hits_after" || "$(active_session_count)" != "1" ]]; then
  printf 'temporary refresh failure did not preserve fail-closed session state\n' >&2
  exit 1
fi
python3 - "$TMP_DIR/auth-down.headers" <<'PY'
import sys
headers = open(sys.argv[1], encoding="utf-8").read().lower()
if "location:" in headers or "max-age=0" in headers:
    raise SystemExit("temporary refresh failure redirected or cleared the session")
PY
start_auth

printf 'Checking real auth-mini refresh preserves the gateway audience without /me...\n'
status=$(protected_status "$ALLOWED_JAR" "$body")
after_refresh=$(active_refresh_token)
if [[ "$status" != "200" || -z "$after_refresh" || "$after_refresh" == "$before_refresh" ]]; then
  before_present=false
  after_present=false
  rotated=false
  [[ -n "$before_refresh" ]] && before_present=true
  [[ -n "$after_refresh" ]] && after_present=true
  [[ -n "$before_refresh" && -n "$after_refresh" && "$after_refresh" != "$before_refresh" ]] && rotated=true
  printf 'expected refresh success with rotated token, status=%s before_present=%s after_present=%s rotated=%s\n' "$status" "$before_present" "$after_present" "$rotated" >&2
  exit 1
fi
assert_stored_access_claims "$ALLOWED_USER_ID" localhost

printf 'Checking logout durably revokes gateway session...\n'
logout_status=$(curl --ipv4 -sS -o /dev/null -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/logout")
if [[ "$logout_status" != "302" || "$(active_session_count)" != "0" ]]; then
  printf 'expected logout redirect and zero active sessions, status=%s active=%s\n' "$logout_status" "$(active_session_count)" >&2
  exit 1
fi

printf 'Checking exact refresh rejection revokes local session...\n'
REFRESH_FAIL_JAR="$TMP_DIR/refresh-fail-cookies.txt"
state=$(login_start "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-login.headers")
seed_otp allowed@example.com 654321
mint_tokens allowed@example.com 654321 "$TMP_DIR/refresh-fail-tokens.json" "$PUBLIC_BASE/auth/callback" localhost
callback_session "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-tokens.json" "$state" 200
corrupt_active_refresh_and_expire
hits_before=$(upstream_hits)
status=$(curl --ipv4 -sS -o /dev/null -D "$TMP_DIR/refresh-rejected.headers" -b "$REFRESH_FAIL_JAR" -c "$REFRESH_FAIL_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
hits_after=$(upstream_hits)
if [[ "$status" != "302" || "$(active_session_count)" != "0" || "$hits_before" != "$hits_after" ]]; then
  printf 'expected exact refresh rejection to revoke and redirect, status=%s active=%s\n' "$status" "$(active_session_count)" >&2
  exit 1
fi
python3 - "$TMP_DIR/refresh-rejected.headers" <<'PY'
import sys
headers = open(sys.argv[1], encoding="utf-8").read().splitlines()
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie:")]
session = [value for value in cookies if value.lower().startswith("amg_session=")]
state = [value for value in cookies if value.lower().startswith("amg_login_state=")]
if len(session) != 1 or "max-age=0" not in session[0].lower() or "expires=thu, 01 jan 1970" not in session[0].lower():
    raise SystemExit("exact rejection redirect lost session clear cookie")
if len(state) != 1 or "expires=" not in state[0].lower() or "max-age=" in state[0].lower():
    raise SystemExit("exact rejection redirect lost independent login-state cookie")
PY

printf 'Checking user-id allowlist denial does not reach upstream...\n'
DENIED_JAR="$TMP_DIR/denied-cookies.txt"
state=$(login_start "$DENIED_JAR" "$TMP_DIR/denied-login.headers")
seed_otp denied@example.com 111111
mint_tokens denied@example.com 111111 "$TMP_DIR/denied-tokens.json" "$PUBLIC_BASE/auth/callback" localhost
assert_token_claims "$TMP_DIR/denied-tokens.json" "$DENIED_USER_ID" localhost
callback_session "$DENIED_JAR" "$TMP_DIR/denied-tokens.json" "$state" 403
hits_before=$(upstream_hits)
status=$(protected_status "$DENIED_JAR" "$body")
hits_after=$(upstream_hits)
if [[ "$status" != "403" || "$hits_before" != "$hits_after" ]]; then
  printf 'expected denied user to receive isolated 403, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking a real wrong-audience token is rejected without a session or upstream hit...\n'
WRONG_JAR="$TMP_DIR/wrong-cookies.txt"
state=$(login_start "$WRONG_JAR" "$TMP_DIR/wrong-login.headers")
seed_otp allowed@example.com 444444
# auth-mini 156484e requires explicit audiences to include the redirect host,
# so mint the token the way another HTTPS app would receive it.
mint_tokens allowed@example.com 444444 "$TMP_DIR/wrong-tokens.json" "https://$WRONG_AUDIENCE/auth/callback"
assert_token_claims "$TMP_DIR/wrong-tokens.json" "$ALLOWED_USER_ID" "$WRONG_AUDIENCE"
sessions_before=$(active_session_count)
hits_before=$(upstream_hits)
callback_session "$WRONG_JAR" "$TMP_DIR/wrong-tokens.json" "$state" 401
hits_after=$(upstream_hits)
if [[ "$(active_session_count)" != "$sessions_before" || "$hits_before" != "$hits_after" ]]; then
  printf 'wrong-audience callback created a session or reached upstream\n' >&2
  exit 1
fi

printf 'Checking an auth-mini SSO-delegated session is accepted and survives main-site logout...\n'
SSO_JAR="$TMP_DIR/sso-cookies.txt"
state=$(login_start "$SSO_JAR" "$TMP_DIR/sso-login.headers")
seed_otp allowed@example.com 555555
mint_main_site_tokens allowed@example.com 555555 "$TMP_DIR/main-site-tokens.json"
assert_claim_json "$TMP_DIR/main-site-tokens.json" aud '"127.0.0.1"'
sso_authorize "$TMP_DIR/main-site-tokens.json" "$TMP_DIR/sso-tokens.json" "$PUBLIC_BASE/auth/callback" localhost
assert_token_claims "$TMP_DIR/sso-tokens.json" "$ALLOWED_USER_ID" localhost
assert_claim_json "$TMP_DIR/sso-tokens.json" amr '["sso","email_otp"]'
callback_session "$SSO_JAR" "$TMP_DIR/sso-tokens.json" "$state" 200
status=$(protected_status "$SSO_JAR" "$body")
if [[ "$status" != "200" ]] || ! grep -q "user_id=$ALLOWED_USER_ID" "$body"; then
  printf 'expected SSO-delegated session to reach upstream, got %s\n' "$status" >&2
  exit 1
fi
main_logout_status=$(curl --ipv4 -sS -o /dev/null -w '%{http_code}' -X POST \
  -H "authorization: Bearer $(access_token_of "$TMP_DIR/main-site-tokens.json")" \
  "$AUTH_BASE/session/logout")
sso_before_refresh=$(active_refresh_token)
expire_active_access
status=$(protected_status "$SSO_JAR" "$body")
sso_after_refresh=$(active_refresh_token)
if [[ "$main_logout_status" != "200" || "$status" != "200" || "$sso_after_refresh" == "$sso_before_refresh" ]]; then
  printf 'SSO-delegated session did not refresh independently of main-site logout, logout=%s status=%s\n' "$main_logout_status" "$status" >&2
  exit 1
fi
assert_stored_access_claims "$ALLOWED_USER_ID" localhost
assert_claim_json stored amr '["sso","email_otp"]'
logout_status=$(curl --ipv4 -sS -o /dev/null -b "$SSO_JAR" -c "$SSO_JAR" -w '%{http_code}' "$PUBLIC_BASE/logout")
status=$(protected_status "$SSO_JAR" "$body")
if [[ "$logout_status" != "302" || "$status" != "302" ]]; then
  printf 'SSO-delegated gateway logout failed, logout=%s status=%s\n' "$logout_status" "$status" >&2
  exit 1
fi

printf 'Checking a multi-audience token naming the gateway is accepted and refreshed...\n'
MULTI_JAR="$TMP_DIR/multi-cookies.txt"
MULTI_AUDIENCES='["localhost","status.example"]'
state=$(login_start "$MULTI_JAR" "$TMP_DIR/multi-login.headers")
seed_otp allowed@example.com 777777
mint_multi_audience_tokens allowed@example.com 777777 "$TMP_DIR/multi-tokens.json" "$PUBLIC_BASE/auth/callback" "$MULTI_AUDIENCES"
assert_claim_json "$TMP_DIR/multi-tokens.json" aud "$MULTI_AUDIENCES"
callback_session "$MULTI_JAR" "$TMP_DIR/multi-tokens.json" "$state" 200
multi_before_refresh=$(active_refresh_token)
expire_active_access
status=$(protected_status "$MULTI_JAR" "$body")
multi_after_refresh=$(active_refresh_token)
if [[ "$status" != "200" || "$multi_after_refresh" == "$multi_before_refresh" ]]; then
  printf 'multi-audience session did not refresh, status=%s\n' "$status" >&2
  exit 1
fi
assert_claim_json stored aud "$MULTI_AUDIENCES"
logout_status=$(curl --ipv4 -sS -o /dev/null -b "$MULTI_JAR" -c "$MULTI_JAR" -w '%{http_code}' "$PUBLIC_BASE/logout")
if [[ "$logout_status" != "302" ]]; then
  printf 'multi-audience gateway logout failed, logout=%s\n' "$logout_status" >&2
  exit 1
fi

printf 'Checking direct gateway proxy mode with real auth-mini state...\n'
ADAPTER_PUBLIC_BASE="$PUBLIC_BASE"
stop_gateway
PUBLIC_BASE="http://localhost:$GATEWAY_PORT"
GATEWAY_UPSTREAM_URL="http://127.0.0.1:$UPSTREAM_PORT"
start_gateway
PROXY_BASE="$PUBLIC_BASE"
PROXY_JAR="$TMP_DIR/proxy-cookies.txt"
state=$(login_start "$PROXY_JAR" "$TMP_DIR/proxy-login.headers")
seed_otp allowed@example.com 333333
mint_tokens allowed@example.com 333333 "$TMP_DIR/proxy-tokens.json" "$PROXY_BASE/auth/callback" localhost
callback_session "$PROXY_JAR" "$TMP_DIR/proxy-tokens.json" "$state" 200
force_touch_due
status=$(curl --ipv4 -sS -o "$TMP_DIR/proxy-body.txt" -D "$TMP_DIR/proxy.headers" -b "$PROXY_JAR" -c "$PROXY_JAR" -w '%{http_code}' "$PROXY_BASE/")
if [[ "$status" != "200" ]] \
  || ! grep -q "user_id=$ALLOWED_USER_ID" "$TMP_DIR/proxy-body.txt" \
  || grep -q 'allowed@example.com' "$TMP_DIR/proxy-body.txt"; then
  printf 'direct proxy-mode HTTP failed with user-ID-only identity, status %s\n' "$status" >&2
  exit 1
fi
assert_absolute_renewal "$TMP_DIR/proxy.headers"

printf 'Checking direct proxy-mode refresh outage isolation and recovery...\n'
proxy_before_refresh=$(active_refresh_token)
expire_active_access
hits_before=$(upstream_hits)
stop_auth
status=$(protected_status "$PROXY_JAR" "$TMP_DIR/proxy-auth-down.txt")
hits_after=$(upstream_hits)
if [[ "$status" != "503" || "$hits_before" != "$hits_after" ]]; then
  printf 'direct proxy-mode auth outage isolation failed\n' >&2
  exit 1
fi
start_auth
status=$(protected_status "$PROXY_JAR" "$TMP_DIR/proxy-refreshed.txt")
proxy_after_refresh=$(active_refresh_token)
if [[ "$status" != "200" || -z "$proxy_after_refresh" || "$proxy_after_refresh" == "$proxy_before_refresh" ]]; then
  printf 'direct proxy-mode refresh recovery failed\n' >&2
  exit 1
fi
assert_stored_access_claims "$ALLOWED_USER_ID" localhost

force_touch_due
websocket_check "$PROXY_JAR" "$GATEWAY_PORT" localhost
hits_before=$(upstream_hits)
status=$(curl --ipv4 -sS -o /dev/null -b "$DENIED_JAR" -w '%{http_code}' "$PROXY_BASE/")
hits_after=$(upstream_hits)
if [[ "$status" != "403" || "$hits_before" != "$hits_after" ]]; then
  printf 'direct proxy-mode denial isolation failed\n' >&2
  exit 1
fi
logout_status=$(curl --ipv4 -sS -o /dev/null -b "$PROXY_JAR" -c "$PROXY_JAR" -w '%{http_code}' "$PROXY_BASE/logout")
hits_before=$(upstream_hits)
status=$(protected_status "$PROXY_JAR" "$TMP_DIR/proxy-after-logout.txt")
hits_after=$(upstream_hits)
if [[ "$logout_status" != "302" || "$status" != "302" || "$hits_before" != "$hits_after" ]]; then
  printf 'direct proxy-mode logout isolation failed\n' >&2
  exit 1
fi
stop_gateway
GATEWAY_UPSTREAM_URL=""
PUBLIC_BASE="$ADAPTER_PUBLIC_BASE"
start_gateway

printf 'Checking a slow upstream cannot move absolute Cookie expiry...\n'
SLOW_JAR="$TMP_DIR/slow-cookies.txt"
state=$(login_start "$SLOW_JAR" "$TMP_DIR/slow-login.headers")
seed_otp allowed@example.com 222222
mint_tokens allowed@example.com 222222 "$TMP_DIR/slow-tokens.json" "$PUBLIC_BASE/auth/callback" localhost
callback_session "$SLOW_JAR" "$TMP_DIR/slow-tokens.json" "$state" 200
expected_expiry=$(shorten_active_deadline)
status=$(curl --ipv4 -sS -o /dev/null -D "$TMP_DIR/slow.headers" -b "$SLOW_JAR" -c "$SLOW_JAR" -w '%{http_code}' "$PUBLIC_BASE/slow")
if [[ "$status" != "200" ]]; then
  printf 'slow-upstream request failed before response-delay assertion\n' >&2
  exit 1
fi
python3 - "$TMP_DIR/slow.headers" "$SLOW_JAR" "$expected_expiry" <<'PY'
import sys
headers_path, jar_path, expected = sys.argv[1:]
headers = open(headers_path, encoding="utf-8").read().splitlines()
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie: amg_session=")]
if len(cookies) != 1 or f"Expires={expected}" not in cookies[0] or "max-age=" in cookies[0].lower():
    raise SystemExit("slow response changed the absolute session expiry")
jar = open(jar_path, encoding="utf-8").read()
if "amg_session" in jar:
    raise SystemExit("receipt-time cookie jar retained an already expired renewal")
PY

printf 'E2E passed: real audience-bound auth-mini (SSO delegation, multi-audience), Rust gateway, nginx, protected HTTP/WebSocket upstream.\n'
