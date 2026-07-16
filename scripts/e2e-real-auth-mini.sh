#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AUTH_MINI_RUST_DIR=${AUTH_MINI_RUST_DIR:-/tmp/opencode/auth-mini-reference/rust-backend}
AUTH_MINI_EXPECTED_COMMIT=${AUTH_MINI_EXPECTED_COMMIT:-86b4aaa8ca97d1218217a7f6f0144251a5f30c9b}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}

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

TMP_DIR=$(mktemp -d)
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
    status=$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)
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

seed_otp() {
  local email=$1
  local code=$2
  python3 - "$AUTH_DB" "$AUTH_BASE" "$email" "$code" <<'PY'
import hashlib, sqlite3, sys
db_path, issuer, email, code = sys.argv[1:]
connection = sqlite3.connect(db_path)
try:
    connection.execute("UPDATE app_meta SET issuer = ?, rp_id = 'localhost' WHERE id = 'APP'", (issuer,))
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
    ALLOW_EMAILS=allowed@example.com \
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
  "$AUTH_MINI_RUST_DIR/target/debug/auth-mini" --db "$AUTH_DB" --host 127.0.0.1 --port "$AUTH_PORT" >"$TMP_DIR/auth-mini.log" 2>&1 &
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
pid /tmp/amg-e2e-nginx-$$.pid;
error_log /dev/stderr warn;
events {}
http {
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
      auth_request_set \$auth_email \$upstream_http_x_auth_mini_email;
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
      proxy_set_header X-Auth-Mini-Email \$auth_email;
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
  status=$(curl -sS -o /dev/null -D "$headers" -c "$jar" -w '%{http_code}' "$PUBLIC_BASE/")
  if [[ "$status" != "302" ]]; then
    printf 'expected unauthenticated protected request to redirect, got %s\n' "$status" >&2
    return 1
  fi
  python3 - "$headers" <<'PY'
import sys, urllib.parse
headers = open(sys.argv[1], encoding="utf-8").read().splitlines()
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
state = query.get("state", [None])[0]
if not state:
    raise SystemExit(f"missing state in {location}")
print(state)
PY
}

mint_tokens() {
  local email=$1
  local code=$2
  local tokens_file=$3
  curl -fsS \
    -H 'content-type: application/json' \
    --data "{\"email\":\"$email\",\"code\":\"$code\"}" \
    "$AUTH_BASE/email/verify" >"$tokens_file"
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
  status=$(curl -sS -o "$output" -D "$headers" -b "$jar" -c "$jar" -w '%{http_code}' \
    -H 'content-type: application/json' \
    --data @"$body_file" \
    "$PUBLIC_BASE/auth/callback/session")
  if [[ "$status" != "$expected" ]]; then
    printf 'callback expected %s, got %s\n' "$expected" "$status" >&2
    return 1
  fi
  python3 - "$headers" <<'PY'
import sys
headers = open(sys.argv[1], encoding="utf-8").read().splitlines()
cookies = [line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("set-cookie:")]
sessions = [value for value in cookies if value.lower().startswith("amg_session=")]
if len(sessions) != 1 or "expires=" not in sessions[0].lower() or "max-age=" in sessions[0].lower():
    raise SystemExit("callback session cookie must use absolute Expires without Max-Age")
PY
}

protected_status() {
  local jar=$1
  local output=$2
  curl -sS -o "$output" -b "$jar" -c "$jar" -w '%{http_code}' "$PUBLIC_BASE/"
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
  curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/__hits"
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
  python3 - "$port" "$jar" <<'PY'
import base64, os, socket, sys
port = int(sys.argv[1])
jar = sys.argv[2]
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
    f"Host: 127.0.0.1:{port}\r\n"
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
PUBLIC_BASE="http://127.0.0.1:$NGINX_PORT"
AUTH_DB="$TMP_DIR/auth-mini.sqlite"
GATEWAY_DB="$TMP_DIR/gateway.sqlite"

printf 'Building auth-mini and gateway binaries...\n'
printf 'Pinned auth-mini commit: %s\n' "$AUTH_MINI_ACTUAL_COMMIT"
cargo build --manifest-path "$AUTH_MINI_RUST_DIR/Cargo.toml" --bin auth-mini >/dev/null
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin auth-mini-gateway --example upstream >/dev/null

start_auth

env HOST=127.0.0.1 PORT="$UPSTREAM_PORT" SLOW_RESPONSE_MILLISECONDS=5000 "$ROOT_DIR/target/debug/examples/upstream" >"$TMP_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_status "http://127.0.0.1:$UPSTREAM_PORT/" 200 upstream

start_gateway
start_nginx

printf 'Checking unauthenticated redirect and real auth-mini login callback...\n'
ALLOWED_JAR="$TMP_DIR/allowed-cookies.txt"
state=$(login_start "$ALLOWED_JAR" "$TMP_DIR/login.headers")
seed_otp allowed@example.com 123456
mint_tokens allowed@example.com 123456 "$TMP_DIR/allowed-tokens.json"
callback_session "$ALLOWED_JAR" "$TMP_DIR/allowed-tokens.json" "$state" 200

body="$TMP_DIR/protected-body.txt"
status=$(protected_status "$ALLOWED_JAR" "$body")
if [[ "$status" != "200" ]] || ! grep -q 'allowed@example.com' "$body"; then
  printf 'expected authorized protected HTTP response, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking successful HTTP touch propagates an absolute-only renewal...\n'
force_touch_due
curl -sS -o /dev/null -D "$TMP_DIR/touch.headers" -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" "$PUBLIC_BASE/"
assert_absolute_renewal "$TMP_DIR/touch.headers"

printf 'Checking WebSocket proxy after auth_request...\n'
force_touch_due
websocket_check "$ALLOWED_JAR"

printf 'Checking protected upstream 500 is not remapped as auth unavailable...\n'
status=$(curl -sS -o /dev/null -b "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/upstream-500")
if [[ "$status" != "500" ]]; then
  printf 'expected protected upstream 500 to remain 500, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking gateway connection failure maps to 503 without upstream access...\n'
hits_before=$(upstream_hits)
stop_gateway
status=$(curl -sS -o /dev/null -D "$TMP_DIR/gateway-down.headers" -b "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
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
status=$(curl -sS -o /dev/null -D "$TMP_DIR/auth-down.headers" -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
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

printf 'Checking real auth-mini refresh and Pending identity finalization...\n'
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

printf 'Checking logout durably revokes gateway session...\n'
logout_status=$(curl -sS -o /dev/null -b "$ALLOWED_JAR" -c "$ALLOWED_JAR" -w '%{http_code}' "$PUBLIC_BASE/logout")
if [[ "$logout_status" != "302" || "$(active_session_count)" != "0" ]]; then
  printf 'expected logout redirect and zero active sessions, status=%s active=%s\n' "$logout_status" "$(active_session_count)" >&2
  exit 1
fi

printf 'Checking exact refresh rejection revokes local session...\n'
REFRESH_FAIL_JAR="$TMP_DIR/refresh-fail-cookies.txt"
state=$(login_start "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-login.headers")
seed_otp allowed@example.com 654321
mint_tokens allowed@example.com 654321 "$TMP_DIR/refresh-fail-tokens.json"
callback_session "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-tokens.json" "$state" 200
corrupt_active_refresh_and_expire
hits_before=$(upstream_hits)
status=$(curl -sS -o /dev/null -D "$TMP_DIR/refresh-rejected.headers" -b "$REFRESH_FAIL_JAR" -c "$REFRESH_FAIL_JAR" -w '%{http_code}' "$PUBLIC_BASE/")
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

printf 'Checking allowlist denial does not reach upstream...\n'
DENIED_JAR="$TMP_DIR/denied-cookies.txt"
state=$(login_start "$DENIED_JAR" "$TMP_DIR/denied-login.headers")
seed_otp denied@example.com 111111
mint_tokens denied@example.com 111111 "$TMP_DIR/denied-tokens.json"
callback_session "$DENIED_JAR" "$TMP_DIR/denied-tokens.json" "$state" 403
hits_before=$(upstream_hits)
status=$(protected_status "$DENIED_JAR" "$body")
hits_after=$(upstream_hits)
if [[ "$status" != "403" || "$hits_before" != "$hits_after" ]]; then
  printf 'expected denied user to receive isolated 403, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking direct gateway proxy mode with real auth-mini state...\n'
ADAPTER_PUBLIC_BASE="$PUBLIC_BASE"
stop_gateway
PUBLIC_BASE="http://127.0.0.1:$GATEWAY_PORT"
GATEWAY_UPSTREAM_URL="http://127.0.0.1:$UPSTREAM_PORT"
start_gateway
PROXY_BASE="$PUBLIC_BASE"
PROXY_JAR="$TMP_DIR/proxy-cookies.txt"
state=$(login_start "$PROXY_JAR" "$TMP_DIR/proxy-login.headers")
seed_otp allowed@example.com 333333
mint_tokens allowed@example.com 333333 "$TMP_DIR/proxy-tokens.json"
callback_session "$PROXY_JAR" "$TMP_DIR/proxy-tokens.json" "$state" 200
force_touch_due
status=$(curl -sS -o "$TMP_DIR/proxy-body.txt" -D "$TMP_DIR/proxy.headers" -b "$PROXY_JAR" -c "$PROXY_JAR" -w '%{http_code}' "$PROXY_BASE/")
if [[ "$status" != "200" ]] || ! grep -q 'allowed@example.com' "$TMP_DIR/proxy-body.txt"; then
  printf 'direct proxy-mode HTTP failed with status %s\n' "$status" >&2
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

force_touch_due
websocket_check "$PROXY_JAR" "$GATEWAY_PORT"
hits_before=$(upstream_hits)
status=$(curl -sS -o /dev/null -b "$DENIED_JAR" -w '%{http_code}' "$PROXY_BASE/")
hits_after=$(upstream_hits)
if [[ "$status" != "403" || "$hits_before" != "$hits_after" ]]; then
  printf 'direct proxy-mode denial isolation failed\n' >&2
  exit 1
fi
logout_status=$(curl -sS -o /dev/null -b "$PROXY_JAR" -c "$PROXY_JAR" -w '%{http_code}' "$PROXY_BASE/logout")
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
mint_tokens allowed@example.com 222222 "$TMP_DIR/slow-tokens.json"
callback_session "$SLOW_JAR" "$TMP_DIR/slow-tokens.json" "$state" 200
expected_expiry=$(shorten_active_deadline)
status=$(curl -sS -o /dev/null -D "$TMP_DIR/slow.headers" -b "$SLOW_JAR" -c "$SLOW_JAR" -w '%{http_code}' "$PUBLIC_BASE/slow")
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

printf 'E2E passed: real auth-mini, Rust gateway, nginx, protected HTTP/WebSocket upstream.\n'
