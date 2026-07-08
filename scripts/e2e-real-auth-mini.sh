#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AUTH_MINI_RUST_DIR=${AUTH_MINI_RUST_DIR:-/tmp/opencode/auth-mini-reference/rust-backend}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

need cargo
need curl
need python3

if [[ ! -f "$AUTH_MINI_RUST_DIR/Cargo.toml" ]]; then
  printf 'AUTH_MINI_RUST_DIR must point to auth-mini rust-backend; got %s\n' "$AUTH_MINI_RUST_DIR" >&2
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
  for log in auth-mini gateway upstream; do
    if [[ -f "$TMP_DIR/$log.log" ]]; then
      printf '\n--- %s.log ---\n' "$log" >&2
      sed -n '1,120p' "$TMP_DIR/$log.log" >&2 || true
    fi
  done
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
    GATEWAY_PUBLIC_BASE_URL="$PUBLIC_BASE" \
    AUTH_MINI_ISSUER="$AUTH_BASE" \
    AUTH_MINI_PUBLIC_BASE_URL="$AUTH_BASE" \
    GATEWAY_DB="$GATEWAY_DB" \
    GATEWAY_COOKIE_SECRET='e2e-cookie-secret-change-me-32chars' \
    COOKIE_SECURE=false \
    COOKIE_SAME_SITE=lax \
    ALLOW_EMAILS=allowed@example.com \
    REQUIRE_PASSKEY=false \
    REFRESH_SKEW_SECONDS=60 \
    "$ROOT_DIR/target/debug/auth-mini-gateway" \
    >"$TMP_DIR/gateway.log" 2>&1 &
  GATEWAY_PID=$!
  wait_status "http://127.0.0.1:$GATEWAY_PORT/healthz" 204 gateway
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
      error_page 401 = /__login_redirect;
      error_page 403 = @forbidden;

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
    }

    location @forbidden { return 403 "Forbidden\n"; }
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
  local status
  status=$(curl -sS -o "$output" -b "$jar" -c "$jar" -w '%{http_code}' \
    -H 'content-type: application/json' \
    --data @"$body_file" \
    "$PUBLIC_BASE/auth/callback/session")
  if [[ "$status" != "$expected" ]]; then
    printf 'callback expected %s, got %s: %s\n' "$expected" "$status" "$(cat "$output")" >&2
    return 1
  fi
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

websocket_check() {
  local jar=$1
  python3 - "$NGINX_PORT" "$jar" <<'PY'
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
        raise SystemExit(f"websocket handshake failed: {response!r}")
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
        raise SystemExit(f"websocket echo mismatch: {echoed!r}")
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
cargo build --manifest-path "$AUTH_MINI_RUST_DIR/Cargo.toml" --bin auth-mini >/dev/null
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin auth-mini-gateway --example upstream >/dev/null

"$AUTH_MINI_RUST_DIR/target/debug/auth-mini" --db "$AUTH_DB" --host 127.0.0.1 --port "$AUTH_PORT" >"$TMP_DIR/auth-mini.log" 2>&1 &
AUTH_PID=$!
wait_status "$AUTH_BASE/healthz" 200 auth-mini

env HOST=127.0.0.1 PORT="$UPSTREAM_PORT" "$ROOT_DIR/target/debug/examples/upstream" >"$TMP_DIR/upstream.log" 2>&1 &
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
  printf 'expected authorized protected HTTP response, got %s: %s\n' "$status" "$(cat "$body")" >&2
  exit 1
fi

printf 'Checking WebSocket proxy after auth_request...\n'
websocket_check "$ALLOWED_JAR"

printf 'Checking gateway restart preserves SQLite session...\n'
stop_gateway
start_gateway
status=$(protected_status "$ALLOWED_JAR" "$body")
if [[ "$status" != "200" ]]; then
  printf 'expected session to survive gateway restart, got %s\n' "$status" >&2
  exit 1
fi

printf 'Checking real auth-mini refresh through persisted refresh token...\n'
before_refresh=$(active_refresh_token)
expire_active_access
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

printf 'Checking refresh failure revokes local session...\n'
REFRESH_FAIL_JAR="$TMP_DIR/refresh-fail-cookies.txt"
state=$(login_start "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-login.headers")
seed_otp allowed@example.com 654321
mint_tokens allowed@example.com 654321 "$TMP_DIR/refresh-fail-tokens.json"
callback_session "$REFRESH_FAIL_JAR" "$TMP_DIR/refresh-fail-tokens.json" "$state" 200
corrupt_active_refresh_and_expire
status=$(protected_status "$REFRESH_FAIL_JAR" "$body")
if [[ "$status" != "302" || "$(active_session_count)" != "0" ]]; then
  printf 'expected refresh failure to revoke and redirect to login, status=%s active=%s\n' "$status" "$(active_session_count)" >&2
  exit 1
fi

printf 'Checking allowlist denial does not reach upstream...\n'
DENIED_JAR="$TMP_DIR/denied-cookies.txt"
state=$(login_start "$DENIED_JAR" "$TMP_DIR/denied-login.headers")
seed_otp denied@example.com 111111
mint_tokens denied@example.com 111111 "$TMP_DIR/denied-tokens.json"
callback_session "$DENIED_JAR" "$TMP_DIR/denied-tokens.json" "$state" 403
status=$(protected_status "$DENIED_JAR" "$body")
if [[ "$status" != "403" ]]; then
  printf 'expected denied user to receive 403, got %s: %s\n' "$status" "$(cat "$body")" >&2
  exit 1
fi

printf 'E2E passed: real auth-mini, Rust gateway, nginx, protected HTTP/WebSocket upstream.\n'
