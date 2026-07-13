# Production Deployment

This guide describes how to deploy `auth-mini-gateway` in front of a protected app with nginx and a separately deployed auth-mini server.

## Target Topology

```text
Browser
  |
  v
nginx public HTTPS origin: https://app.example.com
  |-- public gateway routes: /login, /auth/callback, /auth/callback/session, /logout, /healthz
  |-- internal auth subrequest: /_auth -> gateway /auth/check
  |
  v
protected upstream app, reachable only from nginx

gateway private listener: 127.0.0.1:3000 or container network gateway:3000
  |
  v
auth-mini public issuer: https://auth.example.com
```

Production assumptions:

- One active gateway instance writes to one durable SQLite database.
- nginx terminates TLS and proxies both HTTP and WebSocket traffic.
- The protected upstream is not directly reachable from the public network.
- auth-mini is already deployed and configured with the public issuer that appears in its access-token `iss` claim.

## Prerequisites

- A deployed auth-mini server.
- nginx with `auth_request` support.
- A protected upstream service reachable from nginx.
- Persistent storage for the gateway SQLite database.
- A strong cookie secret, generated once and kept stable across gateway restarts.

Generate a cookie secret:

```bash
openssl rand -base64 48
```

## auth-mini Requirements

Before deploying the gateway, configure auth-mini itself:

- Its issuer must be the externally visible auth-mini origin, for example `https://auth.example.com`.
- That issuer URL must be reachable by the gateway because `AUTH_MINI_ISSUER` is used both as the expected JWT issuer and as the HTTP base for `/jwks`, `/me`, `/session/refresh`, and `/session/logout`.
- Passkey deployments must use the correct auth-mini RP ID and browser origin for the auth-mini domain.
- Users who should reach the protected app must authenticate through auth-mini and then match the gateway allowlist by email or auth-mini user id.

If your internal network uses a different service name than the public issuer, make the public issuer hostname resolvable from the gateway as well. Do not set `AUTH_MINI_ISSUER` to an internal URL unless auth-mini also signs tokens with that exact URL as `iss`.

## Gateway Configuration

Use these variables as the production baseline:

```env
HOST=0.0.0.0
PORT=3000
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
AUTH_MINI_ISSUER=https://auth.example.com
AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
AUTH_MINI_LOGIN_URL=
GATEWAY_DB=/data/auth-mini-gateway.sqlite
GATEWAY_COOKIE_SECRET=<strong-random-secret>
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
ALLOW_EMAILS=alice@example.com,bob@example.com
ALLOW_USER_IDS=
SESSION_TTL_SECONDS=604800
SESSION_ABSOLUTE_TTL_SECONDS=2592000
SESSION_TOUCH_INTERVAL_SECONDS=3600
LOGIN_STATE_TTL_SECONDS=600
REFRESH_SKEW_SECONDS=60
LOGOUT_REDIRECT=/
```

Important settings:

- `GATEWAY_PUBLIC_BASE_URL` is the protected app origin served by nginx. It is used for callback redirects and return target validation.
- `AUTH_MINI_ISSUER` must exactly match auth-mini's JWT issuer and must be reachable by the gateway.
- `AUTH_MINI_PUBLIC_BASE_URL` is the browser-visible auth-mini origin used to build the default login URL.
- `AUTH_MINI_LOGIN_URL` is optional. Set it only if the default `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login` is not correct for your auth-mini UI.
- `GATEWAY_DB` must point to persistent storage. Back up this file and its WAL files consistently.
- `GATEWAY_COOKIE_SECRET` must remain stable. Rotating it invalidates all browser gateway cookies.
- `COOKIE_SECURE` should be `true` for HTTPS production deployments.
- Session settings must satisfy `0 < SESSION_TOUCH_INTERVAL_SECONDS <= SESSION_TTL_SECONDS <= SESSION_ABSOLUTE_TTL_SECONDS`. Defaults are one-hour touch merging, seven-day inactivity, and a hard 30-day lifetime.

## Docker Deployment

Build the image:

```bash
docker build -t auth-mini-gateway:latest .
```

Run the gateway on a private network with a persistent volume:

```bash
docker run -d \
  --name auth-mini-gateway \
  --restart unless-stopped \
  --network your-private-network \
  -v auth-mini-gateway-data:/data \
  -e HOST=0.0.0.0 \
  -e PORT=3000 \
  -e GATEWAY_PUBLIC_BASE_URL=https://app.example.com \
  -e AUTH_MINI_ISSUER=https://auth.example.com \
  -e AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com \
  -e GATEWAY_DB=/data/auth-mini-gateway.sqlite \
  -e GATEWAY_COOKIE_SECRET='<strong-random-secret>' \
  -e COOKIE_SECURE=true \
  -e COOKIE_SAME_SITE=lax \
  -e ALLOW_EMAILS=alice@example.com,bob@example.com \
  -e SESSION_TTL_SECONDS=604800 \
  -e SESSION_ABSOLUTE_TTL_SECONDS=2592000 \
  -e SESSION_TOUCH_INTERVAL_SECONDS=3600 \
  -e LOGIN_STATE_TTL_SECONDS=600 \
  auth-mini-gateway:latest
```

Do not publish the gateway port directly to the internet. Let nginx reach it on a private interface or container network.

## Docker Compose Deployment

`examples/docker-compose.yml` is a starting point. It builds the gateway and a demo upstream, but production deployments should provide their own auth-mini service and protected upstream.

Set environment values before starting the example topology:

```bash
export NGINX_PORT=8080
export GATEWAY_COOKIE_SECRET='<strong-random-secret>'
export AUTH_MINI_ISSUER=https://auth.example.com
export AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
export ALLOW_EMAILS=alice@example.com,bob@example.com
```

Then start the topology:

```bash
docker compose -f examples/docker-compose.yml up -d --build
```

For real production, replace the demo `upstream` service and add your own TLS/certificate management. The checked-in example nginx config listens for plain HTTP on container port `8080`; it is not a complete TLS production config by itself.

## Host or systemd Deployment

Build a release binary:

```bash
cargo build --release --bin auth-mini-gateway
sudo install -m 0755 target/release/auth-mini-gateway /usr/local/bin/auth-mini-gateway
```

Create a service user and data directory:

```bash
sudo useradd --system --home /var/lib/auth-mini-gateway --create-home auth-mini-gateway
sudo install -d -o auth-mini-gateway -g auth-mini-gateway -m 0750 /var/lib/auth-mini-gateway
sudo install -d -m 0750 /etc/auth-mini-gateway
```

Create `/etc/auth-mini-gateway/env`:

```env
HOST=127.0.0.1
PORT=3000
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
AUTH_MINI_ISSUER=https://auth.example.com
AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
GATEWAY_DB=/var/lib/auth-mini-gateway/auth-mini-gateway.sqlite
GATEWAY_COOKIE_SECRET=<strong-random-secret>
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
ALLOW_EMAILS=alice@example.com,bob@example.com
SESSION_TTL_SECONDS=604800
SESSION_ABSOLUTE_TTL_SECONDS=2592000
SESSION_TOUCH_INTERVAL_SECONDS=3600
LOGIN_STATE_TTL_SECONDS=600
REFRESH_SKEW_SECONDS=60
LOGOUT_REDIRECT=/
```

Protect the environment file because it contains `GATEWAY_COOKIE_SECRET`:

```bash
sudo chown root:auth-mini-gateway /etc/auth-mini-gateway/env
sudo chmod 0640 /etc/auth-mini-gateway/env
```

Create `/etc/systemd/system/auth-mini-gateway.service`:

```ini
[Unit]
Description=auth-mini gateway
After=network-online.target
Wants=network-online.target

[Service]
User=auth-mini-gateway
Group=auth-mini-gateway
EnvironmentFile=/etc/auth-mini-gateway/env
ExecStart=/usr/local/bin/auth-mini-gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/auth-mini-gateway

[Install]
WantedBy=multi-user.target
```

Start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now auth-mini-gateway
sudo systemctl status auth-mini-gateway
```

## nginx Configuration

Start from `examples/nginx.conf` and adjust upstream names, TLS, and server names.

Minimum requirements:

- Public routes proxy to the gateway: `/login`, `/auth/callback`, `/auth/callback/session`, `/logout`, `/healthz`.
- `/auth/check` is not public. Use an internal nginx location such as `/_auth`.
- Protected locations use `auth_request /_auth`.
- Denied requests do not reach the protected upstream.
- WebSocket locations keep `proxy_http_version 1.1`, `Upgrade`, and `Connection` headers.
- Strip browser cookies before proxying to upstream unless your upstream explicitly needs them.

Core pattern:

```nginx
map $http_upgrade $connection_upgrade {
  default upgrade;
  '' close;
}

location = /_auth {
  internal;
  proxy_pass http://gateway/auth/check;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Original-URI $request_uri;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header Cookie $http_cookie;
}

location / {
  auth_request /_auth;
  auth_request_set $auth_user_id $upstream_http_x_auth_mini_user_id;
  auth_request_set $auth_email $upstream_http_x_auth_mini_email;
  auth_request_set $auth_set_cookie $upstream_http_set_cookie;
  add_header Set-Cookie $auth_set_cookie always;
  error_page 401 = /__login_redirect;
  error_page 403 = @forbidden;
  error_page 500 = @auth_unavailable;
  proxy_intercept_errors off;

  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection $connection_upgrade;
  proxy_set_header Cookie "";
  proxy_set_header X-Auth-Mini-User-Id $auth_user_id;
  proxy_set_header X-Auth-Mini-Email $auth_email;
  proxy_pass http://protected_upstream;
}

location = /__login_redirect {
  internal;
  proxy_pass http://gateway/login;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Original-URI $request_uri;
  add_header Set-Cookie $auth_set_cookie always;
}

location @forbidden {
  return 403 "Forbidden\n";
}

location @auth_unavailable {
  add_header Cache-Control "no-store" always;
  add_header Retry-After "5" always;
  return 503 "Authentication service temporarily unavailable\n";
}
```

`auth_request` turns a subrequest status other than `2xx`, `401`, or `403` into a main-request `500`; the `error_page 500` mapping above deliberately converts that authentication-phase failure to `503`. Keep `proxy_intercept_errors off` so a protected upstream's own `500` remains `500`. Do not log `$http_cookie`, `$auth_set_cookie`, `Authorization`, callback bodies, or identity headers.

The first `add_header` propagates an idle-touch renewal to successful HTTP and WebSocket handshake responses. The redirect location's `add_header` preserves the independent `amg_session` clear header while proxied `/login` sets `amg_login_state`; both `Set-Cookie` headers are required.

## Verification Before Rollout

Run these checks before moving real users:

1. Health check:

   ```bash
   curl -i https://app.example.com/healthz
   ```

   Expected: `204 No Content`.

2. Unauthenticated request:

   ```bash
   curl -i https://app.example.com/
   ```

   Expected: redirect to auth-mini login. The upstream should not receive the request.

3. Browser login:

   Open `https://app.example.com/`, complete auth-mini login, and confirm the browser returns to the protected app.

4. Allowlist denial:

   Sign in as an auth-mini user outside `ALLOW_EMAILS` and `ALLOW_USER_IDS`.

   Expected: `403 Forbidden`; upstream should not receive the request.

5. Logout:

   Visit `https://app.example.com/logout` or call `POST /logout` through your UI.

   Expected: local gateway session revoked and later protected requests require login again.

6. WebSocket, if your app uses it:

   Confirm a logged-in browser can establish the app's WebSocket connection and an anonymous browser cannot.

7. Gateway restart persistence:

   Restart the gateway process while logged in.

   Expected: existing valid gateway sessions remain valid because they are stored in SQLite.

## Operations

### SQLite Persistence

The gateway uses SQLite WAL mode. Keep these files together during backup or restore:

- `auth-mini-gateway.sqlite`
- `auth-mini-gateway.sqlite-wal`
- `auth-mini-gateway.sqlite-shm`

Use one active writer. Do not run multiple active gateway instances against the same SQLite database.

### Backup

For simple single-host deployments, stop the gateway briefly and copy the database files together. For online backups, use SQLite backup tooling that understands WAL mode.

Backup the gateway DB separately from the auth-mini DB. The gateway DB contains gateway sessions and refresh-token material; protect it as sensitive data.

### Upgrades

Schema v2 is additive. It adds authoritative idle/absolute deadlines and identity-pending columns while retaining `session_expires_at` as an old-binary compatibility gate. Migration never extends a legacy session's existing deadline. An unknown future schema version or malformed legacy timestamp refuses startup.

1. Stop the single active writer and take a WAL-consistent backup.
2. Preserve the previous binary/image, environment, and nginx config.
3. Deploy the binary, lifecycle environment variables, and nginx config as one unit.
4. Start the gateway and confirm schema migration completes before opening traffic.
5. Verify login, a touch renewal with absolute `Expires` and no positive `Max-Age`, refresh, `503` isolation, logout, and WebSocket handshake.
6. Monitor pending-session count/age, SQLite errors, invalidation spikes, and refresh-flight outcomes.

Before rollout, run `scripts/e2e-old-binary-compat.sh` against the intended base ref (default `origin/master`), `scripts/e2e-wal-backup-restore.sh`, and `scripts/e2e-real-auth-mini.sh` against the pinned auth-mini source. The old-binary harness builds and runs the actual pre-change binary; it does not simulate old behavior with new code. The WAL drill uses SQLite's backup API while committed data remains in WAL frames, restores to a separate database, checks integrity/schema/snapshot boundaries, and starts the real gateway against the restored copy.

### Rollback

1. Keep `auth_request` or a maintenance deny in place; never expose the upstream during rollback.
2. Stop the new gateway and all refresh flights.
3. Restore the previous binary/image and old environment. Do not lower `user_version` or drop v2 columns.
4. Ready rows remain readable by the old binary. Pending rows have a past compatibility deadline and therefore fail closed; the old binary may prune them, requiring login again.
5. If the database is suspect, restore the WAL-consistent backup. A token rotated after that backup may be superseded and require login again.
6. Never repair Pending rows by manually copying tokens, email, or revocation values.

## Security Notes

- Do not log `Authorization` headers, callback bodies, access tokens, refresh tokens, signed gateway cookies, or `GATEWAY_COOKIE_SECRET`.
- Keep the gateway private. Public traffic should enter through nginx.
- Keep the protected upstream private. Public bypass around nginx defeats the gateway.
- Use HTTPS in production and set `COOKIE_SECURE=true`.
- Treat auth-mini as the authority for authentication methods. The gateway authorizes verified identities through exact email/user-id allowlists.
- Treat identity headers from `/auth/check` as data for the upstream, not as proof outside the nginx-protected path.

### Refresh and identity residuals

- The gateway disables automatic HTTP redirects for auth-mini calls. Redirect responses are unavailable results; in particular, a `307`/`308` cannot replay the refresh POST or its credentials to `Location`.
- JWKS, `/me`, and refresh success require exact `200 OK`. Other `2xx` responses are contract drift and fail closed without advancing identity state or token generation.
- A timeout, transport error, `429`, `5xx`, unknown response, parse failure, or other indeterminate refresh result denies the current request with `503`, keeps the local session, and permits a later independent request to retry.
- Only exact refresh-endpoint `401` errors `session_invalidated` and `session_superseded` are remote revoke authority. auth-mini currently may fold an internal failure into `session_invalidated`; alert on invalidation spikes and track an auth-mini follow-up to return `5xx` for internal errors.
- If auth-mini commits token rotation but its response is lost, all requests already joined to that flight receive `503`. A later independent refresh may receive `session_superseded`, conditionally revoke the old local generation, and require login. The gateway does not automatically retry a rotating POST.
- After successful rotation, tokens are durably `Pending` until fresh matching `/me` data is stored. Every non-fresh `/me` result—including exact `401 invalid_access_token`—keeps Pending and returns `503`; `/me` cannot revoke or clear the session.
- Logout is local-first and terminal. A failed remote logout never restores local access.

### Cookie deadlines

Positive `amg_session` and login-state cookies use only an absolute IMF-fixdate `Expires`. Session expiry comes directly from the database's effective idle/absolute deadline, so a slow upstream cannot shift it later. Clear cookies use both `Max-Age=0` and a 1970 `Expires`. The database remains the authorization authority if a client clock is wrong.

### Silent SSO capability gate

The pinned auth-mini evidence does not establish no-interaction session reuse for a top-level redirect. The capability gate is **FAIL / unsupported**. Do not claim silent SSO in production; it requires a separate auth-mini task and a real browser-flow gate.

## Troubleshooting

### Login redirects but callback fails

Check:

- `GATEWAY_PUBLIC_BASE_URL` exactly matches the public protected app origin.
- auth-mini can redirect to `${GATEWAY_PUBLIC_BASE_URL}/auth/callback`.
- Browser can reach `AUTH_MINI_PUBLIC_BASE_URL`.
- Gateway can reach `AUTH_MINI_ISSUER`.

### Gateway says auth-mini session is invalid

Check:

- `AUTH_MINI_ISSUER` exactly matches the JWT `iss` configured in auth-mini.
- `AUTH_MINI_ISSUER/jwks` is reachable from the gateway.
- auth-mini's clock and gateway host clock are reasonably synchronized.

### User logs in but gets 403

Check:

- User email is listed in `ALLOW_EMAILS`, or auth-mini user id is listed in `ALLOW_USER_IDS`.

### Sessions disappear after restart

Check:

- `GATEWAY_DB` points to persistent storage, not a container layer or temporary directory.
- `GATEWAY_COOKIE_SECRET` did not change.
- The gateway process can read and write the SQLite DB path.

### WebSocket fails after login

Check:

- nginx forwards `Upgrade` and `Connection` headers.
- The WebSocket route is inside the protected location that uses `auth_request`.
- The upstream supports WebSocket over the proxied path.
