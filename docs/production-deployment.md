# Production Deployment

This guide describes both supported modes of `auth-mini-gateway` with a
separately deployed auth-mini server. Public TLS remains terminated by Acorn
nginx in both modes.

## Choose a mode

`UPSTREAM_URL` is the mode gate:

- **Adapter mode:** leave it unset or exactly empty. The gateway serves auth
  routes and `/auth/check`; node-local nginx enforces `auth_request` and proxies
  the app. Unknown gateway routes remain `404`.
- **Proxy mode:** set one absolute `http`/`https` URL without credentials,
  query, or fragment. The gateway authenticates every non-owned route and
  streams it to that fixed target. A fixed base path is allowed.

The value is trusted operator configuration read only at startup. It is not a
routing template: request Host, paths, queries, forwarding fields, cookies,
redirects, and absolute-form authorities cannot change its scheme, authority,
DNS destination, or TLS SNI.

## Adapter topology

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

## Proxy topology for NAT-hosted OpenCode

```text
Browser
  -> Acorn nginx :443 (public TLS)
  -> Acorn loopback 127.0.0.1:18081 (frps TCP remotePort)
  -> authenticated TLS FRP tunnel
  -> Axiom frpc local target 127.0.0.1:7780
  -> auth-mini-gateway 127.0.0.1:7780
  -> OpenCode 127.0.0.1:4096

auth-mini-gateway -> auth-mini issuer (JWKS, refresh, logout)
```

Only nginx `:443` and the firewalled frps control port are externally reachable.
Acorn `18081`, Axiom `7780`, and OpenCode `4096` are loopback-only. FRP never
maps `3000` or `4096`. Acorn nginx remains the public TLS endpoint.

Minimal proxy-mode listener settings:

```env
HOST=127.0.0.1
PORT=7780
UPSTREAM_URL=http://127.0.0.1:4096
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256
GATEWAY_MAX_ACTIVE_UPSTREAMS=128
GATEWAY_MAX_BLOCKING_RESOLVERS=8
TRUSTED_PROXY_CIDRS=
```

Leave trust empty for initial rollout. Enable the exact observed frpc peer CIDR
only after Acorn nginx is proven to overwrite XFF with one `$remote_addr` value.

Production assumptions for both modes:

- One active gateway instance writes to one durable SQLite database.
- Acorn nginx terminates public TLS.
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
- That issuer URL must be reachable by the gateway because `AUTH_MINI_ISSUER` is used both as the expected JWT issuer and as the HTTP base for `/jwks`, `/session/refresh`, and `/session/logout`.
- Passkey deployments must use the correct auth-mini RP ID and browser origin for the auth-mini domain.
- Current auth-mini signs redirect logins with the callback hostname as the JWT audience. The gateway requires that exact audience: the normalized `GATEWAY_PUBLIC_BASE_URL` hostname must be the origin users actually complete login against, and each deployed gateway hostname needs its own gateway instance/config pair.
- Users who should reach the protected app must authenticate through auth-mini and match `ALLOW_USER_IDS` by exact auth-mini user id.

If your internal network uses a different service name than the public issuer, make the public issuer hostname resolvable from the gateway as well. Do not set `AUTH_MINI_ISSUER` to an internal URL unless auth-mini also signs tokens with that exact URL as `iss`.

## Gateway Configuration

Use these variables as the production baseline:

```env
HOST=0.0.0.0
PORT=3000
UPSTREAM_URL=
GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256
GATEWAY_MAX_ACTIVE_UPSTREAMS=128
GATEWAY_MAX_BLOCKING_RESOLVERS=8
TRUSTED_PROXY_CIDRS=
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
AUTH_MINI_ISSUER=https://auth.example.com
AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
AUTH_MINI_LOGIN_URL=
GATEWAY_DB=/data/auth-mini-gateway.sqlite
GATEWAY_COOKIE_SECRET=<strong-random-secret>
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
ALLOW_USER_IDS=<auth-mini-user-id-1>,<auth-mini-user-id-2>
SESSION_TTL_SECONDS=604800
SESSION_ABSOLUTE_TTL_SECONDS=2592000
SESSION_TOUCH_INTERVAL_SECONDS=3600
LOGIN_STATE_TTL_SECONDS=600
REFRESH_SKEW_SECONDS=60
LOGOUT_REDIRECT=/
```

Important settings:

- `GATEWAY_PUBLIC_BASE_URL` is the protected app origin served by nginx. It is used for callback redirects and return target validation. Its normalized hostname is also the required JWT audience for every initial, refreshed, and recovered access token; the login redirect adds an explicit `aud` parameter only for exact loopback origins.
- `UPSTREAM_URL` empty selects adapter mode. In proxy mode use one fixed
  loopback target, such as `http://127.0.0.1:4096`; invalid values stop startup
  without making a reachability request.
- `GATEWAY_MAX_DOWNSTREAM_CONNECTIONS` and `GATEWAY_MAX_ACTIVE_UPSTREAMS`
  default to `256` and `128`. Proxy mode requires `D >= U + 16`.
- `GATEWAY_MAX_BLOCKING_RESOLVERS` defaults to `8` and accepts `1..=32`.
  Domain resolution concurrency is `min(U,R)`; IPv4/IPv6 literals do not use R.
- `TRUSTED_PROXY_CIDRS` defaults empty. Every entry must include an explicit
  prefix. Trust applies only to the immediate socket peer and never changes
  authentication, routing, DNS, TLS, or pooling.
- `AUTH_MINI_ISSUER` must exactly match auth-mini's JWT issuer and must be reachable by the gateway.
- `AUTH_MINI_PUBLIC_BASE_URL` is the browser-visible auth-mini origin used to build the default login URL.
- `AUTH_MINI_LOGIN_URL` is optional. Set it only if the default `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login` is not correct for your auth-mini UI.
- `GATEWAY_DB` must point to persistent storage. Back up this file and its WAL files consistently.
- `GATEWAY_COOKIE_SECRET` must remain stable. Rotating it invalidates all browser gateway cookies.
- `COOKIE_SECURE` should be `true` for HTTPS production deployments.
- `ALLOW_USER_IDS` is the only authorization list: exact comma-separated auth-mini user IDs (JWT `sub` values). Obtain them from the auth-mini admin view or from existing gateway session rows, and provision them before rollout; an empty list denies every user. `ALLOW_EMAILS` is unsupported and any nonempty value fails startup with `allow_emails_unsupported`.
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
  -e GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256 \
  -e GATEWAY_MAX_ACTIVE_UPSTREAMS=128 \
  -e GATEWAY_MAX_BLOCKING_RESOLVERS=8 \
  -e GATEWAY_PUBLIC_BASE_URL=https://app.example.com \
  -e AUTH_MINI_ISSUER=https://auth.example.com \
  -e AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com \
  -e GATEWAY_DB=/data/auth-mini-gateway.sqlite \
  -e GATEWAY_COOKIE_SECRET='<strong-random-secret>' \
  -e COOKIE_SECURE=true \
  -e COOKIE_SAME_SITE=lax \
  -e ALLOW_USER_IDS='<auth-mini-user-id-1>,<auth-mini-user-id-2>' \
  -e SESSION_TTL_SECONDS=604800 \
  -e SESSION_ABSOLUTE_TTL_SECONDS=2592000 \
  -e SESSION_TOUCH_INTERVAL_SECONDS=3600 \
  -e LOGIN_STATE_TTL_SECONDS=600 \
  auth-mini-gateway:latest
```

Do not publish the gateway port directly to the internet. Let nginx reach it on a private interface or container network.

For proxy mode on a NAT host, bind the gateway to `127.0.0.1:7780`, configure
`UPSTREAM_URL=http://127.0.0.1:4096`, and let FRP map only `7780`. The statement
above means the listener remains behind Acorn nginx/FRP rather than becoming a
second public TLS endpoint.

## Docker Compose Deployment

`examples/docker-compose.yml` is a starting point. It builds the gateway and a demo upstream, but production deployments should provide their own auth-mini service and protected upstream.

Set environment values before starting the example topology:

```bash
export NGINX_PORT=8080
export GATEWAY_COOKIE_SECRET='<strong-random-secret>'
export AUTH_MINI_ISSUER=https://auth.example.com
export AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
export ALLOW_USER_IDS='<auth-mini-user-id-1>,<auth-mini-user-id-2>'
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
GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256
GATEWAY_MAX_ACTIVE_UPSTREAMS=128
GATEWAY_MAX_BLOCKING_RESOLVERS=8
TRUSTED_PROXY_CIDRS=
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
AUTH_MINI_ISSUER=https://auth.example.com
AUTH_MINI_PUBLIC_BASE_URL=https://auth.example.com
GATEWAY_DB=/var/lib/auth-mini-gateway/auth-mini-gateway.sqlite
GATEWAY_COOKIE_SECRET=<strong-random-secret>
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
ALLOW_USER_IDS=<auth-mini-user-id-1>,<auth-mini-user-id-2>
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
LimitNOFILE=4096
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

### Adapter mode

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

### Acorn proxy mode

Use `examples/nginx-proxy.conf` as the directly deployable server. Its `map`
belongs in the `http` context. The relevant server is:

```nginx
map $http_upgrade $gateway_connection {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate     /etc/nginx/tls/app.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/app.example.com.key;

    underscores_in_headers on;
    ignore_invalid_headers on;
    client_max_body_size 0;
    client_body_timeout 24h;
    send_timeout 24h;

    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_http_version 1.1;
        proxy_set_header Cookie $http_cookie;
        proxy_pass_header Set-Cookie;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header X-Real-IP "";
        proxy_set_header X-Forwarded-Port "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $gateway_connection;

        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
        gzip off;
        proxy_connect_timeout 10s;
        proxy_send_timeout 24h;
        proxy_read_timeout 24h;
        proxy_socket_keepalive on;
        proxy_intercept_errors off;
        proxy_next_upstream off;
        proxy_redirect off;
    }
}
```

This is one all-path gateway location. It deliberately has no `auth_request`,
Cookie clear, `$proxy_add_x_forwarded_for`, response buffering, request
buffering, or proxy retry. Both header directives are explicit: underscore
aliases reach the hardened gateway for rejection, while other nginx-invalid
headers remain discarded.

## FRP v0.64.0+ configuration

`auth.tokenSource` requires frp v0.64.0 or newer. Pin matching frps/frpc
versions. Use `examples/frps.toml` on Acorn:

```toml
bindAddr = "0.0.0.0"
bindPort = 7000
proxyBindAddr = "127.0.0.1"
allowPorts = [{ single = 18081 }]
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/token"
transport.tls.force = true
transport.tls.certFile = "/etc/frp/tls/server.crt"
transport.tls.keyFile = "/etc/frp/tls/server.key"
```

Use `examples/frpc.toml` on Axiom:

```toml
serverAddr = "frp.example.com"
serverPort = 7000
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/token"
transport.tls.enable = true
transport.tls.trustedCaFile = "/etc/frp/tls/ca.crt"
transport.tls.serverName = "frp.example.com"

[[proxies]]
name = "auth-mini-gateway"
type = "tcp"
localIP = "127.0.0.1"
localPort = 7780
remotePort = 18081
```

There is no PROXY protocol. Firewall frps `7000` to Axiom. Validate before
cutover:

```bash
nginx -t
frps verify -c /etc/frp/frps.toml
frpc verify -c /etc/frp/frpc.toml
frps --version
frpc --version
```

## Capacity, FD, thread, and memory gates

Startup refuses a finite soft `RLIMIT_NOFILE` below the checked mode budget:

```text
proxy required  = D + U + 8 + 1 + 512  # defaults: 905
adapter required = D + 1 + 512           # defaults: 769
```

Keep `LimitNOFILE=4096`. Resolver work adds no separate FD term because it is
already one U phase. The Tokio blocking ceiling is exactly `64 + R + 16`, so
defaults log `88` and R=32 logs `112`. FD capacity does not prove thread or
memory capacity. Record these independently:

```bash
systemctl show auth-mini-gateway -p LimitNOFILE -p TasksMax -p MemoryMax
grep -E '^(Threads|VmRSS|VmSize):' /proc/$(pidof auth-mini-gateway)/status
```

Under the R-resolver plus 64-auth stress gate, record peak thread and memory
values. If `MemoryMax` is finite, retain at least 25% above measured peak RSS.
If `TasksMax` is finite, leave room for main + Tokio async workers + the logged
blocking maximum + 32 non-Tokio/process slots.

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

   Sign in as an auth-mini user outside `ALLOW_USER_IDS`.

   Expected: `403 Forbidden`; upstream should not receive the request.

5. Logout:

   Visit `https://app.example.com/logout` or call `POST /logout` through your UI.

   Expected: local gateway session revoked and later protected requests require login again.

6. WebSocket, if your app uses it:

   Confirm a logged-in browser can establish the app's WebSocket connection and an anonymous browser cannot.

   In proxy mode, also test a long-lived SSE response and an upload larger than
   64 KiB. Proxy request and response bodies are streamed; only the local login
   callback body has the 64 KiB control-plane limit.

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

Before rollout, run `scripts/e2e-old-binary-compat.sh` against the pinned
pre-lifecycle ref (default `f0519d1`, overridable with `OLD_GATEWAY_REF`),
`scripts/e2e-wal-backup-restore.sh`, and `scripts/e2e-real-auth-mini.sh` against
the pinned auth-mini source (set `AUTH_MINI_BIN` to exercise the exact
auth-mini release binary being deployed). Also run `scripts/e2e-proxy-mode.sh` and
`scripts/e2e-mode-switch.sh`; they use local ephemeral fixtures and explicitly
report missing prerequisites or operator-requested skips. The old-binary
harness builds and runs the actual
pre-change binary; it does not simulate old behavior with new code. The WAL
drill uses SQLite's backup API while committed data remains in WAL frames,
restores to a separate database, checks integrity/schema/snapshot boundaries,
and starts the real gateway against the restored copy.

### User-ID and audience migration

Current auth-mini binds redirect logins to the callback hostname as a signed JWT audience and reserves `/me` for self-audience tokens. This gateway binary enforces that contract: it derives the expected audience from the `GATEWAY_PUBLIC_BASE_URL` hostname, requires it on initial, refreshed, and recovered tokens, and authorizes only exact `ALLOW_USER_IDS` values.

1. Obtain exact auth-mini user IDs for every allowed user from the auth-mini admin view (**Admin → Users** lists each user's ID and email; the admin API is `GET /admin/users` with an administrator self-audience token), from a read-only query on the auth-mini host (`SELECT id FROM users WHERE email = '<email>'` against the auth-mini SQLite database), or from existing gateway session rows (`SELECT DISTINCT user_id FROM gateway_sessions`; never copy token columns). The `/integration/user-ids` directory returns IDs only and cannot map an email to an ID.
2. Set `ALLOW_USER_IDS` on each gateway service and remove or empty `ALLOW_EMAILS`; a nonempty `ALLOW_EMAILS` intentionally blocks startup.
3. Deploy the fixed gateway to each distinct public hostname; two hostnames sharing one auth-mini issuer require separate expected audiences and therefore separate gateway configs.
4. Complete a fresh login and refresh drill per hostname before opening traffic.

Existing Ready sessions remain usable under user-ID policy until their recorded access refresh boundary. A legacy session whose next token carries the issuer audience or no audience is conditionally revoked at refresh or Pending recovery and the browser logs in again; the migration window is bounded by the recorded refresh boundary and never broadens access. Users whose IDs were not provisioned receive `403` until provisioned.

### Rollback

1. Keep `auth_request` or a maintenance deny in place; never expose the upstream during rollback.
2. Stop the new gateway and all refresh flights.
3. Restore the previous binary/image and old environment. Do not lower `user_version` or drop v2 columns.
4. Ready rows remain readable by the old binary, including new rows with NULL email. Pending rows have a past compatibility deadline and therefore fail closed; the old binary may prune them, requiring login again.
5. If the database is suspect, restore the WAL-consistent backup. A token rotated after that backup may be superseded and require login again.
6. Never repair Pending rows by manually copying tokens, email, or revocation values.
7. Rolling back only the gateway cannot restore fresh login or refresh against current auth-mini, because the previous gateway depends on the now self-audience-only `/me`. Prefer rolling forward. Full functional rollback requires the previous gateway binary together with a pre-audience auth-mini deployment.

### Proxy-mode rollout and old-binary rollback

The proxy listeners never change meaning:

- Acorn nginx public TLS: `:443`;
- Acorn frps remote listener: `127.0.0.1:18081`;
- Axiom gateway: `127.0.0.1:7780`, with
  `UPSTREAM_URL=http://127.0.0.1:4096`;
- OpenCode: `127.0.0.1:4096` only.

For hardened rollout, keep public traffic maintenance-denied, start the new
gateway, and set the candidate nginx server explicitly to:

```nginx
underscores_in_headers on;
ignore_invalid_headers on;
```

Run `nginx -t`, reload, verify the exact `18081 -> 7780 -> 4096` path, and test
HTTP, streaming upload, SSE, WebSocket, U/R saturation, trusted XFF, and the
underscore `400` before removing maintenance.

An old proxy binary cannot safely receive underscore aliases. Rollback is
therefore ordered and fail-closed:

1. Enable maintenance deny while retaining a loopback/operator path through
   the candidate server block. Do not use a local `return 503` path that skips
   proxy header parsing.
2. Apply `examples/nginx-proxy-rollback.conf`, which pins:

   ```nginx
   underscores_in_headers off;
   ignore_invalid_headers on;
   ```

3. Run `nginx -t`. On failure, remain denied and stop.
4. Reload nginx under maintenance and verify reload success.
5. While the hardened gateway still serves `7780`, send a raw anonymous,
   non-owned request through that exact candidate server path:

   ```bash
   printf 'GET /rollback-alias-probe HTTP/1.1\r\nHost: app.example.com\r\nX_Auth_Mini_User_Id: attacker\r\nConnection: close\r\n\r\n' \
     | openssl s_client -quiet -connect 127.0.0.1:443 -servername app.example.com
   ```

   Require the normal anonymous `302`, zero OpenCode hit, and not the hardened
   underscore `400`. This proves nginx discarded the alias.
6. If the probe is missing or inconclusive, remain denied. Otherwise stop the
   hardened gateway, wait for process/SQLite release, start the prior verified
   binary on `127.0.0.1:7780`, and verify auth/cookies/HTTP/SSE/WebSocket.
7. Keep `LimitNOFILE=4096`, canonical XFF overwrite, FRP `18081 -> 7780`, and
   loopback OpenCode. Remove maintenance only after all checks pass.

If the prior proxy fails, use the separately approved adapter rollback. Never
point FRP at OpenCode `4096`. In-flight streams and tunnels close on switch; no
database restore is required solely for this binary rollback.

## Security Notes

- Do not log `Authorization` headers, callback bodies, access tokens, refresh tokens, signed gateway cookies, or `GATEWAY_COOKIE_SECRET`.
- Keep the gateway private. Public traffic should enter through nginx.
- Keep the protected upstream private. Public bypass around nginx defeats the gateway.
- Use HTTPS in production and set `COOKIE_SECURE=true`.
- Treat auth-mini as the authority for authentication methods. The gateway authorizes verified identities through the exact `ALLOW_USER_IDS` allowlist only.
- Treat identity headers from `/auth/check` as data for the upstream, not as proof outside the nginx-protected path.
- In proxy mode, the gateway strips browser `Cookie`, `Authorization`,
  `Proxy-Authorization`, inbound `Forwarded`/`X-Forwarded-*`, spoofed
  `X-Auth-Mini-*`, fixed hop-by-hop fields, and every field nominated by
  `Connection`. It rejects underscore header names before auth and injects only
  the verified user ID.
- The proxy preserves the external Host for application semantics but never
  uses it to select the upstream. `X-Forwarded-Proto` comes from
  `GATEWAY_PUBLIC_BASE_URL`, `X-Forwarded-Host` from the accepted Host, and one
  canonical `X-Forwarded-For` from the direct peer by default. An explicitly
  trusted immediate peer may supply exactly one strict bare IP. The value never
  influences gateway auth, routing, DNS, TLS, or pooling.
- Established WebSockets are authorized at handshake time. A later logout
  blocks new handshakes but does not terminate an already established tunnel.
- Do not configure the protected app to rely on browser cookies or a generic
  Authorization header in proxy mode; those credentials are deliberately not
  forwarded.

### Refresh and identity residuals

- The gateway disables automatic HTTP redirects for auth-mini calls. Redirect responses are unavailable results; in particular, a `307`/`308` cannot replay the refresh POST or its credentials to `Location`.
- JWKS and refresh success require exact `200 OK`. Other `2xx` responses are contract drift and fail closed without advancing identity state or token generation.
- A timeout, transport error, `429`, `5xx`, unknown response, parse failure, or other indeterminate refresh result denies the current request with `503`, keeps the local session, and permits a later independent request to retry.
- Only exact refresh-endpoint `401` errors `session_invalidated` and `session_superseded` are remote revoke authority. auth-mini currently may fold an internal failure into `session_invalidated`; alert on invalidation spikes and track an auth-mini follow-up to return `5xx` for internal errors.
- If auth-mini commits token rotation but its response is lost, all requests already joined to that flight receive `503`. A later independent refresh may receive `session_superseded`, conditionally revoke the old local generation, and require login. The gateway does not automatically retry a rotating POST.
- After successful rotation, tokens are durably `Pending` until the persisted access JWT is re-verified locally (signature, issuer, exact gateway-hostname audience, matching `sub`/`sid`) and the row finalizes to Ready with no email. No `/me` call occurs in callback, refresh, or crash recovery.
- A cryptographically valid refreshed or recovered token signed for another audience is terminal for that local generation: the expected generation is conditionally revoked and the browser must log in again. Temporary or uncertain verification failures still return `503` without revoking.
- Logout is local-first and terminal. A failed remote logout never restores local access.

### Cookie deadlines

Positive `amg_session` and login-state cookies use only an absolute IMF-fixdate `Expires`. Session expiry comes directly from the database's effective idle/absolute deadline, so a slow upstream cannot shift it later. Clear cookies use both `Max-Age=0` and a 1970 `Expires`. The database remains the authorization authority if a client clock is wrong.

### Silent SSO capability gate

auth-mini `156484e` and later reuse the browser's auth-mini main-site session for the gateway's top-level login redirect and return a delegated gateway-audience session (`amr` includes `sso`). The gateway needs no configuration for this. Gateway logout revokes only the delegated session; to force a fresh interactive login, also sign out on the auth-mini site. See [silent-sso-capability.md](silent-sso-capability.md) for the evidence boundary.

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
- The token audience matches the gateway: current auth-mini signs `aud` as the normalized `GATEWAY_PUBLIC_BASE_URL` hostname (or, for a multi-audience session, an array that must contain it). A token minted for another downstream hostname, or an older token with issuer/no audience, is rejected at callback and conditionally revoked at refresh or Pending recovery.
- auth-mini's clock and gateway host clock are reasonably synchronized.

### User logs in but gets 403

Check:

- The user's exact auth-mini user id (JWT `sub`) is listed in `ALLOW_USER_IDS`. Email is not an authorization input; `ALLOW_EMAILS` is unsupported and blocks startup when nonempty.

### Sessions disappear after restart

Check:

- `GATEWAY_DB` points to persistent storage, not a container layer or temporary directory.
- `GATEWAY_COOKIE_SECRET` did not change.
- The gateway process can read and write the SQLite DB path.

### WebSocket fails after login

Check:

- In adapter mode, nginx forwards `Upgrade` and `Connection` and the route is
  inside the protected `auth_request` location.
- In proxy mode, FRP/Acorn preserve HTTP/1.1 upgrade traffic to gateway `7780`,
  the app listens on loopback `4096`, and the app returns the exact RFC 6455
  accept/subprotocol response.
- The upstream supports WebSocket over the proxied path.
