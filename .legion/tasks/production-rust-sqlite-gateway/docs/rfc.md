# RFC: Production Rust/SQLite Gateway

## Status

- **Task:** `production-rust-sqlite-gateway`
- **Profile:** heavy implementation RFC
- **Decision:** proposed

## Context

The current gateway is a validated TypeScript PoC. The new requirement is to stop treating the gateway as a PoC and rebuild it as a production-grade Rust/SQLite system, matching auth-mini's operational style.

The production target is explicitly a single active gateway instance backed by durable SQLite WAL storage. Multi-active gateway instances sharing one SQLite file are out of scope.

## Goals

- Replace production gateway runtime with Rust.
- Persist gateway sessions and login state in SQLite.
- Keep auth-mini as the external auth authority and consume its existing HTTP/JWKS contracts.
- Preserve nginx `auth_request` as the upstream protection boundary.
- Prove behavior with real auth-mini + gateway + nginx + upstream E2E, not mock-only tests.

## Non-Goals

- No OIDC provider work.
- No Passkey/WebAuthn implementation inside the gateway.
- No RBAC/organization/admin UI/multi-tenant product scope.
- No multi-active SQLite session store.
- No direct upstream reverse proxying inside the gateway.

## Proposed Stack

Use a Rust binary with a small dependency set aligned with auth-mini:

- `rusqlite` with `bundled` SQLite for persistent storage.
- `rusqlite_migration` for versioned schema initialization.
- `serde`, `serde_json`, `chrono`, `sha2`, `url`.
- std TCP HTTP handling to match auth-mini's low-dependency server shape, unless implementation discovers an unavoidable protocol gap.
- `ureq` or similarly small blocking HTTP client for auth-mini calls.
- JWT/JWK verification implemented with focused crypto crates for EdDSA/JWKS verification, or a minimal vetted JWT crate if it keeps the dependency surface smaller and reviewable.

Rationale:

- Using the same std + `rusqlite` style avoids introducing a separate web framework/runtime stack.
- Blocking HTTP and SQLite fit the single active instance model.
- The gateway is front-auth glue, not a high-concurrency API gateway.

## Service Endpoints

- `GET /healthz`: non-sensitive health check.
- `GET /login`: validates `return_to` or `X-Original-URI`, creates durable one-time login state, sets state cookie, redirects to auth-mini login URL.
- `GET /auth/callback`: serves the first-party bridge page that reads URL fragment token data.
- `POST /auth/callback/session`: validates one-time state, verifies access token, checks `sid`, calls `/me`, persists gateway session, sets opaque session cookie, returns safe redirect target or `403` for authenticated unauthorized users.
- `GET /auth/check`: nginx-facing auth endpoint; validates session cookie, loads durable session, refreshes if needed, checks policy, returns `204`, `401`, or `403`.
- `POST /logout`: durably revokes gateway session, clears cookie, attempts auth-mini `/session/logout`.
- `GET /logout`: optional compatibility convenience only if documented as non-preferred.

## SQLite Schema

`gateway_sessions`:

- `id TEXT PRIMARY KEY`
- `auth_session_id TEXT NOT NULL`
- `access_token TEXT NOT NULL`
- `refresh_token TEXT NOT NULL`
- `user_id TEXT NOT NULL`
- `email TEXT`
- `amr_json TEXT NOT NULL`
- `access_expires_at TEXT NOT NULL`
- `session_expires_at TEXT NOT NULL`
- `revoked_at TEXT`
- `refresh_generation INTEGER NOT NULL DEFAULT 0`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

`login_states`:

- `id TEXT PRIMARY KEY`
- `return_to TEXT NOT NULL`
- `expires_at TEXT NOT NULL`
- `consumed_at TEXT`
- `created_at TEXT NOT NULL`

Startup behavior:

- open DB path from config
- create parent directory if needed
- enable `PRAGMA journal_mode = WAL`
- apply migrations atomically
- prune expired login states and expired/revoked sessions opportunistically on startup and during request paths

## Cookie Model

- `amg_session`: opaque session id plus HMAC using `GATEWAY_COOKIE_SECRET`.
- `amg_login_state`: opaque login state id plus HMAC.
- Cookies are `HttpOnly`, `Path=/`, `SameSite=Lax` by default, and `Secure` by default unless explicitly disabled for local HTTP testing.
- Malformed cookies are treated as absent, never as server errors.

## Token Verification And auth-mini Client

The gateway must:

- fetch and cache auth-mini `/jwks`
- verify EdDSA JWT signature
- validate `iss`, `exp`, `typ: access`, `sub`, `sid`, and `amr`
- require callback `session_id` to equal JWT `sid`
- fetch `/me` with the verified access token to get email and identity details
- refresh via `POST /session/refresh`
- call `/session/logout` on gateway logout best-effort, while local revocation remains deterministic

## Refresh And Revocation Concurrency

Refresh must be durable and race-safe:

- perform refresh under a SQLite transaction or compare-and-swap update
- only update a session if it still exists, is not revoked, and the stored `refresh_generation` or old refresh token matches the request that initiated refresh
- increment `refresh_generation` on successful refresh
- if another request already refreshed the same session, use the newer stored session instead of deleting it
- if logout happens while refresh is in flight, refresh writeback must fail and the session must remain revoked

This preserves prior PoC hardening in a durable store.

## Authorization Policy

Configuration:

- `ALLOW_EMAILS`
- `ALLOW_USER_IDS`
- `REQUIRE_PASSKEY`

Behavior:

- deny unknown users
- allow email or user-id matches
- when `REQUIRE_PASSKEY=true`, require `amr` to include `webauthn`
- persist authenticated-but-unauthorized sessions so nginx can consistently return `403`

## nginx Integration

Keep the previous boundary:

- public routes: `/login`, `/auth/callback`, `/auth/callback/session`, `/logout`, `/healthz`
- internal-only route: `/auth/check`
- protected upstream catch-all uses `auth_request /_auth`
- denied requests must not reach upstream
- WebSocket `Upgrade` and `Connection` headers remain forwarded by nginx after auth passes
- upstream service is not directly published in Compose

## Migration From TypeScript PoC

- Remove Node production entrypoints and dependencies after Rust replacement is complete.
- Keep only non-production helpers if explicitly needed for E2E and documented.
- Dockerfile builds the Rust binary and runs it as production command.
- README and `.env.example` describe Rust/SQLite runtime, not Node.
- Existing Legion PoC docs remain historical evidence.

## E2E Verification Strategy

Mandatory E2E deploys:

- real auth-mini Rust server
- production Rust gateway
- nginx
- protected HTTP/WebSocket upstream

Mandatory checks:

- real auth-mini issues tokens through real HTTP endpoint, preferably seeded Email OTP as auth-mini's own Rust E2E does
- gateway callback creates durable session from real auth-mini tokens
- gateway restart preserves valid session from SQLite
- expired access token refreshes through real auth-mini `/session/refresh`
- refresh failure revokes durable gateway session
- logout durably revokes session and cannot be undone by in-flight refresh
- allowlist denial returns `403` and does not reach upstream
- unauthenticated request redirects to login and does not reach upstream
- authorized HTTP reaches upstream
- authorized WebSocket reaches upstream
- upstream is not directly exposed

Passkey-specific verification:

- Best target: use a real auth-mini WebAuthn credential flow, either through a browser/virtual authenticator harness or by porting auth-mini's test credential generator into the E2E harness.
- Minimum acceptable fallback if browser/WebAuthn automation is not available: real auth-mini token issuance via Email OTP/Ed25519 plus a documented explicit limitation, and a separate policy test proving `REQUIRE_PASSKEY=true` rejects real non-`webauthn` `amr` tokens. This fallback is not a full Passkey E2E and must be called out in `test-report.md`.

## Rollback

- Revert PR to restore the TypeScript PoC gateway.
- Operational rollback before deploy remains removing nginx gateway front-auth integration and returning to the previous Basic Auth setup.
- SQLite schema is new for the Rust gateway; no existing production gateway DB migration is required.

## Alternatives Considered

### Keep TypeScript and add SQLite

- Pros: smallest implementation diff.
- Cons: directly violates user requirement to use auth-mini's Rust/SQLite stack.
- Decision: reject.

### Rust with a full async web framework

- Pros: mature routing and middleware.
- Cons: deviates from auth-mini's low-dependency runtime and adds framework behavior to a small front-auth adapter.
- Decision: reject by default; revisit only if std HTTP blocks required correctness.

### Multi-instance session store

- Pros: higher availability.
- Cons: conflicts with selected single-active SQLite deployment target and adds distributed coordination.
- Decision: out of scope.

## Open Risks

- Passkey full automation may require extra harness work; design review must decide whether fallback is acceptable for this task.
- JWT/JWKS verification crate selection needs security review before implementation if not implemented minimally.
- Replacing the project stack may invalidate current npm-based smoke scripts; verification must prove the new Rust path independently.
