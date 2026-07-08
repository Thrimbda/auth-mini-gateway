# Walkthrough: Production Rust/SQLite Gateway

## Mode

implementation

## Reviewer Summary

This change replaces the TypeScript PoC gateway with a Rust service backed by SQLite WAL persistence. The gateway keeps auth-mini external, consumes auth-mini HTTP/JWKS contracts, and continues to rely on nginx `auth_request` for protected HTTP/WebSocket upstream traffic.

## Main Changes

- Added Rust project files: `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, and `src/main.rs`.
- Implemented runtime config parsing in `src/config.rs` for public/auth-mini URLs, SQLite DB path, cookie settings, TTLs, allowlists, Passkey policy, and logout redirect.
- Implemented signed opaque cookies in `src/cookies.rs` for `amg_session` and `amg_login_state`.
- Implemented SQLite store in `src/db.rs` with WAL initialization, session/login-state tables, TTL pruning, durable revocation, and refresh compare-and-swap.
- Implemented minimal HTTP handling in `src/http.rs`, including response header safety checks against response splitting.
- Implemented auth-mini client and JWT/JWKS verification in `src/auth_mini.rs` and `src/jwt.rs`.
- Implemented gateway routes in `src/server.rs`: `/healthz`, `/login`, `/auth/callback`, `/auth/callback/session`, `/auth/check`, and `/logout`.
- Replaced Node Docker/docs/examples with Rust runtime packaging and SQLite configuration.
- Added `examples/upstream.rs`, a small Rust HTTP/WebSocket protected upstream used by examples and E2E.
- Added `scripts/e2e-real-auth-mini.sh`, which runs real auth-mini, Rust gateway, nginx, and protected upstream end to end.
- Removed production Node/TypeScript files, npm config, mock auth-mini, mock upstream, and npm smoke test.

## Security-Relevant Behavior

- Browser cookies contain only signed opaque IDs, not auth-mini access/refresh tokens.
- Login state is persisted, one-time, TTL-bound, and cleared after callback.
- Callback verifies EdDSA JWTs against auth-mini `/jwks`, validates issuer/type/expiry/sub/sid/amr, requires callback `session_id` to match JWT `sid`, and fetches `/me` before creating a gateway session.
- Access-token refresh uses persisted refresh tokens and SQLite CAS semantics so stale refreshes cannot overwrite logout or newer refresh state.
- Logout revokes the local session durably and attempts auth-mini logout best-effort.
- Authorization is deny-by-default using email/user-id allowlists and optional `webauthn` `amr` requirement.
- Unsafe identity header values are denied before forwarding `X-Auth-Mini-*` headers through nginx.
- E2E diagnostics avoid logging access tokens, refresh tokens, session cookies, cookie secrets, or callback bodies.

## Verification Evidence

- `cargo fmt && cargo test && cargo build --bin auth-mini-gateway --example upstream`: PASS with 11 unit tests.
- `scripts/e2e-real-auth-mini.sh`: PASS with real auth-mini, Rust gateway, nginx, and protected HTTP/WebSocket upstream.
- `docs/review-change.md`: PASS after security review, no blocking findings.

## Known Limitations

- Full browser/virtual-authenticator WebAuthn automation was not implemented in the E2E harness. The fallback is documented in `docs/test-report.md`: real auth-mini Email OTP issuance/refresh/logout is E2E-tested, while Passkey policy is covered by unit tests.
- `GET /logout` remains enabled as compatibility convenience per the RFC; POST remains the preferred method.
- The supported production topology is one active gateway instance with local durable SQLite WAL storage, not multi-active SQLite sharing.

## Reviewer Pointers

- Start with `src/server.rs` for route behavior and auth flow.
- Check `src/db.rs` for persistence, revocation, and refresh CAS semantics.
- Check `src/jwt.rs` and `src/auth_mini.rs` for auth-mini boundary handling.
- Check `scripts/e2e-real-auth-mini.sh` for end-to-end proof against real auth-mini and nginx.
- Check `.legion/tasks/production-rust-sqlite-gateway/docs/test-report.md` and `review-change.md` for evidence and review status.
