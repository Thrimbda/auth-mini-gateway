# Task Summary: production-rust-sqlite-gateway

## Status

- Implementation completed in worktree branch `legion/production-rust-sqlite-gateway`.
- RFC review passed before implementation.
- Verification passed: Rust unit/build checks plus real auth-mini + Rust gateway + nginx + protected HTTP/WebSocket upstream E2E.
- Readiness/security review passed with no blocking findings after fixing initial review blockers.

## Outcome

The repository now contains a production-oriented Rust/SQLite auth-mini gateway. It supersedes the earlier TypeScript PoC runtime for production behavior.

Implemented capabilities:

- Rust gateway binary with low-dependency std TCP HTTP handling
- SQLite WAL-backed durable sessions and login state
- one-time login state with TTL and persisted consume marker
- opaque HMAC-signed HttpOnly browser cookies
- auth-mini `/jwks` fetch/cache and EdDSA JWT verification
- auth-mini `/me`, `/session/refresh`, and `/session/logout` integration
- durable refresh-token rotation with SQLite compare-and-swap
- logout and refresh-failure local revocation
- deny-by-default allowlist policy with optional `webauthn` `amr` requirement
- first-party callback bridge for auth-mini fragment redirects
- nginx `auth_request` compatibility for HTTP and WebSocket upstreams
- Docker/Compose/docs updated for Rust runtime
- real auth-mini E2E harness using seeded Email OTP and nginx

## Key Evidence

- Plan: `.legion/tasks/production-rust-sqlite-gateway/plan.md`
- RFC: `.legion/tasks/production-rust-sqlite-gateway/docs/rfc.md`
- RFC review: `.legion/tasks/production-rust-sqlite-gateway/docs/rfc-review.md`
- Test report: `.legion/tasks/production-rust-sqlite-gateway/docs/test-report.md`
- Change review: `.legion/tasks/production-rust-sqlite-gateway/docs/review-change.md`
- Walkthrough: `.legion/tasks/production-rust-sqlite-gateway/docs/report-walkthrough.md`
- PR body draft: `.legion/tasks/production-rust-sqlite-gateway/docs/pr-body.md`

## Important Design Notes

- Production topology is one active gateway instance with durable SQLite WAL storage. Multi-active gateway instances sharing one SQLite file remain out of scope.
- auth-mini stays external and unmodified; the gateway consumes its HTTP/JWKS contracts.
- Browser cookies never contain auth-mini access or refresh tokens; token material stays in SQLite.
- Refresh writeback requires the old persisted refresh token to still match and the session to remain unrevoked.
- Unsafe identity values are denied before forwarding `X-Auth-Mini-*` headers through nginx.
- E2E uses real auth-mini Email OTP issuance, refresh, and logout. Full browser WebAuthn automation remains a follow-up; Passkey policy is unit-tested via `amr`.

The later `remove-auth-method-policy` task supersedes the optional `webauthn` authorization requirement. Current gateway authorization uses identity allowlists only; auth-mini owns authentication methods.

## Residual Follow-Up

- Add full browser/virtual-authenticator WebAuthn E2E when the environment supports it.
- Add E2E callback/login-state replay assertions.
- Validate `AUTH_MINI_LOGIN_URL` during config parsing.
- Document operational assumptions for direct gateway exposure hardening.
- Before OpenCode rollout, verify the protected upstream is not directly reachable from any public origin.
