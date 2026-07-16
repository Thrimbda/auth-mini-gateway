# Wiki Log

## 2026-07-08

- Created initial wiki for `auth-mini-gateway-poc`.
- Added task summary, current decisions, reusable front-auth/refresh/callback patterns, and maintenance follow-up items.
- Added `production-rust-sqlite-gateway` task summary after implementation, verification, review, and walkthrough.
- Updated decisions to make Rust/SQLite single-active gateway the current production runtime and demote the TypeScript PoC to historical status.
- Added real auth-mini E2E and auth_request identity-header patterns.
- Updated maintenance follow-ups for WebAuthn browser smoke, replay assertions, login URL validation, and direct gateway exposure documentation.
- Added `production-deployment-docs` task summary after docs implementation, verification, review, and walkthrough.
- Updated current decisions with docs entry points, stricter `AUTH_MINI_ISSUER` deployment guidance, and rollback access-control requirements.
- Replaced direct-exposure documentation follow-up with ongoing production-doc maintenance and compromise rollback follow-ups.

## 2026-07-10

- Added `remove-auth-method-policy` task summary.
- Updated current authorization truth: auth-mini owns authentication methods; gateway enforces exact identity allowlists without branching on `amr`.

## 2026-07-13

- Added the `harden-mobile-session-lifecycle` task summary after Heavy RFC review, implementation, full verification, security remediation, and walkthrough.
- Updated current decisions for 7-day inactivity, 30-day absolute lifetime, schema v2 no-extension migration, exact refresh rejection, no redirects, exact `200 OK`, absolute Cookie expiry, and non-redirecting `503` behavior.
- Expanded refresh-race and real-E2E patterns with shared-result single-flight, durable identity pending, old-binary compatibility, and WAL backup/restore.
- Recorded external auth-mini follow-ups for silent SSO, refresh result recovery, and internal-error status separation, plus a physical Safari smoke.

## 2026-07-15

- Added the `authenticated-reverse-proxy` task summary after Heavy RFC review, async implementation, full verification, security remediation, and reviewer walkthrough.
- Superseded the nginx-only proxy decision with two explicit modes: default `auth_request` adapter or one fixed authenticated upstream proxy selected by `UPSTREAM_URL`.
- Added durable decisions for shared authentication, static destination authority, local control-route precedence, browser-secret stripping, and verified identity injection.
- Added the authenticated fixed-upstream proxy pattern covering streaming, one-attempt pooling, WebSocket validation, and early-final upload cancellation.
- Recorded environment follow-ups for the external real-auth-mini composed run, physical Acorn/FRP mode switch, and richer secret-safe observability.

## 2026-07-16

- Added the `harden-proxy-production-boundaries` task summary after repeated RFC review, implementation, independent verification, security remediation, and walkthrough.
- Added current decisions for D/U/R capacity, full sender/driver/resolver ownership, auth-worker isolation, exact RLIMIT startup validation, recoverable accept backoff, and sanitized fatal/panic boundaries.
- Added current trust decisions for underscore-header rejection and explicit immediate-peer CIDR plus one-value XFF handling.
- Added reusable lifetime-owned capacity and trusted-forwarding handoff patterns.
- Replaced the abstract proxy rollout follow-up with exact Acorn `18081`, Axiom `7780`, OpenCode `4096`, systemd resource, trusted-peer, and rollback evidence gates.

## 2026-07-17

- Added the `enable-http2-proxy` task summary after RFC correction, implementation, full verification, security review, and reviewer walkthrough.
- Added current decisions for ALPN-authoritative HTTPS selection, explicit cleartext protocol choice, configured-only H2 authority, and independent per-stream authentication and admission.
- Expanded proxy and lifetime patterns with one-dispatch/no-downgrade behavior, per-exchange H2 capacity, same-connection SETTINGS proof, fixed-memory revocation monitoring, and physical-close ownership.
- Recorded the pinned Hyper CONNECT behavior, generation-retirement and conservative-capability residuals, missing real-auth fixture, upgrade review gate, and separate production rollout requirement.
