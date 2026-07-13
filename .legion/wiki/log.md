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
