# RFC Review: Production Rust/SQLite Gateway

## Decision

**PASS**

The RFC is implementable, verifiable, rollbackable, and appropriately scoped for the `production-rust-sqlite-gateway` task. It satisfies the hard design requirements to replace the production gateway with Rust, persist gateway state in SQLite, and require final E2E evidence with real auth-mini, the Rust gateway, nginx, and a protected upstream.

## Sources Reviewed

- `.legion/tasks/production-rust-sqlite-gateway/plan.md`
- `.legion/tasks/production-rust-sqlite-gateway/docs/research.md`
- `.legion/tasks/production-rust-sqlite-gateway/docs/rfc.md`
- `.legion/tasks/production-rust-sqlite-gateway/docs/implementation-plan.md`

## Blocking Findings

None.

## Gate Assessment

### Implementability

Adequate. The RFC defines the Rust service boundary, required gateway endpoints, auth-mini HTTP contracts, SQLite schema, cookie model, authorization policy, nginx boundary, and migration path away from the TypeScript production entrypoint. The implementation plan breaks this into coherent milestones: Rust skeleton, SQLite store, HTTP gateway, auth-mini integration, nginx/Compose/E2E, and hardening.

The design avoids reimplementing auth-mini credential flows and keeps WebAuthn/Email OTP/user storage in auth-mini, which matches the task non-goals.

### Verifiability

Adequate. The RFC requires final E2E to deploy:

- real auth-mini Rust server;
- production Rust gateway;
- nginx;
- protected HTTP/WebSocket upstream.

It also requires checks for real token issuance, callback session creation, restart persistence, refresh success, refresh failure revocation, logout revocation/race safety, allowlist denial, unauthenticated denial, authorized HTTP, authorized WebSocket, and direct-upstream non-exposure. This is strong enough to prevent a mock-only or gateway-only implementation from satisfying the task.

### Passkey/WebAuthn Verification

Not a blocker.

The RFC correctly keeps Passkey/WebAuthn ceremony outside the gateway and scopes the gateway requirement to enforcing auth-mini's `amr` claim. The best verification target is a real auth-mini WebAuthn credential flow through a browser virtual authenticator or auth-mini's test credential generator. The fallback is acceptable for this design gate only because it is bounded and explicit: use real auth-mini token issuance/refresh/logout for the hard E2E path, prove `REQUIRE_PASSKEY=true` rejects real non-`webauthn` `amr` tokens, and record in `test-report.md` that this is not full Passkey E2E.

Final verification must not claim full Passkey/WebAuthn E2E unless a real `webauthn` auth-mini token is produced and accepted through the gateway. If the implementation cannot achieve the full WebAuthn path, the limitation is acceptable only as a documented coverage limitation, not as a production claim that Passkey login was exercised end to end.

### Rollback

Adequate. The RFC keeps rollback simple: revert the PR to restore the TypeScript PoC gateway, or operationally remove nginx gateway front-auth integration and return to the previous Basic Auth setup. The SQLite schema is new to the Rust gateway, so no existing production gateway database migration rollback is required.

### Scope

Appropriate. The RFC does not expand into OIDC provider work, gateway-owned WebAuthn, RBAC, organizations, admin UI, multi-tenancy, multi-active SQLite, or direct upstream proxying. nginx remains the proxy and gateway remains the front-auth decision service.

## Non-blocking Suggestions

- Add an explicit E2E assertion for the first-party fragment bridge and one-time login state replay rejection, not only direct callback-session creation from real tokens.
- Treat JWT/JWKS crate selection as an early implementation checkpoint and record the selected crate/security rationale before relying on it for production verification.
- Specify production HTTP hardening during implementation: request body/header limits, connection/read timeouts, method restrictions, and secret/token/cookie log redaction.
- Prefer a refresh implementation that does not hold a SQLite write transaction open across the network call to auth-mini; use snapshot-read plus compare-and-swap writeback to preserve logout-vs-refresh safety.
- If feasible, add a positive Passkey policy test that accepts a real auth-mini token with `amr: ["webauthn"]` when `REQUIRE_PASSKEY=true`; otherwise keep the RFC's documented fallback limitation visible in the final test report.
