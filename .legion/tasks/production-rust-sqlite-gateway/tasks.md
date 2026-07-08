# production-rust-sqlite-gateway Tasks

## Current Phase

- [x] Brainstorm entry selected because the user introduced a new production requirement without naming an existing task path.
- [x] Deployment shape confirmed: single active Rust gateway instance with SQLite WAL durable storage.
- [x] Design gate.
- [x] Implementation.
- [x] Verification.
- [x] Review, walkthrough, and wiki writeback.

## Checklist

- [x] Capture stable task contract for production Rust/SQLite gateway.
- [x] Write RFC covering Rust crates, SQLite schema/migrations, callback/session model, refresh/revocation concurrency, nginx integration, Docker packaging, migration/removal of TS PoC, and real auth-mini E2E.
- [x] Review RFC before implementation.
- [x] Replace production Node/TypeScript gateway runtime with Rust.
- [x] Implement SQLite schema initialization, session persistence, login state, revocation, TTL pruning, and race-safe refresh.
- [x] Implement auth-mini JWKS/JWT verification, `/me`, refresh, and logout client behavior in Rust.
- [x] Preserve callback bridge, safe redirects, cookie security, allowlist, and Passkey policy.
- [x] Update Docker/Compose/docs for Rust runtime.
- [x] Add Rust unit/integration tests.
- [x] Add real auth-mini E2E deployment and verification harness.
- [x] Record verification evidence in `docs/test-report.md`.
- [x] Run readiness/security review and record result.
- [x] Generate walkthrough/PR body and update Legion wiki.

## Status Notes

- Prior task `auth-mini-gateway-poc` delivered a TypeScript PoC and documented production persistence plus real auth-mini smoke as follow-up.
- User explicitly rejected PoC scope for this task and required Rust + SQLite plus real auth-mini end-to-end verification.
- Implementation, verification, and readiness/security review are complete; walkthrough/PR body and wiki writeback remain.
- Reviewer walkthrough, PR body, and wiki writeback are complete. Commit/PR creation remains unperformed pending explicit user request.
