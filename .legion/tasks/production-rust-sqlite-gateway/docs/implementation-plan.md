# Implementation Plan: Production Rust/SQLite Gateway

## Milestone 1: Rust Project Skeleton

- Add `Cargo.toml`, Rust source layout, config parser, and build scripts.
- Update Dockerfile to build Rust binary.
- Keep TypeScript PoC until Rust path is functionally equivalent, then remove production Node entrypoints.

## Milestone 2: SQLite Store

- Add migrations and WAL initialization.
- Implement login state/session CRUD, TTL pruning, revocation, restart persistence, and compare-and-swap refresh updates.

## Milestone 3: HTTP Gateway

- Implement request parsing/routing for login, callback, callback session, auth check, logout, and health.
- Implement HMAC cookies and safe redirects.

## Milestone 4: auth-mini Integration

- Implement JWKS fetch/cache and JWT verification.
- Implement `/me`, `/session/refresh`, and `/session/logout` clients.
- Preserve allowlist and Passkey policy semantics.

## Milestone 5: nginx/Compose/E2E

- Update nginx and Compose for Rust gateway.
- Add real auth-mini service to E2E topology.
- Add protected upstream and smoke harness.

## Milestone 6: Verification And Hardening

- Add Rust unit/integration tests.
- Run real auth-mini E2E.
- Run readiness/security review and fix blockers before walkthrough/wiki/PR.
