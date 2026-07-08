# Research: Production Rust/SQLite Gateway

## Sources

- Previous task summary: `.legion/wiki/tasks/auth-mini-gateway-poc.md`
- Previous task decisions and maintenance: `.legion/wiki/decisions.md`, `.legion/wiki/maintenance.md`
- auth-mini reference repository: `/tmp/opencode/auth-mini-reference`
- auth-mini Rust backend Cargo: `/tmp/opencode/auth-mini-reference/rust-backend/Cargo.toml`
- auth-mini Rust HTTP server: `/tmp/opencode/auth-mini-reference/rust-backend/src/http.rs`
- auth-mini Rust external server E2E: `/tmp/opencode/auth-mini-reference/rust-e2e/rust-server.test.ts`
- ctx7 docs: `/rusqlite/rusqlite`, `/websites/rs_rusqlite_migration`

## Current Repository State

The repository currently contains a TypeScript PoC gateway with:

- in-memory gateway sessions and login states
- auth-mini HTTP/JWKS client in Node
- nginx and Docker Compose smoke examples
- mock auth-mini for composed smoke tests

The PoC passed readiness review, but wiki maintenance explicitly records production persistence and real auth-mini smoke as follow-up.

## auth-mini Technology Shape

The auth-mini Rust backend uses:

- Rust 2021
- `rusqlite` with bundled SQLite
- low-dependency std TCP HTTP handling, not a large Rust web framework
- `serde`, `serde_json`, `chrono`, `sha2`, `url`
- Ed25519/JWKS support through crypto crates

For gateway alignment, the production gateway should use the same style: Rust binary, SQLite storage, small dependency set, and HTTP/JWKS integration over copying auth-mini internals.

## SQLite Guidance

ctx7 documentation confirms:

- `rusqlite::Connection::execute` supports parameterized `INSERT`/`UPDATE`/`DELETE`/`PRAGMA` and returns affected row count.
- prepared statements are appropriate for repeated safe parameterized SQL.
- `PRAGMA journal_mode = WAL` is the documented way to enable WAL mode.
- `rusqlite_migration` supports atomic schema migrations and uses versioned migrations; docs show `Migrations::to_latest(&mut conn)` and `M::up(...)`.

These are sufficient for a single-active gateway using SQLite transactions and compare-and-swap updates.

## Real auth-mini E2E Reference

auth-mini's own Rust E2E starts the real Rust binary, creates a temp SQLite DB, seeds OTP rows directly, then calls real HTTP endpoints such as `/admin/setup`, `/admin/config`, `/email/verify`, `/ed25519/start`, `/ed25519/verify`, `/session/refresh`, and `/me`.

For gateway E2E, this is the strongest practical baseline because token issuance and refresh happen through real auth-mini. The gateway E2E should add nginx and upstream around it.

## WebAuthn Automation Note

auth-mini has a TS helper that builds WebAuthn registration/authentication credential JSON for tests. A production Rust gateway does not need to reimplement WebAuthn, but the E2E can either:

- port enough of the test credential generator to Rust if full Passkey E2E is required in the same stack, or
- use auth-mini's real Email OTP/Ed25519 token issuance for hard E2E and separately validate gateway Passkey policy against real token `amr` semantics where possible.

The RFC should treat real auth-mini token/refresh/logout as mandatory and Passkey browser/helper automation as a design risk to be resolved before final verification sign-off.
