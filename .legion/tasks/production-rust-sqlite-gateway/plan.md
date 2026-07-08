# Production Rust/SQLite Gateway

## Task Contract

- **Task ID:** `production-rust-sqlite-gateway`
- **Name:** Production Rust/SQLite auth-mini gateway
- **Goal:** replace the TypeScript PoC gateway with a production-ready gateway implemented with the same core technology shape as auth-mini: Rust service plus SQLite persistence.
- **Problem:** the current repository proves the adapter model, but it remains PoC-oriented: TypeScript runtime, in-memory sessions, mock auth-mini smoke, and non-production persistence. The gateway must become a durable Rust/SQLite system that can sit in front of nginx-protected services and be validated against a real auth-mini deployment, not only mocks.

## Acceptance

- The gateway runtime is Rust-based and no longer depends on the TypeScript Node server for production behavior.
- SQLite persists gateway sessions, login state, refresh-token material, expiration, revocation, and policy-relevant identity data.
- The service survives gateway process restart without losing valid gateway sessions.
- Expired access tokens refresh through real auth-mini using persisted refresh tokens; refresh failure revokes the gateway session.
- Logout revokes the gateway session durably and cannot be undone by an in-flight refresh.
- Browser cookies remain opaque, signed or MAC-protected, HttpOnly, SameSite-aware, and Secure-configurable.
- Login callback still handles auth-mini fragment redirects through a first-party bridge page and validates one-time state.
- Authorization remains deny-by-default using email allowlist, optional auth-mini user id allowlist, and configurable Passkey requirement through `amr`.
- nginx `auth_request` protects HTTP and WebSocket upstream traffic and does not proxy denied requests.
- End-to-end verification deploys a real auth-mini server, the Rust gateway, nginx, and a protected upstream, then proves login, refresh, logout, allowlist denial, and WebSocket behavior.
- The previous TypeScript PoC code path is removed or clearly demoted so production entrypoints, docs, tests, and Docker packaging use Rust.

## Scope

- Replace the gateway implementation with a Rust service aligned with auth-mini's operational style.
- Use SQLite as the durable gateway store, with schema initialization/migration in the Rust runtime.
- Keep auth-mini external and unmodified; gateway consumes auth-mini HTTP contracts such as login redirect, `/jwks`, `/me`, `/session/refresh`, and `/session/logout`.
- Provide production-oriented configuration for bind address, public base URL, auth-mini issuer/public URL, SQLite database path, cookie secret, allowlists, Passkey policy, TTLs, and secure cookie settings.
- Preserve nginx as the reverse proxy and front-auth caller; gateway does not proxy protected upstream traffic.
- Add automated Rust tests and an E2E harness that runs real auth-mini plus gateway plus nginx plus upstream.
- Update Docker/Compose/docs to build and run the Rust gateway.
- Carry forward the previous PoC's security learnings: refresh single-flight/compare-and-swap semantics, bounded login state, open redirect protection, and direct-upstream exposure checks.

## Non-Goals

- Do not turn auth-mini into an OIDC Provider.
- Do not reimplement Passkey/WebAuthn, Email OTP, auth-mini user storage, or credential storage inside the gateway.
- Do not add RBAC, organizations, admin UI, audit product, or multi-tenancy.
- Do not make SQLite support multiple active gateway instances sharing one session database; target deployment is one active gateway instance with durable SQLite WAL storage.
- Do not proxy OpenCode traffic directly from the gateway; nginx remains responsible for upstream proxying.

## Assumptions

- The production target is a single active gateway instance, supervised by systemd/container runtime, with SQLite on durable local or mounted storage.
- auth-mini can be launched in E2E using its Rust binary or source build and configured with issuer/RP values suitable for the test harness.
- Full browser Passkey automation may require a browser/WebAuthn test harness; if unavailable in CI, E2E must still use real auth-mini endpoints and document any passkey automation limitation explicitly.
- SQLite WAL mode is acceptable for this deployment model.
- The previous PoC behavior remains the functional baseline unless contradicted by this contract.

## Constraints

- No access token, refresh token, session cookie, cookie secret, or callback body may be logged.
- Durable session updates must be race-safe: parallel refreshes and logout-vs-refresh races must fail closed.
- Login state must be one-time, persisted with TTL, and pruned.
- Return targets must be relative same-origin paths unless explicitly allowed.
- Unknown users are denied by default.
- Gateway management/debug endpoints must not be exposed publicly.
- E2E must use real auth-mini for token issuance and refresh; mocks are not sufficient for final acceptance.

## Risks

- Full Passkey automation against real auth-mini may be limited by browser/WebAuthn support in the execution environment; the test design must make this explicit and provide the strongest feasible real-auth-mini proof.
- Migrating from TypeScript to Rust changes project structure, Docker packaging, and test infrastructure in one task; design and review gates are required.
- SQLite can provide durable single-instance production behavior, but it is not a multi-active distributed session store.
- Refresh token rotation requires careful compare-and-swap or transaction semantics to avoid session resurrection or accidental logout.

## Design Summary

- Implement the gateway as a Rust HTTP service with SQLite-backed session and login-state tables.
- Keep the auth-mini integration boundary HTTP/JWKS-based; do not link to or copy auth-mini internals beyond compatible operational patterns.
- Use durable transactions for callback session creation, refresh rotation, revocation, and TTL pruning.
- Keep the first-party callback bridge because auth-mini still returns login tokens in URL fragments.
- Replace mock-only smoke with a real auth-mini E2E deployment path while keeping small local mocks only for focused unit tests if needed.

## Phases

- Brainstorm: materialize this production task contract.
- Design gate: write and review RFC for Rust stack, SQLite schema, migration from PoC, refresh/revocation concurrency, and real auth-mini E2E strategy.
- Implementation: replace TypeScript production gateway with Rust/SQLite implementation and update examples/docs.
- Verification: run Rust tests and real auth-mini + gateway + nginx + upstream E2E; record evidence and any environment limitations.
- Review and handoff: readiness/security review, walkthrough/PR body, Legion wiki writeback, PR lifecycle completion.
