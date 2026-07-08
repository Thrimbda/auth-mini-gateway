# Review: Production Rust/SQLite Gateway

## Decision

PASS

## Security Lens

Applied. The change touches auth/session/token/cookie handling and the nginx front-auth trust boundary.

## Blocking Findings

None.

## Prior Blocker Re-check

- `scripts/e2e-real-auth-mini.sh` no longer logs refresh-token values on refresh-rotation failure; it logs only token presence and rotation booleans.
- `src/http.rs` centrally rejects unsafe response header names/values, including CR/LF and control bytes.
- `src/server.rs` denies unsafe identity values before forwarding `X-Auth-Mini-*` headers across the nginx `auth_request` boundary.

## Verification Sufficiency

Sufficient.

- `cargo fmt && cargo test && cargo build --bin auth-mini-gateway --example upstream`: PASS with 11 unit tests.
- `scripts/e2e-real-auth-mini.sh`: PASS with real auth-mini, Rust gateway, nginx, and protected HTTP/WebSocket upstream.
- Passkey browser automation remains documented as an environment-specific limitation; unit policy tests cover `REQUIRE_PASSKEY=true` behavior and E2E covers real auth-mini token issuance, refresh, and logout.

## Non-blocking Suggestions

- Add E2E replay assertions for consumed callback/login state.
- Validate `AUTH_MINI_LOGIN_URL` during config parsing.
- Document operational assumptions for direct gateway exposure hardening.
