# Test Report: Production Rust/SQLite Gateway

## Scope

Validated the Rust/SQLite gateway replacement, SQLite durability/concurrency behavior, nginx auth boundary, and real auth-mini integration.

## Commands

### Rust Unit/Build Checks

```bash
cargo fmt && cargo test && cargo build --bin auth-mini-gateway --example upstream
```

Result: PASS

Evidence:

- 11 Rust unit tests passed.
- Covered signed cookie parsing/tamper rejection, safe return target normalization, auth-mini login URL construction, deny-by-default/passkey policy, response-splitting header value rejection, one-time login state, durable revocation, and refresh compare-and-swap behavior.
- Built the production `auth-mini-gateway` binary and Rust protected upstream example.

### Real auth-mini + Gateway + nginx + Upstream E2E

```bash
scripts/e2e-real-auth-mini.sh
```

Result: PASS

Evidence:

- Built and launched real auth-mini Rust binary from `/tmp/opencode/auth-mini-reference/rust-backend`.
- Seeded auth-mini SQLite Email OTP rows and minted real auth-mini tokens through `/email/verify`.
- Launched the Rust gateway with SQLite persistence.
- Launched a Rust protected HTTP/WebSocket upstream.
- Launched nginx via Docker fallback because local `nginx` was unavailable.
- Verified unauthenticated protected HTTP redirects to login and does not reach upstream.
- Verified callback session creation using real auth-mini access/refresh tokens.
- Verified authorized HTTP reaches upstream with forwarded identity headers.
- Verified authorized WebSocket handshake and echo through nginx after `auth_request`.
- Verified gateway restart preserves the valid session from SQLite.
- Forced access-token expiry and verified refresh through real auth-mini `/session/refresh` rotates the persisted refresh token.
- Verified `/logout` durably revokes the gateway session.
- Corrupted the persisted refresh token, forced access expiry, and verified refresh failure revokes the local session.
- Verified an authenticated but non-allowlisted user receives `403` and does not reach upstream.
- Verified the E2E failure path avoids printing refresh-token values by logging only token presence/rotation booleans.

## Passkey Automation Note

The E2E harness uses real auth-mini Email OTP token issuance, not browser WebAuthn automation. Passkey policy is covered by Rust unit tests that prove `REQUIRE_PASSKEY=true` rejects non-`webauthn` `amr` and allows `webauthn`. Full browser/virtual-authenticator WebAuthn automation remains an environment-specific follow-up.

## Choice Rationale

- `cargo test` provides fast proof for local security invariants and SQLite race behavior.
- `scripts/e2e-real-auth-mini.sh` is the strongest available end-to-end proof because token issuance, refresh, and logout all cross the real auth-mini HTTP/JWKS boundary while nginx protects both HTTP and WebSocket upstream traffic.
