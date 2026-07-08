## Summary

- Replace the TypeScript PoC gateway with a Rust/SQLite production gateway.
- Add durable SQLite sessions/login state, refresh CAS, revocation, signed cookies, safe redirects, auth-mini JWT/JWKS verification, and nginx `auth_request` routes.
- Update Docker/docs/examples for Rust and add a real auth-mini + nginx + protected HTTP/WebSocket upstream E2E harness.

## Verification

- `cargo fmt && cargo test && cargo build --bin auth-mini-gateway --example upstream`
- `scripts/e2e-real-auth-mini.sh`
- Readiness/security review: PASS, no blocking findings.

## Notes

- E2E uses real auth-mini Email OTP token issuance, refresh, and logout. Full browser WebAuthn automation remains a documented environment-specific follow-up; Passkey policy is unit-tested through `amr` handling.
- Production target remains one active gateway instance with durable SQLite WAL storage.
