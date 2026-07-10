## Summary

- remove `REQUIRE_PASSKEY` and gateway-level `amr` authorization
- keep exact email/user-id allowlists deny-by-default
- treat auth-mini as the sole authority for authentication methods
- update active examples and deployment docs

The reported generic callback failure was a hidden `403`: the identity was allowlisted, but its real auth-mini session used Email OTP rather than `webauthn`.

## Validation

- `cargo fmt --check`
- `cargo test` (`11 passed`)
- active source/config/docs method-policy scan
- real auth-mini + nginx Email OTP callback and protected HTTP/WebSocket E2E
- real unknown-identity denial E2E
- security/readiness review: PASS
