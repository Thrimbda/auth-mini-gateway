# Log

- Production diagnosis found allowlisted Email OTP sessions were rejected only because `REQUIRE_PASSKEY=true`; the callback bridge rendered the resulting `403` as generic login failure.
- Product decision: auth-mini owns authentication method; gateway owns identity allowlist authorization.
- Removed `REQUIRE_PASSKEY` config and `amr` policy branch while preserving token verification and allowlist denial.
- `cargo fmt --check` and `cargo test` passed (`11 passed`).
- Active source/config/docs scan found no remaining method-policy references; historical `.legion/tasks/**` remains unchanged.
- Initial real E2E attempt failed before gateway testing because local nginx could not open `/dev/stderr` in the tool environment. Re-run through the script's Docker nginx path passed all real auth-mini Email OTP, HTTP/WebSocket, persistence, refresh/logout, refresh-failure, and unknown-identity denial checks.
