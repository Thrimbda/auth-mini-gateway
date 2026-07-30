# Fix audience-bound auth-mini login

## Summary

Current official auth-mini binds redirect-login access tokens to the callback hostname as JWT `aud` and reserves `/me` for self-audience tokens. The gateway ignored `aud` and then called `/me`, so valid fresh logins failed at the callback bridge.

This change makes the gateway a proper audience-aware relying party:

- derives the expected audience from `GATEWAY_PUBLIC_BASE_URL`;
- requires exact string JWT `aud` for callback, refresh, and Pending recovery;
- creates/finalizes sessions from signed claims without calling `/me`;
- conditionally revokes rotated generations whose signed audience is incompatible;
- authorizes exact `ALLOW_USER_IDS` only and rejects nonempty `ALLOW_EMAILS` at startup;
- emits only `X-Auth-Mini-User-Id` to adapter/proxy upstreams;
- updates active docs, examples, the real auth-mini drill, and benchmark identity fixtures.

Schema v2 is unchanged. Legacy sessions fail closed into bounded re-login when their missing/issuer audience reaches refresh or Pending recovery.

## Validation

- `cargo fmt --check`
- `cargo test` — 119 library + 50 proxy integration tests passed
- Real official auth-mini `c4e28f5cabe4dc248c137f2efb48453e35131ba6` E2E — passed
- `scripts/e2e-old-binary-compat.sh` — passed
- `scripts/e2e-proxy-mode.sh` — passed
- `scripts/e2e-mode-switch.sh` — passed
- `cargo test --manifest-path benchmarks/http2-regression/Cargo.toml` — 126 unit + 21 integration tests passed
- `git diff --check` — passed

See `.legion/tasks/diagnose-login-callback-failure/docs/test-report.md` and `docs/review-change.md` for detailed evidence.

## Rollout note

Before deploying, provision exact auth-mini user IDs in `ALLOW_USER_IDS` and clear `ALLOW_EMAILS`; a nonempty email allowlist intentionally blocks startup. Gateway-only rollback does not restore login against current auth-mini.
