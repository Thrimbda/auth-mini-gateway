# Implementation Plan: Audience-Bound Gateway Sessions

> Derived from `docs/rfc.md`; implementation may begin only after `review-rfc` PASS.

## Milestone 1: Audience and Callback Boundary

### Scope

- `src/config.rs`
- `src/jwt.rs`
- `src/auth_mini.rs`
- `src/main.rs`
- `src/server.rs`

### Steps

- [ ] Derive normalized expected audience from the validated gateway public hostname.
- [ ] Add exact loopback detection and append explicit login `aud` only for loopback callback URLs.
- [ ] Pass expected audience into `AuthMiniClient` and both initial/refreshed verification paths.
- [ ] Introduce signed-token tests for exact audience acceptance and malformed/mismatched rejection.
- [ ] Remove callback `/me`; create Ready sessions with signed `sub` and NULL email.
- [ ] Add callback success, wrong-audience, and allow/deny tests.

### Verification

```bash
cargo fmt --check
cargo test jwt
cargo test callback
cargo test config
```

### Rollback Notes

- No storage change. Reverting this milestone restores the prior callback code but not compatibility with current auth-mini.

## Milestone 2: Refresh, Legacy, and User-ID Identity

### Scope

- `src/auth_mini.rs`
- `src/server.rs`
- `src/db.rs` tests or a minimal Ready-finalization helper
- `src/policy.rs`
- proxy/integration tests

### Steps

- [ ] Replace Pending `/me` recovery with local JWKS verification and exact audience validation.
- [ ] Reuse Pending persistence as the crash-safe rotation barrier, then finalize NULL-email Ready state.
- [ ] Add stale-safe conditional revocation for signed audience rejection.
- [ ] Make authorization exact user-ID-only and fail startup on nonempty `ALLOW_EMAILS`.
- [ ] Stop emitting trusted email identity while continuing to strip caller-supplied email headers.
- [ ] Cover current refresh, Pending crash recovery, legacy audience, logout/expiry races, shared flight outcomes, and upstream-zero denial.

### Verification

```bash
cargo fmt --check
cargo test
scripts/e2e-old-binary-compat.sh
scripts/e2e-proxy-mode.sh
scripts/e2e-mode-switch.sh
```

### Rollback Notes

- Keep `PRAGMA user_version=2` and all existing columns. The old binary remains storage-compatible.
- A functional old-binary rollback against current auth-mini still cannot create/refresh downstream sessions; use the RFC full-system rollback.

## Milestone 3: Official Auth-Mini Proof and Guidance

### Scope

- `scripts/e2e-real-auth-mini.sh`
- `.env.example`
- `README.md`
- `docs/README.md`
- `docs/production-deployment.md`
- active nginx/proxy examples where email identity is documented

### Steps

- [ ] Pin the fresh official auth-mini commit and keep E2E artifacts under repository `target/`.
- [ ] Preseed deterministic user IDs and mint loopback redirect tokens with explicit `aud`.
- [ ] Prove matching callback, wrong audience, ID denial, refresh preservation, logout, outage recovery, adapter, proxy, HTTP, and WebSocket behavior.
- [ ] Remove active email-allowlist and trusted-email-header guidance; document ID provisioning and bounded legacy re-login.
- [ ] Record the production secret/user-ID rollout blocker without exposing values.

### Verification

```bash
cargo fmt --check
cargo test
AUTH_MINI_RUST_DIR=/tmp/opencode/auth-mini-official-20260730/rust-backend \
AUTH_MINI_EXPECTED_COMMIT=c4e28f5cabe4dc248c137f2efb48453e35131ba6 \
scripts/e2e-real-auth-mini.sh
```

### Rollback Notes

- Repository changes do not edit production secrets or deploy services.
- Preserve the previous docs and binary only as part of the full gateway + auth-mini rollback described in the RFC.
