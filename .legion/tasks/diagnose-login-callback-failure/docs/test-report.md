# Test Report: Audience-Bound Gateway Sessions

> **Date:** 2026-07-30
> **Scope:** Verify the RFC-approved audience, callback, refresh, user-ID authorization, rollback, and operator-migration behavior.
> **Upstream fixture:** official `zccz14/auth-mini` at `c4e28f5cabe4dc248c137f2efb48453e35131ba6`

## Validation Strategy

The strongest direct proof is the real current-auth-mini drill: it mints a signed redirect token whose `aud` is the gateway hostname while the issuer hostname is different, proves that token cannot call `/me`, completes the gateway callback, refreshes while preserving audience, and rejects a real signed wrong-audience token. Repository unit/integration tests then pin the deterministic verifier, state machine, concurrency, deny isolation, and header behavior. Old-binary and mode-switch drills prove that the unchanged schema-v2 storage and existing proxy topology remain fail-closed.

No Nix build was run.

## Executed Commands

| Command | Result | Evidence |
|---|---|---|
| `cargo fmt --check` | PASS | Formatting clean after all source, script, example, and benchmark edits. |
| `cargo test` | PASS | 119 library tests, 50 proxy integration tests, and doc-test discovery passed; 0 failed. |
| `AUTH_MINI_RUST_DIR=/tmp/opencode/auth-mini-official-20260730/rust-backend AUTH_MINI_EXPECTED_COMMIT=c4e28f5cabe4dc248c137f2efb48453e35131ba6 scripts/e2e-real-auth-mini.sh` | PASS | Real audience-bound auth-mini + gateway + nginx + protected HTTP/WebSocket upstream passed. |
| `scripts/e2e-old-binary-compat.sh` | PASS | Ready/NULL read, Pending deny/logout/prune, NULL repair, and safe re-upgrade passed with schema v2 unchanged. |
| `scripts/e2e-proxy-mode.sh` | PASS | Direct proxy-mode integration suite passed. |
| `scripts/e2e-mode-switch.sh` | PASS | Fail-closed adapter/proxy mode-switch drill passed. |
| `cargo test --manifest-path benchmarks/http2-regression/Cargo.toml` | PASS | 126 unit tests, 21 integration tests, and the process-arm smoke passed after making the benchmark identity fixture user-ID-only. |
| `git diff --check` | PASS | No whitespace or patch-format errors. |

## Real Auth-Mini Contract Coverage

The real drill verified all of the following against the official current auth-mini binary:

- The login redirect contains the exact gateway callback, one-time state, and exactly one loopback `aud` parameter.
- `/email/verify` receives the same callback and explicit loopback audience.
- The issued access JWT contains the expected signed `sub`, `aud`, and `typ`; values are checked locally and never printed.
- The downstream-audience token receives `401` from auth-mini `/me`, while the gateway callback succeeds without calling `/me`.
- The gateway stores a Ready session with NULL email and authorizes only the configured exact user ID.
- Refresh rotates credentials and preserves `aud=localhost`; the persisted refreshed token is decoded and checked without printing it.
- A real signed token for a different audience receives callback `401`, creates no gateway session, sets no session cookie, and produces no protected-upstream hit.
- A valid non-allowlisted user receives stored-session `403` and no upstream access.
- Logout, exact refresh rejection, temporary auth outage recovery, gateway restart persistence, absolute-only renewal cookies, adapter mode, direct proxy mode, HTTP, WebSocket, and slow-upstream behavior remain intact.

## Deterministic Coverage

Repository tests cover:

- Exact normalized audience derivation for production HTTPS and loopback hosts.
- Signed JWT acceptance only for one exact string `aud`; missing, empty, mismatched, array, object, and numeric `aud` fail after signature validation.
- Callback success without any identity fetch, audience rejection, `sid` mismatch, replayed one-time state, stored-session `403`, and exact user-ID allow/deny.
- Refresh Pending persistence, local finalization, crash recovery, shared single-flight outcomes, and stale-safe conditional revoke for signed audience rejection.
- Temporary/JWKS/contract uncertainty remaining `503` without clearing a recoverable session.
- Logout, idle expiry, and absolute expiry winning over late Pending finalization.
- Adapter and proxy identity emitting only `X-Auth-Mini-User-Id`; spoofed email headers remain stripped.
- Schema-v2 migration, old-binary compatibility, WAL behavior, and proxy transport regressions.

## Configuration and Documentation Scan

- Active configuration examples now use `ALLOW_USER_IDS` only.
- `ALLOW_EMAILS` appears only as an explicit unsupported-startup migration warning in active docs/config, or as historical task evidence.
- `X-Auth-Mini-Email` appears only in stripped-header/security assertions, historical evidence, or the benchmark-compatible fixture signal; runtime and active nginx examples no longer inject it as trusted identity.
- The HTTP/2 regression benchmark direct/fixture identity checks were updated to require only `X-Auth-Mini-User-Id`.

## Secret Boundary

- The real drill writes fixture token files only under repository `target/`, removes its temporary directory on exit, and prints no token, signed cookie, callback body, or fixture user ID.
- Gateway logs and test output contain fixed event classes only for the new audience paths.
- The pre-existing `gateway_logs_never_contain_cookie_token_or_secret_values` integration test passed.

## Failures and Skips

None. All selected verification commands passed.

## Remaining Operational Blocker

Production rollout is intentionally blocked until each deployment provisions exact auth-mini user IDs in `ALLOW_USER_IDS` and removes/empties `ALLOW_EMAILS`. Repository implementation and verification are complete; production secret/config changes are outside this task.
