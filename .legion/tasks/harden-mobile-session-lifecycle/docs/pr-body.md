## Summary

> **HIGH RISK:** authentication lifecycle, rotating refresh credentials, SQLite schema migration, and nginx `auth_request` behavior.

Hardens mobile/PWA session behavior without relying on browser background refresh:

- new sessions use **7d idle / 30d absolute / 1h touch merge**;
- one-time login state uses **10m**;
- access refresh is request-driven;
- temporary/uncertain auth failures return non-redirecting `503` and preserve the session;
- only exact refresh `401 session_invalidated|session_superseded` revokes locally;
- silent SSO remains **FAIL / unsupported**.

## What changed

- Added additive schema v2 with authoritative idle/absolute deadlines and durable identity `Pending`. Legacy rows satisfy `E <= A <= old deadline`; Pending uses a past v1 compatibility gate, so rollback remains fail-closed (`src/db.rs:306-365,446-568`).
- Added typed refresh outcomes and an exact-`200`, no-redirect auth-mini boundary. 3xx and unexpected 2xx cannot replay refresh credentials or advance state (`src/auth_mini.rs:111-171,202-304`).
- Added per-session shared-result flights. Same-version joiners share success/rejected/temporary/indeterminate; Pending G+1 aliases the running rotation flight (`src/flight.rs:15-186`, `src/server.rs:351-367`).
- Rotation now persists new tokens as Pending before `/me`; only fresh matching identity finalizes Ready. `/me` 401 and every other non-fresh result preserve Pending and return `503` (`src/server.rs:293-381,475-525`).
- Positive cookies use DB-derived absolute `Expires` with no positive `Max-Age`; nginx propagates renewal/clear cookies to HTTP/WS responses and maps auth failure to `503` without rewriting upstream `500` (`src/cookies.rs:18-90`, `examples/nginx.conf:46-98`).
- Local logout remains immediate and terminal; late refresh/identity completion cannot resurrect revoked or expired sessions (`src/server.rs:538-570`, `src/db.rs:277-415`).

## Security review fixes

The first `review-change` found:

- **RC-01 HIGH:** automatic redirect following could replay a refresh POST/credential to `Location` — fixed with `redirect::Policy::none()` plus target-zero-hit tests.
- **RC-02 HIGH:** generic 2xx acceptance could advance state on 201/206 — fixed by exact `200 OK` checks plus wire/handler state-invariance tests.
- **RC-03 MEDIUM:** the old 35-test report overstated hard-gate coverage — withdrawn and replaced with 46 tests plus actual old-binary, WAL restore, and separated real-service evidence.

Final `review-change`: **PASS / READY**, blockers none (`.legion/tasks/harden-mobile-session-lifecycle/docs/review-change.md:9-27`).

## Verification

- [x] `cargo fmt --check`
- [x] `cargo test` — 46 passed
- [x] `cargo clippy --all-targets -- -D warnings`
- [x] release build
- [x] actual pre-change binary compatibility E2E
- [x] WAL-consistent backup/restore drill
- [x] pinned real auth-mini + nginx + HTTP/WebSocket upstream E2E
- [x] nginx syntax, Compose rendering, diff/config/docs checks, redacted secret scan

The real-service E2E covered OTP callback, HTTP/WS Cookie propagation, gateway/auth-mini outage isolation, restart, temporary recovery, real rotation/Pending finalization, logout, exact rejection, 403, and slow-upstream expiry. 3xx/201/206, malformed `/me`, shared-flight barriers, and terminal races are covered by named deterministic wire/handler tests, not mislabeled as real-service injection.

**No physical mobile Safari was run.** Receipt-time expiry used a curl cookie jar after a delayed real-nginx response; do not interpret this as Safari-device coverage. Full evidence: `.legion/tasks/harden-mobile-session-lifecycle/docs/test-report.md`.

## Rollout / rollback

Roll out binary + lifecycle env + nginx together after stopping the single writer and taking a WAL-consistent backup. Preserve the old binary/env/nginx config; monitor Pending age/count, SQLite errors, flight outcomes, and invalidation spikes.

Rollback must keep `auth_request` or maintenance deny active. Do not downgrade `user_version` or drop v2 columns. Ready rows remain old-binary readable; Pending rows fail closed and may require re-login. Restore the WAL-consistent backup if needed; never manually repair token/identity/revocation fields (`docs/production-deployment.md:367-387`).

## Accepted residuals / follow-ups

- **R-01:** remote rotation commit + lost response remains bounded fail-closed. Joined requests share `503`; a later exact superseded response may revoke and require login. No automatic rotating-POST retry.
- **R-02:** auth-mini may fold an internal failure into exact `session_invalidated`; monitor invalidation spikes and follow up in auth-mini to return 5xx for internal errors. This authority is refresh-only, never `/me`.
- **Silent SSO:** capability gate is **FAIL / unsupported**. A separate auth-mini contract/implementation and real browser-flow gate are required (`docs/silent-sso-capability.md`).

Reviewer walkthrough: `.legion/tasks/harden-mobile-session-lifecycle/docs/report-walkthrough.md`.
