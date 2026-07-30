# Report Walkthrough: Audience-Bound Gateway Sessions

> **Mode:** implementation
> **Date:** 2026-07-30
> **Task:** `diagnose-login-callback-failure`

## Reviewer Entry Point

Start with the problem and boundary in `plan.md`, then read `docs/rfc.md` for the approved state machine, `docs/test-report.md` for proof, and `docs/review-change.md` for the final security/correctness decision.

## What Was Broken

The deployed gateway asked users to log in through auth-mini, received a valid redirect callback, and then called auth-mini `/me` with the returned access token. Current official auth-mini `c4e28f5` binds that token to the gateway callback hostname (`aud=<gateway hostname>`) and reserves `/me` for the issuer hostname audience. The valid downstream token therefore failed `/me`, the gateway collapsed that into callback `401`, and the callback bridge displayed the generic `Login failed. Please try again.`

The stale local auth-mini checkout hid the cause because it stopped at `86b4aaa`, before upstream commit `7a9b55f` introduced audience-bound redirect tokens.

## What Changed

- `GATEWAY_PUBLIC_BASE_URL` now yields one normalized expected JWT audience. Production HTTPS derives it from the callback hostname; exact loopback login adds the required explicit `aud` parameter.
- Access-token verification now requires an exact string `aud` after signature, issuer, type, expiry, `sub`, `sid`, and `amr` validation.
- Callback creates a Ready gateway session directly from signed claims and no longer calls `/me`.
- Refresh still stores the rotated generation behind the schema-v2 Pending gate, then finalizes locally from the verified JWT. Pending recovery re-verifies the persisted token.
- A signed token with the wrong audience during refresh or Pending recovery conditionally revokes only the expected generation and forces re-login; temporary/JWKS uncertainty remains `503` without clearing.
- Authorization is exact `ALLOW_USER_IDS` only. Nonempty `ALLOW_EMAILS` fails startup instead of being silently ignored.
- Adapter and proxy paths inject only `X-Auth-Mini-User-Id`; email is neither an authorization fact nor a trusted identity header.
- Active docs, examples, the real auth-mini drill, and the HTTP/2 benchmark fixture were updated to the same user-ID-only contract.

## Evidence

`docs/test-report.md` records these passing gates:

- `cargo fmt --check`
- `cargo test`: 119 library + 50 proxy integration tests
- Real official auth-mini `c4e28f5` E2E: login redirect, signed audience, `/me` isolation, callback, refresh preservation, wrong-audience rejection, user-ID allow/deny, logout, outage recovery, adapter/proxy, HTTP, WebSocket, and slow-upstream checks
- `scripts/e2e-old-binary-compat.sh`
- `scripts/e2e-proxy-mode.sh`
- `scripts/e2e-mode-switch.sh`
- HTTP/2 regression crate: 126 unit + 21 integration tests
- `git diff --check`

`docs/review-change.md` applies the required security lens and records **PASS** with no blocking findings.

## Migration Impact

- Production must provision exact auth-mini user IDs in `ALLOW_USER_IDS` and clear `ALLOW_EMAILS` before starting this binary.
- Existing sessions remain bounded: an already allowlisted user ID can remain usable until the recorded refresh boundary; a legacy missing/issuer audience is revoked at refresh or Pending recovery and requires login again.
- Schema v2 is unchanged; old binaries can still read the database.
- Rolling back only the gateway does not restore login against current auth-mini. Full functional rollback requires the previous gateway plus pre-audience auth-mini.

## Review Result

Ready for PR review and merge. The only remaining blocker is operational, not repository readiness: production `ALLOW_USER_IDS` values must be provisioned outside this repository.
