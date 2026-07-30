# Review Change: Audience-Bound Gateway Sessions

> **Review stage:** `review-change`
> **Date:** 2026-07-30
> **Reviewed:** `plan.md`, `docs/rfc.md`, `docs/review-rfc.md`, `docs/test-report.md`, and the full worktree diff
> **Security lens:** Applied (authentication, session, token, identity, and trust-boundary changes)

## Verdict

**PASS**

The change is ready for delivery. It implements the approved design without widening scope: current auth-mini audience-bound tokens can complete login without `/me`, tokens minted for another hostname remain rejected, refreshed and persisted Pending generations use the same boundary, and authorization is exact user-ID-only. Verification evidence is direct and current: deterministic signed-token tests, full repository tests, a real official auth-mini `c4e28f5` E2E, old-binary storage compatibility, proxy/mode-switch drills, and the HTTP/2 benchmark suite all pass.

## Blocking Findings

None.

## Security Review

| Boundary | Result |
|---|---|
| Audience verification | `src/jwt.rs` verifies Ed25519 first, then issuer/type/expiry/sub/sid/amr, and checks `aud` last as one exact string. `AudienceRejected` cannot be produced by an unsigned or otherwise invalid token. |
| Cross-client replay | No missing, issuer-host, alternate-type, or other-gateway audience is accepted. The claim is not normalized by the verifier. |
| Callback | One-time state remains consumed before token verification. Callback no longer calls `/me`; invalid token/audience creates no session, while valid non-allowlisted identity preserves the existing stored-session `403` behavior. |
| Refresh/Pending | Signed audience rejection uses the existing generation/token/state conditional revoke. Temporary, JWKS, and other uncertainty remain shared `503` without clearing. Logout, idle expiry, and absolute expiry CAS guards remain unchanged. |
| Identity injection | Adapter and proxy paths emit only `X-Auth-Mini-User-Id`. Email is not an authorization input and is not emitted as trusted identity; spoofed email headers remain stripped. |
| Configuration | The expected audience is derived with the same hostname normalization as current auth-mini. Loopback login sends explicit `aud` exactly once; production HTTPS omits it. Nonempty `ALLOW_EMAILS` fails startup without echoing its value. |
| Storage/rollback | Schema v2 and all columns are unchanged. Old binaries remain storage-compatible; docs correctly state that gateway-only rollback cannot restore login against current auth-mini. |
| Secrets/privacy | New diagnostics use fixed value-free event classes. The real drill checks token claims locally without printing tokens and keeps temporary artifacts under repository `target/`. |

## Correctness and Scope Review

- `src/auth_mini.rs` removes the downstream `/me` identity path and applies the expected audience to initial, refreshed, and recovered token verification.
- `src/server.rs` creates callback sessions from signed claims, finalizes refreshed Pending generations locally, and uses stale-safe conditional revoke for signed audience migration failures.
- `src/config.rs`, `src/policy.rs`, `src/proxy.rs`, active examples, deployment docs, and the real-auth drill consistently complete the user-ID migration.
- `src/db.rs` is unchanged; this matches the RFC's no-DDL decision.
- HTTP/2 benchmark fixtures were adjusted to stop expecting a trusted email header while retaining their historical session-evidence shape.
- `.legion` task evidence is limited to the current task directory.

## Non-blocking Residuals

1. Legacy Ready rows remain usable by an already allowlisted user ID until their recorded refresh boundary. This bounded window is explicit in the RFC and cannot admit a new cross-audience token.
2. A JWKS failure during a fresh callback still maps to callback `401`; no session exists to preserve, and this matches existing callback semantics.
3. A cryptographically valid refreshed token with the right audience but mismatched `sid`/`sub` remains an indeterminate `503` path. It fails closed and is the pre-existing post-commit ambiguity boundary.
4. Non-loopback HTTP `GATEWAY_PUBLIC_BASE_URL` now fails startup. This is an intentional current-auth-mini contract tightening and is documented.

## Evidence Review

`docs/test-report.md` records concrete commands and results:

- `cargo fmt --check` and `cargo test`: 119 library + 50 proxy integration tests passed.
- Real official auth-mini `c4e28f5` E2E: callback, wrong-audience rejection, refresh audience preservation, user-ID allow/deny, adapter/proxy, HTTP, WebSocket, outage, logout, and slow-upstream checks passed.
- Old-binary compatibility, proxy-mode, and mode-switch drills passed.
- HTTP/2 regression crate: 126 unit and 21 integration tests passed.
- `git diff --check` passed.

The evidence is sufficient for merge readiness. Production rollout remains separately blocked on provisioning exact `ALLOW_USER_IDS` and clearing `ALLOW_EMAILS`, as documented in the plan, RFC, README, and deployment guide.
