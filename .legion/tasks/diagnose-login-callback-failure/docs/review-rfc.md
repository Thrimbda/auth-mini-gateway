# Review RFC: Audience-Bound Gateway Sessions

> **Review stage:** `review-rfc`
> **Date:** 2026-07-30
> **Reviewed:** `plan.md`, `docs/research.md`, `docs/rfc.md`, `docs/implementation-plan.md`
> **Scope:** Design implementability, verification, rollback, and authentication boundary only

## Verdict

**PASS**

The design can enter implementation. It matches the current official auth-mini contract, removes the invalid downstream `/me` dependency, and closes the gateway's pre-existing failure to enforce audience. It does so without introducing a second identity authority, an unverifiable legacy-profile inference, or a schema migration.

The RFC gives implementable state transitions for initial callback, Ready refresh, Pending crash recovery, signed audience rejection, temporary uncertainty, logout, expiry, and legacy sessions. Verification and rollback are explicit enough to detect a cross-client acceptance bug or an unrecoverable refresh loop before delivery.

## Adversarial Review

| Lens | Adversarial case | Review result |
|---|---|---|
| Audience boundary | A valid token minted for `status-axiom.0xc1.wang` is posted to `opencode-axiom.0xc1.wang` | **Closed.** Exact signed string equality rejects it after signature and all non-audience claims pass. |
| Self token replay | A token with issuer-host audience is posted to a gateway callback | **Closed.** Issuer audience is never an accepted compatibility profile. |
| Claim ambiguity | `aud` is absent, empty, array-valued, object-valued, or differently encoded | **Closed.** Only one exact string is accepted; the claim is not normalized by the verifier. |
| Legacy inference | Existing email or issuer audience is used to guess that a session belongs to this gateway | **Closed.** No inference or dual profile exists. Legacy Ready is bounded until refresh; Legacy Pending is re-verified and then finalized or revoked. |
| Rotation loss | Auth-mini rotates refresh credentials but returns a signed wrong-audience token | **Closed.** The expected local generation is conditionally revoked and re-login is required instead of an endless `503` loop. |
| Stale flight | An old refresh leader rejects after another request has advanced the row | **Closed.** Existing generation/token/state CAS prevents revoking the newer row. |
| Crash after persistence | Process exits after Pending token persistence but before Ready finalization | **Closed.** The compatibility gate remains deny; restart re-verifies the persisted token and finalizes without `/me`. |
| Logout/expiry race | Pending recovery finishes after logout, idle expiry, or absolute expiry | **Closed.** Existing finalize CAS guards remain binding and cannot resurrect the session. |
| Mutable email | A historical email continues to authorize or reaches the protected upstream | **Closed.** New policy and identity output are user-ID-only; historical DB email is ignored and new writes clear it. |
| Rollback | Previous gateway binary is restored while current auth-mini remains | **Explicitly bounded.** Storage remains readable, but fresh login/refresh is not claimed to work. Full functional rollback requires both pre-change components. |
| Verification credibility | Tests only use gateway mocks and never mint the new upstream token | **Closed.** The real drill pins official `c4e28f5`, supplies redirect target/audience, checks refresh preservation, and tests a real wrong-audience callback. |
| Secret boundary | A failure report prints callback body, token, state, identity, or expected/actual audience | **Closed.** RFC requires fixed event classes and value-free artifact checks. |

## Implementation Hard Conditions

These conditions are already present in the RFC and are repeated here as stop conditions for `engineer` and `verify-change`:

1. `AudienceRejected` may be returned only after Ed25519 signature verification and every non-audience claim check succeeds. A malformed or untrusted token must not be mislabeled as a signed audience migration case.
2. Initial, refreshed, and persisted Pending tokens must use the same derived expected audience.
3. Audience rejection during refresh/Pending recovery must use stale-safe conditional revoke; an unconditional row revoke is a review failure.
4. No current-profile callback or refresh path may call `/me`.
5. No session email may influence policy or be emitted as trusted identity under the new binary.
6. `PRAGMA user_version` must remain `2`; any DDL or schema bump returns the design to `spec-rfc`.
7. Nonempty `ALLOW_EMAILS` must fail startup rather than be silently ignored.
8. Production rollout remains blocked until exact `ALLOW_USER_IDS` values are provisioned outside this repository.

## Non-blocking Suggestions

- Parse and structurally append gateway-owned parameters to arbitrary `AUTH_MINI_LOGIN_URL` in a later hardening task. The current design remains safe because any conflicting target yields an audience mismatch and fails closed.
- Consider a future operator-facing identity migration command that prints only user IDs from existing rows. It is not needed to implement or verify this protocol fix.

## Accepted Residuals

- A Legacy Ready row can remain usable by an already allowlisted user ID until its recorded access refresh boundary. The token is server-side persisted evidence previously accepted by this gateway, and the window is bounded by auth-mini access-token expiry.
- A non-audience verification uncertainty after remote rotation can still produce one `503` before a later exact superseded response causes re-login. This is the existing bounded post-commit ambiguity and does not admit access.
- The real contract drill simulates the bridge POST rather than automating a browser. Fragment field names and bridge code are unchanged; the changed login URL, issuance, callback handler, audience, refresh, and policy boundaries are exercised.

## Handoff

Design gate PASS. Return to `legion-workflow` and enter `engineer` in the existing worktree. Implementation must follow the RFC milestones and stop on any hard-condition violation.
