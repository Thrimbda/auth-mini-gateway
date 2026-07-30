# Research: auth-mini Audience-Bound Login Compatibility

> **Profile:** RFC Heavy / high-risk authentication contract change
> **Date:** 2026-07-30
> **Target upstream:** official `zccz14/auth-mini` at `c4e28f5`

## 1. Problem Restatement

Official auth-mini commit `7a9b55f` changed redirect login tokens from an issuer-only profile to a hostname audience profile. A login for `https://opencode-axiom.0xc1.wang/auth/callback` now receives `aud: "opencode-axiom.0xc1.wang"`. The gateway verifies signature, issuer, type, expiry, `sub`, `sid`, and `amr`, but ignores `aud`; it then calls auth-mini `/me`. Current auth-mini reserves `/me` for the issuer hostname audience, so the valid downstream token receives `401` and the gateway callback collapses that result into `401 Invalid auth-mini session`. The bridge renders every non-2xx result as `Login failed. Please try again.`

The fix must both restore login and close the existing cross-client replay gap by requiring the configured gateway hostname audience.

## 2. Upstream Contract Evidence

- `rust-backend/src/audience.rs:12-79` in official auth-mini defines the audience matrix and normalization.
- Non-loopback redirects require HTTPS and derive `aud` from the normalized callback hostname; explicit `aud` is forbidden (`audience.rs:25-45`).
- Exact loopback callbacks (`localhost`, `127.0.0.1`, `::1`) require an explicit normalized hostname `aud` (`audience.rs:34-38,73-78`).
- Access JWTs contain string claims `sub`, `sid`, `iss`, `aud`, `amr`, `typ`, `iat`, and `exp` (`rust-backend/src/jwks.rs:71-95`).
- Refresh preserves the session audience (`rust-backend/src/session.rs:119-175`).
- `/me` requires the session audience to equal the normalized issuer hostname (`rust-backend/src/session.rs:217-229`).
- The official backend guide explicitly requires downstream services to validate `aud`, authorize from trusted JWT claims, and not call `/me` (`docs/integration/backend-jwt-verification.md:20-26`).
- Old auth-mini sessions are backfilled to the issuer hostname because their original redirect target was not stored (`rust-backend/src/db.rs:113-126,415-516`).

## 3. Gateway Entry Points

- `src/server.rs:2216-2235` builds the callback and login URL. It currently omits the loopback `aud` parameter.
- `src/server.rs:1616-1698` consumes one-time state, verifies callback tokens, calls `/me`, and creates the gateway session.
- `src/jwt.rs:29-108` verifies access tokens but does not inspect `aud`.
- `src/auth_mini.rs:104-126,179-255` owns JWKS verification and `/me` access.
- `src/server.rs:1781-2123` performs refresh, persists a v2 Pending generation, calls `/me`, and finalizes identity.
- `src/db.rs:306-365` already provides a crash-safe Pending compatibility gate and compare-and-swap finalization.
- `src/policy.rs:14-25` currently permits either email or user ID.
- `src/server.rs:1751-1778,1879-1885` and `src/proxy.rs:3380-3431` can emit email as a verified upstream identity header.
- `scripts/e2e-real-auth-mini.sh:5-30,308-315` pins old auth-mini `86b4aaa` and mints a self-audience token without `redirect_uri` or `aud`, so it cannot detect the current failure.

## 4. Runtime Evidence

- The local `~/Work/auth-mini` checkout tracks `git@github.com:Thrimbda/auth-mini` and stops at `86b4aaa`; the fresh official checkout is eight commits ahead at `c4e28f5`.
- The running Axiom gateway uses `AUTH_MINI_ISSUER=https://auth.0xc1.wang` and `GATEWAY_PUBLIC_BASE_URL=https://opencode-axiom.0xc1.wang`.
- Therefore a fresh redirect token has downstream audience `opencode-axiom.0xc1.wang`, while `/me` requires self audience `auth.0xc1.wang`.
- Existing sessions continue to refresh successfully. That is consistent with auth-mini migration backfilling old sessions to the issuer audience and explains why the regression affects fresh login while old sessions can remain usable.
- Runtime logs intentionally contain fixed event classes but no callback body, token, cookie, email, user ID, or session ID.

## 5. Existing Conventions and Constraints

- Auth-mini remains external and unmodified (`.legion/wiki/decisions.md:5,21-23,27-28`).
- Browser state remains an opaque signed cookie; access and refresh tokens remain server-side (`.legion/wiki/decisions.md:21-22`).
- Authentication succeeds before exact allowlist authorization; unknown identities remain denied (`.legion/wiki/decisions.md:23-24`).
- Temporary or indeterminate refresh failures preserve the local session and return unavailable; only bounded exact rejection classes revoke (`.legion/wiki/decisions.md:36-38`).
- One active gateway process with SQLite WAL is the supported topology (`.legion/wiki/decisions.md:25-26`).
- Schema v2 Pending is an old-binary fail-closed gate. A rollback binary sees Pending as expired and cannot authorize it (`src/db.rs:306-365,643-660`).

## 6. Risks and Pitfalls

- Accepting issuer audience as a gateway compatibility exception would admit a token that was not minted for this relying party.
- Accepting missing `aud` would preserve the pre-change cross-client replay boundary and make the intended fix incomplete.
- Keeping `/me` for legacy sessions would require a durable session profile and two authorization semantics, with no reliable way to prove the original redirect target of old sessions.
- Keeping email snapshots would continue authorizing on a mutable value that the current signed token does not contain.
- A refresh response rotates the remote refresh token before local persistence. If its signed `aud` is incompatible, the old local token pair cannot recover and must end in bounded re-login rather than an endless `503` loop.
- A gateway rollback alone cannot restore fresh login against current auth-mini because the old gateway still calls self-audience `/me`. A complete rollback must also restore a pre-audience auth-mini binary or accept login outage.
- Two gateway origins sharing one issuer must derive and enforce different audiences.

## 7. Resolved Unknowns

- **Identity source:** use signed JWT `sub`; the user selected `ALLOW_USER_IDS` migration.
- **Email:** current downstream JWT has no email. New gateway sessions cannot authorize or emit email.
- **Schema:** no schema version or new column is needed. Existing Pending state is sufficient as a crash-safe token adoption barrier.
- **Legacy session policy:** no issuer/no-audience exception. Existing sessions use ID-only policy immediately and are forced through strict audience validation on their next refresh or Pending recovery.
- **Loopback tests:** derive expected audience from the gateway public hostname and append explicit `aud` only for exact loopback callbacks.

## 8. Remaining Operational Input

- Production `ALLOW_USER_IDS` values must be provisioned before rollout. They can be obtained from the auth-mini admin view or from existing gateway session rows without exposing tokens. This blocks production rollout, not repository implementation.

## 9. References

- Task contract: `.legion/tasks/diagnose-login-callback-failure/plan.md`
- Official upstream commit: `7a9b55f` (`feat: bind JWT audience to login destination`)
- Official current checkout: `/tmp/opencode/auth-mini-official-20260730` at `c4e28f5`
- Gateway decisions: `.legion/wiki/decisions.md`
- Prior session design: `.legion/tasks/harden-mobile-session-lifecycle/docs/rfc.md`
