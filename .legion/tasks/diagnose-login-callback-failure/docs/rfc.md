# RFC: Audience-Bound Gateway Sessions

> **Profile:** RFC Heavy / High Risk
> **Status:** Draft for `review-rfc`
> **Created / Updated:** 2026-07-30
> **Design target:** official auth-mini `c4e28f5`

## Executive Summary

- **Problem:** Current auth-mini binds redirect tokens to the callback hostname and forbids downstream-audience tokens from `/me`; the gateway still calls `/me`, so every fresh callback fails.
- **Decision:** Derive one expected audience from `GATEWAY_PUBLIC_BASE_URL`, require the exact string `aud` on initial and refreshed JWTs, use signed `sub` as identity, and authorize only `ALLOW_USER_IDS`.
- **Session flow:** Callback creates a Ready session without `/me`. Refresh retains the existing Pending durability gate, then finalizes from the already verified JWT without profile lookup. Crash recovery re-verifies the persisted token before finalizing.
- **Legacy policy:** Do not accept missing or issuer audience. Existing sessions stop using email immediately and re-login when strict audience validation fails at refresh or Pending recovery.
- **Storage:** Keep schema v2. The nullable historical `email` column remains for old-binary readability but is neither an authorization fact nor an emitted identity under the new binary.
- **Rollout:** Provision exact auth-mini user IDs, clear `ALLOW_EMAILS`, deploy, and verify a fresh callback for every gateway hostname.
- **Rollback:** Rolling back only the gateway cannot restore fresh login against current auth-mini. Full functional rollback requires the pre-change gateway plus pre-`7a9b55f` auth-mini; auth-mini's additive audience migration is designed to tolerate that binary rollback.

## 1. Context and Evidence

Official auth-mini now resolves redirect audience before minting a session, signs it as a string `aud`, persists it with the auth-mini session, and preserves it through refresh. `/me` is intentionally self-audience only. The official integration guidance tells downstream backends to validate the JWT and authorize from its claims rather than querying `/me`.

The gateway currently does the opposite at the identity boundary: it ignores `aud`, then treats `/me` as required callback and refresh identity evidence. The deployed origins make the incompatibility deterministic:

```text
issuer host:   auth.0xc1.wang
callback host: opencode-axiom.0xc1.wang
token aud:     opencode-axiom.0xc1.wang
/me requires:  auth.0xc1.wang
```

See `docs/research.md` for source and runtime evidence.

## 2. Goals

1. Restore fresh callback login against current official auth-mini without calling `/me`.
2. Require signature, exact issuer, exact gateway hostname audience, access type, expiry, `sub`, `sid`, and `amr` for initial and refreshed access tokens.
3. Authorize only exact signed `sub` values in `ALLOW_USER_IDS`; deny unknown users by default.
4. Preserve opaque cookies, server-side token storage, one-time state, refresh rotation, single-flight, inactivity/absolute deadlines, and proxy isolation.
5. Give legacy Ready and Pending sessions a bounded fail-closed path without accepting issuer or missing audience.
6. Preserve schema-v2 and actual-old-binary storage readability.
7. Prove the contract with deterministic signed-token tests and a real current-auth-mini issuance/refresh drill.

## 3. Non-goals

- Do not modify auth-mini, add email claims, create a profile endpoint, or implement token exchange.
- Do not retain email allowlist authorization for new or existing sessions under the new binary.
- Do not emulate OIDC/OAuth audience or introspection semantics.
- Do not redesign cookies, session lifetimes, proxy transport, nginx routing, or multi-active storage.
- Do not provide a silent compatibility mode that accepts issuer-audience or no-audience access tokens.
- Do not expose detailed callback errors or any token/identity value in browser or runtime diagnostics.

## 4. Hard Constraints

- **Security:** Audience comparison occurs only after successful Ed25519 verification. `aud` must be one JSON string exactly equal to the normalized configured hostname; arrays, empty strings, missing values, and other types fail.
- **Privacy:** Never log tokens, callback bodies, signed cookies, email, `sub`, `sid`, configured allowlist values, or raw URLs.
- **Authorization:** Authentication and user authorization remain separate. A valid token for the gateway can still receive `403` if `sub` is not allowlisted.
- **Availability:** Transport, timeout, 429, 5xx, JWKS, malformed unsigned data, and persistence uncertainty remain `503` without clearing a still-recoverable session.
- **Rotation:** A cryptographically valid refreshed token with an incompatible audience is terminal for that local generation because the remote refresh token has already rotated; conditionally revoke and require login.
- **Compatibility:** Keep `PRAGMA user_version=2` and the current table shape. Old binaries must still open the database.

## 5. Definitions

- **Expected audience:** The normalized hostname of the exact callback origin represented by `GATEWAY_PUBLIC_BASE_URL`; it excludes scheme, port, path, query, fragment, and IPv6 brackets.
- **Current profile:** An access JWT with a present string `aud` exactly equal to expected audience.
- **Legacy profile:** Any persisted gateway session whose current or next auth-mini token has missing `aud` or issuer-host audience. Legacy is a migration description, never an accepted verifier mode.
- **Ready:** The persisted token generation is verified and may proceed to user-ID policy.
- **Pending:** A refreshed token generation is durably stored behind the v1-compatible deny gate but has not completed local finalization.

## 6. Proposed Design

### 6.1 Configuration and Audience Derivation

`Config` gains a derived `auth_mini_audience: String`; operators do not set a second production audience value.

1. Parse `GATEWAY_PUBLIC_BASE_URL` as an absolute HTTP(S) URL with a host.
2. Require HTTPS unless the host is exactly `localhost`, `127.0.0.1`, or `::1`.
3. Normalize `Host` exactly like official auth-mini:
   - domain: URL-normalized form with trailing dot removed;
   - IPv4: canonical address text;
   - IPv6: canonical address text without brackets.
4. Build the callback as the origin-root path `/auth/callback` and use the same normalized host as expected audience.
5. For non-loopback HTTPS callbacks, send `redirect_uri` and `state` only; auth-mini derives `aud`.
6. For exact loopback callbacks, also send `aud=<derived audience>` because current auth-mini requires it.

`AUTH_MINI_LOGIN_URL` remains an optional UI entry point. The gateway-owned `redirect_uri`, `state`, and loopback `aud` remain appended. Duplicate or custom UI target mistakes can only produce a token rejected by the exact verifier; they cannot broaden access. Structural custom-login URL cleanup is outside this task.

`ALLOW_EMAILS` becomes unsupported. A nonempty value fails startup with a fixed `allow_emails_unsupported` class so an operator cannot mistake a silently ignored email list for active authorization. Empty or unset is accepted during migration. `ALLOW_USER_IDS` remains an exact comma-separated set; empty means deny all.

### 6.2 JWT Verification Boundary

`verify_access_token` receives `expected_audience` and returns a typed error class after verifying the signature.

Required claims and checks:

| Check | Required behavior |
|---|---|
| Header/JWK | exact EdDSA, known `kid`, OKP/Ed25519 key |
| Signature | valid before claims become trusted |
| `iss` | exact configured issuer origin |
| `aud` | exact string expected audience |
| `typ` | exact `access` |
| `exp` | integer and strictly in the future |
| `sub` | nonempty string |
| `sid` | nonempty string |
| `amr` | array of strings |

Audience failures are distinguished from all other verification failures only after signature success and every non-audience claim check succeeds:

- `Missing`, non-string, empty, or mismatched `aud` -> `AudienceRejected`.
- Signature, key, issuer, type, expiry, `sub`, `sid`, and `amr` failures -> generic token verification failure.

The verifier does not normalize the claim. Auth-mini already signs the normalized canonical string, so exact equality avoids alternate encodings.

### 6.3 Callback State Machine

```text
valid state + callback body
  -> verify signature/issuer/aud/type/expiry/sub/sid/amr
  -> require body session_id == signed sid
  -> create Ready gateway session with signed sub, amr, exp, email=NULL
  -> evaluate exact ALLOW_USER_IDS
  -> 200 + opaque session cookie, or 403 + same stored session cookie
```

The callback never calls `/me`.

- Invalid/missing state or callback fields remains `400`.
- Any token verification, audience, or `sid` mismatch remains `401` with no gateway session.
- Valid token but unknown `sub` remains `403`; protected upstream is not reached.
- DB failure remains server failure under the existing local route mapping.
- The one-time state remains consumed before token verification, preserving replay resistance.

### 6.4 User-ID-Only Identity and Headers

- `evaluate_session_policy` checks only exact `session.user_id` membership in `ALLOW_USER_IDS`.
- New callback and refresh finalization write `email=NULL`.
- The new binary neither reads session email for authorization nor emits `X-Auth-Mini-Email` to nginx or fixed upstreams.
- `X-Auth-Mini-User-Id` remains the sole injected identity header and still passes unsafe-byte validation.
- The physical email column remains nullable so current and old binaries can read the same schema. It is historical data only under the new binary.

### 6.5 Refresh and Pending Recovery

The existing v2 Pending gate remains useful even though remote identity lookup is removed.

#### Ready refresh

1. Acquire the existing per-session flight and JWKS snapshot.
2. Call exact auth-mini refresh once for the flight.
3. Require returned `session_id` to equal the stored auth-mini session ID.
4. Verify the new access JWT including exact expected audience; require signed `sid` and `sub` to match the existing session.
5. Register the `(generation+1, Pending)` flight alias.
6. CAS the rotated token pair, signed identity, `amr`, and expiry into Pending using the existing compatibility deny gate.
7. Immediately CAS Pending to Ready with `email=NULL`; no network request occurs between persistence and finalization.
8. Publish shared Ready and re-read before policy/touch.

#### Crash recovery from Pending

1. Acquire/join the existing flight for the Pending generation.
2. Fetch/cache JWKS using existing bounded behavior.
3. Re-verify the persisted access token with exact issuer and gateway audience.
4. Require signed `sid` and `sub` to match the persisted session.
5. Finalize Pending to Ready with `email=NULL` using generation, user, revocation, and deadline CAS guards.

The old Pending `/me` call and all `IdentityFetchOutcome` types are removed.

#### Failure mapping

| Failure | Local state | Result |
|---|---|---|
| Refresh exact `session_invalidated` / `session_superseded` | conditional revoke | shared `401`, clear cookie |
| Signed refreshed/pending token has missing, malformed, or wrong `aud` | conditional revoke same generation | shared `401`, clear cookie |
| Refresh/JWKS timeout, transport, 429, or 5xx | unchanged | shared `503`, no clear |
| Other token verification or contract uncertainty | unchanged | shared `503`, no clear |
| Pending finalize CAS loses to logout/expiry | inactive/revoked wins | `401`, clear cookie |
| Persistence uncertainty | fail closed | shared `503` |

Audience rejection uses the same expected-version and refresh-token CAS discipline as remote rejection. A stale flight cannot revoke a newer generation.

### 6.6 Legacy Durable Sessions

No issuer/no-audience token is accepted.

- **Legacy Ready:** The session is immediately subject to ID-only policy and emits only user ID. It may remain usable until its recorded access refresh boundary. On refresh, auth-mini preserves its issuer/missing audience, strict verification returns `AudienceRejected`, the expected generation is conditionally revoked, and the browser re-enters login.
- **Legacy Pending:** The new recovery path re-verifies its persisted token. A matching gateway audience finalizes safely; issuer/missing/wrong audience is conditionally revoked and re-login is required.
- **Current Ready:** Refresh preserves the gateway audience and completes Pending -> Ready without `/me`.
- **Unknown user:** A cryptographically valid current-profile session remains stored but receives `403`, preserving existing authenticated-but-unauthorized semantics.

This creates a bounded migration window no longer than the locally recorded access-token refresh boundary for Ready sessions. It does not infer legacy state from email, token age, auth method, or issuer hostname.

### 6.7 Logout and Revocation

Local logout remains durable-first and remote logout remains best effort. Current auth-mini permits logout for any valid session audience, so no special flow is needed. Late Pending finalization retains existing CAS guards and cannot undo logout or expiry.

## 7. Alternatives Considered

### Option A: Strict gateway audience with user-ID identity (selected)

- **Pros:** Matches current official contract; closes cross-client replay; no upstream or schema change; no mutable email authorization; separately binds each gateway hostname.
- **Cons:** Requires user-ID provisioning and bounded re-login for legacy sessions; gateway-only rollback cannot restore login against current auth-mini.

### Option B: Persist dual legacy/current profiles and retain `/me`

- **Pros:** Could preserve old email allowlists and some sessions without re-login.
- **Cons:** Old rows cannot prove their original relying-party hostname; issuer-audience acceptance weakens the new boundary; adds schema/state/rollback complexity; keeps two identity authorities.
- **Decision:** Rejected as unsafe and unnecessary.

### Option C: Infer legacy from existing email or decoded token

- **Pros:** Avoids schema changes and may look operationally convenient.
- **Cons:** Email presence is not proof of token destination; unverified/inferred profile state is attacker-influenced or stale; cannot distinguish another downstream audience safely.
- **Decision:** Rejected.

### Option D: Pin auth-mini before `7a9b55f`

- **Pros:** Restores the old behavior with no gateway implementation.
- **Cons:** Abandons the upstream audience security boundary and leaves gateway cross-client replay possible.
- **Decision:** Retained only as full-system emergency rollback, not the forward design.

## 8. Migration, Rollout, and Rollback

### 8.1 Data Migration

- No DDL, `user_version`, backfill, or token rewrite.
- Existing v2 rows remain readable.
- New writes and successful refresh finalization set email NULL.
- Existing non-NULL email values are ignored and never emitted by the new binary.

### 8.2 Operator Migration

1. Obtain exact auth-mini user IDs from the auth-mini admin view or existing gateway rows without copying token columns.
2. Set `ALLOW_USER_IDS` for each gateway service.
3. Remove or empty `ALLOW_EMAILS`; a nonempty value intentionally blocks startup.
4. Deploy the fixed gateway to each distinct public hostname.
5. Complete a fresh login and refresh drill for each hostname.
6. Expect old browser sessions to receive `403` if their ID was not provisioned or one bounded `401`/login redirect when a legacy audience reaches refresh.

### 8.3 Rollout Gates

- Deterministic audience and callback tests pass.
- Real current-auth-mini redirect-target issuance and refresh pass.
- Wrong-audience callback and refresh never reach protected upstream.
- Both adapter and direct proxy modes inject only user ID.
- Runtime logs and test artifacts pass secret/identity-value scan.

### 8.4 Rollback

Trigger rollback on callback failure for a correctly allowlisted ID, audience false rejection, refresh loops, protected-upstream admission on denial, or unexpected secret logging.

1. Stop rollout and preserve the SQLite WAL-consistent backup.
2. If current auth-mini remains deployed, prefer rolling forward to the fixed gateway; the previous gateway cannot sustainably create or refresh downstream sessions because it calls `/me`.
3. Full functional rollback requires the previous gateway binary plus pre-`7a9b55f` auth-mini. Official auth-mini tests establish that its additive audience column tolerates old-binary inserts and later repair.
4. New gateway rows use the unchanged schema and remain readable by the old gateway. Their NULL email means only existing `ALLOW_USER_IDS` can authorize them, and refresh under the old gateway may fail until re-login against old auth-mini.
5. Never expose the protected upstream directly as rollback.

## 9. Observability

Use fixed, value-free events only:

- `event=callback_session outcome=audience_rejected`
- `event=refresh_flight outcome=audience_rejected`
- `event=pending_finalize outcome=audience_rejected`
- existing `flight_leader`, `flight_joined`, `ready`, `temporary`, `indeterminate`, `rejected`, touch, and logout events remain.

Do not log expected/actual audience, origin, token, user ID, session ID, email, state, cookie, callback body, or allowlist values. Callback HTTP status remains the first operational discriminator: `400` state/body, `401` token/audience, `403` user policy, `503` dependency/uncertainty.

## 10. Security and Privacy

| Threat | Control |
|---|---|
| Token minted for another gateway hostname | Exact signed `aud` equality after signature verification |
| Issuer/self token replayed to gateway | Issuer audience does not equal gateway hostname and is rejected |
| Missing/array/alternate audience bypass | Require one exact JSON string; no normalization of claim |
| Callback replay | Existing one-time state cookie/DB consumption remains |
| Stale refresh flight revokes newer generation | Existing version/token/state conditional revoke |
| Stale mutable email authorizes user | Email removed from policy and identity headers |
| Browser or proxy injects identity | Existing stripping plus gateway-only `X-Auth-Mini-User-Id` injection |
| Secret leakage during diagnosis | Fixed event classes and artifact scans; no raw callback diagnostics |

## 11. Testing Strategy

### 11.1 Configuration Unit Tests

- Production HTTPS hostname normalization including case, trailing dot, port, and IDNA behavior.
- Exact loopback detection for `localhost`, `127.0.0.1`, and `::1`; reject `127.0.0.2`, `0.0.0.0`, and non-loopback HTTP.
- Login URL omits explicit `aud` for production HTTPS and includes it exactly once for loopback.
- Nonempty `ALLOW_EMAILS` fails startup; empty/unset is accepted.

### 11.2 Signed JWT Unit Tests

Generate deterministic Ed25519 fixtures and test:

- matching string `aud` accepted;
- wrong, missing, empty, array, object, and number `aud` rejected;
- wrong audience cannot be rescued by matching issuer/sub/sid;
- signature, issuer, type, expiry, sub, sid, and amr checks remain enforced;
- audience errors are distinguishable only after valid signature.

### 11.3 Server and DB Tests

- Callback succeeds without any identity HTTP call and stores `email=NULL`.
- Valid current token + allowlisted `sub` -> `200`; unknown `sub` -> stored session + `403`.
- Audience callback rejection -> `401`, no session, state consumed.
- Refresh current audience -> Pending persistence -> Ready with NULL email and one remote refresh.
- Crash/restart Pending current audience -> local re-verification -> Ready without `/me`.
- Legacy issuer/missing/wrong audience on refresh/Pending -> expected-generation revoke, shared `401`, no upstream.
- Temporary/JWKS/other verification uncertainty -> shared `503`, no clear, no upstream.
- Logout/idle/absolute expiry beats late finalization.
- Adapter and proxy identity contain only safe user ID; spoofed email remains stripped and no trusted email is injected.

### 11.4 Real Current-Auth-Mini Drill

Update `scripts/e2e-real-auth-mini.sh` to:

- pin official `c4e28f5`;
- keep all build/test output under repository `target/`;
- use auth-mini at `127.0.0.1` and gateway public URL at `localhost` so issuer and gateway hostnames differ;
- preseed deterministic allowed/denied users and OTPs;
- assert login redirect has exact callback, state, and loopback `aud=localhost`;
- call `/email/verify` with the same `redirect_uri` and explicit `aud`;
- assert access JWT `aud` locally without printing it;
- complete direct callback POST with `ALLOW_USER_IDS` and prove no `/me` dependency;
- expire access, refresh, assert rotated token preserves audience, and authorize again;
- mint a valid wrong-audience token and require callback `401` with zero upstream hits;
- retain logout, exact refresh rejection, temporary outage, allowlist denial, adapter, proxy, HTTP, and WebSocket checks;
- scan logs/artifacts for fixture secrets and identity values.

The script still simulates the callback bridge POST rather than driving a browser. That is acceptable because the fragment field names and bridge code are unchanged; login URL parameters, real token issuance, callback handler, refresh, and policy are exercised end to end.

### 11.5 Commands

```bash
cargo fmt --check
cargo test
scripts/e2e-old-binary-compat.sh
AUTH_MINI_RUST_DIR=/tmp/opencode/auth-mini-official-20260730/rust-backend \
AUTH_MINI_EXPECTED_COMMIT=c4e28f5cabe4dc248c137f2efb48453e35131ba6 \
scripts/e2e-real-auth-mini.sh
scripts/e2e-proxy-mode.sh
scripts/e2e-mode-switch.sh
```

The exact full official commit hash is recorded by the script and task test report. No Nix build is part of this repository verification.

## 12. Milestones

### Milestone 1: Audience and callback boundary

- Add derived audience and loopback login parameter behavior.
- Add exact JWT audience verification and deterministic fixtures.
- Remove callback `/me`; create NULL-email Ready sessions from signed claims.
- **Acceptance:** Matching current-profile callback succeeds; wrong/missing audience fails; ID allow/deny is exact.
- **Rollback impact:** Code-only; no DB change.

### Milestone 2: Refresh, legacy, and identity boundary

- Replace Pending `/me` finalization with local token re-verification.
- Conditionally revoke audience-incompatible refresh/Pending generations.
- Make policy and emitted identity user-ID-only; reject nonempty `ALLOW_EMAILS`.
- **Acceptance:** Current refresh recovers across crash; legacy audience forces bounded re-login; no email authorization/header remains.
- **Rollback impact:** Schema remains readable; functional rollback still depends on auth-mini version.

### Milestone 3: Current-upstream proof and operator guidance

- Update active examples/docs and the real-auth script.
- Run repository, old-binary, adapter/proxy, and official auth-mini gates.
- **Acceptance:** All required checks pass with secret-safe evidence and explicit rollout blocker for missing production IDs.
- **Rollback impact:** Documentation and scripts only.

## 13. Open Questions

No implementation-blocking design questions remain. Production rollout remains blocked until exact `ALLOW_USER_IDS` values are provisioned outside this repository.

## 14. Implementation Notes

- Expected files: `src/config.rs`, `src/jwt.rs`, `src/auth_mini.rs`, `src/server.rs`, `src/policy.rs`, related tests, active examples/docs, and `scripts/e2e-real-auth-mini.sh`.
- Keep schema-v2 SQL and old-binary compatibility tests intact.
- Prefer deleting obsolete `/me` types and mocks over preserving an unused downstream identity path.
- Keep code changes local to existing callback/refresh functions; do not introduce a second session architecture.

## 15. References

- Plan: `.legion/tasks/diagnose-login-callback-failure/plan.md`
- Research: `.legion/tasks/diagnose-login-callback-failure/docs/research.md`
- Official guide: `/tmp/opencode/auth-mini-official-20260730/docs/integration/backend-jwt-verification.md`
- Official audience code: `/tmp/opencode/auth-mini-official-20260730/rust-backend/src/audience.rs`
- Gateway JWT verifier: `src/jwt.rs`
- Gateway callback/refresh: `src/server.rs`
- Gateway persistence: `src/db.rs`
