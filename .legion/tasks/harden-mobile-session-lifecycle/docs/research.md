# Research: mobile session lifecycle hardening

> **Profile:** RFC Heavy / High Risk
> **Date:** 2026-07-13
> **Scope:** read-only investigation; no production code or external repository was changed

## 1. Problem restatement

The gateway currently gives every local session one fixed deadline, treats every refresh failure as permanent, and does not copy a renewal cookie from an nginx auth subrequest to the browser-facing response. The task must add a 7-day inactivity deadline under a non-sliding 30-day absolute deadline, preserve sessions across temporary auth-mini failures, keep explicit revocation fail-closed, and migrate schema v1 without extending any existing session.

The stable contract is `.legion/tasks/harden-mobile-session-lifecycle/plan.md`. The current task is design-only; auth-mini remains external and unmodified.

## 2. Repository entry points and current behavior

| Area | Evidence | Current behavior relevant to this RFC |
|---|---|---|
| Schema/bootstrap | `src/db.rs:50-103` | `PRAGMA user_version=1`; one `gateway_sessions.session_expires_at`; no idle/absolute split and no version-2 migration. |
| Session create/read | `src/db.rs:158-202` | Creation sets one fixed `now + SESSION_TTL_SECONDS` deadline. Active reads require only that deadline and `revoked_at IS NULL`. |
| Refresh CAS | `src/db.rs:214-270` | Durable old-refresh-token compare-and-swap prevents stale writeback, but does not prevent duplicate remote refresh calls. |
| Pruning | `src/db.rs:272-283` | Expired/revoked rows are deleted opportunistically; no separate absolute deadline exists. |
| Auth check | `src/server.rs:180-230` | Every refresh error eventually revokes locally, clears the cookie, and returns `401`; a successful `204` does not touch the session or emit a cookie. |
| Refresh flow | `src/server.rs:232-262` | Calls refresh, verifies the JWT, calls `/me`, then persists. Failure after remote token rotation but before persistence can lose the rotated token. |
| Logout | `src/server.rs:264-296` | Local revoke precedes best-effort remote logout; this is the correct fail-closed ordering to preserve. |
| Cookies | `src/cookies.rs:17-74` | Opaque HMAC value, `HttpOnly`, `Path=/`, configured `SameSite`/`Secure`, and fixed caller-supplied `Max-Age`. |
| Configuration | `src/config.rs:34-77`, `.env.example:13-15` | Session default/sample is 8 hours; login-state default/sample is 300 seconds; refresh skew is 60 seconds. |
| Wall clock | `src/util.rs:7-13`, `src/db.rs`, `src/server.rs`, `src/jwt.rs` | `Utc::now()`/`now_unix()` are called directly across modules, so exact deadline tests cannot control time globally. |
| Concurrency model | `src/server.rs:19-43` | One OS thread per connection; there is no per-session in-process single-flight registry. |
| nginx boundary | `examples/nginx.conf:46-84` | `auth_request` captures identity headers only. It neither captures subrequest `Set-Cookie` nor deliberately maps auth-subrequest errors to browser-facing `503`. |
| Deployment docs | `docs/production-deployment.md:56-87,218-277,343-357` | Documents the old 8-hour/300-second settings and old nginx pattern; rollback already requires retaining a verified access-control layer. |
| Real E2E | `scripts/e2e-real-auth-mini.sh` | Uses real auth-mini, nginx, SQLite, HTTP, and WebSocket, but currently asserts every refresh failure revokes and redirects. It mutates timestamps directly instead of using a controlled clock. |

There are 11 current Rust tests, mainly cookie, policy, redirect, login-state, and refresh-CAS checks. Lifecycle boundaries, migration v1→v2, typed refresh errors, true single-flight, nginx cookie propagation, and `503` recovery are not covered.

## 3. Existing conventions and historical decisions

- nginx remains the only public reverse proxy and the protected upstream must not be directly reachable (`.legion/wiki/decisions.md`).
- The browser stores only an opaque signed gateway cookie; auth-mini access/refresh tokens remain in SQLite (`.legion/wiki/decisions.md`).
- Production supports one active gateway over SQLite WAL, not multi-active shared SQLite (`.legion/wiki/decisions.md`).
- Final validation must use real auth-mini plus nginx and protected HTTP/WebSocket upstreams (`.legion/wiki/patterns.md`).
- Refresh writeback must confirm the old refresh token/session state and logout must win over in-flight refresh (`.legion/wiki/patterns.md:13-21`).
- Authentication-method policy belongs to auth-mini. This task must not reintroduce gateway `amr`/Passkey authorization (`.legion/wiki/tasks/remove-auth-method-policy.md`).
- Logs and diagnostics must not contain token values, signed cookies, cookie secrets, callback bodies, or unsafe identity values (`.legion/wiki/decisions.md`).

## 4. auth-mini refresh contract (read-only sibling evidence)

The inspected sibling was `/home/c1/Work/auth-mini` at commit `86b4aaa8ca97d1218217a7f6f0144251a5f30c9b` (2026-07-10). No sibling files were modified.

### Public HTTP contract

- `POST /session/refresh` accepts exactly `session_id` and `refresh_token` (`rust-backend/src/session.rs:12-53`; `openapi.yaml:286-320`).
- `200` returns a rotated access/refresh pair.
- `400 {"error":"invalid_request"}` means request-contract failure.
- `401 {"error":"session_invalidated"}` means the session can no longer be refreshed.
- `401 {"error":"session_superseded"}` means the presented rotating refresh token is no longer current.
- The endpoint rotates the stored refresh-token hash using a compare-and-swap update (`rust-backend/src/session.rs:85-140`).
- The documented refresh-token lifetime is 30 days and is reset by successful refresh (`rust-backend/src/session.rs:9-10,105-119`). The gateway's local 30-day absolute deadline therefore remains necessary to prevent indefinite local extension.

### Important contract caveat

`handle_session_refresh` maps `SessionSuperseded` specifically, but maps every other session-layer error to `401 session_invalidated` (`rust-backend/src/http.rs:544-559`). Some internal SQLite/signing/random-token failures are collapsed into `SessionInvalidated` in `rust-backend/src/session.rs`. From the wire, `session_invalidated` is an explicit rejection and is the only contract available to the gateway, but an auth-mini internal fault can therefore look permanent. This is recorded as a review risk, not hidden as a settled fact.

### `/me` is not a refresh/session revocation authority

Second-round review identified an important narrower boundary at the same fixed auth-mini commit:

- OpenAPI defines `GET /me` `401 invalid_access_token` only as a missing, malformed, expired, or revoked **access token** (`openapi.yaml:269-285,782-789`). It does not claim that the refresh token or auth-mini session is permanently unusable.
- `handle_me` returns the same `401 invalid_access_token` when access authentication fails and when `current_user_response` returns **any** error (`rust-backend/src/http.rs:849-857`). Profile or SQLite failures can therefore be folded into the same wire result.
- `authenticate_access_token` folds JWT verification, session lookup/DB failure, missing session, expiry, and user mismatch into `InvalidAccessToken` (`rust-backend/src/session.rs:143-165`).

Therefore `/me` status/body cannot safely distinguish recoverable access-token/profile failure from permanent refresh/session rejection. Only a fresh valid `200` profile whose user matches the verified JWT and existing session may finalize identity-pending. Every other `/me` result—including exact `401 invalid_access_token`, transport/status/body/parse failure, and identity mismatch—must keep the row Pending and return fail-closed `503`. Identity mismatch is alertable contract/security drift, not a refresh rejection. Remote conditional revoke authority remains limited to exact rejection from `POST /session/refresh`.

### Ambiguous refresh outcome

The protocol has no idempotency key, result lookup, or previous-refresh-token grace path. If auth-mini commits rotation and the response is lost—or the gateway crashes after receiving it but before durable CAS—the gateway only retains the old token. A later retry receives `session_superseded` and cannot recover the new token. Single-flight prevents duplicate local calls but cannot solve this post-commit ambiguity. `review-rfc` accepted this as a bounded fail-closed residual with an explicit two-request/next-independent-request test boundary.

## 5. nginx auth_request semantics

Current official nginx documentation was retrieved through Context7 from `/websites/nginx`:

- `auth_request` allows a 2xx subrequest result.
- It denies with the corresponding `401` or `403`.
- Any other subrequest status is considered an error.
- `auth_request_set` can expose a value from the completed authorization subrequest.

Source: <https://nginx.org/en/docs/http/ngx_http_auth_request_module.html>

Consequences:

1. A gateway `503` is not passed through by `auth_request` as `503`; nginx turns the authorization phase into an internal error (normally `500`). The protected location needs an explicit auth-error `500` → named-location `503` mapping.
2. A subrequest `Set-Cookie` is not automatically a browser-facing main-response header. The protected location must capture `$upstream_http_set_cookie` through `auth_request_set` and add it to the final response with `always` semantics.
3. The composed E2E must prove that this mapping does not rewrite a protected upstream's own `500`; keep `proxy_intercept_errors off` and test that boundary.
4. The auth subrequest must emit at most one gateway session cookie because `$upstream_http_set_cookie` is used as one captured value. Login-state cookies continue to come from the separate login proxy response.

## 6. Silent SSO capability gate

**Conclusion: current auth-mini does not support no-interaction SSO for the gateway's top-level login redirect. Do not claim or implement silent SSO in this gateway PR.**

Evidence at the fixed sibling commit:

- The redirect integration guide requires the user to complete Email OTP, Passkey, or Ed25519 login before returning tokens (`docs/integration/login-redirect.md:7-14,140-148`).
- `LoginRoute` only sends a callback after one of those explicit handlers produces new tokens (`ui-web/src/routes/login.tsx:76-180`). It contains no branch that observes an already authenticated SDK session and returns it to `redirect_uri`.
- The browser SDK/provider can persist and recover auth-mini-origin localStorage (`ui-web/src/app/providers/demo-provider.tsx:70-89`; `src/sdk/browser-runtime.ts:927-934`). This establishes only a local auth-mini UI session, not redirect SSO.
- `LoginRoute` does not read the provider's recovered `session` at all, and `completeLogin` only sends a caller callback after a new interactive method returns tokens (`ui-web/src/routes/login.tsx:30-45,146-167`). `/login` is also outside the authenticated `AppShell` redirect logic (`ui-web/src/app/router.tsx:9-20`).
- Existing login tests cover interactive email/passkey/Ed25519 callbacks and local login, not no-interaction redirect reuse (`ui-web/src/routes/login.test.tsx:208-381`).

Required external follow-up: auth-mini needs an explicit, tested top-level authorize/resume capability that awaits SDK recovery, validates a server-side redirect allowlist, defines interaction/prompt policy, and safely returns or rotates an existing session. It must not be approximated by gateway automation or iframe/background refresh.

## 7. Constraints and non-goals derived from evidence

- New local sessions use 7-day inactivity and 30-day absolute lifetime; only an allowed `204` auth decision touches inactivity.
- A WebSocket counts as activity only at the authenticated handshake.
- A temporary/indeterminate refresh failure returns unavailable, does not touch, does not clear/revoke, and never reaches upstream.
- Only recognized explicit auth-mini rejection can revoke because of refresh; local logout and normal local expiry remain independent deterministic revocation paths.
- No multi-active coordination, token-at-rest encryption, cookie-secret rotation, native-app SDK, or auth-mini protocol change is introduced here.
- Email is initially obtained from `/me`. The failed RFC review rejected a 30-day snapshot: after rotation the gateway must durably persist the new tokens in a fail-closed identity-pending state, then call/retry `/me` before authorization.

## 8. Review addendum and required proof

- `review-rfc` accepted post-commit refresh response loss as a bounded fail-closed residual: one indeterminate flight returns `503` to all joiners; the next independent exact superseded response conditionally revokes and requires login.
- `review-rfc` accepted trusting only exact `401 session_invalidated/session_superseded`; all other status/body combinations remain unavailable.
- `review-rfc` accepted the 3600-second touch interval and rejected the email snapshot alternative.
- Positive session Cookie must use an absolute `Expires`, not a positive relative `Max-Age`, because the latter starts when the browser receives the delayed main response.
- Second-round `review-rfc` requires `/me` to have no local revoke/clear authority: only fresh valid matching `200` finalizes; every other result remains Pending and returns `503` until retry, normal Pending→Pending refresh, local logout, or local expiry resolves the state.
- [ ] Prove same-generation success/rejected/temporary/indeterminate joiners share one flight result and one remote call.
- [ ] Prove durable identity-pending is denied by both new and actual old binaries, survives crash for retry, and cannot be finalized after logout/expiry.
- [ ] Prove `/me` exact `401 invalid_access_token`, folded profile/internal failure, malformed success, and identity mismatch all preserve Pending, do not clear/touch/authorize, and hit no protected upstream.
- [ ] Prove repeated independent `/me` flights can recover on a later fresh valid profile; an access-expiry race does not revoke, and only a later exact refresh rejection conditionally revokes.
- [ ] Prove a slow upstream cannot move positive session Cookie expiry and a receipt-time Cookie jar/browser drops an already-expired Cookie.
- [ ] Prove with real nginx that the captured session cookie survives the final upstream response and the `401` internal redirect that also sets login state.
- [ ] On the final `401` redirect, assert two distinct `Set-Cookie` headers by name: clear `amg_session` and positive `amg_login_state`.
- [ ] Prove real nginx returns final `503` with no `Location`, no session clearing, and zero protected-upstream hits for gateway timeout/429/5xx classes.
- [ ] Confirm the deployment's log/metric collector can alert on fixed low-cardinality outcome fields without recording Cookie/Authorization headers.

## 9. References

- Contract: `.legion/tasks/harden-mobile-session-lifecycle/plan.md`
- Task log/status: `.legion/tasks/harden-mobile-session-lifecycle/log.md`, `tasks.md`
- Current truth: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`, `.legion/wiki/maintenance.md`
- Prior production RFC: `.legion/tasks/production-rust-sqlite-gateway/docs/rfc.md`
- Gateway source: `src/db.rs`, `src/server.rs`, `src/auth_mini.rs`, `src/cookies.rs`, `src/config.rs`, `src/http.rs`, `src/jwt.rs`
- Deployment/E2E: `examples/nginx.conf`, `scripts/e2e-real-auth-mini.sh`, `docs/production-deployment.md`
- Read-only auth-mini evidence: `/home/c1/Work/auth-mini/openapi.yaml`, `rust-backend/src/session.rs`, `rust-backend/src/http.rs`, `ui-web/src/routes/login.tsx`, `ui-web/src/app/router.tsx`
