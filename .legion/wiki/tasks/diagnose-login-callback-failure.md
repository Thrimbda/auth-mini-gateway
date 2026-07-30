# diagnose-login-callback-failure

## Metadata

- `task-id`: `diagnose-login-callback-failure`
- `status`: `completed`
- `risk`: `high`
- `schema-version`: `gateway-session-v2` (unchanged)
- `historical`: `false`
- `supersedes`: email-or-user-id gateway authorization
- `superseded-by`: `(none)`

## Outcome Summary

- Current official auth-mini binds redirect login tokens to the callback hostname as JWT `aud` and reserves `/me` for issuer/self audience.
- The gateway now derives the expected audience from `GATEWAY_PUBLIC_BASE_URL`, verifies exact signed string `aud` for callback, refresh, and Pending recovery, and no longer calls `/me` for downstream sessions.
- Callback and refresh sessions are built from signed `sub`/`sid`/`amr`/`exp`; schema v2 remains unchanged and Pending remains the crash-safe rotation barrier.
- Authorization and trusted identity are exact user-ID-only: `ALLOW_USER_IDS` is the only allowlist, nonempty `ALLOW_EMAILS` fails startup, and only `X-Auth-Mini-User-Id` is injected.
- Real official auth-mini `c4e28f5` E2E, full repository tests, old-binary compatibility, proxy/mode-switch, and HTTP/2 benchmark suites passed.

## Reusable Decisions

- A gateway serving a distinct public hostname must validate the exact auth-mini audience derived from that hostname; issuer-host audience is never a gateway compatibility exception.
- Downstream auth-mini JWTs are authorized from signed claims, not `/me`; `/me` is reserved for Auth Mini self-audience profile/account management.
- Email is not an authorization input or trusted emitted identity when it is absent from the signed downstream token.
- Signed audience rejection after remote refresh rotation is terminal for the expected local generation and uses the same stale-safe conditional revoke discipline as exact refresh rejection.
- Gateway-only rollback cannot restore login against current auth-mini; full functional rollback requires both the previous gateway and pre-audience auth-mini.

## Related Raw Sources

- `plan`: `.legion/tasks/diagnose-login-callback-failure/plan.md`
- `log`: `.legion/tasks/diagnose-login-callback-failure/log.md`
- `tasks`: `.legion/tasks/diagnose-login-callback-failure/tasks.md`
- `research`: `.legion/tasks/diagnose-login-callback-failure/docs/research.md`
- `rfc`: `.legion/tasks/diagnose-login-callback-failure/docs/rfc.md`
- `reviews`: `.legion/tasks/diagnose-login-callback-failure/docs/review-rfc.md`, `.legion/tasks/diagnose-login-callback-failure/docs/review-change.md`
- `test report`: `.legion/tasks/diagnose-login-callback-failure/docs/test-report.md`
- `report`: `.legion/tasks/diagnose-login-callback-failure/docs/report-walkthrough.md`
- `pr body`: `.legion/tasks/diagnose-login-callback-failure/docs/pr-body.md`

## Notes

- Production rollout remains blocked until exact `ALLOW_USER_IDS` values are provisioned and `ALLOW_EMAILS` is cleared for each gateway service.
- Existing sessions can remain usable by an already allowlisted user ID until their recorded refresh boundary; legacy issuer/missing audience then requires re-login.
- PR #16 merged as `9083f358463a185d6890ac1096c4745e0a5bf6c0` with no required GitHub checks reported.
