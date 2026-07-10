# Change Review

## Blocking Findings

None.

## Decision: PASS

The implementation is consistent with the requested policy boundary, and the previous verification blocker is resolved by the task-local test report and passing real auth-mini/nginx integration run.

No additional correctness, security, maintainability, or scope blocker was found in the reviewed diff against `master`, including the untracked task/wiki files.

## Security Lens

Security lens applied because the change affects authentication method handling, identity, and authorization.

- `src/policy.rs:14-25` authorizes only when either the normalized email exactly matches `ALLOW_EMAILS` or the user ID exactly matches `ALLOW_USER_IDS`; otherwise it returns `Deny`.
- Both session creation and every `/auth/check` decision use the same policy (`src/server.rs:140-148`, `src/server.rs:217-229`, `src/server.rs:384-392`). An authenticated but unknown identity receives `403`; the changed code does not add a route around policy evaluation.
- Identity remains anchored to a signature/issuer/type/expiry-verified auth-mini access token, callback `sid` equality, and `/me` user-ID equality (`src/jwt.rs:29-106`, `src/server.rs:152-177`). Refresh repeats token verification and user/session binding (`src/server.rs:232-261`).
- JWT `amr` remains shape-validated, stored, and refreshed, but it is no longer passed into or consulted by authorization. This preserves the task's token/session-data boundary while making auth-mini solely responsible for selecting authentication methods.
- Existing signed-cookie, state-consumption, identity-header safety, refresh-failure revocation, and nginx `auth_request` enforcement paths are unchanged. No new bypass was identified in the diff.
- Active runtime configuration, examples, scripts, README, and deployment documentation no longer expose `REQUIRE_PASSKEY` or describe gateway Passkey-only policy. Older `.legion/tasks/**` evidence remains historical; the older production wiki task explicitly records that this task supersedes its former `amr` policy.

## Scope Review

The changes stay within the approved scope: remove `REQUIRE_PASSKEY`, remove `amr`-based authorization, preserve verified token/session data and exact allowlists, and update active examples/docs. No production behavior outside that boundary was changed.

## Evidence Assessed

- Full working-tree diff against `master`, plus untracked `.legion/tasks/remove-auth-method-policy/**` and `.legion/wiki/tasks/remove-auth-method-policy.md`.
- `.legion/tasks/remove-auth-method-policy/docs/test-report.md`: PASS.
- `cargo fmt --check`; `cargo test` with 11 passing tests; active-reference scan; diff whitespace check.
- Real auth-mini/nginx E2E passed Email OTP callback and protected HTTP access, authenticated WebSocket proxying, SQLite session persistence, refresh-token rotation, logout revocation, refresh-failure revocation, and non-allowlisted identity denial before upstream access.
- Reviewer check: `git diff --check master` passed.

## Residual Risks

- Deployment topology remains part of the security boundary: a protected upstream reachable outside nginx can bypass gateway authorization. This is pre-existing and documented.
- Gateway sessions cache the `/me` email until refresh. An auth-mini email change may therefore take effect at the gateway only after refresh or local session expiry. This is pre-existing and unchanged by the diff.
- `amr` remains a required, shape-validated auth-mini token claim. Its value no longer affects authorization, but a future auth-mini token-contract change that removes `amr` would still require a separate compatibility change.
