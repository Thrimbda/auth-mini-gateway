# Task Summary: auth-mini-gateway-poc

## Status

- Implementation completed in worktree branch `legion/auth-mini-gateway-poc-gateway`.
- RFC review passed after adding composed nginx verification.
- Verification passed: `npm test`, `npm run typecheck`, `npm run build`, Compose config, and Compose-network smoke.
- Readiness/security review passed with no blocking findings.
- Historical: superseded for production runtime by `production-rust-sqlite-gateway`.

## Outcome

The repository previously contained a runnable TypeScript PoC gateway that used auth-mini as an external authentication authority and exposed nginx-facing front-auth decisions. This summary is retained as historical evidence; production runtime knowledge should start from `production-rust-sqlite-gateway`.

Implemented capabilities:

- auth-mini login redirect and fragment callback bridge
- one-time login state
- opaque signed HttpOnly gateway session cookie
- server-side in-memory session/token storage
- auth-mini JWT verification through `/jwks`
- `/me` identity lookup
- session refresh through `/session/refresh`
- logout with local revocation and auth-mini logout attempt
- email/user-id allowlist
- optional Passkey-only policy via `amr: webauthn`
- nginx `auth_request` example with HTTP and WebSocket upstream support
- Docker Compose smoke topology with mock auth-mini and non-published upstream

## Key Evidence

- Plan: `.legion/tasks/auth-mini-gateway-poc/plan.md`
- RFC: `.legion/tasks/auth-mini-gateway-poc/docs/rfc.md`
- RFC review: `.legion/tasks/auth-mini-gateway-poc/docs/rfc-review.md`
- Test report: `.legion/tasks/auth-mini-gateway-poc/docs/test-report.md`
- Change review: `.legion/tasks/auth-mini-gateway-poc/docs/review-change.md`
- Walkthrough: `.legion/tasks/auth-mini-gateway-poc/docs/report-walkthrough.md`

## Important Design Notes

- auth-mini returns login tokens in the URL fragment, so the gateway needs a browser callback bridge page; a server-only callback cannot work.
- Unauthorized but authenticated users keep a gateway session so nginx can return `403` instead of repeatedly treating them as unauthenticated `401`.
- Refresh is per-session single-flight and guarded against stale failures and logout-vs-refresh resurrection.
- In-memory storage is bounded and prunes expired entries, but remains a PoC limitation.

## Residual Follow-Up

- Choose production session persistence if this moves beyond PoC.
- Verify the real OpenCode direct-origin/network boundary before replacing Basic Auth.
- Replace mock auth-mini smoke with real auth-mini deployment smoke during rollout.
