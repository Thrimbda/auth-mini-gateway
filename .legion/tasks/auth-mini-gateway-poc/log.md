# auth-mini-gateway-poc Log

## 2026-07-08

- Started via explicit user request to use Legion workflow.
- No existing `.legion/` directory or source files were present in the repository.
- Cloned `https://github.com/zccz14/auth-mini` into `/tmp/opencode/auth-mini-reference` for read-only reference.
- Confirmed delivery shape with the user: runnable Node.js/TypeScript PoC gateway repository, nginx example, PoC upstream, callback bridge, allowlist config, and tests; auth-mini remains external and unmodified.
- Materialized initial task contract in `plan.md` and `tasks.md`.
- Opened PR envelope worktree at `.worktrees/auth-mini-gateway-poc` on branch `legion/auth-mini-gateway-poc-gateway` after user-approved empty-repo `master` bootstrap.
- Wrote `docs/rfc.md` and ran `review-rfc`; initial review failed on missing nginx/front-auth verification path.
- Updated RFC with composed nginx + gateway + upstream smoke verification requirements; `review-rfc` passed with no blocking findings.
- Implemented TypeScript Node gateway with opaque signed cookies, server-side in-memory sessions, auth-mini JWT verification, refresh, allowlist/passkey policy, callback bridge, auth check, and logout.
- Added nginx `auth_request` example, Docker Compose PoC, mock auth-mini, PoC upstream with WebSocket echo, and nginx smoke script.
- Added Vitest coverage for safe return targets, state replay, cookie tamper, allowlist denial, Passkey policy, refresh success/failure, and logout.
- Engineer local checks: `npm test` passed, `npm run typecheck` passed after one mock-auth-mini typing fix, and `npm run build` passed.
- Verification passed: `npm test`, `npm run typecheck`, `npm run build`, Compose config validation, and Compose-network nginx smoke all passed.
- Verification fixes made: excluded `dist/**` from Vitest, parameterized Compose host ports, used repo-local ignored `.docker/` for Docker config, corrected Docker/package start path to `dist/src/server.js`, and retained authenticated-but-unauthorized gateway sessions so nginx receives `403` instead of `401`.
- Wrote verification evidence to `docs/test-report.md`.
- `review-change` initially failed on two blockers: concurrent refresh could delete a valid refreshed session, and public in-memory login/session stores lacked TTL cleanup/caps.
- Fixed review blockers with per-session refresh single-flight, stale refresh-failure guard, opportunistic TTL pruning, max login/session caps, malformed-cookie handling, EdDSA-only JWT verification, and regression tests.
- Fixed nginx example after Compose logs showed `proxy_pass` with URI is invalid inside named locations; replaced it with internal exact location `/__login_redirect`.
- Re-ran `npm test`, `npm run typecheck`, `npm run build`, and Compose smoke successfully after hardening.
- `review-change` re-review found a logout-vs-refresh race that could resurrect a deleted session; fixed refresh writeback to require the session still exists with the same refresh token and added regression coverage.
- Re-ran `npm test` (11 tests), `npm run typecheck`, `npm run build`, and Compose smoke successfully after the logout race fix.
- Final `review-change` passed with no blocking findings.
- Generated implementation-mode `docs/report-walkthrough.md` and `docs/pr-body.md` from existing RFC, verification, and review evidence.
- Completed Legion wiki writeback under `.legion/wiki/` with task summary, decisions, patterns, maintenance, and wiki log.
