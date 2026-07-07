# auth-mini-gateway-poc Tasks

## Current Phase

- [x] Brainstorm entry selected because no existing task id/path was provided.
- [x] Delivery shape confirmed: runnable PoC gateway repository, auth-mini as external dependency.
- [ ] Design gate.
- [ ] Implementation.
- [ ] Verification.
- [ ] Review, walkthrough, and wiki writeback.

## Checklist

- [x] Capture task goal, problem, acceptance, assumptions, constraints, risks, scope, non-goals, design summary, and phases.
- [ ] Write RFC covering gateway endpoints, callback bridge, session storage, JWT verification, refresh, allowlist, nginx config, WebSocket compatibility, and rollback/non-production limits.
- [ ] Review RFC before implementation.
- [ ] Initialize TypeScript project and runtime configuration.
- [ ] Implement gateway login, callback bridge, session creation, auth check, refresh, allowlist, and logout.
- [ ] Add nginx auth_request and PoC upstream examples.
- [ ] Add tests for login callback state, safe redirects, cookie/session tamper handling, JWT verification, refresh success/failure, allowlist denial, logout, and upstream denial behavior.
- [ ] Record verification evidence in `docs/test-report.md`.
- [ ] Run readiness review and record result.
- [ ] Generate walkthrough and update Legion wiki.

## Status Notes

- Repository started empty except for `.git/`.
- Reference repository inspected at `https://github.com/zccz14/auth-mini`; relevant contracts are auth-mini login redirect, `/jwks`, `/session/refresh`, `/session/logout`, and `/me`.
