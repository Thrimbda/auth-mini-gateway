# auth-mini-gateway-poc Tasks

## Current Phase

- [x] Brainstorm entry selected because no existing task id/path was provided.
- [x] Delivery shape confirmed: runnable PoC gateway repository, auth-mini as external dependency.
- [x] Design gate.
- [x] Implementation.
- [x] Verification.
- [x] Review, walkthrough, and wiki writeback.

## Checklist

- [x] Capture task goal, problem, acceptance, assumptions, constraints, risks, scope, non-goals, design summary, and phases.
- [x] Write RFC covering gateway endpoints, callback bridge, session storage, JWT verification, refresh, allowlist, nginx config, WebSocket compatibility, and rollback/non-production limits.
- [x] Review RFC before implementation.
- [x] Initialize TypeScript project and runtime configuration.
- [x] Implement gateway login, callback bridge, session creation, auth check, refresh, allowlist, and logout.
- [x] Add nginx auth_request and PoC upstream examples.
- [x] Add tests for login callback state, safe redirects, cookie/session tamper handling, JWT verification, refresh success/failure, allowlist denial, logout, and upstream denial behavior.
- [x] Record verification evidence in `docs/test-report.md`.
- [x] Run readiness review and record result.
- [x] Generate walkthrough.
- [x] Update Legion wiki.

## Status Notes

- Repository started empty except for `.git/`.
- Reference repository inspected at `https://github.com/zccz14/auth-mini`; relevant contracts are auth-mini login redirect, `/jwks`, `/session/refresh`, `/session/logout`, and `/me`.
