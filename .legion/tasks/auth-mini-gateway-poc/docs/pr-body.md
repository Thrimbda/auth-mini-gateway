## Summary

- Initialize `auth-mini-gateway` as a runnable Node.js/TypeScript PoC gateway for nginx `auth_request` front authentication.
- Add auth-mini login callback bridging, server-side gateway sessions, JWT/JWKS verification, refresh, logout, allowlist, and Passkey policy support.
- Add nginx/Docker Compose/PoC upstream/mock auth-mini examples plus smoke and automated tests.

## Validation

- `npm test` passed: 11 tests.
- `npm run typecheck` passed.
- `npm run build` passed.
- Compose config validation passed.
- Compose smoke passed for denied-not-proxied, allowed HTTP, allowed WebSocket, and no direct upstream host port.

## Legion Evidence

- Plan: `.legion/tasks/auth-mini-gateway-poc/plan.md`
- RFC: `.legion/tasks/auth-mini-gateway-poc/docs/rfc.md`
- RFC review: `.legion/tasks/auth-mini-gateway-poc/docs/rfc-review.md`
- Test report: `.legion/tasks/auth-mini-gateway-poc/docs/test-report.md`
- Change review: `.legion/tasks/auth-mini-gateway-poc/docs/review-change.md`
- Walkthrough: `.legion/tasks/auth-mini-gateway-poc/docs/report-walkthrough.md`

## Notes

- Sessions are in-memory for the PoC and are not restart-safe or horizontally scalable.
- Real OpenCode rollout still needs direct-origin network verification before replacing Basic Auth.
