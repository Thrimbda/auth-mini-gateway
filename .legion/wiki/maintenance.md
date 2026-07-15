# Maintenance

## auth-mini gateway follow-up

- Before OpenCode rollout, verify OpenCode is not reachable directly from any public origin and only accepts traffic through nginx/gateway enforcement.
- Decide whether `GET /logout` remains as compatibility convenience or should be disabled in deployment examples in favor of `POST /logout`.
- Add E2E replay assertions for consumed callback/login state.
- Validate `AUTH_MINI_LOGIN_URL` during gateway config parsing.
- Keep `docs/production-deployment.md` aligned with future runtime config, nginx, and rollback behavior changes.
- Consider adding compromise-specific rollback steps for suspected cookie secret, SQLite DB, or refresh-token exposure.
- Add an auth-mini top-level authorize/resume flow with redirect allowlisting and browser tests before claiming silent SSO.
- Add auth-mini refresh idempotency, result lookup, or previous-token recovery to close the post-commit lost-response residual.
- Make auth-mini internal refresh failures return 5xx instead of folding them into `401 session_invalidated`.
- Run a physical mobile Safari smoke for overnight suspension, first-request recovery, and absolute `Expires` behavior.
- Rerun `scripts/e2e-real-auth-mini.sh` with the pinned auth-mini checkout to capture direct proxy login, refresh outage/recovery, denial, WebSocket, and logout evidence.
- Before OpenCode proxy rollout, execute the physical Acorn maintenance-deny and FRP `7780` to `7781` mode-switch drill; prove gateway adapter port `3000` and OpenCode port `4096` have no public/FRP route.
- Expand structured proxy/admission observability toward the RFC recommendations without logging URI, Host, identity, cookies, tokens, upstream values, or raw transport errors.
