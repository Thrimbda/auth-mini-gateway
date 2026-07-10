# Maintenance

## auth-mini gateway follow-up

- Before OpenCode rollout, verify OpenCode is not reachable directly from any public origin and only accepts traffic through nginx/gateway enforcement.
- Decide whether `GET /logout` remains as compatibility convenience or should be disabled in deployment examples in favor of `POST /logout`.
- Add E2E replay assertions for consumed callback/login state.
- Validate `AUTH_MINI_LOGIN_URL` during gateway config parsing.
- Keep `docs/production-deployment.md` aligned with future runtime config, nginx, and rollback behavior changes.
- Consider adding compromise-specific rollback steps for suspected cookie secret, SQLite DB, or refresh-token exposure.
