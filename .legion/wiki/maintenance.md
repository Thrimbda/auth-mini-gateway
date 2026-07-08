# Maintenance

## auth-mini gateway follow-up

- Before OpenCode rollout, verify OpenCode is not reachable directly from any public origin and only accepts traffic through nginx/gateway enforcement.
- Run a real auth-mini Passkey/WebAuthn browser smoke with the deployed issuer/RP ID before replacing Basic Auth.
- Decide whether `GET /logout` remains as compatibility convenience or should be disabled in deployment examples in favor of `POST /logout`.
- Add E2E replay assertions for consumed callback/login state.
- Validate `AUTH_MINI_LOGIN_URL` during gateway config parsing.
- Document operational assumptions for direct gateway exposure hardening.
