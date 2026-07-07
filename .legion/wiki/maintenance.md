# Maintenance

## auth-mini gateway follow-up

- Select a production session store before using this gateway beyond a single-process PoC. Candidate stores should support TTL, revocation, and single-flight or compare-and-swap semantics for refresh.
- Before OpenCode rollout, verify OpenCode is not reachable directly from any public origin and only accepts traffic through nginx/gateway enforcement.
- Run a real auth-mini Passkey smoke with the deployed issuer/RP ID before replacing Basic Auth.
- Decide whether `GET /logout` remains as a PoC convenience or should be disabled in deployment examples in favor of `POST /logout`.
