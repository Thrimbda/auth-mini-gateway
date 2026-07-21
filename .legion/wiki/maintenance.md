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
- Rerun `scripts/e2e-real-auth-mini.sh` with the pinned auth-mini checkout to close the current real-auth compatibility gap and capture direct proxy login, refresh outage/recovery, denial, WebSocket, logout, and secret-boundary evidence.
- Re-review the same-connection SETTINGS proof, ongoing fixed-memory capability monitor, enqueue linearization, transport-drop witness, and pre-service nonzero CONNECT boundary before upgrading pinned Hyper/h2.
- Before any OpenCode or HTTP/2 production rollout, validate Acorn nginx and FRP with deployed credentials, prove selected-protocol and `http1` rollback evidence, then prove the physical `:443 -> 127.0.0.1:18081 -> Axiom 127.0.0.1:7780 -> OpenCode 127.0.0.1:4096` chain and no unintended public/FRP route to `3000`, `7780`, or `4096`.
- Install the hardened gateway unit and record effective `LimitNOFILE`, `TasksMax`, `MemoryMax`, Threads, VmRSS, and VmSize under R + 16 margin + 64-auth stress before public exposure.
- Keep `TRUSTED_PROXY_CIDRS` empty until Axiom proves the exact frpc direct peer and Acorn proves one-value `$remote_addr` XFF overwrite; then enable only the observed CIDR and repeat non-influence checks.
- Run native maintenance-deny, hardened underscore, and old-binary rollback probes before relying on the checked nginx rollback artifact.
- Expand structured proxy/admission observability toward the RFC recommendations without logging URI, Host, identity, cookies, tokens, upstream values, or raw transport errors.

## HTTP/2 performance proof follow-up

- Treat exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2` as terminal `BLOCKED`: do not retry it, change thresholds, or convert the absence of samples into a no-regression claim.
- Preserve partial unsealed root `cal-smoke-743fa30d7371-a03fd3cf021e` and the sealed terminal evidence until the delivery lifecycle authorizes cleanup.
- Main implementation PR #13 is merged, and artifact commit `d19ce2e` passed `delivery-ready`, full tests, strict Clippy, and focused closeout review. The closeout PR is still pending; after it merges, run `delivery-retained` against the fetched durable base before cleaning ignored benchmark evidence, removing the worktree/branches, or refreshing main.
