# Test Report: auth-mini-gateway PoC

## Result

**PASS**

The implemented PoC passed gateway automated tests, TypeScript typecheck, production build, Docker Compose config validation, and composed nginx + gateway + upstream smoke verification.

## Why These Checks

- `npm test` directly exercises the gateway authentication/session/policy behavior required by the task contract.
- `npm run typecheck` validates the TypeScript implementation and tests at compile time.
- `npm run build` validates the production output used by the Docker image.
- `docker compose -f examples/docker-compose.yml config` validates the shipped Compose topology and confirms the upstream service has no published port.
- The Compose smoke command verifies the core PoC claim at the nginx boundary: denied requests do not reach upstream, allowed HTTP reaches upstream, allowed WebSocket reaches upstream, and direct upstream host exposure is absent.

## Commands Executed

### Automated Gateway Tests

```bash
npm test
```

Result:

```text
Test Files  1 passed (1)
Tests  11 passed (11)
```

Coverage represented by tests:

- safe relative return targets and open redirect rejection
- one-time login state and replay rejection
- signed gateway session cookie tamper rejection
- successful auth-mini callback session creation
- allowlist denial after valid auth-mini login
- `REQUIRE_PASSKEY=true` denial for `email_otp`
- refresh success through auth-mini `/session/refresh`
- serialized concurrent refresh for the same gateway session
- refresh failure clearing gateway access
- logout clearing gateway session and calling auth-mini logout
- logout-vs-refresh concurrency cannot resurrect a deleted gateway session
- TTL pruning and capacity bounds for abandoned login states and expired sessions

### Typecheck

```bash
npm run typecheck
```

Result: pass.

### Build

```bash
npm run build
```

Result: pass.

### Compose Config

```bash
NGINX_PORT=18080 AUTH_MINI_PORT=17777 docker compose -f examples/docker-compose.yml config
```

Result: pass. The rendered config publishes nginx and mock auth-mini for PoC driving, and does not publish the `upstream` service.

### nginx/Gateway/Upstream Smoke

Host port `8080` was already in use, so the smoke used the example's configurable ports `18080/17777`. The local `nginx` binary was not installed, so nginx validation ran through the Compose nginx container.

```bash
mkdir -p .docker && \
DOCKER_CONFIG=$PWD/.docker COMPOSE_BAKE=false NGINX_PORT=18080 AUTH_MINI_PORT=17777 \
  docker compose -f examples/docker-compose.yml up -d --build && \
DOCKER_CONFIG=$PWD/.docker \
  docker compose -f examples/docker-compose.yml exec -T \
  -e SKIP_DOCKER_PORT_CHECK=1 \
  upstream sh -c 'set -- $(getent hosts nginx); NGINX_IP=$1; set -- $(getent hosts mock-auth-mini); AUTH_IP=$1; SMOKE_BASE_URL=http://$NGINX_IP:8080 SMOKE_AUTH_URL=http://$AUTH_IP:7777 SMOKE_UPSTREAM_URL=http://127.0.0.1:4000 node scripts/smoke-nginx.mjs' && \
! DOCKER_CONFIG=$PWD/.docker docker compose -f examples/docker-compose.yml port upstream 4000
```

Result:

```text
nginx smoke passed
no port 4000/tcp for container examples-upstream-1: 0/tcp
```

Smoke behavior verified:

- unauthenticated `GET /` through nginx redirected to `/login` and did not increment upstream hits
- authenticated but non-allowlisted user received `403` and did not increment upstream hits
- allowlisted Passkey user reached the HTTP upstream and incremented hits
- allowlisted Passkey user reached the WebSocket echo endpoint and incremented hits
- upstream service had no host port published

Cleanup:

```bash
DOCKER_CONFIG=$PWD/.docker NGINX_PORT=18080 AUTH_MINI_PORT=17777 docker compose -f examples/docker-compose.yml down -v
```

Result: cleanup completed.

## Notes And Fixes During Verification

- Initial `npm test` after build discovered Vitest also matched `dist/tests`; added `vitest.config.ts` to exclude build output.
- Initial Compose run failed because host port `8080` was occupied; parameterized `NGINX_PORT` and `AUTH_MINI_PORT` in the example Compose file.
- Docker initially attempted to write `/docker`; using repo-local ignored `.docker/` as `DOCKER_CONFIG` made the smoke reproducible in this environment.
- Gateway container initially pointed to `dist/server.js`; corrected runtime start path to `dist/src/server.js`.
- Smoke exposed that unauthorized users needed a gateway session to let nginx distinguish `403` from `401`; callback now stores authenticated-but-unauthorized sessions while `/auth/check` denies them with `403`.
- Readiness review found concurrent refresh and unbounded in-memory store blockers; added single-flight refresh, stale refresh-failure guard, TTL pruning, capacity limits, and regression tests.
- Re-review found logout-vs-refresh could resurrect a deleted session; refresh writeback now verifies the session still exists with the same refresh token before updating, and a regression test covers logout while refresh is delayed.
- nginx rejected `proxy_pass` with a URI inside a named location; replaced the named login redirect with internal exact location `/__login_redirect`.
- In this Docker/Alpine environment, Node fetch did not resolve Compose service names even after `getent` did, so the smoke command resolves service IPs in shell before invoking the Node smoke script.

## Residual Risks

- Session storage is intentionally in memory and not restart-safe or horizontally scalable.
- The PoC mock auth-mini is only for nginx smoke; real deployment still needs an actual auth-mini issuer, passkey setup, and direct-origin network review before replacing OpenCode Basic Auth.
