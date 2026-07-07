# RFC Review: auth-mini-gateway PoC

## Decision

**PASS**

The updated RFC is implementable, verifiable, rollbackable, and appropriately scoped for the PoC. The prior blocking nginx/front-auth verification gap is resolved by adding a composed nginx + gateway + PoC upstream smoke path with observable upstream counters and explicit checks for denied-not-proxied behavior, authorized HTTP proxying, authorized WebSocket upgrade behavior, and direct-upstream non-exposure.

## Sources Reviewed

- `.legion/tasks/auth-mini-gateway-poc/plan.md`
- `.legion/tasks/auth-mini-gateway-poc/docs/rfc.md`
- Previous review in `.legion/tasks/auth-mini-gateway-poc/docs/rfc-review.md`

## Blocking Findings

None.

## Prior Blocking Finding Resolution

### nginx/front-auth behavior verification

Resolved. The RFC now requires a composed smoke path in `examples/` using Docker Compose or local nginx. It must prove:

- unauthenticated requests through nginx redirect to `/login` without incrementing upstream hit count;
- authenticated but unauthorized sessions return `403` without incrementing upstream hit count;
- authorized HTTP requests reach the upstream and increment its hit count;
- authorized WebSocket upgrades reach the upstream echo endpoint;
- the upstream is not directly published from Compose, or a documented network check proves it is unreachable from outside the Compose network.

This is sufficient for the design gate because it verifies the core PoC claim at the nginx boundary rather than only testing the gateway in isolation. The fallback requirement to record attempted commands and a manual procedure when Docker or nginx is unavailable is acceptable for a PoC, provided automated gateway tests still pass.

## Non-blocking Suggestions

- The nginx example still shows `return 302 /login?return_to=$request_uri`; implementation should follow the RFC note to use an escaping helper or safe nginx variable if request URIs with special characters are accepted.
- If `GET /logout` remains, document it as a PoC convenience and prefer `POST /logout` in examples to avoid encouraging logout-by-link behavior.

## Rollback Assessment

Adequate. The RFC keeps the rollback path simple: remove the nginx `auth_request` configuration and return to the existing Basic Auth setup. Gateway-down behavior is fail-closed.

## Scope Assessment

Appropriate for the PoC. The RFC does not expand into OIDC, RBAC, production persistence, or gateway-owned upstream proxying. The added composed smoke path strengthens verification without expanding product scope.
