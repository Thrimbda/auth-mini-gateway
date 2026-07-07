# auth-mini-gateway PoC

## Task Contract

- **Task ID:** `auth-mini-gateway-poc`
- **Name:** Auth Mini Gateway PoC
- **Goal:** prove that an independent gateway can adapt auth-mini Passkey/JWT login into an nginx front-auth pattern that can later replace Basic Auth in front of OpenCode.
- **Problem:** auth-mini issues browser-facing access/refresh tokens after Passkey, Email OTP, or device login, while nginx needs a per-request allow/deny decision before proxying to an upstream. The gateway must bridge these models without reimplementing Passkey or exposing auth-mini tokens to protected pages.

## Acceptance

- Unauthenticated access to a protected page is redirected into the auth-mini login flow.
- After successful Passkey login, the browser returns to the originally requested target.
- Refreshing the protected page after login keeps access without exposing long-lived tokens to ordinary pages.
- Missing, deleted, or tampered gateway cookies fail closed and do not reach the protected upstream.
- Users outside the configured allowlist are denied even after successful auth-mini login.
- Expired access tokens are refreshed through auth-mini when possible; refresh failure clears the gateway session and requires login again.
- Logout immediately revokes the gateway session and attempts auth-mini session logout without logging token material.
- nginx can ask the gateway before proxying, and denied requests do not reach the PoC upstream.
- WebSocket-oriented upstreams are not broken by the chosen nginx auth boundary.

## Scope

- Initialize this empty repository as a runnable PoC gateway project.
- Implement a Node.js/TypeScript gateway service that exposes browser login/logout/callback endpoints and an nginx-facing auth check endpoint.
- Include a minimal callback bridge page because auth-mini returns login tokens in URL fragments that are not sent to servers.
- Maintain gateway-owned server-side browser sessions addressed by secure, HttpOnly cookies.
- Verify auth-mini JWTs with auth-mini `GET /jwks`, including issuer and expiration validation.
- Refresh auth-mini sessions with `POST /session/refresh` using the server-side refresh token.
- Authorize access by email allowlist and optional auth-mini user id allowlist.
- Support a configurable `requirePasskey` policy based on the JWT `amr` claim.
- Provide nginx and PoC upstream examples suitable for later OpenCode integration.
- Provide automated tests for the gateway authentication, authorization, session, refresh, and safety behavior.

## Non-Goals

- Do not turn auth-mini into an OIDC Provider.
- Do not reimplement Passkey/WebAuthn, Email OTP, or credential storage.
- Do not add RBAC, organizations, groups, admin UI, multi-tenancy, or full audit logging.
- Do not directly proxy OpenCode traffic from the gateway; nginx remains the reverse proxy.
- Do not solve production persistence or distributed session storage beyond a PoC-friendly server-side store.

## Assumptions

- auth-mini runs as an external service and is configured with an issuer reachable by the gateway and browser.
- auth-mini login redirect follows `https://auth.example.com/web/#/login?redirect_uri=...&state=...` and returns tokens in the callback URL fragment.
- auth-mini access tokens include `sub`, `sid`, `iss`, `exp`, and `amr`; user email is obtained from auth-mini `/me` using the verified access token.
- nginx will be configured so protected upstream traffic can only be reached through an auth check path, not directly from the public origin.
- PoC storage can be in memory, provided sessions are revocable, expiring, and clearly documented as non-production persistence.

## Constraints

- Browser cookies must be HttpOnly, SameSite-aware, Secure-configurable, and signed or opaque so tampering fails closed.
- access tokens, refresh tokens, session cookies, and cookie secrets must not be logged.
- Login state must be one-time and tied to a bounded return target to prevent callback reuse and open redirects.
- Return targets must be same-origin relative paths or explicitly configured safe origins only.
- Unknown users are denied by default.
- Email OTP may create or recover accounts, but protected-service access is controlled by explicit configuration and the `requirePasskey` policy.
- Gateway management/debug surfaces must bind to private/local interfaces or be absent from the public nginx config.

## Risks

- The auth-mini redirect result arrives in the fragment, so a server-only callback would never receive tokens; the gateway needs a small first-party bridge page that posts the fragment to the server.
- JWT verification alone does not expose email; the gateway must call `/me` at login/refresh time or derive email from trusted future claims if auth-mini changes.
- In-memory sessions are acceptable for PoC but will not survive restarts or scale horizontally.
- nginx `auth_request` behavior for WebSocket upgrades must be validated with configuration, because the auth check happens before the upgrade is proxied.
- Direct upstream origin access must be blocked outside the gateway/nginx path, otherwise authentication can be bypassed.

## Design Summary

- Use a small TypeScript HTTP service as the gateway, separate from auth-mini and the upstream.
- Use auth-mini only for login, token issuance, refresh, logout, `/jwks`, and `/me`.
- Store auth-mini access/refresh/session ids server-side in a gateway session keyed by an opaque secure cookie.
- Expose an nginx-facing auth endpoint that validates the gateway session, refreshes tokens when needed, checks allowlist policy, and returns only allow/deny status plus optional identity headers.
- Keep nginx responsible for TLS, upstream proxying, WebSocket forwarding, and preventing unauthenticated traffic from reaching upstream.

## Phases

- Brainstorm: establish and materialize this task contract.
- Design gate: write and review an RFC for endpoints, session model, nginx integration, security boundaries, and verification plan.
- Implementation: create the PoC project, gateway service, nginx/upstream examples, and tests inside the approved scope.
- Verification: run automated tests and record credible validation evidence for the acceptance criteria.
- Review and handoff: perform readiness review, generate walkthrough/PR body, and write reusable decisions into the Legion wiki.
