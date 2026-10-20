# Silent SSO Capability Gate

## Verdict

**Provided by auth-mini `156484e` and later; gateway-transparent.** The gateway
does not emulate or detect silent SSO. It sends the same top-level login
redirect and receives the same fragment callback; auth-mini decides whether a
login form is needed.

## History

The earlier review inspected auth-mini `86b4aaa8ca97d1218217a7f6f0144251a5f30c9b`,
which had no session-reuse contract, and recorded this gate as
**FAIL / unsupported**. Official auth-mini later added it (`d4f33d9`, `209317e`,
`156484e`), and the gate was re-evaluated against
`156484e69d00487151a283edf96930fac9bc9cae`.

## Pass criteria and evidence

1. **auth-mini defines the session-reuse contract.** Met:
   `docs/integration/login-redirect.md` ("静默复用主站会话") and
   `docs/reference/http-api.md` (`POST /session/authorize`). The login page first
   resolves an auth-mini main-site session (issuer audience), then delegates a
   new, independent session for the redirect's audience. Delegated tokens carry
   `amr: ["sso", <source method>]` across refresh.
2. **No new token exposure.** Met: the delegated tokens use the existing
   fragment callback. `POST /session/authorize` accepts only self-audience
   tokens, so a gateway's stored downstream token cannot mint tokens for other
   audiences, and a non-loopback target cannot request the issuer audience.
3. **Browser proof.** Pending. The real-auth E2E drives the delegation at the
   HTTP API level; no browser run has yet shown that a second gateway login
   completes without interaction. Run this once in production after rollout:
   sign in to one gateway hostname, then open another gateway hostname in the
   same browser and confirm it returns without a login form.
4. **Gateway integration reviewed separately.** Met: `scripts/e2e-real-auth-mini.sh`
   mints a main-site session, delegates a gateway-audience session through
   `/session/authorize`, completes the callback, refreshes after main-site
   logout, and logs out of the gateway.

## Operational consequences

- Logging out of the main auth-mini site does not revoke a gateway's delegated
  session; it ends at gateway logout, refresh rejection, or gateway expiry.
- Gateway logout revokes only the gateway's delegated session. While the
  auth-mini main-site session remains in the browser, the next gateway login
  can complete without a form. To force an interactive login, also sign out on
  the auth-mini site.
- Authorization is unchanged: `ALLOW_USER_IDS` is matched against `sub`; `amr`
  is stored but not used for authorization.
