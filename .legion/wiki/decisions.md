# Decisions

## auth-mini gateway PoC

- Keep auth-mini external and unmodified; gateway only adapts auth-mini login/token/session behavior to nginx front-auth decisions.
- Keep nginx as the reverse proxy and WebSocket proxy; gateway does not proxy protected upstream traffic.
- Browser stores only opaque signed gateway cookies. auth-mini access/refresh tokens stay server-side in gateway sessions.
- Use a first-party callback bridge page for auth-mini fragment redirects because URL fragments are never sent to servers.
- Deny unknown users by default through email/user-id allowlists, with optional Passkey-only enforcement via JWT `amr`.
- Preserve authenticated-but-unauthorized gateway sessions so nginx can return `403` without allowing upstream access.
