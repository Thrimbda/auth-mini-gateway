# Silent SSO Capability Gate

## Verdict

**FAIL / unsupported.** The gateway does not claim or emulate silent SSO.

## Evidence boundary

The design review inspected auth-mini commit `86b4aaa8ca97d1218217a7f6f0144251a5f30c9b`. That version documents the interactive login fragment callback, but it does not provide a verified contract or browser flow in which a top-level redirect reuses an existing auth-mini browser session without user interaction.

This result does not affect request-driven access-token refresh for an existing gateway session. It means that, after the gateway session is terminally expired or revoked, the gateway cannot promise that a new auth-mini login redirect will complete without interaction.

## Pass criteria for a future auth-mini task

1. auth-mini defines the session-reuse contract and its privacy/security constraints.
2. A fixed auth-mini version implements the flow without exposing tokens to gateway logs or URLs beyond the existing fragment callback boundary.
3. A real mobile Safari or equivalent browser test proves a top-level redirect returns without interaction when eligible and requires interaction when not eligible.
4. The gateway integration is reviewed separately; this repository must not infer support from an undocumented auth-mini browser cookie.
