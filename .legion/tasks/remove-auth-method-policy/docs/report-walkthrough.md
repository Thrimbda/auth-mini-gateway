# Reviewer Walkthrough

Mode: implementation.

## Problem

An allowlisted Email OTP user completed auth-mini login but the gateway callback page displayed `Login failed. Please try again.` Diagnosis showed the callback returned `403`: gateway required `amr=webauthn` through `REQUIRE_PASSKEY=true`. The bridge mapped every non-2xx response to the same generic message.

## Change

- Remove `REQUIRE_PASSKEY` runtime configuration.
- Remove gateway authorization branching on JWT `amr`.
- Preserve exact email/user-id allowlists and deny unknown identities by default.
- Preserve JWT verification, server-side token storage, refresh/logout, callback state, and nginx `auth_request` behavior.
- Remove the obsolete option from active examples and deployment docs.

## Evidence

- `cargo fmt --check`: PASS.
- `cargo test`: PASS, `11 passed`.
- Active config/source/docs reference scan: no method-policy references.
- Real auth-mini + nginx E2E: Email OTP callback/upstream PASS; WebSocket, restart persistence, refresh/logout, refresh-failure revoke PASS; unknown identity denial PASS.
- Security/readiness re-review: PASS, no blockers.

## Security Boundary

Auth-mini remains the authentication authority. Gateway still verifies the auth-mini token/session and requires an exact allowlisted email or user ID before upstream access. This change removes only the additional gateway-owned authentication-method restriction.
