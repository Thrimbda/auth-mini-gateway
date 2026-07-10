# Remove Auth Method Policy

## Goal

Make auth-mini the sole authority for authentication methods. Auth-mini-gateway should authorize verified identities only through exact email/user-id allowlists.

## Scope

- Remove `REQUIRE_PASSKEY` runtime configuration.
- Remove gateway policy decisions based on JWT `amr`.
- Preserve JWT verification, session storage, email/user-id allowlists, and deny-by-default behavior.
- Update active examples and deployment docs.

## Non-Goals

- Do not remove `amr` from verified token/session data.
- Do not broaden allowlists or change callback/cookie/session topology.
- Do not modify historical task evidence.

## Acceptance

- Email OTP, Passkey, and Ed25519 sessions are treated equivalently after valid auth-mini verification.
- Allowlisted email or user ID is still required.
- Unknown identities remain denied.
- Tests and formatting pass; active config/docs contain no `REQUIRE_PASSKEY` reference.
