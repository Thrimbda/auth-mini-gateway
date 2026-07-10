# Task Summary: remove-auth-method-policy

## Outcome

Auth-mini-gateway no longer exposes or reads `REQUIRE_PASSKEY` and no longer branches authorization on JWT `amr`. Auth-mini remains responsible for authentication method and token issuance. Gateway verifies the auth-mini token/session and authorizes only exact email/user-id allowlist matches.

## Preserved Boundaries

- Unknown identities remain denied by default.
- JWT issuer, signature, expiry, type, subject, session ID, and `amr` shape remain verified.
- Auth-mini tokens remain server-side; browser receives only the opaque signed gateway cookie.
- Callback state, per-origin cookies, refresh, logout, and nginx `auth_request` behavior are unchanged.

## Evidence

- `cargo fmt --check`
- `cargo test`: `11 passed`
- Active source/config/docs scan contains no `REQUIRE_PASSKEY`, `require_passkey`, or Passkey-policy references.

## Source

- `.legion/tasks/remove-auth-method-policy/`
