# Review: Production Deployment Docs

## Decision

PASS

## Security Lens

Applied. The change documents auth/session/token handling, issuer requirements, nginx `auth_request`, rollback, and protected-upstream boundaries.

## Blocking Findings

None.

## Prior Blocker Re-check

- Rollback guidance no longer implies an auth bypass; it requires a previously verified alternative access-control configuration or maintenance/deny traffic.
- Verification evidence now uses `git add -A && git diff --cached --check`, so newly added docs are covered by the whitespace check.

## Verification Sufficiency

Sufficient for this documentation-only change.

- `git add -A && git diff --cached --check`: PASS.
- `cargo test`: PASS with 11 unit tests.

## Non-blocking Suggestions

- Consider adding an explicit root README note that auth-mini must sign tokens with the exact `AUTH_MINI_ISSUER` URL.
- Consider adding compromise rollback guidance for suspected cookie secret, DB, or refresh-token exposure.
