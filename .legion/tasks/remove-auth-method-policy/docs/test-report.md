# Test Report

## Result

PASS.

## Commands

```sh
cargo fmt --check
cargo test
rg -n 'REQUIRE_PASSKEY|require_passkey|Passkey-only|Passkey policy' --glob '!.legion/tasks/**' .
git diff --check
```

Results:

- Formatting passed.
- Rust tests passed: `11 passed`, including allowlisted identity allow and unknown identity deny.
- Active source/config/docs have no authentication-method policy references.
- Diff whitespace check passed.

## Real Integration

Command shape:

```sh
TMPDIR=<repo-local-dir> \
AUTH_MINI_RUST_DIR=<repo-local-auth-mini>/rust-backend \
bash scripts/e2e-real-auth-mini.sh
```

The first attempt used local nginx and failed before gateway tests because the tool environment could not open `/dev/stderr`. Re-running through the script's supported Docker nginx path passed.

Passed real integration paths:

- real auth-mini Email OTP token issuance and callback
- allowlisted Email OTP identity reaches protected HTTP upstream
- authenticated WebSocket proxy
- gateway restart preserves SQLite session
- auth-mini refresh and refresh-token persistence
- logout revokes gateway session
- refresh failure revokes local session
- non-allowlisted identity receives denial and does not reach upstream

No production tokens, cookies, OTPs, or secrets were recorded.
