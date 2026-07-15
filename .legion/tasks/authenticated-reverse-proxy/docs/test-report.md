# Final verification report: authenticated reverse proxy

> Date: 2026-07-15
> Worktree: `/home/c1/Work/auth-mini-gateway/.worktrees/authenticated-reverse-proxy`
> Base revision: `3e4c273` plus uncommitted authenticated-proxy changes
> Verdict: **PASS**

## Mandatory commands

| Command | Result |
|---|---|
| `cargo fmt --check` | **PASS** - exit 0, no output |
| `cargo clippy --all-targets --all-features -- -D warnings` | **PASS** |
| `cargo test` | **PASS** - 55 unit and 13 integration tests; 0 failed/ignored |
| `cargo build --release --bin auth-mini-gateway` | **PASS** |

## Security-review fixes

### Early upstream final

**PASS.** `early_upstream_final_cancels_upload_closes_downstream_and_disables_reuse` proves a prompt `413`, downstream close, no later body forwarding, no reuse of the affected upstream connection, and successful use of a fresh connection.

### Non-ASCII identity parity

**PASS.** `non_ascii_identity_header_bytes_match_auth_check_and_proxy` proves `/auth/check` and proxy injection preserve identical verified UTF-8 header bytes.

### WebSocket nominated headers

**PASS.** Request-side nomination of required WebSocket fields returns local `400` with no upstream hit. Upstream `101` nomination of required/selected fields returns sanitized `502` and never commits a downstream `101`.

### HTTP root initialization

**PASS.** Plain HTTP upstream initialization does not require native TLS roots; HTTPS continues to fail closed without roots. Existing TLS integration proves trusted roots succeed and an untrusted certificate returns sanitized `502`.

## Exact 18 outcomes

| # | Outcome | Result |
|---:|---|---|
| 1 | Adapter unknown route 404 | **PASS** |
| 2 | `/auth/check` 204/401/403 and identity headers | **PASS** |
| 3 | Authenticated GET proxy | **PASS** |
| 4 | POST/PUT/PATCH/DELETE method, query, and body preservation | **PASS** |
| 5 | Unauthenticated 302 with no upstream hit | **PASS** |
| 6 | Forbidden 403 with no upstream hit | **PASS** |
| 7 | Spoofed identity removal and overwrite | **PASS** |
| 8 | Browser Cookie stripping | **PASS** |
| 9 | Verified-session-only identity | **PASS** |
| 10 | Body over 64 KiB streams | **PASS** |
| 11 | Chunked response | **PASS** |
| 12 | SSE data before completion | **PASS** |
| 13 | Authenticated bidirectional WebSocket | **PASS** |
| 14 | Unauthenticated WebSocket isolation | **PASS** |
| 15 | Sanitized unreachable-upstream 502 | **PASS** |
| 16 | All six gateway-owned routes remain local | **PASS** |
| 17 | Existing refresh/logout compatibility | **PASS** |
| 18 | Secret-free real-binary logs | **PASS** |

## Focused commands

| Command | Result |
|---|---|
| `cargo test --test proxy_integration early_upstream_final_cancels_upload_closes_downstream_and_disables_reuse -- --nocapture` | **PASS** |
| `cargo test --test proxy_integration non_ascii_identity_header_bytes_match_auth_check_and_proxy -- --nocapture` | **PASS** |
| `cargo test --test proxy_integration authenticated_websocket_is_bidirectional_and_transport_failures_are_sanitized -- --nocapture` | **PASS** |
| `cargo test upstream_initialization -- --nocapture` | **PASS** - 2 passed |

## Additional evidence

The following repository-local drills passed:

- `scripts/e2e-proxy-mode.sh`
- `scripts/e2e-mode-switch.sh`
- `scripts/e2e-old-binary-compat.sh`
- `scripts/e2e-wal-backup-restore.sh`

The pinned external auth-mini checkout required by `scripts/e2e-real-auth-mini.sh` is unavailable. This is non-blocking under the approved RFC scope; in-repository real-binary, proxy, refresh/logout, and security tests all pass.

## Final verdict

**PASS.** All mandatory commands, all 55 unit tests, all 13 integration tests, the security-review fixes, and the exact 18 required outcomes pass.
