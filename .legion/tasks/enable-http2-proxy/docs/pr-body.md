## Summary

> **Mode:** `implementation`
> **Verification:** **PASS**
> **Implementation/security review:** **PASS**, security lens applied
> **Production rollout:** not performed and not in scope

- Serves downstream HTTP/1.1 and HTTP/2 prior knowledge, with independent auth and admission for each delivered H2 stream.
- Adds `UPSTREAM_PROTOCOL=auto|http1|http2`: HTTPS `auto` prefers ALPN-selected H2 and uses H1 for `http/1.1` or no ALPN; cleartext `http1` sends no H2 probe and explicit `http2` uses fail-closed h2c prior knowledge.
- Supports ordinary H1/H2 proxy combinations and all WebSocket bridges: H1→H1, H1→H2, H2→H1, and H2→H2.
- Intentionally changes cleartext compatibility: an existing cleartext `UPSTREAM_URL` must now set `UPSTREAM_PROTOCOL=http1` or `http2`; omission/`auto` fails startup.
- Reviewer hotspots are `src/config.rs`, `src/server.rs`, `src/proxy.rs`, `src/capacity.rs`, Cargo feature/lock changes, operator docs, `tests/proxy_integration.rs`, and the real-auth E2E compatibility setting.

## Safety / behavior

- Exactly one upstream `send_request`; failures never replay a body or reopen address/generation/protocol selection.
- Configured `UpstreamBase` alone controls routing, TLS identity, and pooling. Credentials, cookies, forged identity/forwarding, and hop headers are removed before canonical forwarding and verified identity are injected.
- Every H2 sender requires initial SETTINGS plus client-ACK proof on the same connection. The fixed-memory observer remains attached and retires the exact generation on later effective RFC 8441 capability revocation.
- One bounded eight-owner pool combines exclusive H1 owners with shared/retiring H2 generations; H2 stream limits are bounded by U, 100, and the initial peer limit.
- U remains one permit per application exchange. Two-half request/response ownership, tunnel leases, and physical transport-close witnesses prevent early capacity release.
- No new direct dependency was added; only HTTP/2/`server-auto` features on existing dependencies and transitive lockfile resolution changed. No production infrastructure or external repository changed.

## Testing

- [x] Focused library/component: **19 passed, 0 failed**
- [x] Focused protocol/security integration: **32 passed, 0 failed**
- [x] Full `cargo test`: **160 passed, 0 failed** — 110 library + 50 integration
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- [x] `cargo build --release --bin auth-mini-gateway`
- [x] Release hook verifier — 2 artifacts, 0 forbidden symbols; release API unresolved as required
- [x] `cargo check --all-targets`
- [x] `git diff --check`
- [x] `scripts/e2e-proxy-mode.sh` — 50 passed
- [x] `scripts/e2e-mode-switch.sh` — 1 passed
- [x] `scripts/e2e-old-binary-compat.sh` — all assertions passed
- [x] `scripts/e2e-wal-backup-restore.sh` — all assertions passed

`review-change.md` is **PASS** with the security lens applied and no blocking finding.

## Known limitations

- Pinned Hyper 1.10.1 closes the downstream H2 connection before service for a syntactically valid, consistent, nonzero CONNECT Content-Length. EOF/close and zero service/auth/U/upstream dispatch are proven; wire RST and sibling survival are not guaranteed.
- Illegal later `SETTINGS_ENABLE_CONNECT_PROTOCOL: 1→0` retires the affected upstream generation and can fail its in-flight siblings; there is no migration or replay.
- Initial capability false followed by later true remains conservatively WebSocket-ineligible; ordinary H2 remains usable.
- The real-auth E2E was skipped because the pinned local fixture was missing; nothing was fetched.
- No production rollout or production-infrastructure validation was performed.

## Rollback

- **Upstream-only:** set `UPSTREAM_PROTOCOL=http1` and restart. This clears H2 generations and disables upstream H2, but leaves downstream H2/RFC 8441 enabled.
- **Full protocol rollback:** deploy the previous HTTP/1-only binary through the existing maintenance/old-binary procedure for downstream parser, stream-admission, or RFC 8441 regressions.
- **Adapter rollback:** unset `UPSTREAM_URL` through the existing adapter-mode maintenance path.

No data, schema, cookie/session, or capability-cache migration requires repair.
