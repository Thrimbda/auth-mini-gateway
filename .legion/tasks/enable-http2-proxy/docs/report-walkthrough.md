# Delivery walkthrough: enable HTTP/2 proxy support

> Mode: `implementation`
> Verification: `test-report.md` **PASS**
> Readiness/security review: `review-change.md` **PASS**, security lens applied
> Production rollout: not performed and not in scope

## Reviewer decision

The latest RFC correction for ongoing RFC 8441 capability revocation passed focused `review-rfc`. The subsequent implementation verification and repeated implementation/security review both passed with no blocking finding. Review should therefore focus on the protocol, ownership, and accepted-residual boundaries below rather than infer any production rollout.

## User-visible behavior and compatibility

| Area | Delivered behavior |
|---|---|
| Downstream | The existing cleartext listener serves HTTP/1.1 and HTTP/2 prior knowledge. Each delivered H2 stream independently runs route validation, authentication, authorization, and capacity admission. |
| Upstream selection | `UPSTREAM_PROTOCOL=auto|http1|http2`; missing/empty means `auto`. HTTPS `auto` offers ALPN `[h2,http/1.1]`, prefers selected `h2`, and uses H1 only for `http/1.1` or no ALPN. A selected H2 path never falls back after failure. |
| Cleartext upstream | `http1` performs a direct H1 handshake with no H2 probe. `http2` uses h2c prior knowledge and fails closed if the H2 proof cannot complete. `auto` is rejected at startup. |
| Ordinary proxy traffic | Downstream H1/H2 can proxy to upstream H1/H2 while preserving methods, streaming uploads/responses, SSE, and backpressure. |
| WebSockets | Strict RFC 6455/RFC 8441 translation covers all four bridges: H1→H1, H1→H2, H2→H1, and H2→H2. Ordinary CONNECT and non-WebSocket extended protocols remain rejected. |

**Intentional compatibility change:** an existing cleartext `UPSTREAM_URL` now requires explicit `UPSTREAM_PROTOCOL=http1` or `http2`; omission or `auto` fails startup. HTTPS keeps `auto` as its default. There is no data, cookie, session, or schema migration.

## Core safety design

- **No replay:** selection closes around one candidate and exactly one `send_request`. Handshake, SETTINGS, capability, GOAWAY, REFUSED_STREAM, reset, stale-generation, or send failure does not reopen address, generation, or H1/H2 selection.
- **Fixed routing and sanitation:** configured `UpstreamBase` alone controls upstream scheme, authority, dial target, SNI/certificate identity, and pool membership. Downstream authority is validation/public metadata only. Cookies, credentials, forwarding claims, forged identity, and hop-by-hop fields are removed; only canonical forwarding data and verified identity are injected.
- **Same-connection H2 proof:** the plaintext I/O wrapper observes the initial server SETTINGS and the client ACK on the exact connection Hyper will use before publishing a sender or dispatching an application request.
- **Ongoing capability revocation:** the same fixed-memory frame scanner remains attached. A later effective `SETTINGS_ENABLE_CONNECT_PROTOCOL: 1→0` makes the exact generation nonselectable, linearizes against enqueue, and retires that generation without replay or H1 downgrade.
- **Bounded combined pool:** one eight-owner pool contains exclusive H1 owners plus live/retiring H2 generations. Each H2 generation is capped by `min(U, 100, initial peer max streams)`; creator reservation precedes pool publication, and stale generation IDs cannot evict replacements.
- **U and lifetime ownership:** U remains one permit per application exchange/stream. A two-half latch retains U and applicable stream leases until Hyper drops/discards the request wrapper and the response reaches EOS/error/drop; tunnels retain leases through bridge completion. Private transport accounting releases U only after the inner TLS/TCP transport is actually destroyed, while pooled generations retain their owner slot through physical close.

## Changed-file walkthrough and hotspots

| Files | Reviewer hotspot |
|---|---|
| `src/config.rs` | `UpstreamProtocol`, exact value-neutral parsing, origin-aware startup rejection, and cleartext compatibility behavior. |
| `src/server.rs` | H1/H2 auto serving, one-shot first-complete-head deadline, finite H2 stream partitions, per-stream auth/admission, H2 authority/split-Cookie validation, and debug-only test hooks excluded from release. |
| `src/proxy.rs` | `H2ProofIo`/`ServerFrameScanner`, `GenerationControl`, ALPN/h2c selection, combined pool and exact-ID retirement, `ExchangeLatch`/`TrackedRequestBody`, fixed target/header rebuilding, and four-way WebSocket translation/cleanup. |
| `src/capacity.rs` | Cloneable downstream H2 stream lease shared by request/response halves or tunnel lifetime. |
| `Cargo.toml`, `Cargo.lock` | HTTP/2 and `server-auto` features enabled on existing dependencies; lockfile additions are transitive. No new direct dependency. |
| `.env.example`, `README.md`, `examples/docker-compose.yml` | Operator setting, intentional cleartext change, protocol behavior, and both rollback modes. |
| `tests/proxy_integration.rs` plus module tests | Raw H2, ALPN/h2c, four WebSocket bridges, SETTINGS proof/revocation, no-replay, capacity, ownership, authority/sanitation, timeout, and release-hook evidence. |
| `scripts/e2e-real-auth-mini.sh` | Pins the existing cleartext compatibility path to `UPSTREAM_PROTOCOL=http1`; the script itself was skipped because its pinned fixture was absent. |
| `src/cookies.rs`, `src/policy.rs` | Test fixture updates for the new config field only. |

## Verification evidence

Evidence below is copied from the current `test-report.md`; this walkthrough did not rerun tests.

| Gate | Recorded result |
|---|---|
| Focused library/component | **PASS** — 19 passed, 0 failed |
| Focused protocol/security integration | **PASS** — 32 passed, 0 failed |
| Full `cargo test` | **PASS** — 160 passed, 0 failed: 110 library + 50 integration |
| `cargo fmt --all -- --check` | **PASS** — exit 0 |
| `cargo clippy --all-targets --all-features -- -D warnings` | **PASS** — exit 0, no warnings |
| `cargo build --release --bin auth-mini-gateway` | **PASS** — optimized target built |
| Release hook code/API/symbol verifier | **PASS** — 2 artifacts, 0 forbidden symbols; release API unresolved as required |
| `cargo check --all-targets` | **PASS** — exit 0 |
| `git diff --check` | **PASS** — exit 0 |
| `scripts/e2e-proxy-mode.sh` | **PASS** — 50 passed, 0 failed |
| `scripts/e2e-mode-switch.sh` | **PASS** — 1 passed, 0 failed |
| `scripts/e2e-old-binary-compat.sh` | **PASS** — all scripted assertions |
| `scripts/e2e-wal-backup-restore.sh` | **PASS** — all scripted assertions |

`review-change.md` records **PASS** after applying the security lens to authentication, protocol selection, tunnels, fixed identity/routing, sanitation, resource ownership, and secret-free logging. The reviewed implementation diff is limited to 13 tracked gateway files; it adds no direct dependency and changes no production infrastructure, deployment, Nix/NixOS, Nginx, FRP, or external repository.

## Accepted residuals

1. Pinned Hyper 1.10.1 closes the downstream H2 connection before gateway service when CONNECT Content-Length is syntactically valid, consistent, and nonzero. Required evidence is EOF/close and zero service/auth/U/upstream dispatch; wire RST and sibling survival are not guaranteed.
2. An illegal later `SETTINGS_ENABLE_CONNECT_PROTOCOL: 1→0` intentionally terminates the affected upstream generation, so its in-flight siblings can fail. They are not migrated or replayed; other generations remain independent.
3. A generation whose initial capability is false remains conservatively WebSocket-ineligible after a later `1`; ordinary H2 remains usable.
4. `scripts/e2e-real-auth-mini.sh` was skipped because the pinned fixture `/tmp/opencode/auth-mini-reference/rust-backend/Cargo.toml` was missing. Nothing was fetched.
5. No production rollout or production-infrastructure validation was performed.

## Reviewer checklist

- [ ] Confirm `UPSTREAM_PROTOCOL` semantics and accept the cleartext startup compatibility change.
- [ ] Inspect same-connection SETTINGS/ACK proof, ongoing bounded scanning, enqueue linearization, and exact-generation retirement.
- [ ] Confirm one-send/no-replay selection and the combined eight-owner pool bounds.
- [ ] Trace U, request/response-half, stream/tunnel, and physical transport-close ownership.
- [ ] Review fixed authority plus credential/forwarding/identity/hop-header sanitation across H1/H2.
- [ ] Review all four WebSocket translations and rejected-upgrade cleanup.
- [ ] Match the recorded test counts/gates and explicitly accept the five residuals above.

## Rollback

- **Upstream-only:** set `UPSTREAM_PROTOCOL=http1`, restart, and verify protocol-selection/dispatch logs plus HTTP, upload, SSE, and WebSocket smoke paths. This clears in-memory H2 generations and sends no upstream H2 traffic, but downstream H2 and RFC 8441 parsing remain enabled.
- **Full downstream/protocol rollback:** deploy the previous HTTP/1-only binary using the existing old-binary maintenance procedure. Use this for downstream auto-detection, stream admission, or RFC 8441 regressions; setting `http1` alone does not disable downstream H2.
- **Adapter rollback:** unset `UPSTREAM_URL` through the existing adapter-mode maintenance path.

No data repair, cache invalidation, or session migration is required.

## Evidence index

- [Plan](../plan.md)
- [Latest RFC](rfc.md)
- [Focused RFC re-review](review-rfc.md)
- [Test report](test-report.md)
- [Implementation/security review](review-change.md)
