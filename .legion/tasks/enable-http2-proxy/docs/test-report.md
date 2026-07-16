# Verification report: enable HTTP/2 proxy after review findings 1-6

**Date:** 2026-07-17
**Verdict:** **PASS**

All mandatory locally executable verification gates passed after the engineer changes for the six findings recorded in `review-change.md`. The exact pinned real-auth fixture was not present, so that conditionally required E2E was skipped without fetching or modifying any external repository. No implementation defect appeared during verification.

## Verification basis and safety

Read before execution:

- `.legion/tasks/enable-http2-proxy/plan.md`
- `.legion/tasks/enable-http2-proxy/docs/rfc.md`
- `.legion/tasks/enable-http2-proxy/docs/review-rfc.md`
- `.legion/tasks/enable-http2-proxy/docs/review-change.md`
- `.legion/tasks/enable-http2-proxy/tasks.md`
- `.legion/tasks/enable-http2-proxy/log.md`
- the current implementation and test diff against `origin/master` / `28a4a273ea9b2725191dce35233f55972beaac6f`

The prior `review-change.md` remains the read-only FAIL artifact that defined findings 1-6; it was not edited. This report verifies the subsequent implementation. Focused ownership/protocol tests ran before broad gates because they directly distinguish the unsafe orderings from the corrected ones.

Every executed verification command had a finite GNU `timeout`; subprocesses in the release-hook verifier also had 30-second limits. No Nix command, deployment, production endpoint, external system, commit, or push was used.

Environment:

```text
rustc 1.96.0 (ac68faa20 2026-05-25)
cargo 1.96.0 (30a34c682 2026-05-25)
GNU timeout 9.8
```

## Result summary

| Gate | Result | Exact result |
|---|---|---|
| Focused library/component evidence | PASS | 19 passed, 0 failed |
| Focused protocol/security integration evidence | PASS | 32 passed, 0 failed |
| `cargo fmt --all -- --check` | PASS | Exit 0, no output |
| Strict Clippy | PASS | Exit 0, no warnings |
| Full `cargo test` | PASS | 160 passed: 110 library + 50 integration; 0 failed |
| Release binary build | PASS | Optimized `auth-mini-gateway` target built |
| Release hook code/API/symbol check | PASS | 2 artifacts checked, 0 forbidden symbols; release API probe unresolved as required |
| `cargo check --all-targets` | PASS | Exit 0 |
| `git diff --check` | PASS | Exit 0, no output |
| Proxy-mode E2E | PASS | 50 passed, 0 failed |
| Mode-switch E2E | PASS | 1 passed, 0 failed |
| Old-binary compatibility E2E | PASS | All scripted assertions passed |
| WAL backup/restore E2E | PASS | All scripted assertions passed |
| Real auth-mini E2E | SKIPPED | Exact pinned fixture absent locally |

## Focused evidence for review findings 1-6

### 1. Request-half ownership waits for real `TrackedRequestBody` drop

Passed:

- `proxy::tests::tracked_request_body_defers_h2_eos_and_cancellation_until_wrapper_drop`
- `h2_early_final_flow_control_holds_two_half_ownership_until_body_drop`

The component test polls a real `TrackedRequestBody` through final DATA and through the cancellation branch. It proves that merely observing terminal EOS/cancellation does not set `request_done`: U, the generation-local stream permit, and the downstream H2 stream lease all remain unavailable until the wrapper itself is dropped. They become available only after that drop witness.

The integration fixture advertises one concurrent stream and an initial H2 stream window of zero, returns an early `413`, and withholds the WINDOW_UPDATE. While Hyper retains the unsent request body, a competing authenticated exchange receives U-capacity `503`, a competing downstream H2 stream receives `503`, upstream hits remain one, and the same physical generation remains the only connection. After the fixture releases flow control and observes request-body completion/drop, all ownership is released and a later exchange reaches the same connection. Together these tests cover real zero-window early-final behavior plus deterministic cancellation cleanup.

### 2. Real `H2ProofIo` byte, completion, and transport-drop evidence

Passed:

- `proxy::tests::real_h2_proof_io_is_byte_transparent_for_fragmented_reads_and_partial_vectored_writes`
- `proxy::tests::h2_proof_io_connection_completion_before_proof_is_fail_closed`
- `proxy::tests::h2_proof_io_signals_transport_only_after_inner_drop_completes`
- both `same_connection_settings_proof` tests

The real wrapper test drives inbound SETTINGS one byte at a time and asserts byte-for-byte equality at the caller. It drives a partial vectored write followed by scalar partial writes, verifies exactly the accepted bytes were observed, verifies the wrapped transport received the complete unchanged client sequence, and reaches the expected proof snapshot.

The Hyper connection test reads the actual client preface/SETTINGS from an in-memory transport, confirms that no pre-proof frame is application HEADERS (`0x1`) or DATA (`0x0`), provides only a fragmented incomplete server SETTINGS frame, then closes the peer. Connection completion is fail-closed, proof status becomes `Failed`, the generation stays nonselectable, and the real wrapped transport-drop witness completes.

The blocking-drop transport test drops a real `H2ProofIo`. While the inner transport's destructor is blocked, `transport_dropped` remains false and U remains unavailable. Only after the inner destructor completes does the witness fire and release U, establishing physical transport destruction before accounting release.

### 3. Ongoing SETTINGS scanning, revocation, and dispatch linearization

Passed:

- `proxy::tests::ongoing_settings_scanner_is_fragmented_bounded_and_last_value_wins`
- `proxy::tests::generation_gate_linearizes_update_before_and_candidate_before_update`
- `proxy::tests::retiring_slot_and_stale_generation_cleanup_are_exact_id_scoped`
- `later_settings_revocation_after_enqueue_retires_generation_without_replay`
- `mixed_auto_pool_does_not_downgrade_ineligible_selected_h2_websocket`

The scanner test exercises every split point of the later 15-byte SETTINGS frame, a 16,384-byte legal DATA skip delivered in 257-byte fragments, coalesced adjacent frames, duplicate ID `0x8` last-value semantics, initial false followed by later `1`, and later effective `1 -> 0`. It checks fixed parser sizing (`size_of::<ServerFrameScanner>() <= 80`); source inspection confirms only fixed 9-byte/6-byte scratches plus scalar state, with no peer-payload-sized retained buffer.

The barrier-controlled generation-gate test proves both total orders:

- update first: revocation makes the generation nonselectable and Extended CONNECT performs zero enqueue;
- candidate first: the gate is held across exactly one synchronous enqueue, revocation waits, then retires the generation after that enqueue.

The actual raw-H2 revocation fixture dispatches a warm request, a held sibling, and one candidate on generation G, then sends the later revocation one byte at a time. The candidate was enqueued once before update; the expected G-wide retirement fails the controlled sibling, closes G's transport, performs no replay/fallback/additional dispatch, and allows a later request only through a new generation. The mixed auto-pool test independently proves selected ineligible H2 does not fall through to idle H1.

Exact-ID retirement evidence proves G becomes a `RetiringH2 { generation: G }` slot while G+1 remains selectable, and stale G completion/retirement cannot remove or mutate G+1.

### 4. Extended CONNECT Content-Length boundary

Passed:

- `proxy::tests::h2_websocket_content_length_accepts_absent_or_consistent_zero_only`
- `h2_connect_classification_is_stream_local_and_zero_hit_until_valid`
- `raw_h2_consistent_nonzero_connect_is_pre_service_fail_closed_with_required_eof`

The validator accepts no Content-Length and consistent zero forms (`0`, `0, 0`, and `000`), while rejecting positive, inconsistent, and syntactically malformed forms. On a real downstream H2 connection, `Content-Length: 0` and the absent form both establish valid Extended CONNECT tunnels; gateway-observed malformed handshake forms remain `400` and stream-local. A raw HPACK/frame fixture bypasses Hyper client validation: the absent control reaches service/auth/upstream and leaves the connection open, while consistent nonzero `Content-Length: 1` is intercepted by pinned Hyper before service, produces required connection completion/EOF, and leaves service/auth/U/upstream counters unchanged. Any observed optional reset is checked as stream 1 `INTERNAL_ERROR`.

### 5. Creator publication and exact slot ownership

Passed:

- `proxy::tests::creator_reservation_precedes_barrier_controlled_publication`
- `peer_limit_one_reserves_creator_before_publication`
- `peer_limit_zero_fails_before_dispatch_and_never_publishes`
- `proxy::tests::retiring_slot_and_stale_generation_cleanup_are_exact_id_scoped`

The barrier test stops between creator reservation and publication with peer limit one. Before publication, the creator owns the sender clone and only local permit, the pool is empty, and another reservation cannot succeed. After publication, the creator still owns its reservation and no H1 fallback entry exists. The protocol fixture independently proves a second exchange needs a second physical generation while the creator holds the peer's sole stream, and a peer limit of zero yields pre-dispatch `502`, zero upstream hits, and no generation reuse/publication.

The retiring-slot test preserves exact owner accounting through retirement and demonstrates stale generation signals cannot evict the replacement ID.

### 6. Initial downstream timeout

Passed:

- `server::tests::initial_downstream_timeout_covers_idle_and_23_byte_near_h2_preface`
- `server::tests::first_complete_head_disarms_only_the_initial_deadline_for_h1_and_h2`

With injected short deadlines, an idle socket and a socket stopped at the first 23 bytes of the 24-byte H2 preface both close within the one initial window. Timely complete H1 and H2 request heads disarm that initial race, and both same connection futures remain usable after three times the original deadline. This distinguishes first-head disarm from a whole-connection timeout or restarted deadline.

### 7. GOAWAY / REFUSED_STREAM no replay

Passed:

- `goaway_and_refused_stream_before_and_after_dispatch_never_replay_request_body`
- `h2_stream_reset_is_not_replayed_and_does_not_kill_a_sibling`
- `stale_pool_failure_does_not_replay_a_non_idempotent_request`

The raw-H2 fixture covers four deterministic modes: GOAWAY before request dispatch, GOAWAY after HEADERS dispatch, REFUSED_STREAM before body DATA, and REFUSED_STREAM after body DATA. Every result is `502`; exactly one physical connection is used. The before-dispatch case observes zero request HEADERS, each post-dispatch case observes exactly one, and only the after-body case observes one DATA sequence. No case opens another connection, sends a second body sequence, or falls back to H1/another generation.

### 8. Debug-only hooks absent from release

Passed:

- `server::tests::release_cfg_excludes_dynamic_integration_hooks_from_app_state_and_public_api`
- release artifact symbol/API verifier after `cargo build --release --bin auth-mini-gateway`

The source-level assertion verifies every dynamic hook field and the hook-bearing public entrypoint are guarded by `#[cfg(debug_assertions)]`, and a release-only exhaustive `AppState` destructure cannot contain those fields.

The finite inline verifier ran `nm -C --defined-only` on:

```text
target/release/deps/libauth_mini_gateway-d0f9a34cd44a1005.rlib
target/release/auth-mini-gateway
```

It searched for the hook entrypoint, `ServeHooks`, and all three hook field names. Result: **2 artifacts checked, 0 forbidden symbols**. It then invoked release metadata compilation with:

```text
use auth_mini_gateway::server::run_server_with_listener_and_roots_and_hooks;
fn main() {}
```

against the release rlib and dependency directory. Compilation failed specifically with the expected unresolved import, proving the hook-bearing API is unavailable in release configuration. The temporary metadata path under `/tmp/opencode` was removed.

## Focused command counts

### Library/component commands

```bash
timeout --signal=TERM --kill-after=15s 5m cargo test --lib same_connection_settings_proof
timeout --signal=TERM --kill-after=15s 5m cargo test --lib upstream_protocol
timeout --signal=TERM --kill-after=15s 5m cargo test --lib downstream_h2_stream_admission_uses_exact_mode_partitions
timeout --signal=TERM --kill-after=15s 5m cargo test --lib first_complete_head_disarms_only_the_initial_deadline_for_h1_and_h2
timeout --signal=TERM --kill-after=15s 5m cargo test --lib rejected_h2_upgrade_gate_holds_all_permits_until_upgraded_drop_point
timeout --signal=TERM --kill-after=15s 5m cargo test --lib stream_half_clones_share_exactly_one_owned_permit
timeout --signal=TERM --kill-after=15s 5m cargo test --lib real_h2_proof_io_is_byte_transparent_for_fragmented_reads_and_partial_vectored_writes
timeout --signal=TERM --kill-after=15s 5m cargo test --lib h2_proof_io_connection_completion_before_proof_is_fail_closed
timeout --signal=TERM --kill-after=15s 5m cargo test --lib ongoing_settings_scanner_is_fragmented_bounded_and_last_value_wins
timeout --signal=TERM --kill-after=15s 5m cargo test --lib generation_gate_linearizes_update_before_and_candidate_before_update
timeout --signal=TERM --kill-after=15s 5m cargo test --lib creator_reservation_precedes_barrier_controlled_publication
timeout --signal=TERM --kill-after=15s 5m cargo test --lib retiring_slot_and_stale_generation_cleanup_are_exact_id_scoped
timeout --signal=TERM --kill-after=15s 5m cargo test --lib tracked_request_body_defers_h2_eos_and_cancellation_until_wrapper_drop
timeout --signal=TERM --kill-after=15s 5m cargo test --lib h2_proof_io_signals_transport_only_after_inner_drop_completes
timeout --signal=TERM --kill-after=15s 5m cargo test --lib h2_websocket_content_length_accepts_absent_or_consistent_zero_only
timeout --signal=TERM --kill-after=15s 5m cargo test --lib initial_downstream_timeout_covers_idle_and_23_byte_near_h2_preface
timeout --signal=TERM --kill-after=15s 5m cargo test --lib release_cfg_excludes_dynamic_integration_hooks_from_app_state_and_public_api
```

Exact aggregate: **19 passed, 0 failed**. The two broad filters ran two tests each; all other exact filters ran one test each.

### Protocol/security integration commands

```bash
timeout --signal=TERM --kill-after=30s 20m cargo test --test proxy_integration h2 -- --nocapture
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration later_settings_revocation_after_enqueue_retires_generation_without_replay
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration goaway_and_refused_stream_before_and_after_dispatch_never_replay_request_body
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration peer_limit
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration authenticated_websocket_is_bidirectional_and_transport_failures_are_sanitized
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration proxy_streams_required_methods_large_chunked_bodies_and_sse_with_sanitation
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration stale_pool_failure_does_not_replay_a_non_idempotent_request
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration gateway_logs_never_contain_cookie_token_or_secret_values
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration https_upstream_accepts_injected_trust_and_rejects_an_untrusted_certificate
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration https_ip_authority_requires_matching_ip_san_without_dns_substitution
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration bracketed_ipv6_gateway_connector_requires_matching_ipv6_ip_san
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration proxy_denials_are_fail_closed_and_do_not_hit_the_upstream
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration every_gateway_owned_route_and_unsupported_method_isolated_from_proxy
timeout --signal=TERM --kill-after=15s 5m cargo test --test proxy_integration underscore_aliases_and_trusted_forwarding_fail_closed_before_upstream
```

Exact counts:

- H2 filter: 18 passed, 32 filtered out.
- Later-SETTINGS filter: 1 passed, 49 filtered out.
- GOAWAY/REFUSED_STREAM filter: 1 passed, 49 filtered out.
- Peer-limit filter: 2 passed, 48 filtered out.
- Ten exact security/regression filters: 1 passed each, 49 filtered out each.
- Aggregate: **32 passed, 0 failed**.

## Mandatory repository gates

### Formatting

```bash
timeout --signal=TERM --kill-after=10s 5m cargo fmt --all -- --check
```

**PASS**, exit 0, no output.

### Strict Clippy

```bash
timeout --signal=TERM --kill-after=30s 20m cargo clippy --all-targets --all-features -- -D warnings
```

**PASS**, exit 0, no warnings or diagnostics.

### Full test suite

```bash
timeout --signal=TERM --kill-after=30s 30m cargo test
```

**PASS** with exact counts:

- `src/lib.rs`: 110 passed, 0 failed, 0 ignored.
- `src/main.rs`: 0 tests.
- `tests/proxy_integration.rs`: 50 passed, 0 failed, 0 ignored.
- Doc tests: 0 tests.
- Total executed: **160 passed, 0 failed**.

### Release build

```bash
timeout --signal=TERM --kill-after=30s 30m cargo build --release --bin auth-mini-gateway
```

**PASS**; optimized release target exists at `target/release/auth-mini-gateway`.

### Release hook code/API/symbol verifier

```bash
timeout --signal=TERM --kill-after=10s 2m python3 -  # inline verifier; nm/rustc subprocesses limited to 30s
```

**PASS**:

```text
release_rlib=libauth_mini_gateway-d0f9a34cd44a1005.rlib
release_hook_symbol_artifacts_checked=2
release_hook_forbidden_symbols=0
release_hook_api_probe=unresolved_as_expected
```

### All-target check

```bash
timeout --signal=TERM --kill-after=30s 20m cargo check --all-targets
```

**PASS**, exit 0.

### Diff whitespace

```bash
timeout --signal=TERM --kill-after=10s 2m git diff --check
```

**PASS**, exit 0, no output.

## Repository E2Es

### Proxy mode

```bash
timeout --signal=TERM --kill-after=30s 30m scripts/e2e-proxy-mode.sh
```

**PASS**: 50 integration tests passed, 0 failed; script printed `Direct proxy-mode integration E2E passed.`

### Adapter/proxy mode switch

```bash
timeout --signal=TERM --kill-after=30s 15m scripts/e2e-mode-switch.sh
```

**PASS**: 1 passed, 0 failed, 49 filtered out; script printed `Fail-closed adapter/proxy mode-switch drill passed.`

### Old-binary compatibility

```bash
timeout --signal=TERM --kill-after=30s 30m scripts/e2e-old-binary-compat.sh
```

**PASS**: Ready/legacy-NULL reads, Pending denial/logout/prune, NULL repair, and safe re-upgrade assertions passed.

### WAL backup/restore

```bash
timeout --signal=TERM --kill-after=30s 20m scripts/e2e-wal-backup-restore.sh
```

**PASS**: WAL-consistent snapshot, integrity/schema checks, exclusion of post-backup mutations, and restored-session authorization assertions passed.

## Conditional real-auth E2E

The exact required default fixture remains:

```text
path: /tmp/opencode/auth-mini-reference/rust-backend
commit: 86b4aaa8ca97d1218217a7f6f0144251a5f30c9b
```

Preflight result:

```text
fixture=missing
path=/tmp/opencode/auth-mini-reference/rust-backend/Cargo.toml
expected=86b4aaa8ca97d1218217a7f6f0144251a5f30c9b
```

Therefore `scripts/e2e-real-auth-mini.sh` was **not run**. Nothing was fetched, cloned, or modified. This is the contract-allowed environmental skip, not an implementation failure.

## Dependency, scope, artifact, privacy, and mutation boundaries

- **Dependencies:** PASS. A programmatic comparison with `origin/master:Cargo.toml` found `added_direct_dependencies=[]` and `removed_direct_dependencies=[]`. The only direct manifest changes activate HTTP/2/server-auto features on existing dependencies; lockfile additions are transitive feature resolution.
- **Scope:** PASS. The implementation diff has 13 tracked changed files and no path under Nix/NixOS, Nginx, FRP, deployment, or infrastructure directories. No external repository or production system was touched. The production-artifact regression test passed in both the full suite and proxy E2E.
- **Artifacts:** PASS. Post-E2E workspace scans found no `*.sqlite*`, `.env`, `*.pcap`, `*.pcapng`, `*.har`, `*.pem`, `*.key`, `*.crt`, or `*secret*` file. Build output remains under ignored `target/`; E2E temporary state was cleaned.
- **Log secrecy:** PASS. The general secret-log test and successful selected-H2 exact-event test passed in focused execution, the full suite, and proxy E2E. They cover injected cookie, token, authority, WebSocket key, session, and secret markers.
- **Repository mutation:** No implementation, test, Cargo, Legion control, wiki, or review file was edited during verification. This report is the only intended repository write. No commit or push was made.
- **Nix safety:** No Nix build, evaluation, deployment, `nixos-rebuild`, or other Nix command was run.

## Final decision

**PASS.** All explicitly requested ownership, transport-drop, proof-I/O, ongoing-SETTINGS, revocation-linearization, Extended CONNECT, creator-publication, exact-generation, timeout, GOAWAY/REFUSED_STREAM, no-replay, and release-hook evidence passed. All mandatory formatting, strict-Clippy, full-test, release, release-symbol/API, all-target, diff, and four local E2E gates passed. The only skip is the exact-fixture-dependent real-auth E2E, whose pinned fixture is absent locally. No implementation blocker was found.
