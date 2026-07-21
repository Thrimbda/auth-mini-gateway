# Focused RFC amendment review: shipped H1 upload lifecycle

> **Reviewed:** 2026-07-19
> **Inputs:** `../plan.md`, `research.md`, the complete latest `rfc.md`, exact Git objects `28a4a273ea9b2725191dce35233f55972beaac6f` and `1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad`, and their exact archived release binaries
> **Scope:** fresh-per-operation downstream-H1 upload topology; no-retry closure; latency, throughput, CPU, RSS, warmup/thread, direct-ceiling, connection-ledger, runtime, storage, and H2 estimands; regression check of the approved statistical, artifact, security, and rollback method
> **Decision:** **PASS**

## Gate decision

**PASS.** The amendment now measures the behavior shipped by both exact H1 binaries: a successful body-bearing downstream HTTP/1.1 request receives `Connection: close` and the transport reaches EOF even when the client did not request closure. Making each H1 upload operation own one fresh connection through that EOF is therefore the accurate black-box topology, not a benchmark normalization. The amendment carries that lifecycle through timing, throughput, CPU/RSS, warmup, ceilings, evidence, runtime, storage, H2 interpretation, and verdict precedence without opening a retry, omission, or favorable-rerun path.

No current design finding makes implementation unimplementable, unverifiable, or non-rollbackable.

## Blocking findings

**None.**

## Exact-binary topology verification

The design claim is supported independently at source and wire boundaries:

- Baseline `28a4a27` classifies a positive `Content-Length` as body-bearing, passes that fact as `close_downstream`, and inserts downstream `Connection: close` after the fully consumed upstream response (`28a4a27:src/server.rs:813,1039-1050`; `28a4a27:src/proxy.rs:233-305`). Its HTTP/1 builder otherwise has keepalive enabled, so closure is the shipped body-bearing response policy rather than a disabled-server-keepalive artifact.
- Candidate `1f9821a` retains the same body-bearing decision and downstream close insertion (`1f9821a:src/server.rs:1127,1435-1446`; `1f9821a:src/proxy.rs:1874-2078`). Its downstream-H2 finishing path removes connection-specific headers, preserving H2 streams on the persistent physical connection (`1f9821a:src/server.rs:1448-1479`). Thus `C12` closes its downstream H1 connection, while `C21`/`C22` do not emulate H1 reconnects.
- A reviewer wire probe ran the manifest-matching release binaries SHA-256 `cd8ab94ec184efd940c465e3e3c2d9fa08456580343a1251b85d7880db2d792c` (baseline) and `9269713c59e08a72b5eedae887ec18cd439be5c633829cebc2ac08d14fd2fc01` (candidate). For each binary, two separate fully consumed 1 MiB authenticated POSTs omitted a request `Connection` header; each returned `HTTP/1.1 200`, one `Connection: close` token, no `Keep-Alive`, the exact response body, and transport EOF. The fixture observed both requests over one reused upstream-H1 connection, confirming that the downstream close does not imply or manufacture upstream churn.

That reviewer probe is design evidence only. It does not replace the RFC's sealed, exact-binary, one-shot topology smoke or any campaign evidence.

## Focused amendment checks

| Area | Result | Review |
|---|---|---|
| Fresh H1 operation boundary | **PASS** | `B11`, `C11`, and `C12` upload operations start immediately before their sole TCP connect attempt and finish only after status/ID/body validation, response EOS, a parsed `close` token, absence of `keep-alive`, and transport EOF. No socket is pre-opened or returned to a pool. `B11/C11` therefore remain like-for-like, while `C12` changes only the upstream protocol (§§5, 6.4–6.6). |
| No retry or reconnect | **PASS** | Every started operation has one deterministic operation ID and planned connection ID, one socket creation, one connect attempt/success, and one request. Any connect/write/response/EOS/EOF failure terminates the arm; no layer may reconnect or replay the ID. A later normal operation is a new ID on a new connection. Reuse, retry, reconnect, second-request, and active-count violations are explicit `BLOCKED` evidence-integrity failures, not missing samples or candidate regressions (§§6.4–6.6, 6.14). |
| Latency and p99 | **PASS** | H1 upload latency includes connect through required EOF; H2 upload latency begins at submission on its already-proved persistent connection. Every pre-deadline start, including a drain completion, is retained in `C/A` p99. Response EOS without EOF cannot complete an H1 operation. The asymmetry is explicitly the delivered-topology estimand and cannot silently be reported as framing-only (§§6.5, 6.9, 11). |
| Throughput and bytes | **PASS** | Operations/second counts only validations complete by the common deadline and divides by the exact frozen `T_s`; an H1 response awaiting EOF is not a completion. Started late work must drain and remains visible. Application bytes/s stays descriptive and cannot replace operations/s. Equal per-cell durations preserve the H1 differential, and calibration absorbs any rate reduction caused by reconnect churn (§§6.5–6.9). |
| CPU and peak RSS | **PASS** | Gateway CPU runs from the steady barrier through measured drain and therefore includes accept, request, response, close, and EOF-related gateway work for every counted H1 operation; division uses all completed measured starts whose work is included. Final `VmHWM` still covers startup, proof, full-concurrency materialization, freeze, steady work, and drain. Neither metric can exclude reconnect cost as cold work (§§6.6, 6.9). |
| Warmup and thread lifecycle | **PASS** | The one-operation proof is descriptive only. Ordinary materialization repeatedly drives all `C` lanes through real connect/POST/close/EOF cycles for the full frozen warmup, drains to zero downstream-H1 connections, and only then freezes TIDs. The `D_w+F<=3s` handoff stays below the sealed 10-second Tokio blocking-worker keepalive; the first measured wave opens its connections only after release. Prospective first-Williams signatures, strict post-freeze inventory, conservative dynamic residuals, and no signature retry remain unchanged (§§6.6, 6.8, 6.11). |
| Direct ceilings | **PASS** | Direct-H1 upload uses the same fresh-connect/one-POST/server-close/EOF operation boundary and concurrency, while direct-H2 uses one persistent connection with up to `C` streams. Direct fixture close mode is role-separated and forbidden on gateway-facing upstream connections. Identity mappings, dual bridge mappings, 1.25× headroom, ±10% drift, utilization, lifecycle, and signature gates remain prospective. A close-mode or protocol substitution can only block (§6.3, §§6.8.2, 6.11). |
| Connection evidence and smoke | **PASS** | Phase and arm ledgers reconcile starts, planned IDs, socket creations, attempts/successes, requests, responses, close tokens, EOS, EOF, active/max-active, per-connection request count, and rolling operation↔connection hashes. Valid H1 totals require cumulative connections equal starts, one request per connection, `max_active<=C`, zero active after drains, and zero reuse/retry. H2 instead proves one connection and unique streams. The pre-scout C1/C64 two-wave smoke exercises both exact binaries, all upload arms, direct controls, and persistent non-upload controls before ratios can exist (§§6.4, 6.8.0, 12.5). |
| H2 and bridge comparisons | **PASS** | `C21/C22` intentionally retain one downstream-H2 connection; `C11` is the real fresh-H1 reference. `C12` retains H1 reconnect while changing only upstream to H2. The RFC repeatedly labels upload H2/H1 ratios as whole delivered-topology comparisons—multiplexing/persistence plus framing—not pure framing effects. C1 remains descriptive, and all C16/C64 point/bound/resource gates are unchanged (§§4.2, 6.4–6.5, 11). |
| Verdict closure | **PASS** | Candidate-only missing close/EOF or keepalive is semantic `FAIL` only under a clean guard. The same baseline/control behavior is `BLOCKED`; direct close-mode failure and any harness reuse/retry/count mismatch are `BLOCKED`. Integrity and quality precedence prevents a malformed favorable sample from becoming performance `PASS` or `FAIL` (§6.14). |

## Runtime and storage coherence

| Area | Result | Review |
|---|---|---|
| Arm-time accounting | **PASS** | Fresh connects and EOF waits occur inside proof, warmup, count/steady windows, or their existing drains; they are not a hidden extra stage. `B(s)` still recomputes to `28..60s` for ordinary cells and `43..75s` for WebSocket cells. Lower rates can only increase prospectively frozen `W/T` within their caps or produce `BLOCKED`; they cannot shorten an arm or matrix (§6.12). |
| Inventory and ceilings | **PASS** | The future schedule remains `75N A + 3N D = 78N` arms. The first-level admitted pre-freeze path still has 855 arms, 171 WebSocket arms, and the conservative `17,217s` floor before positive smoke/setup/drain/artifact time. Future minima remain `72,540/120,900/169,260/241,800s` for `N=30/50/70/100`; the displayed lower totals `98,757s` and `147,117s` for `N=30/50` recompute. `N=70/100` therefore still stop before direct/authoritative work rather than selecting a smaller matrix (§6.12). |
| Raw connection representation | **PASS** | Cumulative H1 opens are checked `u64` counters and deterministic rolling hashes, not an unbounded per-connection file. `CONN_LIVE` reserves only simultaneous slots—including upstream-H1 live state and at most `C` downstream-H1 upload slots—while expanded fixed endpoint/lane records retain every decision-bearing phase total. A width, slot, counter, or record-ceiling overflow stops `BLOCKED` before omission (§6.12.1). |
| Reachable raw/storage projection | **PASS** | The one smoke member and expanded endpoint rows enter the no-compression-credit reachable-branch bound. Calibration component matching now includes downstream/upstream connection policy; future `A/D` projection uses matching maxima, upward-rounded per-record values, and 2× safety. Projection underprediction never constrains writers and can only cause later `BLOCKED` (§6.12.1). |
| Actual artifact closure | **PASS** | The unconditional fresh-walk 512 MiB checks still occur before authoritative analysis/verdict and before commit, with formal remaining-output maxima where needed. Exact canonical reconstruction/recompression, ordinary-Git chunk delivery, independent committed verification, merge, fetched durable-base reachability, and cleanup authorization are unchanged. No connection evidence, latency, failed bundle, or raw member can be dropped to fit (§§6.12.1–6.13.4). |

## Approved-method regression recheck

| Method | Result | Review |
|---|---|---|
| Statistics | **PASS** | The five-arm ten-row Williams balance, same-mini-block pairs, pair-local log ratios, one independently frozen `N`, order-stratified 100,000-replicate bootstrap, exact percentile indices, inclusive thresholds, precision/order gates, and global intersection remain unchanged. `S/D` still cannot enter p99, variance, pairs, or bootstrap; `C/A` still require every started-operation latency. |
| Artifact/verifiability | **PASS** | Exact source/binary/toolchain identity, write-once seals, class-mandatory raw members, canonical ustar, intent-derived pinned codec vector, byte-for-byte recompression, source-independent analysis, additive failed/remediation evidence, actual byte caps, and merge-before-cleanup remain intact. The amendment adds smoke and connection evidence to those closures rather than replacing prior evidence. |
| Protocol/security | **PASS** | No gateway hook, keepalive override, injected request `Connection: close`, clock substitution, retry, fallback, or replay is permitted. Actual protocol/SETTINGS, operation IDs, bytes/EOS, authentication, zero auth-mini hits, literal-loopback routing, credential/hop-header sanitation, D/U/stream/tunnel ownership, and secret exclusion remain hard gates. |
| Rollback/remediation | **PASS** | Operational rollback is unchanged. Any candidate or harness change after smoke requires a new additive calibration/campaign; a performance fix may not convert the shipped H1 close policy to keepalive, move connect/EOF outside timing, reuse prior pairs, or discard the failure that motivated remediation. |

No statistical, artifact, authentication, routing, replay, ownership, tunnel, clock, retention, or rollback relaxation was found.

## Non-blocking residuals

1. The mandatory sealed topology smoke must reproduce the exact-binary close/EOF and H2-persistence facts at C1/C64. The reviewer probe above is not permission to skip, retry, or reuse that smoke.
2. Repeated H1 connect/close work may exhaust ephemeral-port/headroom, miss a drain or phase cap, destabilize a prospective thread signature, or make host noise/runtime infeasible. Each is an honest empirical `BLOCKED`, not a design gap or permission to normalize keepalive.
3. Direct-H1 close mode is intentionally conservative for bridge mappings whose gateway-facing upstream H1 connection remains persistent. It can reduce measured headroom and block; it cannot remove a real gateway cost or make a favorable gateway ratio pass.
4. Aggregated fixed connection counters avoid per-open storage, so implementation must satisfy the specified negative tests for reused sockets, duplicate IDs, hidden reconnects, extra requests, missing close/EOF, and every count/hash mismatch. Failure is `BLOCKED`, not grounds to weaken the schema.
5. The 2× compressed-size projection can still underpredict, and additive failed/remediation bundles can consume the task cap. The unconditional actual gates preserve fail-closed behavior.

## Implementation handoff

This is a design PASS, not campaign evidence. The currently in-progress harness must not run an authoritative campaign until its upload load path, direct close mode, smoke, ledgers, lifecycle, bounds, and tests implement this amendment and pass verification. The previous persistent-H1 upload client behavior is not grandfathered by this review.

## Final decision

**PASS.** Return to `legion-workflow` for bounded implementation of the reviewed amendment. Review artifact: `.legion/tasks/prove-http2-performance-regression/docs/review-rfc.md`.
