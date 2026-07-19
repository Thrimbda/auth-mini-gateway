# RFC: Reproducible HTTP/2 performance-regression proof

> **Profile:** RFC Heavy (high-risk protocol/performance evidence)
> **Status:** Approved - `review-rfc` PASS
> **Owner:** task agent / repository owner
> **Created / last updated:** 2026-07-18 / 2026-07-19

## Executive summary

- Compare immutable baseline `28a4a27` with a final candidate Git object at or after `1f9821a`, using Rust/Cargo 1.96.0 and each object's own lockfile.
- Build untouched release gateways from Git archives; run one measured gateway at a time against separate repository-owned fixture, load, sampler, and orchestrator processes.
- Measure all five workloads at concurrency 1/16/64 in five-arm blocks: baseline H1→H1 plus candidate H1→H1, H2→H1, H1→H2, and H2→H2.
- Preserve the shipped downstream-upload topology instead of normalizing it: every 1 MiB upload operation in `B11`, `C11`, and `C12` opens one fresh H1 TCP connection, sends exactly one POST, requires the response's `Connection: close` semantics and transport EOF, and never reconnects or retries that operation. `C21`/`C22` uploads retain one persistent downstream H2 connection with `C` streams; other H1 GET/download/SSE connections remain persistent and WebSocket tunnels remain pre-established.
- Reuse the candidate H1 arm only prospectively inside each block. A ten-row balanced Williams schedule gives every pair equal AB/BA order and balanced position/carryover.
- Run one sealed exact-binary topology smoke before scouts, then use one fresh-process, fixed-warmup count-window scout and freeze equal per-cell calibration durations before a separate ten-row Williams calibration. For each treatment/cell, its prospectively designated first Williams arm freezes the accepted post-materialization thread signature; later calibration and authoritative arms must match. Then derive and freeze one authoritative `N ∈ {30,50,70,100}` and equal per-cell authoritative durations before sampling.
- Use block-level paired log ratios, geometric means, and deterministic order-stratified 100,000-replicate one-sided percentile bootstrap bounds.
- Separate evidence classes prospectively: quality scouts and direct-ceiling arms retain exact count/timing/byte/correctness, resource, thread, noise, endpoint-hash, and lifecycle evidence but never write per-operation latency arrays or enter p99/bootstrap; Williams-calibration and authoritative gateway arms retain every started operation's latency.
- Startup, topology/SETTINGS proof, and WebSocket handshakes are descriptive. Ordinary arms freeze TIDs only after full-concurrency authenticated materialization, including the real connect/POST/close/EOF cycle for downstream-H1 uploads; WebSocket arms first retire lazy auth workers for a bounded keepalive-plus-stability interval and then warm Ping/Pong without auth. A measured H1-upload operation's own TCP connect is steady per-operation work, not excluded cold-path work. New or disappearing TIDs after that workload-aware freeze remain fatal. Final `VmHWM` remains the conservative hard RSS value.
- Assert actual cleartext protocol, operation IDs, bytes, EOS, and zero auth-mini hits at both ends. No production callback or benchmark symbol enters the gateway. Read-only `CLOCK_REALTIME` is bounded by provenance and purpose rather than an incomplete caller list: the untouched archived production gateways and their pinned dependencies retain existing protocol/application uses—including session validation, Hyper automatic HTTP `Date` generation, and tracing—while the harness may use it only for UTC artifact metadata. Harness latency, duration, throughput and CPU windows, deadlines, ordering, schedule, statistics, and campaign/resource accounting never use real time.
- Any semantic candidate failure is `FAIL`; any integrity, host-noise, headroom, precision, runtime, or completeness failure is `BLOCKED`; only the global intersection of all hard gates is `PASS`.
- Start campaign accounting before the bounded topology smoke, then give every arm one fixed successful `Q_obs=10s` quiet observation, separate from additional quiet/cooling reserve. Seal a component-by-component projection that counts completed observations in actual scout/calibration elapsed, adds `Q_obs` plus materialization/settle/freeze caps to every future gateway/direct arm, and retains finite extra-wait/analysis reserves. A projection over 42 hours or actual post-build campaign time over 48 hours is `BLOCKED`; `N=70` and `N=100` remain statistically selectable but are prospectively runtime-inadmissible under these minima and therefore stop `BLOCKED` rather than running a reduced matrix.
- Treat `.perf` as repository-local execution/cache state, never as the delivered evidence. A formal uncompressed bound—including the smoke member and expanded fixed endpoint/connection ledgers—admits only the currently reachable raw phase/branch. After balanced calibration and any admitted calibration-direct panel, build and independently verify the complete calibration bundle, measure exact pinned-codec compression by schema component, and freeze only the selected reachable continuation using the maximum matching compressed bytes per arm/record with a 2× safety factor plus formal fixed overhead. Every bundle is also reconstructed and re-encoded with the sealed exact encoder and compared byte-for-byte. Projection error can only produce a later `BLOCKED`: the unconditional actual tracked total must be `<=512 MiB` before analysis/PASS and again before commit, with no omitted raw member or sample.
- Cleanup has one terminal order: create and verify bundles; commit and push ordinary blobs; obtain an independent committed-chunk check; merge the PR; fetch the durable base/merge commit and prove every artifact and ledger path reachable there; only then delete `.perf`, remove the worktree/branches, and refresh the main workspace. A closed, failed, or otherwise unmerged PR retains `.perf` and the worktree.
- A regression fix requires a new candidate commit and a wholly new sealed calibration plus authoritative campaign. Existing authentication, routing, no-replay, ownership, SETTINGS, and tunnel safety may not be traded for speed.

---

## 1. Context and evidence

The stable contract is `../plan.md`; concise repository and machine evidence is in `research.md`. Functional/security evidence does not establish performance equivalence. The candidate adds downstream protocol detection and stream admission, shared H2 generations, SETTINGS scanning, dispatch linearization, body/lifetime wrappers, and a synchronous per-dispatch INFO event. All can preserve correctness while changing throughput, tail latency, process CPU, or peak RSS.

The naive design is too expensive and statistically weaker than necessary. At C16/C64, independent A/B experiments need eight arm-runs per workload/concurrency replicate: two for baseline/candidate H1 and two for each of three candidate protocol comparisons. A five-arm complete block needs each real arm once. Across the full matrix this is 75 rather than 105 arm-runs per replicate, a 28.6% reduction, while retaining a contemporaneous control and never borrowing a control post hoc across cells.

The current Axiom host is active and cannot be tuned. Therefore `BLOCKED` is a first-class valid outcome; this RFC does not promise that the campaign will produce a performance conclusion.

## 2. Goals

1. Produce reproducible, independently recomputable evidence for every threshold in the contract.
2. Compare the exact shipped H1 hot path, including the candidate's INFO dispatch cost.
3. Measure real cleartext H1/H2 topologies and exact streaming/tunnel work—including shipped per-operation H1 upload reconnect/close behavior and persistent H2 multiplexing—not protocol labels, forced keepalive normalization, or synthetic internal callbacks.
4. Bound false conclusions from temporal drift, order, host load, load-generator ceilings, CPU-tick quantization, p99 sample size, and repeated looks.
5. Retain complete raw evidence for `PASS`, `FAIL`, and `BLOCKED`, and make optimization iterations non-overwriting.
6. Deliver every conclusion-bearing seal as ordinary repository-tracked chunks that remain independently verifiable after worktree cleanup.
7. Keep the gateway's reviewed security, ownership, routing, no-replay, and rollback invariants unchanged.

## 3. Non-goals

- Production rollout, WAN/TLS capacity, HTTP/3, external hosts, distributed load, or production-service tuning.
- Refresh/JWKS/auth-mini network performance; the workload intentionally measures the authenticated `Ready` session proxy hot path.
- A claim about machines other than the recorded current Axiom fingerprint.
- Replacing functional/security tests, measuring every HTTP method, or proving arbitrary payload distributions.
- Treating profiler, microbenchmark, flamegraph, CI host, or direct fixture results as an authoritative gate.
- Weakening logging, auth, header sanitation, fixed routing, SETTINGS proof, no replay, D/U ownership, or tunnel lifetime to obtain a pass.
- Forcing downstream H1 upload keepalive, injecting a client `Connection: close` request header to manufacture the observed response, excluding its reconnect cost as cold path, or otherwise normalizing H1 and H2 connection lifecycles.

## 4. Hard constraints

### 4.1 Immutable comparison contract

- Baseline is exactly `28a4a273ea9b2725191dce35233f55972beaac6f`.
- Candidate begins at `1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad`; that object must be an ancestor of the authoritative candidate, which must be a full Git commit object and is recorded exactly.
- Both gateway builds use the exact observed Rust 1.96.0/Cargo 1.96.0 executables, default release profile, offline/frozen dependency resolution, and the `Cargo.lock` inside each archive.
- Only the current Axiom machine is authoritative. No Nix, sudo, governor/turbo/background-service change, deployment, production endpoint, external repository, or external statistics/load service is allowed.
- Every generated or writable source, build product, cache copy, database, temporary file, raw result, and report stays below the repository worktree. The only non-repository inputs/surfaces are: the exact Git executable and object database, Rust/Cargo toolchain files, dynamic-loader/runtime libraries, and dependency-cache artifacts whose read-only manifests and contents are hashed before use; the inherited `/dev/null` sink; kernel `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`; read-only `CLOCK_REALTIME` for (a) the exact untouched archived baseline/candidate production gateway processes, including code from their pinned dependencies, solely when executing their existing protocol/application semantics and (b) orchestrator/sampler UTC artifact metadata; `getrandom`; literal loopback sockets; and read-only `/proc`/`/sys`. The production allowance is intentionally a provenance-and-purpose boundary, not an assertion that session validation, Hyper automatic HTTP `Date` generation, and tracing exhaust every shipped consumer. All such gateway calls and their cost remain measured production behavior; no benchmark clock, adapter, preload, callback, dependency replacement, or alternate time source is injected into either gateway. Harness-owned fixture/load/control code and its dependencies may not read `CLOCK_REALTIME`, and every harness-owned Hyper server disables automatic date generation; only the sealed orchestrator/sampler UTC-metadata path is exempt. A harness real-time value is explicitly prohibited from defining or adjusting any latency, duration, throughput/count window, CPU sampling/accounting window, operation or phase deadline, ordering, schedule, seed, statistical calculation, or resource/campaign elapsed accounting. Performance/lifecycle durations, operation latencies, throughput windows, CPU-window boundaries, and benchmark deadlines use `CLOCK_MONOTONIC`; campaign elapsed and the 42/48-hour resource-budget clocks use `CLOCK_BOOTTIME`; schedule/order and seeds are presealed and clock-independent. No generated output may be written elsewhere. Non-loopback network access, DNS, production or external endpoints, mutation of any non-descendant process or host setting/service/filesystem, and every Nix command/evaluation/build are prohibited.

- `.perf/prove-http2-performance-regression/` is the only execution/cache root. It may be ignored by Git, but a seal used by a calibration, terminal campaign, remediation decision, or reviewer conclusion may not be deleted until all mandatory bundles and receipts have been independently reproduced from committed chunks, the implementation PR has merged, the durable fetched base/merge commit has passed the path/ledger reachability gate in §6.13.4, and the reviewer report links exact SHA-256 values. Staging, a pushed PR head, an external artifact service, or a home/tmp copy is never cleanup authority. A closed, failed, abandoned, or otherwise unmerged PR keeps both `.perf` and the task worktree. The durable root is exactly `.legion/tasks/prove-http2-performance-regression/artifacts/`; it is ordinary Git content, not Git LFS, a release asset, a CI artifact, or a URL.
- A durable bundle contains `seal.json` and every regular file named by that original seal, including all required raw measurements and prospective locks—not a selected summary. Runtime databases, cookies, tokens, signing keys, payload materializations, build caches, and other secret/cache namespaces are never seal members. A secret in a required evidence file is `BLOCKED`; the file cannot be redacted, omitted, or resealed after observation.

### 4.2 Fixed hard gates

All ratios are treatment/reference and use one-sided paired 95% bounds unless marked descriptive.

| Comparison | Concurrency | Throughput | p99 | CPU/op | Peak RSS |
|---|---:|---|---|---|---|
| Candidate H1→H1 / baseline H1→H1 | 1, 16, 64 | lower bound `>= 0.97` | upper bound `<= 1.05` | upper bound `<= 1.05` | upper bound `<= 1.10` |
| Candidate H2→H2 / candidate H1→H1 | 16, 64 | point estimate `>= 1.00` **and** lower bound `>= 0.97` | upper bound `<= 1.05` | upper bound `<= 1.10` | upper bound `<= 1.15` |
| Candidate H2→H1 / candidate H1→H1 | 16, 64 | lower bound `>= 0.95` | upper bound `<= 1.10` | upper bound `<= 1.10` | upper bound `<= 1.15` |
| Candidate H1→H2 / candidate H1→H1 | 16, 64 | lower bound `>= 0.95` | upper bound `<= 1.10` | upper bound `<= 1.10` | upper bound `<= 1.15` |

Candidate H2/bridge C1 results contain the same raw metrics and confidence calculations but are labeled **descriptive** and never enter the global verdict. H1 C1 remains hard.

For the upload workload, the H1 reference and treatment (`B11`/`C11`) use the same shipped one-connection-per-operation policy, so their differential remains direct. Candidate H2/bridge comparisons intentionally retain their real topology difference: downstream H2 upload (`C21`/`C22`) multiplexes on one persistent H2 connection, while the `C11` reference pays one downstream H1 connect and close per operation. The bounds therefore measure the delivered protocol topology's advantage or cost, not a framing-only abstraction.

## 5. Definitions

- **Cell:** one workload and one concurrency; there are 15.
- **Treatment/arm:** one exact commit plus downstream/upstream protocol topology.
- **Mini-block:** the five arm-runs for one cell and one round, using the same fixture/load binaries and a balanced order.
- **Round:** one mini-block for every cell, in a frozen randomized cell order.
- **Pair:** treatment and reference observations from the same mini-block. Shared candidate H1 observations are intentionally correlated across three comparisons.
- **Arm-run:** one fixed successful ten-second quiet observation, fresh role processes, one topology and cell, one workload-aware materialization/settle lifecycle, one post-materialization TID freeze, and one frozen-duration steady window.
- **Operation:** the exact end-to-end unit in §6.5. For a downstream-H1 upload, it begins immediately before the operation's sole fresh TCP connect attempt and ends only after the validated response and required transport EOF. Operations/second is authoritative; application bytes/second is reported.
- **Downstream-H1 upload arm:** an upload cell in `B11`, `C11`, or `C12`, or its workload-matched direct-H1 ceiling. Its valid topology is one fresh downstream H1 TCP connection and exactly one POST per started operation, with no connection reuse or operation retry.
- **Cold/materialization path:** process readiness, topology/SETTINGS proof, persistent-pool establishment where applicable, authenticated ordinary warmup—including representative per-operation H1 upload connect/close churn—or WebSocket opening/worker retirement, unauthenticated WebSocket Ping/Pong warmup, and final TID freeze. A TCP connect performed by a measured H1-upload operation is not part of this cold path.
- **Steady path:** the frozen equal-duration measurement window immediately after the workload-aware TID freeze, plus bounded completion drain where explicitly stated.
- **Authoritative campaign:** the sealed `N` rounds after calibration; calibration/scout/direct-ceiling observations are never included.
- **Quality-scout evidence (`S`):** a fresh count-window/rate/thread/noise/correctness probe. It retains every raw counter, boundary timestamp, lane quota/count, endpoint count/byte/hash, resource/thread/noise sample, signature, and lifecycle event needed to recompute its transition, but has no per-operation latency member and is ineligible for p99, variance, or bootstrap input.
- **Williams-calibration evidence (`C`):** a fixed-duration gateway arm in the balanced ten-row cycle. It retains every started operation's integer latency and supplies only prospective duration/signature/variance design inputs, never authoritative pairs.
- **Direct-ceiling evidence (`D`):** a calibration or authoritative direct arm used only for exact throughput ceiling, drift, utilization, correctness, resource, thread, and headroom decisions. It retains exact count/timing/byte/hash and lifecycle evidence but has no per-operation latency member and never enters p99 or bootstrap.
- **Authoritative gateway evidence (`A`):** a fixed-duration gateway arm in the frozen campaign. It retains every started operation's integer latency and is the only class that enters final paired estimands/bootstrap.
- **Direct epoch:** calibration epoch `0`, followed by authoritative epochs `1..N/10`, each covering the next ten frozen rounds without changing their Williams-row order.
- **Dynamic-attribution interval:** first proof/materialization work through the authoritative TID freeze. Threads remain inside disjoint broad role CPU sets, are discovered and singleton-pinned as they appear, and any not-yet-attributable runtime is charged conservatively under §6.11 rather than subtracted as benchmark work.
- **Frozen role-attribution interval:** the authoritative TID freeze through completion of measured drain. The complete frozen inventory, singleton map, process/TID reconciliation, and all logical/pair/role contention gates apply without lifecycle tolerance.
- **Accepted thread signature:** the post-materialization semantic role/thread-slot/count map for one treatment/cell, or one direct cell/protocol, excluding ephemeral PID/TID numbers and start timestamps. It is learned only at a prospectively designated calibration observation and then becomes an exact no-retry requirement.
- **Evidence unit:** one write-once sealed calibration directory or one write-once sealed campaign directory. Its source closure is `seal.json` plus exactly every path listed by that seal.
- **Durable bundle:** one deterministic compressed representation of an evidence unit, its chunk/index hashes, and an independent verification receipt stored below the tracked task artifact root. The bundle is valid only as a whole; analysis and reports are never substitutes for raw members.
- **Delivery set:** the additive set of all sealed calibrations plus every authoritative/terminal campaign and any failed, blocked, superseded, or diagnostic campaign cited by the conclusion or used to choose remediation. A later candidate adds entries and never replaces an earlier entry.

---

## 6. Proposed design

### 6.1 Repository-owned process architecture

Add a nested, benchmark-only Rust package (expected path `benchmarks/http2-regression/`) with its own lockfile and these modes:

```text
orchestrator
  ├── fixture: one dual H1/H2 prior-knowledge data listener + auth-mini tripwire
  ├── load: H1/H2 clients, operation corpus, correctness validator
  ├── sampler: /proc and /sys observer
  └── gateway: exact archived release binary (one at a time)
bundle: canonical archive, pinned compression, chunk/index/report materialization
verify-bundle: tracked-chunk validation, canonical reconstruction, exact re-encoding/stream comparison, independent raw recomputation
```

The fixture, load, and sampler are separate OS processes, not threads in the orchestrator. The release gateway is neither linked to nor called by the benchmark package. Communication uses literal loopback data sockets and a separate framed loopback control socket. Every control message carries schema version, run ID, cell, arm, block, and monotonic sequence; stale/cross-run messages fail closed.

The package itself implements both the canonical archive writer/parser and the bundle verifier. Compression is invoked through dependencies pinned exactly by the nested `Cargo.lock`; no host `tar`, `zstd`, home-directory config, or temporary directory participates. Before the mandatory topology smoke, `intent.json` freezes the authoritative encoder identity: package/source tree, lockfile, package checksums, vendored codec source hash and runtime version, build/toolchain identity, producer executed-binary hash for provenance, and the complete parameter vector/rule in §6.13.1. The exact cross-machine identity is the hash-pinned source/lock/vendored-version tuple; each verifier records its own executed-binary hash rather than assuming path-dependent builds are byte-identical. A later design lock copies the intent hash. Bundle-index codec fields are redundant diagnostics only; neither producer nor verifier may derive expected encoder identity from them. Early blocked calibrations therefore remain encodable from their sealed intent, while the delivery encoding cannot drift after observation.

Only the orchestrator persists across a campaign. Every arm-run starts fresh fixture, load, sampler, tripwire, database, and gateway processes from the sealed binaries/config, then terminates all of them after drain. Thus no socket, allocator, fixture counter, client pool, or runtime state crosses treatments; pairing shares design and time block, not mutable process state.

The orchestrator creates only its own descendants, records PID plus `/proc/<pid>/stat` start time, and verifies that tuple before every sample, signal, and wait. It never kills or changes an existing host process. A second gateway descendant is forbidden.

### 6.2 Exact source and binary construction

For each commit:

1. Resolve the full commit and tree with `git cat-file`/`rev-parse`; reject non-commit or missing objects.
2. Extract `git archive <commit>` below the repository execution root. Hash the archive, tree ID, `Cargo.toml`, and `Cargo.lock`.
3. Materialize a hashed repository-local `CARGO_HOME` from already-cached, lock-resolved registry artifacts without network access. Set that path plus `CARGO_NET_OFFLINE=true`; run the recorded Cargo 1.96.0 with `--frozen --release --bin auth-mini-gateway`, a commit-specific repository-local target directory, and no added `RUSTFLAGS`. Missing artifacts are `BLOCKED`, not permission to fetch, use a global mutable cache, or change a lockfile.
4. Copy the resulting executable by content into the run's immutable binary store and record SHA-256, size, ELF build ID when present, and `rustc -vV`/`cargo -vV` output and executable hashes.
5. Build the benchmark package from the final candidate archive and its independent lockfile. Its source/tree/binary hashes become part of the design lock.

No source file is copied between gateway archives. A candidate performance fix creates a new commit and therefore a new archive/binary hash.

Git executable/object-database, toolchain, loader/runtime-library, and dependency-cache access is input-only; Git runs with system/global configuration disabled. Before use, the harness seals a sorted allowlist of every external path actually read with type, size, mode, and SHA-256 content/link target. It also seals a clock-boundary manifest. For each gateway, the manifest records the exact archived object, binary, lockfile, and pinned-dependency hashes and defines its `CLOCK_REALTIME` allowance by process provenance plus existing production protocol/application purpose; known consumers are retained as representative audit evidence, not asserted to be an exhaustive caller list. For the harness, the manifest records every permitted clock ID, exact call site, destination field, and purpose:

| Clock | Allowed provenance/purpose boundary |
|---|---|
| `CLOCK_REALTIME` (read-only) | The exact untouched archived gateway processes and their pinned dependency code, solely for existing production protocol/application semantics; representative consumers include session lookup/expiry/refresh-due/touch-validity decisions, Hyper automatic HTTP `Date` cache/header generation, and tracing. Orchestrator/sampler code may read it solely for UTC artifact labels and the continuity record in §6.3. Fixture/load/control code and all other harness dependency paths are excluded. |
| `CLOCK_MONOTONIC` | Harness operation latency, performance/count/throughput windows, CPU-window boundaries, warmup/settle/freeze/drain durations, keepalive/stability comparisons, and every arm/phase/operation deadline. |
| `CLOCK_BOOTTIME` | Enclosing campaign elapsed, pauses, completed/future runtime reconciliation, the 42-hour projection/48-hour actual resource-budget gates, and bracketing UTC real-time continuity samples without supplying gateway protocol/application semantics. |

Schedule/order, seeds, and statistical calculations consume no clock. The archived gateways retain their exact production clock construction; the harness may not substitute a manual/monotonic benchmark clock. A gateway real-time read is allowed only when the executing process and dependency closure match the sealed archived provenance and no harness code, adapter, or replacement participates. A real-time read by fixture/load/control or any harness path outside the sealed UTC-metadata sites, a gateway provenance/purpose mismatch, a writable clock path, or a real-time value entering any prohibited benchmark or campaign field is `BLOCKED`. The verifier must not reject an otherwise valid archived gateway merely because a shipped dependency consumer was absent from the representative list. The harness opens no cache for writing and verifies the same external-input and clock-boundary manifests after construction. `HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, `TMPDIR`, and every tool output path point below the worktree. A missing/mutated input is `BLOCKED`; fetching, Nix, host-cache update, or fallback to an unsealed executable/library is forbidden.

### 6.3 Launch configuration and safe logging

The orchestrator starts from an empty environment and supplies one allowlisted configuration. The fixture serves H1 and H2 prior knowledge on one auto-detecting data listener, so `UPSTREAM_URL` is byte-identical in all arms. H1 baseline and H1 candidate receive byte-identical values, including `UPSTREAM_PROTOCOL=http1`; the baseline ignores that variable. Candidate upstream-H2 arms change only `UPSTREAM_PROTOCOL=http2`. Important fixed values are explicit defaults: loopback bind, D/U/R `256/128/8`, empty trusted proxies, `COOKIE_SECURE=false`, one allowlisted synthetic user, and session lifetimes `604800/2592000` with touch interval `604800`. Every benchmark-owned Hyper server builder explicitly disables automatic HTTP `Date` generation, and the clock sentinel proves that fixture/load/control dependencies have no other real-time path. Fixture role is sealed per process: gateway-facing upstream H1 upload responses retain the ordinary persistent fixture policy, while only a direct-H1 upload ceiling uses fixture close mode to emit `Connection: close` and close after its sole response. A role/mode crossover or using direct close mode to alter gateway upstream pooling is `BLOCKED`.

Before every arm, the harness creates a fresh schema-v2 WAL database from a hashed template containing exactly one non-revoked `identity_state='ready'` session. Access, idle, and absolute deadlines cover the entire 48-hour campaign bound with sealed margin; no touch or refresh is due. The non-secret UTC session fields, configured lifetimes, and expected production predicates—Ready, active, access not refresh-due, and touch not due—are retained for independent recomputation. It derives the opaque signed cookie externally. Tokens, cookie secret, and cookie value are synthetic and never written to reports; only allowlisted hashes are retained.

Both untouched archived gateways and the pinned dependency code they execute keep their exact production clock construction. Any read-only `CLOCK_REALTIME` use reached through existing production protocol/application behavior is shipped comparison work and remains allowed. Representative consumers include session lookup/expiry, refresh-due, and `touch_ready` validity evaluation; Hyper 1.10.1 automatic HTTP `Date` cache/header generation on H1 and H2 responses; and tracing timestamps. This list documents known behavior but does not narrow the provenance-and-purpose boundary to those call sites. Their values and costs remain in the measured binary; the harness neither replaces the clock nor consumes a gateway-produced time value as benchmark timing. The presence and value of generated `Date` headers are retained as protocol evidence, never as a latency, duration, deadline, ordering, or accounting source.

The sampler records a real-time continuity stream solely as UTC artifact metadata: each sampler `CLOCK_REALTIME` read is bracketed by `CLOCK_BOOTTIME` immediately before and after it, beginning before database finalization and the first proof and continuing at every existing <=10 ms dynamic lifecycle poll and 100 ms frozen bucket boundary through the last gateway response and process finalization. `session-clock.bin` seals those fixed-width triplets, the ready-session UTC fields, the four expected predicates evaluated at every real-time sample, and BOOTTIME-bracketed observations of gateway-produced time-derived protocol metadata such as HTTP `Date`. Every detected backward or forward real-time discontinuity is retained. The guard is clean only if every session sample remains Ready/active/non-refresh-due/non-touch-due and no discontinuity can either cross a session predicate boundary or make baseline/candidate protocol/application behavior non-comparable, including automatic `Date` behavior. A missing sample or comparability-affecting discontinuity is environmental `BLOCKED`, never candidate semantic `FAIL`; a discontinuity proven confined to UTC artifact labels and unable to affect a gateway semantic interval is recorded diagnostically without changing the verdict. A candidate-only authentication or protocol failure is eligible for `FAIL` only when its relevant interval has a clean guard. These real-time samples cannot define or adjust a latency, duration, throughput/count window, CPU window, benchmark operation/phase deadline, ordering, schedule, seed/statistical input, or campaign/resource elapsed value.

`AUTH_MINI_ISSUER` points to the fixture's loopback tripwire. Any accepted connection or HTTP byte is a zero-hit violation. DNS is bypassed by literal loopback addresses.

Both gateways inherit the same already-open `/dev/null` file description for stdout and stderr, with `NO_COLOR=1` and no `RUST_LOG` override. `/dev/null` cannot fill or backpressure. The default shipped INFO subscriber still reads `CLOCK_REALTIME` for its timestamp, formats, and writes the candidate's per-dispatch event; those shipped costs are authoritative, but the tracing timestamp value is never parsed or used by the harness. Session validation, Hyper `Date`, and tracing are recorded as representative production consumers in the clock-boundary manifest, not as an exhaustive call-site allowlist. A file/pipe sink is rejected because candidate-only volume could add storage or drainer bottlenecks. Protocol proof comes from both wire endpoints, not log parsing.

### 6.4 Treatments and exact connection topology

Every cell runs all five treatments:

| Label | Gateway object | Downstream | Upstream |
|---|---|---|---|
| `B11` | baseline | H1.1 | H1.1 |
| `C11` | candidate | H1.1 | H1.1 |
| `C21` | candidate | H2 prior knowledge | H1.1 |
| `C12` | candidate | H1.1 | H2 prior knowledge |
| `C22` | candidate | H2 prior knowledge | H2 prior knowledge |

All sockets are cleartext, arm-local, and created after fresh role startup. Persistence is workload- and side-specific; no socket crosses an arm-run.

- **Downstream H1, GET/download/SSE:** exactly `C` persistent TCP connections, one closed-loop lane and at most one outstanding operation per connection. Each lane reuses only its own proved connection through warmup and steady drain.
- **Downstream H1, 1 MiB upload (`B11`, `C11`, `C12`):** there is no pre-established or reusable downstream pool. Each operation begins immediately before exactly one fresh TCP socket/connect attempt, then sends exactly one authenticated POST on that connection. The request does not inject `Connection: close`; the client must observe the gateway's HTTP/1.1 response with a parsed `Connection` token containing `close` and no `keep-alive`, validate status/operation ID/body EOS, and then observe transport EOF before the operation completes. The socket is never offered another request. A successful next operation has a new operation ID, a new planned connection ID, and its own single connect attempt. A connect, write, response, close-token, EOS, or EOF failure terminates that operation and the arm; no layer may reconnect or retry the same operation ID. At most `C` upload operations and their `C` owned connections are active at once, and zero remain active after proof, either drain, or exit. For every phase and for the whole valid arm, cumulative downstream connections equal started operations and every connection carries exactly one request.
- **Downstream H2:** exactly one persistent TCP connection with at most `C` concurrent streams/tunnels. The client proves the server SETTINGS/ACK exchange before workload materialization. In particular, `C21` and `C22` uploads keep this one connection and use up to `C` concurrent POST streams; they do not emulate the H1 reconnect policy.
- **Upstream H1, ordinary HTTP/SSE:** warmup ends at quiescence with exactly `min(C, 8)` open idle gateway-to-fixture connections, matching the reviewed pool capacity. The downstream-H1 upload close policy does not force upstream closure. During steady state the fixture does not impose an artificial cap; it records active, retiring, and cumulative connections. Application concurrency is `C`, but asynchronous owner retirement can overlap later work, so the only hard physical bound is the reviewed `U + 8 = 136`, not `C`. Connection churn is reported as real gateway behavior. Exceeding 136 live upstream sockets, replayed operation IDs, or a non-H1 request is a topology failure.
- **Upstream H2, ordinary HTTP/SSE:** one serial warm request first establishes exactly one proved generation; all remaining warm and measured streams use that same physical connection. A second H2 fixture connection is a topology failure for C≤64 and peer stream limit 100.
- **WebSocket:** all `C` authenticated tunnels are established before steady measurement. H1 sides use exactly `C` physical connections; each H2 side uses exactly one physical connection carrying `C` Extended CONNECT streams. No pool-idle assertion applies while tunnels own their connections.

The load and fixture retain phase-separated proof, warmup, measured, and drain ledgers. For downstream-H1 uploads the load records, in lane/operation order, planned connection IDs and exact totals for operation starts, socket creations, connect attempts/successes, requests, responses, `close`/`keep-alive` tokens, response EOS, transport EOF, active/max-active connections, requests-per-connection, reuse attempts, retry/reconnect attempts, and rolling hashes binding operation IDs to connection IDs. A valid phase requires one connect attempt and success, one request, one close response, one EOS, and one EOF per started operation; `max_active<=C`, every requests-per-connection value is one, reuse/retry counters are zero, and the phase and arm totals/hashes reconcile. H2 ledgers instead require one downstream connection and unique stream IDs with at most `C` active streams. Both endpoints continue to record actual HTTP version, upstream connection/stream identity, operation ID, and application bytes. Requested configuration is never accepted as proof of actual protocol.

### 6.5 Exact workloads and operation boundaries

All request objects/headers, deterministic payload descriptors, operation IDs, and planned connection IDs are prepared before the start timestamp. No H1-upload socket is opened early. Latency uses `CLOCK_MONOTONIC` nanoseconds and includes client queue/readiness, gateway/auth/proxy work, transport, and incremental validation; for a downstream-H1 upload it also includes the operation's TCP connect and terminal EOF wait.

| Workload | Exact operation | Completion boundary |
|---|---|---|
| Small authenticated GET | `GET /bench/get` with signed session cookie and deterministic operation ID; fixture returns exactly 64 generated bytes and verifies injected identity plus absence of browser credentials. | Immediately before client submission through validated response EOS and exact 64-byte pattern. |
| 1 MiB upload | `POST /bench/upload`, exactly 1,048,576 generated bytes in 64 × 16,384-byte source chunks; fixture validates every byte incrementally and responds only after request EOS with the exact operation ID/count. In downstream-H1 arms, this is the sole request on the operation's fresh connection and the request itself does not force closure. | Downstream H1: immediately before the sole TCP connect attempt through validated status/ID/response EOS, required response `Connection: close`, and transport EOF. Downstream H2: submission on the already-proved persistent H2 connection through validated response EOS. No full-body validation buffer. |
| 1 MiB download | `GET /bench/download`; fixture emits exactly 1,048,576 generated bytes in 64 source chunks; client validates incrementally. | Submission through validated response EOS and exact byte count/pattern. |
| Finite SSE | `GET /bench/sse`; response is `text/event-stream` with exactly 16 ordered events, IDs 0–15, one 128-byte deterministic data field each, then EOS. | Submission through parsed event 15 and clean EOS; missing, repeated, reordered, malformed, or trailing event fails. |
| Framed WebSocket | On each pre-established authenticated tunnel, send one RFC 6455 masked Ping control frame (`opcode 0x9`) with an 8-byte lane/sequence payload and a precomputed fresh mask from the sealed CSPRNG corpus; require one unmasked Pong (`opcode 0xA`) with the identical payload. | Immediately before frame write through complete matching Pong parse. Handshake and close are excluded. |

The design lock contains a once-generated 32-byte seed and SHA-256 test vectors. Corpus block `k` is `SHA-256("amg-http2-perf/v1/payload" || seed || k_be64)`; concatenated blocks form one immutable 1 MiB buffer, whose first 64 bytes and encoded slices also define GET/SSE data. That buffer is materialized before timing and reused read-only, while deterministic phase/lane/sequence operation IDs independently detect replay. For a downstream-H1 upload, the planned connection ID is derived from that same phase/lane/sequence tuple and can be consumed by only that operation. WebSocket masks use `SHA-256("amg-http2-perf/v1/ws-mask" || seed || operation_id_be128)` and the first four digest bytes; the complete calibration-bounded mask table is precomputed before each arm. No corpus, operation ID, connection ID, mask, duration, or gate depends on wall time, and no hashing is added to measured operations. The fixture rejects unknown paths/methods, duplicate operation IDs, wrong protocol, wrong payload, premature/trailing bytes, and replay. The load side independently checks status, downstream protocol, bytes, framing, order, and EOS; downstream-H1 upload additionally checks the response connection tokens, one-request connection identity, and transport EOF. At every phase boundary and arm end the orchestrator reconciles endpoint operation/byte hashes and the §6.4 connection ledger. One mismatch invalidates the arm; a failed operation is never retried, reconnected under the same ID, or dropped.

The downstream-H1 upload connect/close cycle is intentionally part of the shipped steady operation. It is not cold-path normalization: `B11` and `C11` remain directly comparable under the same policy, `C12` measures that policy with an H2 upstream, and `C21`/`C22` intentionally measure persistent downstream-H2 multiplexing against the real `C11` reference. Workload-matched direct H1 ceilings use the identical fresh-connect/one-POST/close/EOF boundary, although class `D` retains no latency array.

`operations/second = exact valid operations / measured elapsed seconds` is the gate metric. For a downstream-H1 upload, an operation is valid only after required EOF; an EOS-validated response still awaiting EOF at the deadline is not a deadline completion and must drain. Request, response, and combined **application** bytes/second are reported separately and are never substituted for operations/second.

### 6.6 Cold path, workload-aware thread materialization, measurement, and drain

Every scout, Williams-calibration, calibration-direct, authoritative-direct, and authoritative-gateway arm uses the same immutable lifecycle and correctness/resource gates; only the prospectively frozen evidence schema differs by class `S/C/D/A`. `Q_obs` is a fixed successful observation, not wait reserve; exceeding any cap is immediately `BLOCKED` and never causes a retry or replacement:

| Symbol | Phase | Exact requirement / cap |
|---|---|---:|
| `Q_obs` | final successful pre-arm quiet observation | exactly 10.000 s |
| `R` | repository-local setup and process spawn through all required role readiness | 2.000 s cap |
| `P` | connection/topology/SETTINGS or direct-protocol proof, including all WebSocket handshakes | 2.000 s cap |
| `W_s` | full-concurrency workload materialization/warmup issuing interval | exactly 3.000 s for scouts; frozen 3–10 s otherwise |
| `D_w` | post-materialization quiescence drain | 2.000 s cap |
| `L_ws` | WebSocket post-auth blocking-worker retirement and inventory settle | 15.000 s cap; success no earlier than 12.000 s |
| `F` | final stop/barrier, authoritative TID freeze, map seal, and steady release | 1.000 s cap |
| `D_m` | post-measurement/count-window drain | 2.000 s cap |
| `X` | clean child exit and per-arm artifact finalization | 1.000 s cap |

For projection and phase reconciliation, `M_s = W_s + D_w` is the explicit thread-materialization cap (`5.000s <= M_s <= 12.000s`). `L_ws=0` for ordinary GET/upload/download/SSE cells and exactly the 15-second prospective cap for WebSocket cells. All phase deadlines, Tokio-keepalive comparisons, inventory-stability intervals, and operation timestamps use `CLOCK_MONOTONIC`; `CLOCK_BOOTTIME` independently accounts for the enclosing campaign.

Each gateway arm-run uses fresh role processes and follows this state machine; a direct arm follows the same workload-class states without a gateway:

0. **Successful quiet observation (`Q_obs`):** with no fresh gateway, fixture, load, or arm sampler present, observe one final continuous successful ten-second interval under §6.11. Time spent searching for that interval or cooling before it is `Q_extra`, never part of `Q_obs`. Begin `R` immediately after the accepted observation.
1. **Setup/spawn/readiness (`R`):** before each exec, apply the role's broad, disjoint CPU mask from §6.11. Start the cap before creating fresh per-arm database/files/sockets, then record spawn-to-`/healthz` latency and startup `VmHWM`; assert every PID/start time and environment hash. Direct readiness means both endpoint roles and the sampler/control channel are ready.
2. **Connection proof (`P`):** start dynamic lifecycle observation before the first operation. Persistent ordinary paths establish their exact downstream topology and H2 SETTINGS/ACK where applicable. A downstream-H1 upload instead executes exactly one descriptive proof operation with its own fresh connection, sole POST, required close response, and EOF, then proves zero active downstream connections; this proof is phase-labeled and cannot be reused as warmup or measured work. Direct H1 upload uses the same proof boundary and direct fixture close mode. Every gateway proof triggers and wire-proves the configured upstream protocol, and the first-operation latency is descriptive. WebSocket gateway arms snapshot the exact pre-auth gateway TID identity set before releasing the first handshake, then authenticate and validate all `C` tunnels; direct WebSocket arms open all `C` tunnels. The validated last-handshake timestamp is `t_auth_done`. These values are descriptive.
3. **Workload-aware materialization:** while broad role affinity remains the inherited safety boundary, enumerate every role's task directory at intervals no greater than 10 ms. Existing and newly observed TIDs are immediately given deterministic provisional singleton slots inside that role set; births and disappearances before the authoritative freeze are retained and charged conservatively under §6.11 rather than treated as steady inventory.
   - **Ordinary GET/upload/download/SSE:** release all `C` lanes together and run the exact authenticated workload closed-loop for `W_s`; every lane remains active whenever it has no operation in flight. Persistent H1/H2 paths use the §6.4 proved connections. Each downstream-H1 upload lane instead opens one fresh connection, sends one POST, waits through required close/EOF, and only then starts the next operation with a new ID and connection; direct H1 upload does the same against fixture close mode. At most `C` such operations/connections are active. No operation—and for H1 upload, no socket/connect attempt—starts at or after the common warmup deadline. Drain all started work within `D_w`, reconcile correctness/topology/tripwire and phase connection ledgers, require zero active downstream-H1 upload connections, and reach the applicable §6.4 downstream and upstream pool states. This full-concurrency phase, not the earlier one-operation proof, is authoritative for materializing lazy Tokio auth and per-connection accept/close work.
   - **WebSocket:** after `t_auth_done`, issue neither authentication requests nor Ping/Pong. Tokio 1.52.3's sealed blocking-worker keepalive is `K_tokio=10.000s`. Stability counting is forbidden before `t_auth_done+K_tokio`. A gateway arm succeeds only when its gateway inventory has returned to the exact pre-auth TID identity set—so every TID born during tunnel authentication has retired—and every present role inventory then remains unchanged for one continuous `S_inv=2.000s`. A direct arm has no gateway-base equality check but observes the same `K_tokio+S_inv` interval for its present roles. Any inventory change resets only the two-second stability clock, never the 15-second cap measured from `t_auth_done`; therefore success is impossible before 12 seconds and must occur by 15 seconds. Keep all tunnels open, then run all `C` lanes closed-loop on unauthenticated Ping/Pong for exactly `W_s` and drain within `D_w`. Any HTTP/auth tripwire activity during settle or Ping/Pong warmup fails the arm.
4. **Authoritative freeze and immediate handoff (`F`):** after the ordinary drain or WebSocket Ping/Pong drain, hold custom roles at their no-work barriers and stop the quiescent gateway. Force boundary counter snapshots, enumerate the complete live inventories, apply the final deterministic singleton maps, compute/check the semantic signatures in §6.11, exclusive-create the lifecycle/map records, and resume the gateway in the same event that releases all `C` steady workers. For ordinary arms the intentional no-issue interval from the warmup deadline through steady release is bounded by `D_w+F <= 3.000s`, only 30% of the sealed ten-second keepalive; there is no other idle gap, and the first steady wave uses the same `C` and exact workload. Persistent paths resume on their frozen topology. A downstream-H1 upload has zero open downstream connections at the freeze, and the release causes each of the first `C` lanes to begin its measured operation by opening its own fresh connection; pre-opening during `F` is forbidden. WebSocket steady work begins with the same `C` already-open tunnels and cannot invoke auth. A new TID, a disappearing frozen TID, or any map/signature change after this freeze is immediately `BLOCKED` through measured drain.
5. **Steady start:** the resume/release event is the common start barrier. The sampler captures gateway/process/per-TID CPU counters, process status, per-CPU/noise counters, and the exact barrier timestamp around that event as specified in §6.11.
6. **Measure:** run a fixed-duration Williams-calibration, authoritative-gateway, or direct arm for exactly its frozen `T_s`. Each lane is closed-loop. An operation is issued only when its start timestamp is before the common monotonic deadline; no new operation starts at or after it. For downstream-H1 upload, the start timestamp immediately precedes the sole socket/connect attempt, so no connection may be opened at or after the deadline; a lane may begin its next operation only with a new operation/connection ID after the prior EOF. Throughput counts only validated completions at or before the deadline and divides by exactly `T_s`; H1 upload validation includes close and EOF. `C/A` arms append one latency for every started operation, including H1 connect-through-EOF; `D` arms use the same operation boundary but append only exact boundary/count/byte/connection-hash summaries and no per-operation latency. Scout attempts substitute the count window in §6.8.1. No automatic transport retry, open-loop correction, or coordinated-omission synthesis is applied.
7. **Steady end/drain (`D_m`):** at the deadline, capture fixed-window counters, stop issuing, and drain every already-started operation. Every class retains exact started/deadline-completed/drain-completed counts and endpoint hashes. For downstream-H1 upload, every drain completion still requires close/EOF, all owned connections must reach zero active, and measured plus drain ledgers must prove cumulative connections equal started operations with no reuse/retry. Drained-operation latencies are present for every `C/A` operation and intentionally absent for `S/D`. Capture the post-drain CPU counter; CPU/op uses start-through-drain ticks divided by all completed measured operations. Require reconciled fixture counts and final `VmHWM` before TERM.
8. **Exit (`X`):** signal only validated children, require zero active fixture/load connections, clean exit, reaping, and atomic per-arm metadata finalization within the cap. At the one-second cap, mark the campaign `BLOCKED` and only then KILL/reap any still-validated child. Emergency cleanup cannot rescue or resume the campaign and remains charged to the 48-hour actual clock.

`Q_obs`, startup, proof, materialization, either warmup drain, WebSocket handshake/settle, final freeze, and process exit are excluded from throughput, p99, and CPU/op. That exclusion applies only to operations in those phases: every TCP connect and EOF wait initiated by a measured downstream-H1 upload operation remains inside its steady latency and gateway CPU window. For `C/A`, measured drain is excluded from throughput time but included in p99 and CPU/op, and every started operation has a retained latency. For `S/D`, exact counts and CPU/resource/connection boundaries remain, but p99 is undefined by design and no latency array is written. Cold/materialization values remain separate; per-operation H1 reconnect is explicitly not reclassified as cold path. Kernel `VmHWM` cannot be reset, so the authoritative RSS metric deliberately covers startup + proof + lazy-thread lifecycle + warmup + freeze + steady + drain. Stage-end `VmHWM` and 100 ms `VmRSS` samples are diagnostic decompositions only. The same numeric caps feed the projection in §6.12; no cap, keepalive, stability interval, handoff bound, connection policy, or evidence class can be changed after intent.

### 6.7 Prospective five-arm block schedule

For treatment codes `[B11,C11,C21,C12,C22] = [0,1,2,3,4]`, use these five rows and their reverses:

```text
0 1 4 2 3
1 2 0 3 4
2 3 1 4 0
3 4 2 0 1
4 0 3 1 2
```

The resulting ten-row Williams cycle has exact properties checked by self-tests: every treatment appears twice in every position; every directed first-order carryover appears twice; and every pair is ordered A-before-B five times and B-before-A five times. Because every allowed `N` is a multiple of ten, each row occurs exactly `N/10` times per cell.

Before sampling, a documented SplitMix64/Fisher–Yates generator shuffles row instances and each round's 15-cell order from the campaign seed. Unbiased bounded draws use rejection sampling. The complete schedule is stored in `design-lock.json`; there is no runtime reshuffle, replacement row, or operator-selected rerun.

The pair for each comparison is always taken from the same mini-block. `C11` is intentionally reused for `C21/C12/C22`, but never across cells, rounds, candidates, or campaigns.

### 6.8 Calibration and the single frozen authoritative N

Calibration is sealed, non-authoritative, and subject to the same correctness, topology, workload-aware thread lifecycle, dynamic/frozen attribution, thermal, quiet-observation, and phase-cap gates as authoritative work. Before the mandatory smoke—and therefore before the first scout—`intent.json` seals the campaign seed, the exact workload-specific downstream and direct connection policies, the smoke schedule/cap, all seven possible scout target levels, deterministic cell/arm order at each level, the uniform signature-establishment rule, and the rule mapping every calibration gateway arm to calibration direct IDs `D[0,cell,protocol]`. Ratios and thread counts are neither consulted nor exposed when choosing a scout transition.

#### 6.8.0 Mandatory pre-scout topology smoke

After both exact archived gateway binaries and the final harness are built, but before any scout, run one sealed functional smoke schedule under a single `T_smoke=300.000s` monotonic cap. `t_campaign` starts before this schedule, so its exact BOOTTIME elapsed `E_smoke` is part of §6.12 rather than hidden setup. Smoke uses fresh processes and synthetic Ready sessions, writes only bounded unit-level `topology-smoke.json` counters/hashes (no latency array or performance ratio), and contributes no scout, calibration, direct, or authoritative observation. No smoke process, socket, counter, TID, or warm state may enter a later arm.

At `C=1` and `C=64`, the schedule performs two full-concurrency sequential waves for every upload treatment. For `B11`, `C11`, and `C12`, exactly `2C` fully consumed successful 1 MiB POST operations must create exactly `2C` distinct downstream H1 connections, observe `Connection: close` plus transport EOF `2C` times, carry one request per connection, keep maximum active connections at most `C`, and record zero keepalive/reuse/retry/reconnect. For `C21` and `C22`, the same `2C` uploads must use exactly one proved persistent downstream H2 connection with unique streams and at most `C` active streams. Workload-matched direct H1/H2 modes repeat those policies, with direct H1 fixture close mode. Separate two-operation-per-lane checks prove that H1 GET/download/SSE retain their `C` persistent connections and that WebSocket Ping/Pong uses the already-established `C` tunnels without another handshake.

The smoke uses the exact §6.4/§6.5 operation and connection ledgers, including distinct operation/connection IDs and no client-forced close header. A candidate-only missing close/EOF or other attributable protocol error is `FAIL`; baseline/control, direct fixture, harness reuse/hidden retry, count/hash mismatch, cap expiry, or incomplete smoke evidence is `BLOCKED` under §6.14. A smoke failure is sealed and not rerun. Passing smoke is only an implementation/topology prerequisite and cannot support a performance claim.

#### 6.8.1 Exact fresh-process count-window state machine

A scout attempt is one complete fresh §6.6 arm: fixed successful `Q_obs`, fresh gateway (except direct work), fixture, load, sampler, tripwire, database, sockets, lifecycle record, and post-materialization thread map. No process, pool, counter, accepted quiet interval, TID, or warm state survives to a doubled target.

1. Complete `Q_obs`, readiness, and proof; then execute the workload-specific §6.6 lifecycle with `W_s=3.000s`: ordinary full-`C` authenticated materialization—including fresh connect/POST/close/EOF per downstream-H1 upload operation—or WebSocket handshake, `K_tokio+S_inv` retirement/settle, and unauthenticated full-`C` Ping/Pong materialization. Reach quiescence within `D_w`; H1 upload must have zero active downstream connections and exact phase-ledger equality. Complete the authoritative freeze within `F`, and reject any post-freeze inventory change.
2. For target `Q`, assign lane `j` exactly `floor(Q/C) + 1[j < Q mod C]` operations. Capture gateway/per-TID CPU counters, `/proc/stat`, and `t_0` immediately before releasing one barrier. No operation exists before that release and no lane may exceed its quota. For downstream-H1 upload, each quota item begins with its own sole connect attempt after `t_0`; exactly `Q` operation starts therefore plan exactly `Q` distinct measured connections, with at most `C` active.
3. The count window ends at `t_1`, the monotonic timestamp of validation of the last of exactly `Q` operations; for downstream-H1 upload this is the last required transport EOF, not merely response EOS. Success requires all `Q` operations, endpoint and connection-ledger reconciliation, and `t_1 - t_0 <= 15.000` seconds. The 15-second deadline is inclusive. If it arrives first, stop issuing, drain already-started work within `D_m`, seal the attempt `BLOCKED`, and do not accept a partial rate or try a larger target. A failed connect/request/response/EOF is never reconnected or retried under the same ID.
4. On success there is no in-flight operation at `t_1`; nevertheless perform the common reconciliation/drain state (normally zero elapsed) and exit within `X`. Capture end counters immediately after `t_1`. The scout stores no per-operation latency array. It stores `Q`, every lane quota/completion count, exact `t_0/t_1`, CPU and resource counter snapshots, endpoint operation/byte totals and rolling hashes, the phase-separated §6.4 connection totals/hashes/violation counters, thread/lifecycle/noise evidence, and correctness/topology results, which are sufficient to recompute every scout transition and diagnostic rate. In a downstream-H1 upload count window, valid measured cumulative connections are exactly `Q`.
5. Let `E_ns=(t_1-t_0)` in exact monotonic nanoseconds, `E_s=E_ns/1,000,000,000`, `G` be gateway `utime+stime` ticks between the two count-window counter snapshots, and `CLK_TCK=100`. The only scout rates are `r_ops=Q/E_s` operations/s and `r_tick=G/E_s` ticks/s; count-window CPU/op is `(G/100)/Q`. H1-upload `E_ns` includes all `Q` fresh connects and EOF waits. `Q_obs`, extra wait, proof, materialization/settle/freeze, either drain, and exit are in neither denominator. Zero/non-monotonic time, counter loss/reset, fewer or more than `Q` operations, a connection-count/policy mismatch, or an attribution failure is `BLOCKED`.

The only non-failure transition is **insufficient count quality**: a valid attempt with `E_s < 2.000` seconds or `G < 100` ticks. Correctness, topology, timeout, noise, thread, headroom, thermal, frequency, phase-cap, or artifact failures always block and are never retried.

#### 6.8.2 Prospective calibration phases

1. **Quality scout and calibration-duration freeze.** For each cell, try common targets `Q ∈ {5,000,10,000,20,000,40,000,80,000,160,000,320,000}` in order. At a target, run all five arms once in the presealed order, each as the fresh state machine above. Accept the target only if all five valid attempts have `E_s >= 2.000` seconds and `G >= 100` ticks. Otherwise double and rerun all five from fresh processes. Insufficient quality at `320,000`, or any failure other than insufficient count quality, is `BLOCKED`.

   Target acceptance depends only on the predeclared count-quality rule. Every scout signature remains raw evidence, but no scout signature is an accepted cross-arm signature and no signature can cause doubling, select a preferred count, or replace an observation. The lifecycle, `W_s`, role CPU sets, polling, provisional/final slot algorithm, and handoff are treatment-blind; no arm is padded with dummy threads, held alive, killed to reach a count, or retried because of its count. A natural product-topology difference may yield a different signature for another treatment, but the harness cannot choose it.

   From only the five accepted scout attempts for cell `s`, compute `r^S_ops(s)` and `r^S_tick(s)` as the minimum accepted `r_ops` and `r_tick`. Before any Williams-calibration arm, freeze equal durations for all five arms in that cell:

   ```text
   T_cal(s) = ceil_to_whole_seconds(max(
                  5 seconds,
                  6,250 / r^S_ops(s),
                  625 / r^S_tick(s)))
   W_cal(s) = ceil_to_whole_seconds(max(
                  3 seconds,
                  1,250 / r^S_ops(s)))
   ```

   Require `5 <= T_cal(s) <= 30` and `3 <= W_cal(s) <= 10`. An exclusive-created, sealed `calibration-plan.json` records the verified topology-smoke hash, every attempted target/result/signature, the accepted target, all 15 exact `W_cal/T_cal` pairs, the ten-row schedules, the prospectively designated first Williams arm for each of the 75 treatment/cell keys, direct IDs/mappings and workload-specific connection policies, `Q_obs/K_tokio/S_inv/L_ws/F` and all other phase caps, and hashes before the next phase.

2. **Balanced calibration and signature freeze.** Run one complete ten-row Williams cycle for every cell—exactly 50 fresh §6.6 gateway arms per cell and 750 total—with its frozen equal `W_cal/T_cal`. For each treatment/cell key, the first occurrence fixed in `calibration-plan.json` is the sole signature-establishment arm; immediately after its successful post-materialization freeze, exclusive-create that key's accepted-signature record. The remaining nine Williams arms for the key must match it exactly after materialization, and every frozen inventory must then survive through drain. An establishment failure, signature mismatch, or workload-specific connection-policy/count mismatch blocks the campaign and is not replaced. These ten pairs per comparison estimate order-stratified log-ratio variance; none is copied into authoritative raw data. Each arm must also meet the 5,000-completion and 500-tick quality floors.

3. **Authoritative parameter derivation.** Derive `N` only from the balanced-calibration log-ratio variances below. Separately, for each cell let `r^C_ops(s)` be the minimum of `deadline_valid_completions/T_cal(s)` and `r^C_tick(s)` the minimum of `fixed_window_gateway_ticks/T_cal(s)` across its 50 accepted calibration arms. Derive authoritative durations only from those rates:

   ```text
   T_auth(s) = ceil_to_whole_seconds(max(
                   5 seconds,
                   6,250 / r^C_ops(s),
                   625 / r^C_tick(s)))
   W_auth(s) = ceil_to_whole_seconds(max(
                   3 seconds,
                   1,250 / r^C_ops(s)))
   ```

   Require `5 <= T_auth(s) <= 30` and `3 <= W_auth(s) <= 10`. Calibration runs therefore depend only on scout data, while authoritative runs depend only on the already-frozen Williams calibration; no value is derived from a run that itself uses that value. Direct results do not choose `N`, `W`, or `T`.

For each hard comparison/metric, let `s_AB` and `s_BA` be balanced-calibration sample standard deviations of log ratios in the two five-observation order strata. Apply floors `ln(1.005)` for throughput/p99/CPU and `ln(1.01)` for RSS. For each candidate `N`, project the one-sided log half-width as:

```text
h(N) = 2 × t95(N-2) × sqrt((s_AB² + s_BA²) / (2N))
t95(28,48,68,98) = 1.701, 1.677, 1.668, 1.661
```

The factor two is a prospective small-calibration safety inflation. Choose the smallest `N ∈ {30,50,70,100}` for which every projected width is at most `ln(1.02)` for throughput, `ln(1.03)` for p99/CPU, and `ln(1.05)` for RSS. If `N=100` does not qualify, stop `BLOCKED` before authoritative sampling. Before any calibration-direct arm, exclusive-create `authoritative-parameters.json` with the selected `N`, all derived `W_auth/T_auth`, variance inputs/outputs, all 75 accepted Williams signature hashes, the exact 30-arm direct order/durations, and the §6.12 prospective lower-bound screen. Statistical selection is not runtime truncation: a selected `N=70` or `N=100` is immediately sealed `BLOCKED` before calibration-direct work because even its minimum future-arm projection exceeds 42 hours; the harness may not substitute `N=50` or `N=30`. Such a terminal branch proceeds directly to the complete reached-branch calibration bundle in step 5 and reserves no direct or authoritative data. Only selected `N=30` or `N=50` proceeds to the exact post-direct admission equation.

4. **Calibration direct epoch.** For an admitted candidate `N`, run exactly the 30 preassigned direct cells `D[0,s,H1]` and `D[0,s,H2]`, each with cell `s`'s derived `W_auth/T_auth`, in the sealed order and full §6.6 lifecycle. The protocol label includes the cell's frozen workload policy: direct-H1 upload opens one fresh connection per operation and requires fixture `Connection: close` plus EOF, direct-H2 upload retains one connection and `C` streams, direct H1 GET/download/SSE is persistent, and direct WebSocket tunnels are pre-established. Each must be uncontaminated under §6.11 and satisfy utilization/correctness. Its first and only scheduled post-materialization signature becomes the accepted direct cell/protocol signature; there is no count-based retry. These runs become the only calibration ceilings for drift and exactly match the durations of authoritative direct epochs. They retain exact fixed-window start/deadline/drain boundaries, counts, bytes, connection-policy counters/hashes, resources, headroom inputs, and lifecycle evidence, but no per-operation latency arrays. Missing or invalid `D[0,s,p]` blocks every mapped scout/calibration arm and prevents a design lock.

5. **Complete calibration bundle and continuation freeze.** After balanced calibration, finish only the branch that remains reachable: a runtime/statistical terminal branch seals its complete reached calibration immediately; an admitted `N=30/50` branch first includes the 30 calibration-direct arms. Run the ordinary raw verifier, build the complete calibration bundle in repository-local staging, reconstruct and re-encode it through `verify-bundle`, record exact compressed bytes by schema component, and install it under the tracked artifact root only if the actual task total passes §6.12.1. No authoritative direct or gateway arm may start before this durable calibration bundle, its independent receipt, the 2× matching-component continuation projection, recompression disk/time terms, and the exact selected branch all pass.

Only then freeze the selected `N`, all `W_auth/T_auth`, accepted treatment/cell and direct cell/protocol signatures, the exact per-workload persistent versus fresh-connection policies and reconciliation equations, calibration frequency/direct envelopes, §6.12.1 storage projection and §6.12 runtime reserves, schedules, seeds, limits, topology-smoke/calibration-plan/authoritative-parameters/bundle hashes, and exact epoch-to-direct mappings in `design-lock.json`. Every authoritative gateway/direct arm must match the corresponding accepted signature exactly; no mismatch is retried or replaced. No performance confidence bound is computed or exposed during authoritative collection. Analysis runs once after all frozen observations have been raw-sealed and bundled under the actual-cap gate. If final precision is unexpectedly inadequate, the outcome is `BLOCKED`; pairs are not added after a look.

Once the mandatory topology smoke begins, any candidate, harness, fixture, corpus, connection policy, limit, state-machine, or analysis change seals that calibration as superseded/`BLOCKED`. A new Git object or design creates a new calibration ID and repeats every phase; calibration is never tuned in place after seeing treatment ratios.

### 6.9 Raw metrics and estimands

Evidence-class eligibility is fixed before execution:

| Class | Per-operation latencies | Permitted statistical use |
|---|---|---|
| Quality scout `S` | forbidden | count quality, rates, thread/noise/correctness transition only |
| Williams gateway `C` | every started operation | prospective `N/W/T` and order-stratified variance only |
| Direct ceiling `D` | forbidden | throughput/headroom/drift/utilization/correctness only |
| Authoritative gateway `A` | every started operation | final paired estimands and bootstrap |

For every fixed-duration `C/A` gateway arm:

- **Throughput:** validated operations completed by the common deadline divided by exact frozen `T_s`. A downstream-H1 upload is complete only after its fresh connection has produced the validated close response and transport EOF; response EOS alone is insufficient. Operations still in flight at the deadline are not throughput completions but must drain and remain visible in the exact started/drained/connection counts and latency/CPU data.
- **p99:** sort every operation started before the deadline, including bounded-drain completions, and select nearest rank `ceil(0.99 × m)` (one-based) from its integer latency nanoseconds. Downstream-H1 upload latency is connect-start through validated response/EOF; downstream-H2 upload latency starts at stream submission on its persistent connection. No interpolation; `m >= 5,000` is mandatory and the latency-file count must equal the drained completion count.
- **CPU/op:** read process-wide `/proc/<pid>/stat` `utime + stime` immediately before steady start and after bounded drain; `(delta_ticks / 100) / m`. This includes gateway accept, request, close, and EOF work for every measured H1-upload connection. Child CPU and `cutime/cstime` are excluded. A start-time mismatch is not a sample. The separate exact-deadline counter documents fixed-window CPU but is diagnostic.
- **Peak RSS:** final per-arm `VmHWM` KiB from `/proc/<pid>/status`. The maximum sampled `VmRSS` is diagnostic and must not replace `VmHWM`.
- **Bytes/s:** exact application request/response bytes of deadline-completed operations divided by `T_s`; report only.

`S` rates use §6.8.1. `D` throughput uses the same exact deadline count, operation completion boundary, workload-specific connection policy, and `T_s`; its CPU/resource, byte, endpoint/connection-hash, and lifecycle records remain raw headroom evidence, but p99 is undefined and no synthetic latency scalar may be asserted. Every authoritative comparison uses only `A` block log ratios `z_i = ln(treatment_i/reference_i)` for each metric. The point estimate is `exp(mean(z_i))`, a paired geometric-mean ratio. Throughput favors larger values; p99/CPU/RSS favor smaller values.

### 6.10 Deterministic confidence algorithm

For each comparison:

1. Split its `N` block log ratios by whether treatment ran before or after reference; the design requires exactly `N/2` in each stratum.
2. Point estimate is the equal-weight mean of the two stratum means (identical to the overall mean under balance).
3. Seed SplitMix64 from SHA-256 of `analysis-config-hash || comparison-id`. For each of exactly 100,000 replicates, sample `N/2` blocks with replacement inside each stratum using rejection-sampled bounded indices, then average the two stratum means.
4. Sort replicate log means ascending. The lower one-sided 95% percentile is element 4,999 and the upper is element 94,999 using zero-based indices—the nearest-rank inverse ECDF at 0.05 and 0.95.
5. Exponentiate only for presentation/gate ratios. Decisions compare unrounded f64 log values to `ln(threshold)` with inclusive `>=`/`<=`, no epsilon. Store decimal and `to_bits()` hexadecimal forms. Exact threshold equality passes.

Golden-vector tests pin seed derivation, RNG words, rejection behavior, strata, sorted indices, f64 bits, and threshold equality. Raw block ratios are also emitted as CSV for independent inspection.

The global result is an intersection-union decision: every hard gate must pass. No multiplicity correction is added because a false global `PASS` requires falsely passing at least one true component null, whose one-sided size is already bounded at 5%; correlation from the shared control does not invalidate that intersection rule. This does **not** make individual descriptive intervals simultaneous 95% intervals.

### 6.11 Machine placement, headroom, and noise gates

The fixed Ryzen topology uses whole sibling pairs and this exact logical-CPU order:

| Role | Logical CPUs / assignment order | Physical sibling pairs / cache |
|---|---|---|
| Measured gateway | `0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23` | `(0,16)..(7,23)`, CCD/L3 0 |
| Fixture | `8,9,10,24,25,26` | `(8,24),(9,25),(10,26)`, CCD/L3 1 |
| Load | `11,12,13,14,27,28,29,30` | `(11,27)..(14,30)`, CCD/L3 1 |
| Orchestrator + sampler | `15,31` | `(15,31)`, CCD/L3 1 |

The broad role affinity is applied before exec and is never treatment-specific. The persistent orchestrator inventory is frozen once before the first `Q_obs`; any later orchestrator birth/disappearance blocks the campaign. Fresh fixture, load, arm-sampler, and gateway roles begin with their complete broad role mask. From the first proof operation through materialization, the sampler enumerates `/proc/<pid>/task` at no more than 10 ms spacing. Each observed entry is identified by role, PID/TID start time, and `comm` and immediately receives a deterministic provisional singleton CPU inside its role order. A not-yet-observed child can inherit only its parent's subset of the same disjoint role mask, so it cannot execute on another role's CPUs. Pre-freeze births and retirements are expected lifecycle evidence, never grounds for a retry, and are retained with first/last observations and counters.

At the §6.6 `F` barrier, custom roles are quiescent and the gateway is stopped. The sampler takes forced boundary snapshots, enumerates the complete live inventory, and applies the final map. Named harness thread slots use the slot→CPU map sealed in `intent.json`; unnamed live TIDs are sorted by `(comm,start_time,tid)`, assigned a `comm`-local ordinal, and mapped round-robin in the fixed role order. The persisted identity map includes PID/TID/start time for runtime checking. Its semantic signature contains each role's executable hash and sorted `(comm,named-slot-or-comm-local-ordinal,final-role-CPU-slot)` entries and count, but excludes ephemeral PID/TID values and timestamps.

Signature establishment is prospective. Scouts record signatures but never select one. The first Williams occurrence for each treatment/cell is fixed in the already-sealed calibration plan; that one arm freezes the key's accepted signature, the remaining Williams arms must match it, and every authoritative gateway arm must match it exactly. The sole `D[0,s,p]` observation freezes each direct cell/protocol signature before authoritative work; every `D[e,s,p]` must match. The harness uses one lifecycle and assignment algorithm for all treatments, cannot request a thread count, and may not add dummy threads, keep auth workers alive, kill a thread to shape a count, or repeat an arm to obtain a preferred signature. Natural treatment topology can differ only by producing a different prospectively frozen key. A signature mismatch is `BLOCKED`, not an omitted sample.

From the forced freeze snapshot through measured drain, the sampler enumerates every role task at 100 ms cadence and reads per-TID `utime+stime`, process-wide `utime+stime`, singleton `Cpus_allowed_list`, and last-CPU state. Any new TID, frozen-TID disappearance, start-time change, process-wide runtime not bounded by the frozen per-TID sum, changed/non-singleton affinity, or runtime accrued after an observed last CPU outside the assignment is an unattributable/migrated-thread integrity failure and immediately `BLOCKED`. Direct arms apply the same checks to all present roles; the empty gateway role has zero benchmark runtime.

At every bucket boundary `k`, the sampler reads all observed per-TID counters `t⁻[i,k]`, then one per-CPU `/proc/stat` snapshot, then all per-TID counters again as `t⁺[i,k]`. For a frozen bucket `b=(k,k+1)` and the TIDs singleton-pinned to logical CPU `c`, the exact conservative bounds remain:

```text
role_runtime_lower(c,b) = sum_i max(0, t⁻[i,k+1] - t⁺[i,k])
role_runtime_upper(c,b) = sum_i max(0, t⁺[i,k+1] - t⁻[i,k])
attribution_uncertainty(c,b) = role_runtime_upper - role_runtime_lower
scheduled(c,b) = delta(user + nice + system) from the two /proc/stat snapshots
external_upper(c,b) = max(0, scheduled(c,b) - role_runtime_lower(c,b))
capacity(c,b) = delta(user + nice + system + idle + iowait + irq + softirq + steal)
```

The same before/after construction bounds process-wide runtime, which must overlap the sum of the frozen per-TID bounds. `attribution_uncertainty` greater than one tick on any logical CPU/bucket, an impossible counter order, a missing read, or process/TID bounds that do not overlap is `BLOCKED`. The gate therefore uses an upper bound on external scheduled time rather than hiding read skew.

Dynamic-attribution buckets use the same snapshots but give no subtraction credit for runtime before a TID's first singleton snapshot, after its last readable snapshot, or from a task that is born and retires between lifecycle polls. For each role, let `known_role_lower/upper(c,b)` include only fully bracketed singleton slices and define the explicit unattributed role-runtime interval:

```text
u_role_lower(b) = max(0,
    process_runtime_lower(role,b) - sum_c(known_role_upper(c,b)))
u_role_upper(b) = max(0,
    process_runtime_upper(role,b) - sum_c(known_role_lower(c,b)))
external_upper_dynamic(c,b) =
    max(0, scheduled(c,b) - known_role_lower(c,b))
```

No part of `[u_role_lower,u_role_upper]` is subtracted from any logical-CPU, sibling-pair, or role-set scheduled total: the corresponding aggregate always uses `scheduled - sum(known_role_lower)`, so unknown benchmark runtime remains conservatively charged as external on the CPU where `/proc/stat` observed it. Broad affinity confines it to that role set. The interval must be ordered and must make the process bounds overlap `known + u`; an impossible counter order, missing process/per-CPU snapshot, start-time mismatch, or escape from the broad role mask is `BLOCKED`. A task disappearing between pre-freeze enumeration and read is recorded through `u`, not retried. Forced snapshots split buckets at the authoritative freeze, so no bucket mixes dynamic and frozen formulas; after freeze `u=0` is mandatory because lifecycle changes are forbidden. This preserves complete process/TID reconciliation and can only turn uncertain pre-freeze runtime into external-time `BLOCKED`; it can never hide it as benchmark work.

`guest` fields are not added because Linux already includes them in `user/nice`. IRQ, softirq, steal, idle, and iowait remain separate raw fields and are never netted against either role runtime or external scheduled time; steal must be zero. IRQ/softirq remains reported as workload/platform cost rather than being mislabeled as a host task.

Ten 100 ms samples form each nominal one-second bucket; a final fractional tail is merged into the preceding bucket, so every tested bucket is at least one second. The dynamic sampler's additional 10 ms lifecycle polls do not replace these counter brackets. Using exact integer cross-products with no rounding credit, both dynamic- and frozen-attribution intervals must satisfy all six limits:

| Scope | Every one-second bucket | Whole applicable interval |
|---|---:|---:|
| Each logical CPU | `external_upper <= 2.00%` of capacity | `<=1.00%` |
| Each physical sibling pair | `<=1.00%` of pair capacity | `<=0.50%` |
| Each complete role CPU set | `<=0.50%` of role capacity | `<=0.25%` |

Thus one unrelated logical CPU busy for one second is 100% at the CPU, 50% at its sibling pair, and at least 6.25% of the gateway role bucket; it cannot hide in an aggregate. The same accounting and limits apply to gateway, fixture, load, and orchestrator/sampler sets in every scout, Williams-calibration, calibration-direct, authoritative-direct, and authoritative-gateway arm. The dynamic formula may conservatively block an otherwise quiet materialization, but the frozen steady interval is never relaxed.

The following limits are immutable in the applicable calibration plan/design lock. Every arm must complete exactly one successful `Q_obs=10.000s`; that fixed observation is never charged to wait reserve. All failed quiet-search time and non-overlapping thermal cooling before the final observation is `Q_extra`. One arm's `Q_extra` may not exceed 120 seconds, and campaign-wide `Q_extra` consumes only the finite §6.12 `Q_cap`. Once the final successful observation is accepted and `R` starts, any breach blocks the campaign and the arm is not replaced.

| Class | Exact acceptance |
|---|---|
| Fingerprint | Host/kernel/boot ID/CPU topology/online set, SMT, clocksource, toolchain hashes, `CLK_TCK=100`, ASLR, governor/EPP=`performance` on all CPUs, `amd-pstate=active`, boost=`1`, role orders/pairs, thread-assignment algorithm, nofile, and allowed runtime surfaces equal the design lock. |
| Fixed pre-arm quiet observation | Every arm has one distinct, final, continuous `Q_obs=10.000s`. PSI `total` deltas give CPU `some <=0.50%` of observation time and memory/I/O `full=0`; `pswpin/pswpout` and steal deltas are zero. All four CPU sets pass the whole-observation logical/pair/role external-time limits above, subtracting only the persistent frozen orchestrator TIDs; no gateway, fixture, load, or fresh arm sampler exists yet. A failed candidate interval is `Q_extra`, not a shorter or replacement `Q_obs`. |
| Thermal | Tctl exists; arm starts `<=75°C`; treatment/reference starts within 3°C; measured maximum `<85°C`. Non-overlapping cooling before the final `Q_obs` is `Q_extra`; failure to cool within the per-arm 120-second extra-wait cap or campaign `Q_cap` is `BLOCKED`. |
| Frequency | Calibration arm median gateway-CPU `scaling_cur_freq >=4.0 GHz`. The design lock stores the calibration 5th percentile of per-arm medians; every authoritative arm median must be at least 95% of that value, with unchanged policy/boost. |
| During-arm host noise | Dynamic attribution uses the adversarial `u_role` rule; frozen attribution uses the exact singleton rule. Both pass every logical/pair/role limit above; no steal, swap, gateway major fault, memory-full PSI, or I/O-full PSI occurs. IRQ/softirq remains separate. |
| Fixture/load utilization | Each process uses `<=70%` of the capacity of its frozen worker-CPU slots; every listed fixture/load CPU must have its predeclared worker slot. Sampler overhead remains below 50% of the `(15,31)` pair capacity. |
| Direct ceiling | Every gateway arm has the exact prospective mapping below. Each mapped direct arm is present, uncontaminated, uses the exact cell/protocol/connection policy, and has throughput `>=1.25 ×` that gateway arm's throughput. |
| Direct drift | Each authoritative direct result remains within ±10% of its exact `D[0,s,p]` calibration ceiling and still has 25% headroom. Direct observations never enter gateway ratios. |
| Operation/lifecycle quality | Every gateway/direct arm completes its exact `Q_obs`, workload-specific `M_s`, optional WebSocket `L_ws`, and `F` requirements; every fixed-duration arm uses exact frozen `5s <= T_s <= 30s`, has at least 5,000 deadline completions and 5,000 total drained operations, keeps both drains within their two-second caps, and has zero error/retry/drop with exact bytes/protocol/counts and tripwire zero. Every downstream-H1 upload additionally has exactly one planned connection/socket/connect/request/close/EOS/EOF per started operation, cumulative downstream connections equal to started operations in every phase and arm total, `max_active<=C`, zero active after drains, one request per connection, and zero keepalive/reuse/reconnect/hidden-retry counters. Every `C/A` gateway arm retains exactly one latency per drained measured operation, including H1 connect-through-EOF; every `S/D` arm retains no latency array and proves its decisions from exact count/timing/connection-hash/resource records. Every gateway arm additionally has start-through-drain gateway CPU delta `>=500` ticks; direct arms have no gateway-tick floor. |
| Order effect | Absolute difference between AB and BA log-ratio means `<=ln(1.03)` for throughput/p99/CPU and `<=ln(1.05)` for RSS. |
| Final precision | Point-to-one-sided-bound log width `<=ln(1.02)` throughput, `<=ln(1.03)` p99/CPU, and `<=ln(1.05)` RSS. |
| Resource and delivery budget | Before each phase, the formal uncompressed raw-execution bound covers only its currently reachable branch and the full bundle/reconstruction/recompression coexistence peak. Before authoritative sampling, the verified complete calibration bundle supplies the 2× matching-component tracked projection for the exact selected continuation. Actual tracked bytes are unconditionally `<=512 MiB` (`536,870,912` bytes) before analysis/PASS and before commit. The sealed runtime projection, including producer recompression, remains `<=42h`; actual post-build campaign elapsed remains `<=48h`. |

Direct mappings are identities, not a choice made after observing throughput. A direct protocol ID always includes cell `s`'s workload-specific policy: for upload, `D[e,s,H1]` is fresh-connect/one-POST/fixture-close/EOF per operation and `D[e,s,H2]` is one persistent connection with `C` streams; for GET/download/SSE, H1/H2 are persistent; for WebSocket, tunnels are pre-established. Every scout attempt and Williams-calibration arm in cell `s` maps to `D[0,s,H1]`, `D[0,s,H2]`, or both according to topology. Before authoritative epoch `e=1..N/10`, run one sealed 30-arm panel containing exactly `D[e,s,H1]` and `D[e,s,H2]` for every cell in its frozen order. Every gateway arm in that epoch maps in `design-lock.json` as follows:

```text
B11, C11 -> D[e,s,H1]
C21      -> D[e,s,H2] and D[e,s,H1]
C12      -> D[e,s,H1] and D[e,s,H2]
C22      -> D[e,s,H2]
```

A same-protocol direct run exercises both direct client and fixture engines and is tested once; a bridge must independently clear both mapped protocol ceilings. Thus the H1 upload ceilings mapped to `B11`, `C11`, and `C12` all pay the same one-connection-per-operation load/fixture policy, while H2 mappings retain multiplexing; no keepalive ceiling may substitute for H1 upload. A direct result is uncontaminated only if its correctness, workload-aware lifecycle/signature, exact connection/close/EOF counters, dynamic/frozen external-time, utilization, thermal/frequency, quiet/phase-cap, and artifact gates all pass. Missing, contaminated, wrong-cell/protocol, drifted, signature-mismatched, or under-headroom mapped direct data blocks the campaign; no neighboring epoch, alternate protocol, average, or later clean run may replace it.

The sampler also records 100 ms process RSS and 250 ms thermal/frequency data. All original lifecycle observations, pre-auth and post-settle inventories, accepted signatures, per-TID/process/per-CPU counters, bracketing bounds, `u_role`, signed residuals, IRQ fields, logical/pair/role aggregates, and direct IDs are retained for independent recomputation.

### 6.12 Runtime and cost bound

The accepted Williams arm-count arithmetic is unchanged. The mandatory topology smoke is one bounded non-arm phase and contributes neither an observation nor an arm:

| Frozen N | Authoritative arm-runs (`75N`) | Naive independent arm-runs (`105N`) | Saved |
|---:|---:|---:|---:|
| 30 | 2,250 | 3,150 | 900 |
| 50 | 3,750 | 5,250 | 1,500 |
| 70 | 5,250 | 7,350 | 2,100 |
| 100 | 7,500 | 10,500 | 3,000 |

The complete inventory is exact. It begins with exactly one topology-smoke phase. If cell `s` reaches accepted scout target level `k_s ∈ {1..7}`, actual scout attempts are `A_scout=5×sum_s(k_s)` (75–525 gateway arms); balanced calibration is `A_cal=15×10×5=750` gateway arms; calibration direct work on an otherwise admissible path is `A_direct0=15×2=30`; authoritative work is `A_auth=75N`; and authoritative direct work is `A_direct=30×(N/10)=3N`. Thus the notional `N=100` schedule contains at least 8,325 gateway arms and exactly 330 direct arms, and every additional scout level is visible rather than hidden in an estimate. Runtime rejection never changes these counts or authorizes a smaller schedule.

Start the campaign clock `t_campaign` with `CLOCK_BOOTTIME` immediately before the mandatory topology smoke, after builds and pre-smoke deterministic self-tests. It includes `E_smoke`, every scout attempt, calibration/direct/authoritative arm, successful observation, extra wait, cooling interval, design freeze, pause, raw artifact write, raw seal/verify, deterministic bundle/chunk creation, canonical reconstruction, exact pinned-encoder recompression and stream comparison, source-independent analysis/report work, delivery-report/ledger finalization, and final precommit seal. Git staging/commit/reviewer latency is a later delivery gate and cannot change a campaign metric or verdict, but every actual producer-side encoder/recompression invocation is inside this clock and `.perf` remains undeletable while delivery is pending. A boot-ID change is already `BLOCKED`. A normal design-freeze path has:

```text
A_pre = A_scout + A_cal + A_direct0
Q_obs_pre = A_pre × 10.000s
```

`Q_obs_pre` is fixed successful observation time. `Q_extra_pre` is only actual failed quiet-search and non-overlapping cooling time before those final observations. `E_smoke` is the exact one-time BOOTTIME interval for the sealed smoke and must reconcile to `T_smoke<=300.000s`. At design freeze, seal:

- `E_pre = t_freeze - t_campaign`, decomposed into `E_smoke`, every completed `Q_obs`, actual `Q_extra_pre`, every actual scout/Williams-calibration/calibration-direct arm, and every other elapsed gap;
- the smoke schedule/count/hash result and exact `E_smoke`; every scout `Q`, exact `3.000s` warmup and actual count-window `E_ns`; every exact `W_cal/T_cal` and `W_auth/T_auth`; actual settle/materialization/freeze durations; and constants `T_smoke=300.000s`, `Q_obs=10.000s`, `R=P=D_w=D_m=2.000s`, `K_tokio=10.000s`, `S_inv=2.000s`, `L_ws=15.000s`, `F=X=1.000s`;
- campaign-wide **additional** quiet/cooling allowance `Q_cap=7,200s`, which excludes every successful `Q_obs`, and post-freeze non-arm orchestration/raw-seal/source-verify/bundle creation/canonical reconstruction/pinned recompression/stream comparison/source-independent analysis/delivery-report/ledger/final-seal reserve `A_cap=1,800s`; the measured 2× recompression-time projection in §6.12.1 must fit inside the unspent `A_cap`, not add a hidden reserve;
- the five arm counts above, per-cell future counts, all accepted thread signatures, and each component's integer-nanosecond subtotal.

The completed component is itself recomputable, not an opaque stopwatch value:

```text
E_pre = E_smoke + Q_obs_pre + Q_extra_pre + E_other_pre
      + sum_over_actual_scout_attempts(E_arm_actual_without_quiet)
      + sum_over_750_calibration_arms(E_arm_actual_without_quiet)
      + sum_over_30_calibration_direct_arms(E_arm_actual_without_quiet)
```

Each `E_arm_actual_without_quiet` is the exact `CLOCK_BOOTTIME` spawn-to-finalization interval. Its monotonic stages reconcile to `R/P`, workload-specific `L_ws`, fixed `W` plus `D_w`, `F`, fixed `T` or scout count-window `E_ns`, `D_m`, and `X`; per-operation H1 connect/EOF work remains inside `W`, `T`/`E_ns`, or their drains rather than adding an unclassified stage. It contains neither `Q_obs` nor `Q_extra`. `E_other_pre` lists every remaining non-smoke, non-arm, non-quiet interval by BOOTTIME start/end timestamp and purpose; it cannot be negative, overlap another class, or remain unnamed. A campaign stopped before a design lock records its actual completed-observation/arm counts and partial interval rather than pretending that skipped calibration-direct arms ran.

`E_smoke>300.000s`, `Q_extra_pre > Q_cap`, any one arm's `Q_extra >120s`, or a missing/overlapping classification is `BLOCKED`. After freeze, every elapsed nanosecond must likewise be charged exactly once to a fixed successful observation, an arm's spawn-to-finalization interval, additional quiet/cooling, or `A_cap`; an unclassified gap is `BLOCKED`. For cell `s`, define:

```text
M_auth(s) = W_auth(s) + D_w
L(s) = 15.000s if s is WebSocket, else 0
B(s) = Q_obs + R + P + L(s) + M_auth(s) + F
     + T_auth(s) + D_m + X
```

`B(s)` includes exactly one successful ten-second observation and every successful-arm cap; it includes no optional cooling/search time. Fresh H1-upload connects and EOF waits occur inside `W_auth/T_auth` and the existing drains, so they add no hidden per-operation stage or reserve. There are exactly `5N` future authoritative gateway arms and `2×(N/10)` future direct arms for each cell. The sole exact admission projection, evaluated in integer nanoseconds without rounding down, is:

```text
P_total = E_pre
        + sum_over_15_cells((5N + 2×(N/10)) × B(s))
        + (Q_cap - Q_extra_pre)
        + A_cap
```

`E_pre` counts the completed smoke, completed work, and all completed `Q_obs` at actual elapsed time. The sum counts every future authoritative gateway/direct arm at exact frozen `W/T` and the fixed successful-stage caps, including one future `Q_obs` per arm. Only `(Q_cap-Q_extra_pre)` covers additional future quiet search/cooling. Completed-arm manifests must reconcile exactly to `A_scout+A_cal+A_direct0`, and the future schedule to `A_auth+A_direct`; a count, observation, signature, or subtotal mismatch is `BLOCKED`.

The runtime range is no longer implicit. With `3s<=W_auth<=10s` and `5s<=T_auth<=30s`, the cap remains `28s<=B_ordinary(s)<=60s`; adding `L_ws` gives `43s<=B_ws(s)<=75s`. H1 upload churn can lower calibrated rates and therefore raise frozen `W/T` within those existing bounds, but it does not change arm counts or cap formulas; failure to close/EOF within either drain is `BLOCKED`. Twelve cells are ordinary and three are WebSocket, so the future scheduled-arm term spans the following range over allowed frozen per-cell `W/T`:

| Selected N | Future arms (`78N`) | Minimum future cap term | Maximum future cap term |
|---:|---:|---:|---:|
| 30 | 2,340 | 72,540 s (20.150 h) | 147,420 s (40.950 h) |
| 50 | 3,900 | 120,900 s (33.583 h) | 245,700 s (68.250 h) |
| 70 | 5,460 | 169,260 s (47.017 h) | 343,980 s (95.550 h) |
| 100 | 7,800 | 241,800 s (67.167 h) | 491,400 s (136.500 h) |

There is also a rigorous pre-freeze floor on the normal first-level-scout path. Its 855 completed arms contribute 8,550 seconds of fixed `Q_obs`; minimum warmups contribute 2,565 seconds; accepted scout count windows plus minimum calibration/direct measurements contribute 4,050 seconds; and the 171 WebSocket arms require at least `K_tokio+S_inv=12s`, contributing 2,052 seconds. Therefore `E_pre>=17,217s` even before the positive mandatory `E_smoke`, setup, proof, drains, freezes, exits, artifact work, gaps, additional scout levels, or `Q_extra`. Including the full `Q_cap+A_cap=9,000s`, the corresponding lower admission totals are:

| Selected N | Lower-bound `P_total` on a normal design-freeze path |
|---:|---:|
| 30 | 98,757 s (27.433 h) |
| 50 | 147,117 s (40.866 h) |
| 70 | 195,477 s (54.299 h) |
| 100 | 268,017 s (74.449 h) |

Consequently `N=70` and `N=100` are prospectively inadmissible: their future-arm term alone already exceeds 151,200 seconds. Selection of either value seals `BLOCKED` immediately after parameter derivation and before calibration-direct/authoritative work; it does not silently select a smaller `N`. `N=50` is only mathematically possible near the phase minima—it leaves at most 4,083 seconds beyond the displayed mandatory floor, from which actual `E_smoke` also consumes time—and must still pass the exact equation after calibration-direct work. `N=30` also receives no presumption of admission; exact per-cell durations and actual pre-freeze elapsed can block it.

Admission requires `P_total <=151,200s` (42 hours) before the first authoritative direct panel. The verifier recomputes every component from raw manifests and rejects optimistic averages, omitted observations/attempts/arms, alternate `W/T`, use of `Q_cap` for fixed observations, negative remaining reserve, or unsealed input. Regardless of projection, `CLOCK_BOOTTIME-t_campaign` may never exceed `172,800s` (48 hours); crossing it at any phase stops and seals `BLOCKED`. The disk projection uses the same exact inventory and duration/count limits. Insufficient time, disk, reserve, or complete schedule is `BLOCKED`; no partial matrix can be called proof.

#### 6.12.1 Reachable-branch raw storage and tracked-delivery gates

Storage has three distinct fail-closed gates. They may not be collapsed into the former initial Cartesian/no-compression-credit delivery estimate:

1. **Raw execution gate:** before each phase, reserve a formal uncompressed bound for only the phase and branch currently reachable, plus source sealing, bundle staging, canonical reconstruction, decompression, and recompression scratch. This gate takes no compression credit and protects complete writes below `.perf`; it is not the 512 MiB tracked-delivery test.
2. **Post-calibration tracked projection:** only after the complete reached calibration has been raw-verified, bundled, re-encoded, and independently verified, use its measured pinned-codec component sizes to project the one exact selected continuation with at least 2× safety. Unreachable Cartesian combinations are forbidden.
3. **Actual tracked gate:** exact ordinary-file lengths below the artifact root must be `<=536,870,912` before authoritative p99/bootstrap analysis can start, before any `PASS`/performance `FAIL` can be asserted, and again immediately before commit. This actual gate is unconditional and cannot use a compression estimate.

##### Evidence classes and mandatory members

The class is sealed in `intent.json` before any arm and determines the schema, not an observed rate or treatment result:

| Class | Exact arm count on a reached branch | Per-operation latency member | Mandatory operation evidence |
|---|---:|---|---|
| `S` quality scout | `5×sum_s(k_s)`, `1<=k_s<=7`; at most 525 | forbidden | lane quotas/counts, `t_0/t_1`, exact CPU/resource boundaries, bytes, endpoint operation/connection/count/hash reconciliation, correctness/topology, thread/noise/lifecycle |
| `C` Williams gateway | exactly 750 | required: every started operation | all common raw members plus `latencies.u64le` |
| `D` direct ceiling | 30 calibration arms plus exactly `3N` future arms when reachable | forbidden | start/deadline/drain counts and times, bytes, endpoint/connection hashes, workload-specific connection policy, utilization, resource/thread/noise/lifecycle and exact headroom/drift mapping |
| `A` authoritative gateway | exactly `75N` when reachable | required: every started operation | all common raw members plus `latencies.u64le` |

A forbidden latency member is a schema failure, not optional evidence. Conversely, a missing, extra, or count-mismatched `C/A` latency is `BLOCKED`. `S/D` never enter p99, calibration variance, authoritative pairs, or bootstrap, so their exact count-window summaries are the raw evidence needed for every decision they are allowed to make. Once the smoke phase starts, its one mandatory `topology-smoke.json` is a unit-level pre-arm member, not a fifth evidence class; a terminal pre-smoke raw-gate failure records that earlier blocker without inventing the file. The smoke member is capped at 1 MiB, contains the exact §6.8.0 case/counter/hash matrix and terminal state, and has no latency or statistical input.

##### Byte-exact uncompressed schema bound

All quantities are integer octets; `KiB=1,024`, `MiB=1,048,576`. For arm `a`, let:

```text
M(a)     = successful scout count-window elapsed (<=15s), or frozen T_s (<=30s)
d(a)     = R + P + L_ws(a) + W(a) + D_w + F + M(a) + D_m + X
H10(a)   = 2 + ceil(d(a) / 10ms)
H100(a)  = 2 + ceil(d(a) / 100ms)
TID(a)   = sealed maximum distinct raw TID slots for that phase/key
EV(a)    = sealed maximum TID birth/death/pin events
CONN_LIVE(a) = sealed maximum simultaneously represented connection slots/records
               (including the upstream-H1 live bound of 136 and at most C
               downstream-H1 upload lane slots; not a cumulative-open count)
LAT(a)   = sealed maximum started-operation records; zero for S/D
C(a)     = cell concurrency in {1,16,64}
```

The two extra samples cover both boundaries. The fixed binary layouts and JSON byte ceilings below are normative; each binary header includes magic, schema, class, record width/count, and CRC/hash fields within the displayed bytes. The record definitions retain the original monotonic/BOOTTIME timestamps and `/proc` integer fields—not only derived rates.

| Schema component | Applies | Maximum uncompressed bytes |
|---|---|---:|
| `metadata.json` | all | `65,536` |
| `quiet.json` | all | `131,072` |
| `thread-map.json` | all | `131,072` |
| `thread-lifecycle.bin` | all | `128 + 64×H10(a) + 96×EV(a)` |
| `session-clock.bin` | gateway; direct has a fixed N/A record | `128 + 128×H10(a)` |
| `resources.bin` | all | `128 + 160×H100(a)×(32 + TID(a) + 4)` |
| `endpoints.bin` | all | `512 + 160×CONN_LIVE(a) + 512×C(a)` |
| `operation-summary.bin` | all | `256 + 96×C(a)` |
| `latencies.u64le` | `C/A` only | `32 + 8×LAT(a)` |
| `latencies.u64le` | `S/D` | `0` bytes and path forbidden |
| each unit-level intent/plan/signature/projection/machine/schedule/seal file | as listed by the phase schema | `1,048,576` per file; exact file count is sealed before the phase |

The 160-byte resource record contains both bracketing reads needed for the per-CPU or per-TID interval; the four non-TID slots are the process and fixed role/boundary records. The lifecycle stream stores every <=10 ms observation timestamp, inventory hash/count, and every full identity/pin event. The session stream stores every BOOTTIME/REALTIME/BOOTTIME triplet, predicate bits, discontinuity data, and protocol-metadata hash/count. Endpoint and operation summaries store both sides' exact counts/bytes, lane totals, first/last IDs, rolling operation/corpus hashes, live connection/stream identities, EOS, tripwire, and correctness bits.

For downstream-H1 upload, the expanded fixed 512-byte endpoint header and `512×C` lane records store every §6.4 total, first/last deterministic operation/connection sequence, rolling binding hash, max-active value, and keepalive/reuse/retry violation count separately for proof, warmup, measured, and drain phases. `CONN_LIVE` bounds only simultaneously represented socket slots; cumulative opens are checked `u64` counters, not one variable-size record per connection. Because the connection ID is a deterministic function of phase/lane/operation sequence, the verifier recomputes the expected sequence/hash and exact equality `cumulative_connections=started_operations`; reuse or an extra connect changes a counter/hash and cannot be compressed away. This amendment therefore increases the fixed `endpoints.bin` row as shown but adds no variable per-operation connection member. The exact smoke file adds one unit-level 1 MiB maximum through `F_phi`, and both the formal raw bound and measured post-calibration component projection include these larger endpoint records and actual counter values. If the implementation cannot encode these fields within the frozen widths, it is `BLOCKED` pending a new reviewed schema—not permission to omit evidence. Thus removing scout/direct latency arrays removes no input to their permitted count/rate/thread/noise/correctness/headroom decisions.

For class `X`, `U_X(a)` is the sum of the applicable row bounds. Canonical-archive growth for member payload lengths `x_i` is byte-exact:

```text
USTAR(x_1..x_m) = 1,024 + sum_i(512 + 512×ceil(x_i/512))
```

Before Williams calibration, the latency writer cap for treatment/cell key `k` is frozen without looking at a ratio:

```text
LAT_C(k) = C(k) + ceil(4 × r_scout_max(k) × (T_cal(k) + D_m))
```

where `r_scout_max(k)` is that key's accepted exact `Q/E_s` rate. After Williams calibration, the continuation cap is:

```text
LAT_A(k) = C(k) + ceil(2 × max_over_10_C_arms(started/T_cal(k))
                             × (T_auth(k) + D_m))
```

These are storage-writer ceilings, never operation quotas. Before issuing an operation that would exceed a ceiling, the arm stops `BLOCKED` and seals every already-started operation; it cannot stop as a valid short sample, omit a latency, retry, or select another arm. `TID/EV/CONN_LIVE` have the same presealed overflow semantics. H1-upload cumulative/open/attempt counters use checked `u64`; counter overflow, a live slot above `C`, or any equality/hash mismatch is `BLOCKED`. The complete raw schema remains finite while any underprediction is fail-closed.

##### Reachable raw phase formulas

Let `G_phi` be the sealed remaining build/cache/database growth for phase `phi`, and `F_phi` the exact number times the 1 MiB unit-level maxima plus terminal partial-seal reserve. Actual completed bytes are measured and not reserved twice. The additional raw bound is:

```text
R_future(phi, branch) = G_phi + F_phi + sum_of_not-yet-started_reachable_arms U_X(a)
```

The arm sum is exactly:

| Gate point | Not-yet-started reachable arm term; no other branch may be added |
|---|---|
| before mandatory topology smoke | one bounded `topology-smoke.json` plus the reached calibration's intent/terminal maxima; no arm or latency bytes |
| after passing smoke, before first scout | `sum_s sum_{level=1..7} sum_{5 treatments} U_S(s,level,treatment)`; at most 525 `S`, no latency bytes |
| after accepted scouts, before Williams | `sum_s sum_{10 rows} sum_{5 treatments} U_C(s,row,treatment)`; exactly 750 `C` using `LAT_C` |
| after selected runtime-admissible `N=30/50`, before calibration direct | `sum_s sum_{p in {H1,H2}} U_D(0,s,p)`; exactly 30 `D` |
| after verified complete calibration bundle and design lock | `sum_s(5N×U_A(s) + (N/5)×U_D(s))`; exactly `75N A + 3N D` for the selected `N` |
| any terminal scout/calibration branch | only the reached partial/full unit's terminal files, bundle staging, and verification scratch; future `C/D/A` terms are zero unless the state machine can still enter them |

`ZB(n)` is the exact formal compression bound returned by the pinned codec for an `n`-byte canonical stream, and `W_enc` is its sealed maximum encoder/decoder workspace. The canonical bound is itself exact over the reached branch:

```text
U_arc(phi,branch) = USTAR(actual completed member lengths,
                                every not-yet-written member's row maximum,
                                terminal seal maximum)
```

Let `U_src` be the checked sum of the same member payload maxima, excluding ustar headers/padding. Verification extracts that closure once. Canonical reconstruction is required to stream directly through a fixed `B_can=1 MiB` buffer into the encoder, and encoder output is stream-compared against chunk input; creating a canonical or recompressed full-size spool is forbidden. The byte-exact recompression scratch bound is therefore:

```text
V_verify(U_src) = U_src                    # exclusive extracted closure
                + W_enc
                + B_can                    # canonical writer/encoder buffer
                + 2×CHUNK_BYTES            # delivered/re-encoded compare buffers
```

This is not optimistic credit: schema tests prove those are the only scratch writers and fail before either fixed buffer grows. The separate `ZB(U_arc)` term below reserves the staged delivered bundle while the original raw source still exists. Before each phase:

```text
free_bytes > 2 × (R_future + ZB(U_arc) + V_verify(U_src)) + 20 GiB
```

`free_bytes` is measured after existing `.perf` and tracked artifacts consume space. This is the formal raw-execution/coexistence bound requested before the mandatory smoke and every later transition. A high-scout branch that exhausts quality, disk, or the 42-hour reachability screen seals and bundles only what it reached; it does not reserve an impossible `N=50` campaign. Conversely, once a phase is reachable, all of that phase's arms and terminal seal are reserved—operators cannot choose a favorable sub-branch.

Codec time is likewise explicit. Calibration records exact encode, decode, canonical-reconstruction, and re-encode BOOTTIME nanoseconds and input/output bytes, plus an empty-input invocation for fixed overhead. With `K` future codec/reconstruction invocations, `tau0=max empty_invocation_ns` and `rho=max ceil(max(0, elapsed_ns-tau0)/input_bytes)` over matching nonempty calibration operations, the upward-rounded bound is:

```text
T_codec_future = 2 × (K×tau0 + rho×sum_future_input_bytes)
```

It must fit inside the remaining `A_cap=1,800s` and therefore inside `P_total`; it is not hidden in an unclassified gap. The post-push independent check is outside the benchmark clock but uses the same sealed per-bundle timeout and scratch equation; timeout is delivery `BLOCKED` and cannot authorize cleanup.

##### Measured post-calibration tracked projection

A continuing branch may project tracked bytes only after its complete calibration unit exists. For `N=30/50`, that unit contains the sealed topology smoke, all reached scouts, all 750 Williams arms, and all 30 calibration-direct arms. A terminal branch contains every member reached before its blocker. Bundle creation first writes below `.perf/.../delivery-staging/`; `verify-bundle` must pass there before an all-or-nothing install under the artifact root.

The verified calibration bundle directory contains canonical `compression-profile.json`, whose hash is bound by the bundle index and verification receipt and whose length must remain `<=1,048,576` bytes. In addition to the exact complete calibration compressed length, it records exact compressed totals by schema component and, for every future matching key/component, the maximum per-arm value, maximum upward-rounded per-record value, record counts, and witness arm/member hash. Each value comes from a projection-only canonical one-member mini-archive—including that member's normalized ustar header, payload padding, and two end blocks—encoded by the same sealed encoder/parameter program with that mini-archive's canonical length as the sole substitution. Per-arm measurements may be streamed during construction; only aggregate/maxima plus witnesses enter the bounded profile. `verify-bundle` independently recreates every mini-archive, aggregate, maximum, and witness. This profile does not define delivered payload bytes; it supplies auditable empirical units for the prospective equation.

Matching is exact and prospective:

```text
gateway match key = (treatment, workload, concurrency,
                     downstream/upstream connection policy, component schema)
direct match key  = (protocol, workload, concurrency,
                     workload-specific connection policy, component schema)
c_arm(k,j)         = max matching component_compressed_bytes
q_rec(k,j)         = max matching ceil(component_compressed_bytes /
                                       max(1, component_record_count))
S_comp             = 2
p(k,j,n_future)    = S_comp × max(c_arm(k,j),
                                  q_rec(k,j) × max(1,n_future))
```

For an arm-fixed member, `record_count=1`; for latency, resource, lifecycle, clock, live-connection-slot, and lane streams it is the exact fixed-record count. H1-upload cumulative connection totals remain fields in the fixed header/lane records rather than multiplying record count. Taking the maximum of the matching per-arm compressed bytes and the matching bytes-per-record product preserves fixed member/frame/archive overhead even when a future record count is smaller. A future record maximum comes from `LAT_A`, `H10`, `H100`, accepted signatures, topology/connection policy, and the frozen schedule above. No cross-workload, cross-concurrency, cross-protocol, or cross-treatment substitute is allowed; a missing matching component is `BLOCKED`.

The prospective tracked table is byte-exact once calibration is sealed:

| Tracked component | Prospective bytes |
|---|---:|
| prior additive artifact tree, excluding the current calibration | exact `B_prior` from regular-file lengths |
| complete calibration chunks/index/receipt/profile | exact installed `B_cal` |
| future `A` arm components | `sum_A sum_j p(match(A),j,records_max(A,j))` |
| future `D` arm components | `sum_D sum_j p(match(D),j,records_max(D,j))` |
| campaign-only raw manifests, raw seal, analysis-input map, and canonical structural residual | formal `ZB(USTAR(component byte ceilings))` |
| one future bundle index, verification receipt, machine-readable analysis result, delivery report, and ledger growth | `5×1,048,576 = 5,242,880` |
| chunk splitting | `0` additional payload bytes; chunks partition the compressed stream without padding |

All products and sums use checked unsigned integers and round upward. Define the empirical two rows as `P_A` and `P_D`, and the formal final two nonzero rows as `O_fixed`. Admission is:

```text
B_projected = B_prior + B_cal + P_A + P_D + O_fixed
B_projected <= D_task_cap
D_task_cap = 512 MiB = 536,870,912 bytes
```

The selected schedule alone determines the sums: `N=30` never reserves `N=50`; selected `N=70/100` is already terminal under §6.12 and reserves no authoritative data; an exhausted high-scout branch reserves no unreachable Williams/direct/authoritative data. Previously delivered failed/blocked/superseded evidence remains in exact `B_prior` and is never replaced.

This projection is deliberately conservative but is not treated as a proof of future compressibility. It admits execution; it never limits a writer. If a future component or final compressed stream exceeds it, every raw record is still written under the raw bound, the unit is sealed, and staging/verification continues if local disk permits. The result then becomes delivery `BLOCKED`. The harness may not omit a member, stop a valid arm early, discard a latency, recompress at another level, lower `N`, or assert `PASS`. Therefore underprediction can cause only a later honest `BLOCKED`, never sample omission or a false performance conclusion.

##### Unconditional actual cap points

`B_actual` is the checked sum of `st_size` for every regular file below `.legion/tasks/prove-http2-performance-regression/artifacts/`; links and non-regular files are forbidden. It is recomputed from a fresh walk, not trusted from the ledger:

1. before any calibration or authoritative analyzer invocation, using the exact artifact tree that exists at that point; this current-total check supplies no credit for future bytes;
2. after all-or-nothing calibration-bundle installation and before `design-lock.json`/authoritative work;
3. after the raw authoritative/terminal campaign bundle and receipt are staged, verified, and installed, **before authoritative p99/bootstrap analysis starts**, while also requiring `B_actual +` the formal remaining result/report/ledger maxima `<=D_task_cap`;
4. after source-independent analysis/result/report generation and ledger finalization, before any statistical `PASS` or performance `FAIL` is published; and
5. immediately before staging/commit, using the final actual bytes with no remaining estimate.

The campaign `seal.json` closes raw observations and frozen inputs before authoritative analysis; derived `analysis.json` and reviewer reports are separately hash-linked tracked products and are ignored as verifier inputs. If installation would cross the cap, staging remains below `.perf`, the artifact tree is not partially updated, `.perf` and the worktree remain intact, and delivery is `BLOCKED`. Exact equality passes; one byte over fails. No later Git compression, delta, or hosting behavior supplies credit.

### 6.13 Immutable execution and durable-delivery schemas


Use execution schema `amg-http2-perf/v1` and delivery schemas `amg-http2-perf-bundle/v1` and `amg-http2-perf-delivery/v1`. Expected repository-local execution layout:

```text
.perf/prove-http2-performance-regression/
  builds/<commit>/<binary-sha256>/...
  delivery-staging/<evidence-id>/...
  bundle-verify/<bundle-index-sha256>/...
  calibrations/<calibration-id>/
    intent.json
    topology-smoke.json
    delivery-projection.json
    calibration-plan.json
    signatures/<cell>/<treatment>.json
    authoritative-parameters.json
    scouts/<cell>/<target>/<arm>/        # class S; operation-summary.bin; no latencies
    direct/0/<cell>/<protocol>/          # class D; operation-summary.bin; no latencies
    arms/<row>/<cell>/<arm>/             # class C; operation-summary.bin + latencies.u64le
    seal.json
  runs/<run-id>/
    intent.json
    design-lock.json
    projection.json
    delivery-projection.json
    machine.json
    schedule.json
    direct/<epoch>/<cell>/<protocol>/    # class D; operation-summary.bin; no latencies
    arms/<round>/<cell>/<arm>/           # class A; operation-summary.bin + latencies.u64le
    seal.json                            # closes raw observations before analysis
  conclusions/<conclusion-id>/
    analysis.json
    report.md
```

Every arm leaf also contains its applicable `metadata.json`, `quiet.json`, `thread-lifecycle.bin`, `thread-map.json`, `session-clock.bin`, `resources.bin`, and `endpoints.bin` members from §6.12.1. Comments above describe schema membership and are not literal path text.

The tracked delivery layout is separate and survives worktree cleanup:

```text
.legion/tasks/prove-http2-performance-regression/artifacts/
  delivery-index.json
  bundles/
    calibration/<calibration-id>/
      bundle-index.json
      verification.json
      compression-profile.json
      chunks/000000.tar.zst.part ...
    campaign/<run-id>/
      bundle-index.json
      verification.json
      chunks/000000.tar.zst.part ...
  results/<conclusion-id>.json
  reports/<conclusion-id>.md
```

All artifact paths are ordinary tracked Git blobs. Bundle directories and IDs are exclusive-created. `delivery-index.json` is a canonically sorted additive ledger: updates may append new identities and refresh aggregate byte totals, but may never remove an already delivered calibration/campaign, redirect an identity to different content, or treat a newer candidate as replacement evidence.

A calibration/campaign `seal.json` closes only raw observations and frozen inputs. Source-independent `conclusions/<conclusion-id>/analysis.json` and its report are generated after the raw campaign bundle passes the pre-analysis actual-cap gate, then copied byte-identically to tracked `artifacts/results/<conclusion-id>.json` and `artifacts/reports/<conclusion-id>.md`. The result links the verified raw bundle and receipt; the report links that result root, indexes, and receipts without being embedded back into the payload, avoiding a hash cycle. All derived products are ignored as independent-verification inputs.

`intent.json` is exclusive-created before work and records baseline/candidate objects, the authoritative harness source tree/lock/file hashes plus its pre-campaign provenance commit, campaign seed, external-input/runtime-surface boundaries—including clock IDs, exact gateway archive/pinned-dependency provenance and production-semantic boundary, exact harness UTC-metadata sites/fields, and every prohibited real-time dataflow—the exact topology-smoke schedule/cap, every workload/treatment/direct persistent-or-fresh connection policy and counter equation, all potential scout attempts, the prospective `S/C/D/A` class/path map and mandatory members, the treatment-blind signature rule, direct-ID rules, raw record ceilings, and the hash-pinned encoder/parameter program. `topology-smoke.json` is exclusive-created by the single pre-scout schedule and binds its case matrix, exact archived binaries, full operation/connection counters/hashes, elapsed time, and outcome. `calibration-plan.json` freezes that smoke hash, accepted scout transitions, equal calibration `W/T`, lifecycle/connection constants, and the sole first-Williams establishment arm for every treatment/cell. Each `signatures/<cell>/<treatment>.json` is exclusive-created by that arm and cannot be replaced. `authoritative-parameters.json` freezes their hashes, derived `N/W_auth/T_auth`, the exact runtime lower-bound screen, and whether calibration-direct work is authorized. `projection.json` separately stores `E_smoke`, `Q_obs_pre`, `Q_extra_pre`, every future `Q_obs`, `M/L/F` terms, reserves, counts, ranges, and integer-nanosecond subtotals; `design-lock.json` records all three hashes plus the smoke/connection-policy roots and accepted direct signatures.
`delivery-projection.json` stores the phase/branch, topology-smoke unit maximum/actual bytes, class-specific `U_S/U_C/U_D/U_A` inputs, `R_future`, `USTAR/ZB/V_verify` streaming inputs, exact component record widths/counts, `LAT/TID/EV/CONN_LIVE` ceilings, codec workspace/time, prior actual entries, and terminal reserve. Before calibration it contains no tracked-bundle compression estimate. The post-calibration revision additionally stores exact `B_prior/B_cal`, every verified `c_arm/q_rec/p` term, 2× products, formal `O_fixed`, selected reachable schedule, `B_projected`, and all actual-cap checkpoints. Each revision names its predecessor and is sealed before the next phase; the admitted final hash enters `design-lock.json` and the raw source seal.

Every arm/direct directory has the exact class membership in §6.12.1. `quiet.json` records candidate intervals, the exact final successful ten seconds, non-overlapping `Q_extra`, clock ID, and host counters. `thread-lifecycle.bin` records broad masks, every <=10 ms observation/hash, births/deaths, provisional pin timestamps, WebSocket pre-auth inventory, `t_auth_done`, keepalive/stability evidence, dynamic `u_role`, and freeze boundary. `thread-map.json` is exclusive-created only at the post-materialization `F` barrier and stores the full ephemeral map plus semantic signature and accepted-signature key/match. For gateway arms, `session-clock.bin` records the sealed ready-session UTC fields and expected predicates, every BOOTTIME-bracketed real-time artifact sample, observed time-derived protocol metadata including HTTP `Date`, the clock-boundary manifest hash, every detected discontinuity, and the clean/disrupted plus session/protocol-comparability classification; direct arms carry the fixed N/A record. `operation-summary.bin` and `endpoints.bin` retain exact monotonic boundaries, lane/start/deadline/drain counts, operation/byte totals, IDs and rolling hashes at both ends. Their expanded fixed endpoint records also retain phase-separated planned/open/connect/request/response/close/EOS/EOF totals, connection-binding hashes, active maxima, requests-per-connection, and keepalive/reuse/reconnect/retry violations for downstream-H1 upload, or the persistent connection/stream counters for H2 and other paths. `resources.bin` retains original per-TID/process/per-CPU ticks, dynamic/frozen bracketing bounds, `u_role`, signed residuals, IRQ fields, KiB, and counters; derived floats are never the only evidence. Only `C/A` contain `latencies.u64le`, whose fixed header is followed by every integer nanosecond latency in deterministic lane/sequence order; `S/D` reject that path and retain no per-operation latency array.

The seal inventory is the complete raw deliverable evidence closure. Bundle creation has no include/exclude flags: it packages `seal.json` itself and every seal-listed byte exactly once, including `topology-smoke.json` for a reached calibration (campaigns bind its hash through the design lock), intent/design/projection inputs, all class-mandatory arm/direct raw files, and terminal state. It rejects a latency path in `S/D`, requires and count-checks it in `C/A`, and rejects any absent/extra class member. Unknown file types, symlinks, hard links, devices, sockets, non-UTF-8 or unsafe paths, and path aliases are rejected. Build targets, mutable caches, runtime databases, payload buffers, derived analysis/report files, and credential files remain outside the raw seal; required provenance or result links are represented by sealed hashes/manifests and the delivery ledger.

Evidence schemas use allowlisted fields and secret-free binary formats. The bundle command reruns the schema-aware secret/path scanner before reading any source member. Cookies, tokens, signing material, session secrets, raw environment values, or production endpoints cause `BLOCKED`; redacting the sealed source or omitting the affected member is forbidden. Synthetic payloads are represented by seed/hash test vectors, not copied bodies.

Run IDs are exact and collision-resistant: `<UTC-YYYYMMDDTHHMMSSZ>-<candidate12>-<design-lock-sha12>-<seed16hex>`. Calibration IDs use the same form with prefix `cal-`. The orchestrator/sampler's read-only `CLOCK_REALTIME` reads supply only UTC artifact metadata: this path label, optional UTC start/end labels, and the §6.3 real-time continuity record. They never supply a latency, duration, throughput/count window, CPU window, benchmark deadline, ordering, schedule, seed/statistical input, or campaign/resource elapsed value. Full hashes and commits remain in `intent.json`; the abbreviated ID is only a path key. Exclusive creation rejects wall-clock/seed collisions, so a real-time step cannot overwrite evidence.

Files are write-once: temporary names are fsynced and atomically renamed to a path that must not exist. No command overwrites an existing run ID. `seal.json` lists sorted relative paths, byte lengths, and SHA-256 hashes plus a root hash; after sealing, the source directory is read-only and analyzer/report commands write only the separate conclusion directory. Partial, failed, and blocked directories are sealed too.
The original seal root is deterministic and independent of archive metadata: `SHA-256("amg-http2-perf/seal/v1\0" || each sorted entry's u32be(path-byte-length) || path UTF-8 bytes || u64be(file-length) || 32 raw SHA-256 bytes)`. `seal.json` is not an entry in its own root. The bundle's `uncompressed_seal_root_sha256` names this value, while the separate canonical-archive hash additionally covers `seal.json`, normalized headers, padding, and order.

Sealing an evidence unit creates an unconditional delivery obligation. Every sealed calibration is bundled, including one stopped before a design lock. Every authoritative or terminal `PASS`/`FAIL`/`BLOCKED` campaign used in a conclusion is bundled. Any failed, blocked, superseded, or diagnostic evidence cited in a report or used to select remediation is also mandatory. The task ledger retains all such identities and seal roots; a later clean candidate cannot shadow, delete, or relabel an earlier failure.

The `verify` subcommand ignores derived `analysis.json`, validates external inputs and the clock-boundary manifest, exact archived gateway/pinned-dependency provenance, exact harness UTC-metadata sites and destinations, every real-time continuity record and ready-session/protocol-comparability classification, the one-shot topology smoke and `E_smoke`, scout transitions/fresh-process identities, every successful `Q_obs` versus extra wait, lifecycle/settle/freeze caps, accepted signature establishment/matches, calibration and authoritative `W/T`, every dynamic/frozen PID/TID map and attribution bucket, exact workload connection policy/direct mapping, all H1-upload equality/close/EOF/no-reuse/no-retry counters and hashes, H2 persistence/stream counters, class/member inventories, projection arithmetic/ranges/reserves, hashes/counts/schedules, and raw endpoint data. It permits read-only `CLOCK_REALTIME` inside the untouched archived gateways for existing production protocol/application semantics—including session validation, Hyper HTTP `Date`, and tracing without treating that list as exhaustive—and in harness code only for sealed UTC artifact metadata. It proves that no harness real-time value supplied any latency, duration, throughput/count window, CPU window, deadline, ordering, schedule, seed/statistical input, or campaign/resource elapsed value. Calibration mode independently recomputes its allowed design inputs. Campaign pre-analysis mode emits only a canonical `analysis-input-root` and non-statistical integrity/quality blockers; authoritative p99/bootstrap/f64/verdict computation is forbidden until the §6.12.1 pre-analysis actual-cap gate passes, after which analysis mode recomputes it from verified bundle bytes. It exits nonzero on any discrepancy. Reviewer reports link every claim to comparison/direct/projection IDs and raw hashes.

#### 6.13.1 Canonical archive, compression, and chunks

The bundle payload is `amg-http2-perf-canonical-ustar/v1`: a canonical POSIX ustar stream written and parsed by the benchmark package, not a host archive command. Evidence-relative paths are valid UTF-8, use `/`, contain no empty, `.` or `..` component, and must fit the versioned ustar name/prefix limits without extension records.
Paths of at most 100 bytes use an empty prefix and the complete path in `name`; longer paths use the rightmost `/` for which prefix is `1..155` bytes and suffix is `1..100` bytes, excluding the slash. No valid split is `BLOCKED`.

For each archive entry:

- Entries are sorted by the unsigned UTF-8 path bytes and are unique after normalization. `seal.json` is included at its sorted position even though it cannot hash itself.
- Only regular files are encoded; directory entries, links, sparse files, PAX/GNU extensions, ACLs, xattrs, and platform-specific metadata are forbidden.
- Header metadata is normalized to mode `0444`, uid/gid `0`, empty owner/group names, mtime `0`, device numbers `0`, and typeflag `0`; only path and exact file length vary. Header checksum encoding and numeric fields are pinned by golden bytes.
- File bytes are copied unchanged and padded with zeroes to a 512-byte boundary. Exactly two zero blocks terminate the stream; no leading/trailing bytes are allowed.
- The canonical uncompressed stream length and SHA-256 are recorded independently of the original seal root.

The complete canonical stream is compressed as exactly one Zstandard frame by the lockfile-pinned vendored codec. `intent.json` freezes a complete parameter derivation: format `zstd1`, no dictionary, `compressionLevel=9`, `nbWorkers=0`, `pledgedSrcSize=CANONICAL_ARCHIVE_LENGTH`, `contentSizeFlag=1`, `checksumFlag=1`, `dictIDFlag=0`, long-distance matching disabled, every requested compression/frame/worker/job/overlap/LDM/source-hint/target-block value, and the exact hash-pinned resolver that expands level plus canonical length into concrete window/hash/chain/search/min-match/target/strategy and all other parameters exposed by the pinned ABI. After raw sealing, `V_bundle=Resolve(intent_parameter_program, reconstructed_canonical_length)` is the full vector: it enumerates every parameter ID and concrete value in ascending ID order and is frozen by the intent hash plus canonical archive hash before encoding. Every settable effective value is applied explicitly; zero is allowed only as a recorded semantic value, never as an unrecorded default shortcut. Canonical length is the sole input substitution, not operator discretion. An unknown, omitted, duplicated, unsupported, implicitly inherited, or differently resolved parameter is `BLOCKED`.

The authoritative encoder identity is the tuple sealed in extracted `intent.json`: benchmark package/source tree hash, nested lockfile hash, Rust package checksums, vendored libzstd source hash and runtime version, build/toolchain identity, producer executed-binary hash as provenance, parameter-program/resolver hash, and golden-vector root. The bundle-specific full-vector hash is derived from that identity and the reconstructed canonical length, never from index claims. Independent invocation must match the hash-pinned source/lock/package/vendored-version/build identity and golden vectors; it records its own binary hash, which need not equal a path-dependent producer binary hash. `design-lock.json` may copy only the intent hash. The bundle index repeats human-readable values for diagnostics, but those claims are never the source of expected identity. A codec source, binary, version, resolver, or parameter change is a new design and cannot re-encode an existing evidence identity.

The compressed byte stream is split without padding at `CHUNK_BYTES = 48 MiB = 50,331,648` bytes. Every chunk except the last is exactly `CHUNK_BYTES`; the last is `1..CHUNK_BYTES`, and an exact multiple emits no empty chunk. Names are contiguous zero-based six-digit ordinals (`chunks/000000.tar.zst.part`, ...). No tracked chunk may exceed 48 MiB, and each non-chunk schema file is capped at 1 MiB, keeping every ordinary Git blob below 64 MiB without relying on Git LFS or an external store.
The 48 MiB content limit is fixed for this schema specifically so no delivered file approaches GitHub's per-file rejection limit; changing hosting limits later does not permit larger chunks for an existing bundle identity.

#### 6.13.2 Bundle and delivery indexes

`bundle-index.json` is canonical UTF-8 JSON with sorted object keys, array order fixed by schema, decimal integers only for sizes/ordinals, no insignificant whitespace, and one final LF. Its exact bytes are SHA-256-linked by the verification receipt and reviewer report. It records at least:

- schema IDs for the bundle, canonical archive, original evidence, hash, and chunking algorithms;
- evidence kind, calibration/run ID, terminal state, and immutable relative artifact path;
- full baseline commit, full candidate commit, authoritative harness source tree/lock hash, pre-campaign harness provenance commit, calibration ID, and design ID; a content-preserving rebase may change only the provenance commit, never the sealed harness tree/lock identity. `design_id` is the `design-lock.json` SHA-256 when present, otherwise a tagged `intent:<sha256>` or `calibration-plan:<sha256>` predesign identity, never an unexplained null;
- original `seal.json` path and `uncompressed_seal_root_sha256`, copied only after recomputation from the uncompressed source closure;
- `seal_entry_count`, `archive_member_count=seal_entry_count+1` for `seal.json`, and exact source/archive payload byte totals;
- canonical archive schema, byte length, and SHA-256;
- diagnostic copies of compression algorithm/version/full parameter vector and encoder/decoder checksums, plus compressed-stream length/SHA-256; expected encoder identity is always derived from the extracted sealed intent, and every duplicate index value must merely agree;
- fixed `chunk_bytes=50,331,648` and an ordered chunk array containing ordinal, relative path, exact byte length, and SHA-256 for every chunk;
- `chunk_total_bytes`, equal to both the sum of chunk lengths and compressed-stream length, plus the uncompressed/source total sizes needed for scratch and delivery projections;
- the source secret-scan schema/result and the exact expected independent-verifier schema;
- for calibration, the exact `compression-profile.json` path/hash and component-profile schema; campaigns omit this optional field.

`delivery-index.json` lists every bundle index path and SHA-256, verification receipt path and SHA-256, associated machine-readable result and report paths/hashes, seal root, IDs, outcome, per-unit tracked bytes, and exact aggregate bytes under `artifacts/` excluding only the ledger's own bytes (which are added from its actual file length for the 512 MiB gate). Ordering is `(evidence_kind, evidence_id)` and duplicate IDs or roots with divergent content are fatal. Reports consume this ledger but cannot authorize removal from it.
The hash graph is acyclic: chunks plus optional calibration compression profile → bundle index → verification receipt → machine-readable result → delivery report → delivery ledger. The report selects the ledger's evidence identities but does not embed the ledger hash; the ledger is finalized afterward with the report hash and its own actual byte length is added externally when enforcing the cap.

#### 6.13.3 Independent `verify-bundle`

`verify-bundle` takes a canonical `bundle-index.json` from exclusive delivery staging or the tracked artifact tree and a repository-local scratch root only; review/delivery modes accept only committed tracked input. It refuses the original calibration/run directory as an input and performs no lookup in home, `/tmp`, an artifact service, or an untracked copy. Its exclusive scratch path is `.perf/prove-http2-performance-regression/bundle-verify/<bundle-index-sha256>/`; the disk gate covers it, and stale/nonempty scratch is rejected rather than reused.
On first verification it computes the canonical index SHA-256 that the receipt/report will bind. Review and `delivery-ready` modes require that expected index hash from the tracked report/ledger and compare it before trusting any index field; they likewise compare the receipt hash named by the report before using the receipt only as an expected-output check.

In one fail-closed pass it:

1. Canonicalizes and validates the index, checks its path/identity, enumerates exactly the declared contiguous chunks, and verifies each length/SHA-256 before consumption. Index codec fields are retained as untrusted duplicate claims at this point.
2. Streams the chunks in ordinal order through the schema-fixed decoder, verifying total compressed length/SHA-256, frame checksum/content size, one-frame shape, and absence of trailing bytes. It parses the canonical archive into the exclusive scratch path while enforcing declared expansion length, member count/lengths, normalized metadata, sorted unique safe paths, zero padding/end blocks, and the §6.12.1 scratch bound. No path may escape or alias the scratch root.
3. Validates `seal.json`, hashes every extracted raw member, recomputes the original seal root, and requires exact equality with `uncompressed_seal_root_sha256`. It requires the one unit-level topology smoke when reached, enforces class membership (`S/D` forbid latency arrays; `C/A` require exact count equality), and cross-checks baseline, candidate, harness tree, calibration, design, workload connection-policy root, schedule, terminal state, and expected-file identities from extracted manifests rather than duplicate index fields.
4. Derives the sole expected encoder identity and full parameter vector from extracted sealed `intent.json` (and verifies any design-lock copy by intent hash). It verifies the local encoder package/source/lock/vendored-version/toolchain identity and golden vectors against that sealed tuple, records its executed-binary hash separately, then requires every diagnostic index codec field to agree. A frame that merely decodes correctly cannot satisfy this step.
5. Reconstructs the canonical uncompressed archive from the extracted seal closure using the canonical writer—never by replaying the decompressor's input buffer—and stream-compares its complete bytes, length, and SHA-256 with the decoded canonical stream. This proves path ordering, normalized headers, padding, end blocks, and source bytes a second time.
6. Invokes the exact identity-checked encoder on that reconstructed canonical stream with the sealed complete parameter map and pledged length. As encoder bytes are produced, it stream-compares every byte against the concatenated delivered chunks while independently counting length and SHA-256. Success requires byte-for-byte equality through EOF, equal compressed length, equal SHA-256, no early/extra byte, and the same chunk-boundary projection. A valid Zstandard stream produced by another level, worker setting, codec build, or parameter value is therefore rejected even when it has the same decompressed bytes and valid frame checksum.
7. For a calibration bundle, recreates every projection-only component mini-archive and checks every `compression-profile.json` aggregate, maximum, record count, witness hash, compressed length, and SHA-256. It then recomputes the raw phase bounds, 2× continuation projection when one exists, actual artifact bytes, codec scratch, and codec-time terms using checked integer arithmetic.
8. Runs the independent raw verifier over the extracted closure. Derived analysis/report/block-ratio/cached-decision files are not seal members and are never inputs. Calibration/early-blocked units reproduce the topology smoke, per-phase connection equations/hashes, only their permitted design inputs, or exact terminal blocker. A complete campaign's pre-analysis invocation verifies class membership, operation/connection counts, close/EOF/no-reuse/no-retry rules, persistent H2 stream topology, schedules, resources, exact-policy direct gates, and all non-statistical blockers and emits a canonical `analysis-input-root`; it is prohibited from computing p99, bootstrap replicates, f64 result bits, or a performance verdict. Only after the fresh-walk pre-analysis actual-cap gate passes may analysis mode rebuild pairs and metrics from `A` records, execute the 100,000 replicates, and emit f64 `to_bits()`, result root, and verdict. `S/D` can influence only their allowed transition/headroom gates.
9. Verifies the secret-free schema and emits no successful structural receipt unless every prior structural step succeeds; analysis success is a separate hash-linked result after the cap gate.

The exclusive-created `verification.json` records bundle-index path/hash, all chunk and seal roots, extracted intent hash, expected hash-pinned encoder identity, producer and verifier executed-binary hashes, full parameter-map hash, reconstructed canonical length/hash, recompressed comparison length/hash and byte-equality result, component-profile root when present, verifier source/tree/lock hashes, scratch/time accounting, `analysis-input-root`, exact structural blocker, and success status. It contains no raw replacement data or pre-cap performance verdict. The later tracked `results/<conclusion-id>.json` records the independently recomputed f64/result/verdict root and links this receipt. Neither file is trusted by a reviewer: reruns from committed chunks must reproduce both phases and the exact result bytes or fail.

#### 6.13.4 Report hash links and one normative Git/cleanup lifecycle

The following order is the only cleanup authority; no summary, test, command, or PR-head state may define another:

1. **Seal, bundle, and producer-verify.** Seal the reached calibration/campaign raw closure in `.perf`, run ordinary raw structural `verify`, create every mandatory bundle under repository-local staging, and run structural `verify-bundle` using only its index/chunks and exclusive scratch. Verification includes canonical reconstruction and exact sealed-encoder byte comparison but, for a complete campaign, no authoritative p99/bootstrap. Install bundles atomically under the artifact root only after the applicable actual-cap checkpoint in §6.12.1 passes.
2. **Finalize tracked delivery bytes.** Create verification receipts and component profile where applicable, run source-independent analysis only after the pre-analysis actual gate, write the machine-readable result and reviewer report, and finalize the additive ledger. For every transitive evidence unit, the report gives repository-relative index/receipt paths, exact SHA-256 of both, original seal root, baseline/candidate/design IDs, terminal state, result root, and tracked byte total. Recompute final `B_actual<=512 MiB`; a path or label without hashes is not a delivery link.
3. **Commit and push ordinary blobs.** Stage every required chunk, index, receipt, profile, result, report, and ledger as ordinary Git content and commit them on the implementation PR branch. Before push, follow the repository envelope: fetch the durable base and rebase onto it. Any rebase conflict, sealed harness source-tree/lock hash change, artifact removal, or ledger mutation is `BLOCKED` and requires a new calibration or re-verification as applicable; it cannot be papered over. A content-preserving rebase may change commit provenance; after it, recompute every artifact hash, the additive ledger comparison, and final actual task bytes before resolving and pushing the new exact artifact commit. Staged-only, ignored, Git-LFS, release/CI artifact, remote URL, home-directory, or `/tmp` content does not satisfy this gate.
4. **Independent committed-chunk review/check.** From a clean checkout of the exact pushed artifact commit, an independent reviewer or required check runs `delivery-ready --commit <artifact-commit>`. It verifies ordinary committed blobs, result/report/index/receipt hashes, additive parent/base ledger behavior, actual tracked bytes, and reruns `verify-bundle`—including exact recompression—from committed chunks with the source `.perf` closure unavailable. Its signed/content-hashed receipt must be attached to the PR/check result. This is a premerge readiness result only and explicitly grants no deletion authority.
5. **Merge the PR.** Required checks/review, including step 4, must pass and the PR must merge through normal branch protection. Open, draft, failing, closed-without-merge, abandoned, or otherwise unmerged PR state is nonterminal for evidence retention: keep `.perf`, the worktree, and branches. No PR-head reachability test can weaken this rule.
6. **Fetch and prove durable retention.** After merge, fetch the durable base ref, resolve the resulting base/merge commit, and require the reviewed artifact commit's delivered tree to be represented by that merged history. `delivery-retained --base <fetched-base-commit> --merge <merge-commit>` walks the additive ledger from the fetched commit, resolves every result/report/index/receipt/profile/chunk path as an ordinary reachable blob, recomputes every blob SHA-256 and `B_actual`, compares the premerge evidence identity set with the merged set, rejects any removal/mutation, and reruns `verify-bundle` from those durable blobs. It also proves the merge commit is reachable from the fetched durable base ref. Only this postmerge command may emit a deletion authorization, and that authorization is content-bound to the fetched base/merge commit and complete ledger root—not to a branch name or PR head.
7. **Cleanup and refresh.** Only after step 6 succeeds may the owner delete the corresponding `.perf` source/staging/scratch, remove the task worktree, delete merged task branches as repository policy allows, then refresh the main workspace with a fresh fetch and checkout of the durable base. If any cleanup step fails, record the remaining path/branch and do not claim lifecycle completion.

The artifact commit is delivery provenance, not a silent change to the tested gateway: `candidate_commit` remains the earlier exact object recorded by the campaign, and the sealed harness source tree/lock/binary identities remain authoritative even if a content-preserving pre-push rebase changes commit provenance. To avoid self-reference, the report binds content hashes rather than claiming the commit containing itself; premerge and postmerge commands bind the external commit identities in their receipts. Adding immutable evidence chunks does not relabel the candidate, while any benchmark/schema/codec/source-tree change invalidates the relevant design and requires a new calibration.

A reviewer needs no original execution worktree, artifact service, network download, home path, or `/tmp` output. Missing committed or merged reachability, a stale hash, recompression mismatch, failed/closed/unmerged PR, or attempted early cleanup leaves delivery `BLOCKED` and preserves `.perf` plus the worktree for recovery.

### 6.14 Verdict precedence and stop conditions


No sample is manually removed, winsorized, retried, or replaced. The terminal decision is:

1. **BLOCKED — evidence integrity first:** wrong/missing commit, binary, toolchain/cache/clock-boundary manifest, runtime surface, config, machine, topology smoke, quiet-observation accounting, ready-session predicate/real-time continuity or session/protocol-comparability record, comparability-affecting wall-clock disruption, PID/TID start time, lifecycle/settle evidence, accepted signature, frozen thread map, schedule, wrong/missing sealed workload connection policy or direct mapping, incomplete/unreconciled operation/connection ledger or cumulative-count/hash evidence, harness/direct connection reuse or hidden retry/reconnect, evidence class/member set, raw/reachable-branch/component projection, file/hash, expected arm, seal member, canonical reconstruction, sealed encoder identity/parameter map, recompressed byte/length/SHA equality, bundle index/chunk/receipt/result/report hash, committed delivery entry, independent check, merged durable path/ledger reachability, or unattributable harness failure; concurrent measured gateway; wall/disk/recompression-scratch/reserve limit; projected or actual tracked artifacts over 512 MiB; secret-bearing evidence; premature `.perf`/worktree deletion; or incomplete matrix/delivery set.
2. **FAIL — attributable candidate correctness/safety:** with a clean real-time session/protocol-comparability guard, candidate-only wrong authentication/protocol/status/bytes/EOS/framing, duplicate/replay, tripwire hit, topology violation—including a downstream-H1 upload response that advertises/retains keepalive, lacks required `Connection: close`, or fails to reach transport EOF—or gateway crash. This outranks later noise because no statistical performance claim is needed. A baseline/control semantic failure is instead `BLOCKED` as an invalid benchmark basis.
3. **BLOCKED — measurement quality:** any host/noise/headroom/operation/order/precision gate in §6.11 fails. Even an unfavorable point estimate is not called a confirmed regression from invalid evidence.
4. **FAIL — performance:** evidence is complete and precise, but any inclusive hard threshold in §4.2 fails.
5. **PASS:** every hard scalar gate across every required cell passes; descriptive C1 H2 values do not participate.

For the H1 upload policy, that precedence is concrete. Candidate-only keepalive/missing-close/missing-EOF behavior with otherwise clean evidence is semantic `FAIL`. The same behavior from the baseline/control is `BLOCKED`; a direct fixture that does not supply its sealed close mode is also `BLOCKED`. Any load-side connection reuse, reconnect/hidden retry of an operation ID, more than one request on a connection, `max_active>C`, or mismatch among started operations, planned/opened/connected sockets, close responses, EOFs, and cumulative connection totals is evidence-integrity or operation-quality `BLOCKED`. None may be converted into a latency sample, omitted operation, rerun, or favorable performance `FAIL`.

The campaign's statistical/protocol verdict is still computed solely by the unchanged gates above. Delivery is an enclosing integrity gate: analysis cannot start until the raw bundle passes the pre-analysis actual cap, and a numerically reproducible campaign `PASS` is not a deliverable task `PASS` until every mandatory bundle is independently reconstructed/re-encoded, report-linked, committed, independently checked, merged, and proven reachable from the fetched durable base/merge commit. A bundle/projection/retention failure cannot be reclassified as candidate performance `FAIL`, and no delivery rule changes a threshold, pair, sample, workload, or matrix.

Immediate safety stops include Tctl `>=85°C`, raw/bundle disk or 512 MiB actual-cap breach, raw/component projection underrun, writer-record overflow, child PID/TID start-time mismatch, excessive dynamic unattributed runtime, any new/disappearing/migrated TID after the authoritative freeze, accepted-signature mismatch, WebSocket settle failure, a missing/non-clean real-time guard or session/protocol-comparability-affecting wall-clock disruption, missing/contaminated mapped direct ceiling, external/non-loopback address or filesystem write, second gateway, tripwire activity, protocol/byte mismatch, an H1-upload keepalive/close/EOF/reuse/retry/count violation, process escape from broad or singleton affinity, secret-bearing/omitted/class-invalid raw evidence, malformed or mismatched seal/index/chunk/archive/receipt/report hash, canonical-reconstruction or re-encoding mismatch, untracked/unmerged delivery content, premature cleanup, or projection/actual wall limit. A pre-freeze lifecycle change is handled only by the bounded dynamic protocol and can still block through its conservative residual; it is never silently accepted after freeze. The orchestrator terminates only validated children, seals every already-created byte, and leaves `.perf` plus the worktree intact until the postmerge durable-retention authorization in §6.13.4.

---

## 7. Alternatives considered

### A. Five-arm Williams blocks with independent calibration — selected

**Pros:** contemporaneous shared control; exact AB/BA, position, and carryover balance; 28.6% fewer arm-runs; one frozen analysis; compatible with one gateway at a time.

**Cons:** more harness/schedule complexity; candidate-H1 correlations must remain explicit; the sealed 42-hour projection always rejects selected `N=70/100` and can reject `N=30/50`.

### B. Separate randomized A/B campaigns for all 45 comparisons

**Pros:** simplest pairing and reports.

**Cons:** repeats candidate H1 three times at C16/C64, adding 900–3,000 authoritative runs; controls are less contemporaneous across comparisons and host exposure grows. Rejected on cost without added contract value.

### C. Sequential looks at 30/50/70/100 with alpha spending

**Pros:** can stop early for clear outcomes.

**Cons:** requires a reviewed group-sequential boundary for every direction/metric and makes shared-control/global stopping substantially easier to misuse. Ordinary 95% looks are invalid. Rejected in favor of independent calibration and one authoritative N.

### D. Keep one gateway alive and measure many cells

**Pros:** removes thousands of startups and can greatly shorten runtime.

**Cons:** pool/allocator/RSS history crosses workloads, `VmHWM` cannot reset, treatment pairing weakens, and failures contaminate later cells. Rejected; cold paths are measured descriptively instead.

### E. Simultaneous baseline and candidate, external load generator, or internal benchmark hooks

**Pros:** simultaneous versions share some host drift; mature tools may be convenient; hooks can expose internal timing.

**Cons:** versions contend with each other, opaque retry/statistics can violate the contract, and release hooks change the measured/security boundary. Rejected.

### F. Freeze before warmup or tolerate lazy thread changes — rejected

**Pros:** a pre-warmup freeze is simpler to implement; allowing later Tokio births/retirements avoids lifecycle blocks.

**Cons:** a pre-warmup freeze contradicts lazy `spawn_blocking` creation for ordinary authenticated work and ten-second retirement during a WebSocket arm. Tolerating post-freeze changes destroys singleton provenance and process/TID reconciliation. Selected instead: one treatment-blind, workload-aware materialization protocol, conservative dynamic attribution, a bounded WebSocket retirement/settle, and a strict post-materialization freeze shared by scouts, calibration, direct paths, and authoritative work.

### G. Shipped per-operation H1 upload lifecycle — selected

**Pros:** matches the implementation-discovered fact that exact baseline and candidate intentionally close body-bearing downstream H1 requests, including a fully consumed successful 1 MiB POST; keeps `B11`/`C11` directly comparable; charges connect/accept/close/EOF as delivered operation work; and lets the H2 comparisons show their real persistent-multiplexing advantage or cost. The same policy in direct H1 ceilings preserves a meaningful headroom check.

**Cons:** upload p99 is no longer a request-on-warm-connection abstraction, socket churn can lower rates or increase variance, and stronger counters/smoke/schema bytes are required. H2-versus-H1 upload ratios combine protocol framing with the shipped connection lifecycle, so they must not be described as framing-only effects.

Forcing keepalive in either archived gateway, injecting a request `Connection: close` header to manufacture the result, accepting response EOS without transport EOF, pre-opening replacement sockets outside operation timing, or reconnecting/retrying the same operation ID were rejected. Each would change production behavior, hide shipped work, weaken no-retry evidence, or compare a synthetic topology.

### H. Canonical tracked chunk bundles — selected over external or summary-only delivery

**Pros:** every conclusion-bearing raw seal is durably reachable from the merged base before worktree deletion; fixed ordinary-Git chunks avoid per-file limits; canonical metadata, exact sealed-encoder recompression, and seal/index hashes make corruption, parameter drift, and omission independently detectable; reviewers need no expiring service or private machine path.

**Cons:** repository growth is real, bundle/recompression code adds surface, and a 2× calibration-derived projection can still underpredict a later campaign. The unconditional actual cap then blocks delivery; this cost is preferable to omitted samples or a false durable-evidence claim.

External artifact services, Git LFS, release/CI uploads, permanent reliance on a retained `.perf` worktree, and report/analysis-only commits were rejected as delivery mechanisms: none proves that every raw seal member remains reproducible after cleanup. `.perf` and its worktree are nevertheless mandatory recovery state until merged-base retention succeeds. The former initial Cartesian/no-compression-credit tracked projection was rejected because it combined mutually unreachable scout and `N=50` branches; favorable post hoc codec choice, selective recompression, or cross-candidate deduplication remains forbidden.

## 8. Migration, rollout, rollback, and remediation

### 8.1 Migration

No production data, schema, config, or infrastructure migration exists. The benchmark creates disposable repository-local schema-v2 databases and build trees. The only delivery migration is adding the versioned, ordinary-Git artifact root and additive ledger; `.perf` remains ignored execution/cache state.

### 8.2 Harness rollout

1. Obtain focused `review-rfc` PASS on this Draft's delivery closure before implementation proceeds.
2. Land the nested package, expanded fixed endpoint/connection ledgers, raw/delivery schemas, canonical archiver, pinned codec/chunker, fixture, sampler, analyzer, independent verifiers, and synthetic tests without production source/Cargo changes beyond the final candidate's benchmark-only files.
3. Prove exact archive builds, release-hook absence, black-box protocol/correctness paths—including the mandatory fresh-H1-upload versus persistent-H2 topology smoke—analyzer boundaries, deterministic bundle bytes, and source-independent scratch verification.
4. Pass the pre-smoke reachable-phase raw bound, run and seal the one-shot topology smoke, then pass the pre-scout bound; run scouts and Williams calibration with the fixed `S/C` schemas; for an admitted `N=30/50`, run the `D` calibration panel. Seal, bundle, reconstruct/re-encode, and independently verify the complete reached calibration; measure its component compression and pass the exact selected-branch 2× projection before design lock.
5. Run the frozen campaign once with `A` latencies and `D` count/headroom evidence; raw-seal and bundle it before analysis, pass the actual tracked cap, independently derive the result from verified chunks, then hash-link the report and finalize the ledger under the final actual cap.
6. Commit and push all ordinary artifact blobs; obtain the independent committed-chunk check; merge the PR; fetch and verify the durable base/merge commit's complete artifact/ledger reachability; only then delete `.perf`, remove the worktree/branches, and refresh main. A closed, failed, or unmerged PR keeps `.perf` and the worktree.

### 8.3 Rollback

- Harness rollback is deletion/revert of the nested package and unneeded **unsealed** generated cache. Sealed `.perf` evidence may be removed only after the postmerge durable-base retention gate; a pushed, failing, closed, or unmerged PR is not sufficient. Tracked bundle/ledger history is reverted only by an explicit evidence-retention review, never to make a campaign fit or pass. No gateway/data repair is required.
- A failed candidate remains a Git object with sealed, tracked evidence. Operational rollback remains the existing `UPSTREAM_PROTOCOL=http1` restart for upstream H2 or previous H1-only binary for downstream H2; this task performs neither.
- If benchmark implementation changes after calibration, discard no evidence: seal and bundle the campaign `BLOCKED`, create a new run/calibration ID, and start again.
- If rollback or another candidate fails the selected-branch projection or unconditional actual 512 MiB cap, stop `BLOCKED`; do not delete the evidence that established the need for rollback.

### 8.4 Regression remediation

On a precise `FAIL`, retain and durably bundle the full failing run and its calibration before relying on it for remediation. Use only separate diagnostic runs to inspect the demonstrated path; any diagnostic cited as rationale is sealed, bundled, and added to the ledger. Preserve all reviewed safety invariants and shipped protocol semantics: a fix may not turn the required downstream-H1 upload close into keepalive, force closure from the benchmark request, move connection work outside operation timing, or add retry/replay. Add focused tests and commit the optimization. The new commit is a new candidate and must run a complete new topology smoke, scout, calibration, and authoritative matrix whose bundles are additive. Baseline samples, controls, N, failed-run pairs, or prior bundle paths are never reused or replaced. Thresholds may not be edited in-task to convert a failure, and tracked-cap pressure cannot justify omitting the failure.

## 9. Observability

The benchmark observes externally without altering the gateway:

- process spawn/readiness/exit, pre-freeze TID births/deaths/provisional pins, pre-auth/post-settle inventories, accepted semantic signatures, frozen singleton maps, per-TID/process CPU ticks, `VmHWM`, sampled `VmRSS`, major faults, and context switches;
- machine fingerprint, PSI, swap, bracketed per-CPU `/proc/stat`, dynamic `u_role` and frozen signed external-time residuals at logical/pair/role scope, separate IRQ/softirq/steal, frequency policy/samples, Tctl, disk, and `CLOCK_BOOTTIME` campaign time;
- downstream/upstream actual protocol, physical connection and H2 stream counts, SETTINGS/ACK, operation IDs, bytes, EOS, and tripwire hits;
- for downstream-H1 upload, phase/lane planned connection IDs, socket/connect/request/response/close/EOS/EOF totals and binding hashes, active/max-active/cumulative counts, requests per connection, and keepalive/reuse/reconnect/retry violations; for H2 upload, the single persistent connection and stream identities;
- cold/materialization readiness, first connection/proof/request, WebSocket handshake, blocking-worker retirement, inventory stability, warmup, drain, and freeze latency, while separately retaining measured H1-upload connect-through-EOF latency as operation work;
- exact topology-smoke cases and `E_smoke`, every fixed `Q_obs`, separate `Q_extra`, every `C/A` steady-operation latency, explicit absence of `S/D` latency arrays, exact scout/direct count-window summaries, direct epoch/cell/protocol/connection-policy mappings, calibration transitions, and all derived comparison IDs/bounds;
- read-only `CLOCK_REALTIME` UTC artifact/continuity samples, sealed ready-session predicates, observed time-derived protocol metadata such as HTTP `Date`, exact archived gateway/pinned-dependency provenance, and representative production consumer classes such as session validation, Hyper `Date`, and tracing without claiming that list is exhaustive; no real-time value is used as harness latency, duration, throughput/CPU window, deadline, ordering/schedule, or campaign/resource accounting.
- class-specific raw byte bounds, exact calibration component compression, 2× selected-branch products, recompression scratch/time, actual-cap checkpoints, source seal/member roots, canonical and re-encoded stream hashes, every chunk length/hash, additive delivery bytes, independent result roots, report links, committed-check receipt, and fetched merged-base path/ledger reachability.

Progress output contains only completion, correctness, and quality state—not treatment ratios or confidence bounds. Gateway stderr remains at the common safe sink. Benchmark diagnostics never print cookie/token/secret/body values.

After a sealed failure, non-authoritative diagnostics may use `/proc` thread accounting, syscall counts, or unprivileged `perf` if current permissions allow. They must use a new diagnostic ID, cannot be merged into gate data, and cannot justify `PASS`.

## 10. Security and privacy

- **Authentication:** every operation carries a valid opaque cookie for one schema-v2 Ready session and traverses production auth/policy. Fixture assertions require browser credentials absent and verified identity present. The auth-mini tripwire must remain zero.
- **Routing/SSRF:** every endpoint is a literal loopback address chosen by the orchestrator. Fixture control data never enters gateway routing. Any non-loopback socket target stops the run.
- **Replay:** deterministic operation IDs and endpoint reconciliation detect duplicate sends. The load generator never retries or reconnects a failed operation; a later normal H1 upload operation always has a new operation and planned-connection ID.
- **Protocol/tunnel:** actual versions and SETTINGS are wire-observed. Downstream-H1 upload requires the shipped close response and transport EOF with one request per fresh connection, without injecting a close request header; downstream-H2 upload retains one multiplexed connection. WebSocket uses only valid RFC 6455/8441 handshakes and real Ping/Pong frames; D/U ownership remains production behavior.
- **Secrets:** all credentials are synthetic, remain only in per-arm runtime namespaces with restrictive permissions, and are excluded from the seal, canonical archive, indexes, receipts, reports, and raw payload files. Only schema-allowlisted non-secret fields and hashes persist. The schema-aware pre-bundle scan fails closed; no production credential or endpoint is read, and a sealed secret cannot be redacted into eligibility.
- **Resource exhaustion:** fixed C≤64, at most `C` simultaneous fresh H1-upload connections despite cumulative per-operation churn, existing D/U capacities, operation/time/raw-disk/scratch caps, the task-wide 512 MiB ordinary-Git delivery cap, bounded raw/index/report formats, fixed 48 MiB chunks, loopback-only listeners, and thermal stops apply.
- **Durable delivery:** artifact paths reject links/traversal and every extraction/reconstruction/recompression is length/hash/scratch bounded. Chunks, indexes, receipts, profiles, ledger, and reports are ordinary Git blobs independently verified before merge and proven reachable from the fetched durable base/merge commit before cleanup; a PR head is never retention authority. Git LFS, external/CI/release artifacts, home paths, and `/tmp` are forbidden delivery dependencies.
- **Runtime surface:** external Git/toolchain/cache inputs are read-only and hash-allowlisted; all generated state stays in-repository; only `/dev/null`, `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`, read-only `CLOCK_REALTIME` inside the exact untouched archived production gateway processes and their pinned dependencies for existing protocol/application semantics, orchestrator/sampler UTC artifact metadata, kernel randomness, literal loopback, and read-only `/proc`/`/sys` are additionally allowed. Session validation, Hyper automatic HTTP `Date`, and tracing are representative gateway consumers, not an exhaustive allowlist. Fixture/load/control code disables or rejects dependency real-time paths, including Hyper automatic date generation. No harness real-time value can drive latency, duration, throughput/count or CPU windows, deadlines, ordering, schedule, seed/statistics, or campaign/resource accounting; those use the sealed MONOTONIC/BOOTTIME or clock-independent split in §6.2. No benchmark clock is injected into a gateway. Network fetches, production/external endpoints, host mutation, and Nix are forbidden.
- **Release boundary:** no feature, callback, symbol, environment branch, or instrumentation is added to the release request path. The exact archived binary is the subject.

## 11. Threats to validity

1. **Single active host:** results establish only this recorded Axiom state. Dynamic attribution pessimistically charges not-yet-singleton runtime, while the frozen interval uses exact singleton per-TID/per-CPU residual gates. Neither can identify every IRQ source; IRQ/softirq is therefore retained separately, and strict gates can block the campaign.
2. **Closed-loop load:** p99 is the observed end-to-end latency at fixed operation concurrency and does not correct coordinated omission. That is intentional and identical for the H1 baseline/candidate pair; H2 retains its deliberately different persistent multiplexed topology. No open-loop SLO claim is made.
3. **Cleartext/local topology:** no TLS, WAN, packet loss, or production logging sink is represented. The contract's workload-specific cleartext topology—per-operation downstream H1 upload connections, persistent H1 GET/download/SSE, persistent H2, and pre-established tunnels—is authoritative here.
4. **Ready-session corpus:** refresh/JWKS/network-auth cost is excluded. SQLite lookup, cookie verification, policy, sanitation, and proxy dispatch remain real.
5. **Per-run p99:** nearest-rank p99 from at least 5,000 started-and-drained operations has at least 50 observations in the top 1%; the inferential unit remains the process-level paired block, not individual operations.
6. **Bootstrap assumptions:** blocks are treated exchangeable within order strata. Williams balance and randomized cell order reduce temporal/carryover bias but cannot manufacture stationarity; order/precision/direct-drift gates block visible violations.
7. **RSS interpretation:** `VmHWM` includes cold/materialization/settle stages and allocator retention. This is conservative and reproducible but not a steady-only memory decomposition.
8. **H1 upload connection churn and estimand:** exact baseline and candidate intentionally close each body-bearing downstream H1 upload connection. Connect/accept/close/EOF cost and ephemeral-port/socket churn therefore enter H1 upload throughput, p99, CPU, and HWM; the direct-H1 ceiling uses the same policy. `B11`/`C11` remain directly comparable, but H2-versus-H1 upload ratios intentionally combine framing/multiplexing with persistence versus shipped reconnect and must not be generalized as a pure protocol-framing effect. Separately, the gateway's eight-owner upstream H1 pool can create more cumulative upstream connections than H2; that also remains real behavior.
9. **One H2 generation:** serial proof warmup intentionally measures multiplexing up to C64 on one generation. It does not characterize multi-generation failure/revocation behavior already covered by functional tests.
10. **Log sink and wall time:** `/dev/null` preserves shipped formatting, `CLOCK_REALTIME` timestamping, and syscall cost but not journald/disk cost; gateway protocol output also preserves Hyper automatic `Date` generation. Real-time changes can alter UTC labels/tracing values, session active/expired/refresh-due/touch-validity results, HTTP `Date`, or another existing time-derived protocol/application semantic in the exact archived dependency closure. Every discontinuity is retained, and one capable of invalidating baseline/candidate session or protocol comparability is environmental `BLOCKED`; a discontinuity confined to harness UTC labels and proven unable to affect gateway semantics is diagnostic only. Real time never supplies a harness latency, duration, throughput/count or CPU window, deadline, ordering/schedule, or campaign/resource accounting value; those remain MONOTONIC/BOOTTIME or clock-independent as specified in §6.2.
11. **Lazy-thread lifecycle:** ordinary full-`C` materialization, including repeated H1 upload accept/close cycles, can still produce a post-freeze Tokio birth/retirement, and WebSocket auth workers can fail to retire by the 15-second cap. Either becomes honest `BLOCKED`; accepted signatures and no-retry rules prevent choosing a favorable treatment count.
12. **Calibration selection:** the fixed count-window scout and disjoint Williams calibration may still underpredict final variance. Final precision turns that uncertainty into `BLOCKED`; authoritative observations never revise `N/W/T` or accepted signatures.
13. **Runtime admission:** the one-shot bounded `E_smoke`, fixed `Q_obs`, explicit materialization/settle/freeze caps, and finite extra-wait reserves can reject a statistically selected `N`. In particular, `N=70/100` cannot enter authoritative sampling; the 42-hour projection and 48-hour actual deadline are feasibility gates, not permission to reduce the matrix.
14. **Quiet-window cost:** every arm pays a distinct successful ten seconds even on an idle host. `Q_cap` covers only additional search/cooling, so neither calibration nor future work can hide the mandatory cost.
15. **Disk pressure:** the current filesystem has about 62 GB free and is 94% used. Each currently reachable phase uses a formal uncompressed bound—including the smoke file and expanded fixed endpoint records—plus two-times coexistence reserve for staging, extraction, canonical reconstruction, and recompression; it can block large `T_s`/`N`, and sealed evidence is not deleted to evade it.
16. **Repository delivery pressure:** 512 MiB for all task artifacts is intentionally stricter than available filesystem space. Fixed H1-upload connection counters avoid an unbounded per-connection member but the larger endpoint records and smoke still consume tracked bytes. The post-calibration 2× exact-policy matching-component projection can still underpredict a future compressed bundle, while retained failed candidates reduce room for remediation. The unconditional actual gates turn either case into `BLOCKED`; they never authorize latency/member omission, a different codec, or a no-regression conclusion. Scouts/directs omit latency arrays only because their prospective classes never use p99/bootstrap and their complete permitted decision inputs remain raw.

## 12. Executable verification strategy

Expected top-level command shape after implementation:

```bash
cargo run --frozen --release \
  --manifest-path benchmarks/http2-regression/Cargo.toml -- \
  campaign \
  --baseline 28a4a273ea9b2725191dce35233f55972beaac6f \
  --candidate <full-git-commit>
```

It performs archive builds, self-tests, the sealed one-shot topology smoke, reachable-phase raw gates, class-frozen scout/calibration, complete calibration bundling/re-encoding/component profiling, selected-branch design freeze, authoritative collection, raw campaign sealing/bundling before analysis, source-independent analysis, actual-cap checks, and tracked report generation; it exits nonzero for `FAIL` or `BLOCKED`. It never commits Git content or deletes `.perf`; the explicit commit/push/reviewer/merge/durable-retention/cleanup sequence in §6.13.4 follows. Resumability may continue only a not-yet-started arm from the frozen schedule after proving all prior files and machine/boot fingerprint; a partially started topology smoke or arm is never resumed or replaced and makes the campaign `BLOCKED`.

Required automated evidence:

### 12.1 Analyzer/schema tests

- golden nearest-rank p99 and 100,000-replicate percentile indices;
- exact SplitMix64 seeds/draws, unbiased bounded sampling, order strata, pairing, and shared-control identities;
- synthetic inclusive-threshold `PASS`, one-bit-beyond `FAIL`, H2 point-estimate failure, precision/noise/order `BLOCKED`, and verdict precedence, including candidate-only missing-close/EOF `FAIL` versus baseline/direct/harness/retry/count-integrity `BLOCKED`;
- all seven scout transitions, fresh-process doubling, 15-second count timeout, exact count-window denominators, workload-aware lifecycle, pre-Williams `W_cal/T_cal` plus establishment-arm freeze, first-Williams accepted signatures, authoritative `N/W/T` derivation, and no circular inputs; H1-upload count windows end at the last of exactly `Q` EOFs and include `Q` fresh connects, while scouts prove every transition from raw quotas/counts/timestamps/operation-connection counters/hashes with no latency member;
- `N` selection in each bucket, statistical projected-100 failure, and prospective runtime `BLOCKED` for selected `N=70/100` without substitution; proof calibration IDs cannot enter authoritative analysis;
- exact arm inventory and 42-hour equation for `N=30/50/70/100`, the one non-arm `E_smoke<=300s` charged before scouts, actual scout-attempt counts, one fixed successful `Q_obs` per completed/future arm, separate `Q_extra`, unchanged `B_ordinary=28..60s`/`B_ws=43..75s`, the conservative 17,217-second pre-freeze floor plus actual smoke, cap exhaustion, omitted direct arm, and 48-hour stop;
- malformed/truncated/duplicate/endian/count/hash/schedule/PID/TID/lifecycle/signature/quiet/direct/projection data rejected; schema matrix tests require `topology-smoke.json` when reached and every §6.12.1 common/class member, pin the expanded `endpoints.bin` widths, reject latency arrays in `S/D`, require one latency per drained measured operation in `C/A`, require H1-upload latencies to span connect-through-EOF, and prove `S/D` cannot enter p99, variance, pairs, or bootstrap;
- independent `verify` reproduces projection, accepts the sealed archived-gateway provenance/production-purpose boundary plus exact harness UTC-metadata sites rather than a fixed count or exhaustive gateway caller list, proves real time supplied no harness latency/duration/throughput or CPU window/deadline, ordering/schedule, seed/statistical input, or campaign/resource accounting, recomputes session/protocol-comparability disruption classification, and reproduces f64 bits and seal root from raw files.

- canonical-ustar golden bytes prove unsigned-byte path sorting, normalized headers, zero padding/end blocks, no extension records, and byte-complete inclusion of `seal.json`, the reached topology smoke, plus every class-mandatory raw member; byte-exact tests cover every row/formula in the uncompressed table and `USTAR` padding equation;
- lockfile/codec golden vectors pin the intent-derived source/lock/version identity and separately record producer/verifier binary hashes and every full-parameter-map value; reconstruction/recompression tests compare every byte, length, and SHA-256. A negative fixture containing a valid checksummed one-frame Zstandard stream of the same canonical archive made at another level must decode successfully and then fail exact recompression. Chunk tests cover empty rejection, one byte, `CHUNK_BYTES-1`, exact 48 MiB, exact multiples, and one byte over, with contiguous names and no zero final chunk;
- canonical index/ledger tests pin required schema/ID/seal-root/size fields, sorted JSON bytes, chunk length/hash totals, additive prior-candidate entries, fresh-walk actual accounting at every checkpoint, exact 512 MiB acceptance, and one-byte-over `BLOCKED`; index codec claims cannot override the extracted sealed intent;
- malformed/missing/extra/reordered/duplicate chunks, wrong lengths/hashes, multiple/trailing frames, checksum/content-size mismatch, decompression overrun, canonical-reconstruction mismatch, recompressed byte/length/SHA mismatch, wrong encoder identity/parameter, unsafe/aliased paths, non-normalized metadata, missing/extra class members, divergent IDs, stale receipts, and report-hash mismatch are rejected;
- source schemas enumerate and golden-test the topology-smoke member and every mandatory raw member for `S/C/D/A`: all classes retain counters/timestamps/endpoint and operation-connection hashes/resources/threads/noise/lifecycle, fixed H1-upload counters prove cumulative connections equal starts with zero keepalive/reuse/retry, only `C/A` retain all operation latencies, and no report can replace a member; credential/runtime/cache namespaces cannot enter, and injected cookie/token/key/environment fields stop before bundle creation without redaction/exclusion;
- with the source `.perf` evidence unavailable, `verify-bundle` extracts, reconstructs the canonical archive, invokes the exact intent-pinned encoder, stream-compares delivered bytes, reproduces the original seal and exact f64/verdict bits from raw records, ignores deliberately poisoned derived data, and reproduces early `BLOCKED` states without asserting absent scalars; scratch and BOOTTIME tests charge both reconstruction and recompression.

### 12.2 Fixture/load tests

- actual H1/H2 versions and exact workload-specific physical connection/stream counts for all five arms at C1/16/64;
- for every `B11`/`C11`/`C12` upload phase, each started operation opens exactly one new H1 socket, makes one connect attempt, sends exactly one fully consumed 1 MiB POST, observes a gateway-produced `Connection: close` token and transport EOF, never sends a second request, keeps `max_active<=C`, returns to zero active after drain, and makes cumulative downstream connections equal started operations; the request contains no client-forced close header;
- `C21`/`C22` upload tests retain exactly one proved downstream H2 connection, use unique streams with at most `C` active, and reject reconnect; H1 GET/download/SSE tests reuse exactly `C` persistent connections across operations, while WebSocket tests retain pre-established tunnels;
- direct-H1 upload fixture mode repeats fresh-connect/one-POST/close/EOF and direct-H2 repeats one-connection/`C`-stream behavior; direct H1 GET/download/SSE remains persistent and WebSocket remains pre-established;
- exact 64-byte GET, incremental 1 MiB upload/download, 16-event SSE through EOS, and RFC 6455 Ping/Pong remain byte/framing validated;
- negative tests inject response keepalive/missing close, missing/delayed EOF, a second request on one H1 upload connection, connection reuse, duplicate connection ID, hidden automatic retry/reconnect, connect failure, `max_active=C+1`, and every cumulative/open/request/close/EOF count/hash mismatch; none can become a valid completion or replacement operation;
- operation-ID replay/duplicate, wrong byte, wrong EOS/order/status/version, tripwire hit, and unexpected connection all stop without retry; a later normal operation uses a new ID and planned connection, never a retry identity;
- all epoch/cell/protocol/connection-policy direct IDs and prospective arm mappings, including bridge dual mappings, reject missing, contaminated, drifted, keepalive-normalized, or substituted ceilings;
- fixture/load direct ceilings and CPU accounting are measured from separate processes and use the same ordinary/WebSocket lifecycle, operation boundary, and phase caps;
- ordinary warmup releases all `C` lanes under broad role affinity: persistent H1/H2 reaches the required pool/generation topology, while downstream-H1 upload repeatedly executes fresh connect/POST/close/EOF, drains to zero, freezes with no pre-opened socket, and immediately releases same-`C` steady operations without gateway hooks;
- WebSocket opens/authenticates all tunnels, emits no auth during settle or Ping/Pong warmup, and retains the exact tunnel topology through freeze and measurement.

### 12.3 Sampler/orchestrator tests

- known multithreaded children establish process/per-TID tick reconciliation, bracketed per-CPU residuals, semantic signatures, and `VmHWM` at `CLK_TCK=100`;
- deterministic tests permit/record pre-freeze birth and retirement, immediately pin observed TIDs, leave the complete ordered `u_role` interval unsubtracted from external time, and reject impossible process/TID reconciliation; PID/TID reuse, any post-freeze birth/disappearance, singleton-affinity change, migration, or unreadable frozen task prevents sampling/signaling;
- virtual-clock tests pin `K_tokio=10s`, forbid stability credit before it, require a subsequent unchanged `S_inv=2s`, reset stability on change, block at `L_ws=15s`, prove auth-born gateway TIDs have retired, and apply the same lifecycle to gateway/direct scouts, calibration, and authoritative arms;
- signature tests freeze only each predesignated first-Williams treatment/cell arm and `D[0]` direct arm, reject every later mismatch without retry, and prove scout transitions and thread counts are not treatment-selected;
- synthetic external load in each role proves the dynamic and frozen logical-CPU, sibling-pair, and role limits all reject a one-core transient while IRQ/softirq remains separate;
- one-gateway invariant, non-loopback rejection, thermal/disk/quiet/wall stops, exact one-shot topology-smoke plus `Q_obs/R/P/W/D_w/L_ws/F/D_m/X` transitions, ordinary `D_w+F<=3s` handoff, H1-upload zero connections at freeze followed by at most `C` post-release fresh connects, and safe child cleanup;
- stderr `/dev/null` is identical while exact archived-path tests prove shipped synchronous timestamped writes, production session lookup/expiry/refresh-due/touch-validity reads, and Hyper 1.10.1 H1/H2 automatic `Date` generation for responses lacking an explicit header, including `/healthz`, still execute; a clock sentinel allows read-only `CLOCK_REALTIME` from the exact untouched archived gateway process and pinned dependency closure for existing production semantics without requiring an exhaustive consumer list, permits harness reads only at sealed UTC artifact sites, and rejects fixture/load/control dependency use including automatic `Date`; forward/backward discontinuity tests distinguish comparability-affecting environmental `BLOCKED` from metadata-only diagnostic steps, while every harness latency/duration/throughput and CPU window/deadline test uses MONOTONIC and every campaign/resource-clock test uses BOOTTIME;
- arm state transitions exclude proof/materialization operations but include every measured H1-upload connect/accept/close/EOF and measured-drain CPU, include final HWM for all classes, retain connect-through-EOF measured-drain latency only for `C/A`, and never reuse a smoke or doubled-scout process.

- storage tests evaluate the byte-exact expanded endpoint row and smoke unit maximum for pre-smoke, pre-scout, pre-Williams, pre-direct, selected `N=30`, selected `N=50`, and terminal smoke/high-scout/`N=70/100` branches; they prove unreachable branches are never Cartesian-reserved, while every reachable phase is fully reserved. They verify exact calibration component profiles, maximum matching bytes per arm and per record, 2× upward-rounded products, formal fixed overhead, streaming reconstruction/recompression scratch/time, prior bundles, all actual-cap checkpoints, projection underprediction becoming only later `BLOCKED`, raw-writer overflow before omission, and stop-without-truncation behavior;
- Git-lifecycle tests enforce one order: bundle/recompress verify → commit/push → independent exact-commit chunk verification → merge → fetch durable base/merge commit → complete artifact/ledger reachability/reverification → cleanup/branch removal/main refresh. Untracked, staged-only, LFS, URL, mutable PR-head-only, wrong-commit, stale-report, closed, failed, or unmerged states never authorize deletion and retain `.perf` plus the worktree;
- remediation tests preserve an earlier sealed failed/blocked calibration/campaign and any cited diagnostic when a later candidate is added, and block rather than replace evidence when the aggregate cap would be exceeded.

### 12.4 Repository and safety gates

- formatting, strict Clippy for all targets/features, full tests, release gateway builds, benchmark self-tests, and `git diff --check`;
- existing proxy/mode-switch/old-binary/WAL E2Es and relevant HTTP/2 protocol/security tests, plus exact-archive full-body H1 POST checks that both baseline and candidate return their shipped close response and EOF;
- release artifact/source scan proving no benchmark hook/API/symbol, keepalive override, close-header injection, or benchmark-only behavior in gateway paths;
- sandbox sentinel proving external Git/toolchain/cache paths remain read-only, all generated output stays below the worktree, read-only `CLOCK_REALTIME` is bounded to the exact untouched archived gateway/pinned-dependency production-semantic class plus exact orchestrator/sampler UTC artifact sites without an exhaustive gateway call-site list, every harness timing/accounting or fixture/load/control use fails closed, and network/production/Nix/host-mutation paths fail closed;
- read-only `review-change` with security lens after any optimization;
- repository sentinel proving `.perf` may be ignored but task artifacts may not; every artifact blob is `<=48 MiB` for chunks or `<=1 MiB` for schema/report files, aggregate tracked bytes are `<=512 MiB`, and no Git LFS pointer or external/home/tmp delivery dependency exists;
- premerge `delivery-ready` checks result/report hash links and the exact committed blobs, then reruns `verify-bundle` from committed chunks with the source execution tree absent, but emits no cleanup authority;
- the independent reviewer/check must pass before merge; postmerge `delivery-retained` fetches the durable base/merge commit, proves every additive ledger/artifact path and hash reachable there, and reruns verification before permitting `.perf`, worktree, or branch cleanup and main refresh.

### 12.5 Mandatory campaign smoke gate

- The campaign command must exclusive-create `intent.json`, start `t_campaign`, pass the pre-smoke raw bound, and execute the exact §6.8.0 schedule before creating any scout directory. There is no skip flag, keepalive compatibility mode, or retry-on-smoke-failure path.
- The smoke must use the exact archived baseline/candidate binaries and final sealed load/fixture code. Its `B11`/`C11`/`C12` full-success uploads prove fresh connection per operation plus gateway-produced close/EOF; its `C21`/`C22` uploads prove one persistent H2 connection; direct H1/H2 and persistent GET/download/SSE/pre-established WebSocket controls prove the corresponding policies.
- `topology-smoke.json` must independently reconcile every case's started operations, planned/opened/connected sockets, one-request connections, close/EOS/EOF counts, maximum active count, H2 connection/stream counts, and zero reuse/reconnect/retry. A missing case or mismatch follows §6.14 precedence and seals the calibration terminal; smoke is never a performance sample.
- Success must finish within `T_smoke=300.000s`, be included in `E_pre`, raw/delivery bounds, the calibration seal/bundle, and independent verification, then tear down every process/socket before the first arm's distinct `Q_obs`.

## 13. Milestones

1. **Harness and deterministic analysis foundation**
   - Scope: nested package, archive builds, workload-specific persistent/fresh connection engine, expanded fixed endpoint ledgers, class-specific raw/seal schemas, canonical ustar writer/parser, intent-pinned Zstandard/chunker, exact reconstruction/recompression verifier, bundle/index/ledger schemas, process sampler, five workloads, exact protocol/correctness, and synthetic statistics.
   - Acceptance: focused tests distinguish every PASS/FAIL/BLOCKED boundary and exact black-box release path; H1 upload proves one fresh connection/POST/close/EOF per operation with no retry while H2 remains multiplexed; `S/D` contain complete decision evidence without latency arrays, `C/A` retain every latency including H1 connect-through-EOF, canonical/re-encoded bytes and chunk boundaries are golden-tested, and no release hook exists.
   - Rollback impact: remove/revert unexecuted benchmark-only files; no production state and no delivered evidence yet.

2. **Calibration and design freeze**
   - Scope: machine gate, one-shot topology smoke, dynamic and frozen per-thread placement/accounting, workload-aware ordinary/WebSocket lifecycle including H1 upload connection churn, accepted signatures, exact-policy direct mappings, fixed `Q_obs`, fresh-process quality scout, pre-frozen ten-row calibration, authoritative N/T/W, reachable-phase raw bounds, complete calibration bundle/component profile, 2× selected-continuation projection, and actual-cap gate.
   - Acceptance: a sealed calibration first proves and retains the exact smoke topology, then either creates one immutable design lock for runtime-admissible `N=30/50` or returns precise `FAIL`/`BLOCKED` (including smoke, high-scout, and selected `N=70/100` branches); its byte-complete bundle reconstructs and re-encodes exactly, and only its exact reached branch contributes to the tracked projection.
   - Rollback impact: retain the sealed calibration and bundle; changes require a new ID and cannot overwrite the ledger entry.

3. **Authoritative campaign and remediation**
   - Scope: complete frozen matrix, raw campaign seal/bundle before analysis, unconditional actual-cap gates, one source-independent final analysis, diagnostics/fix only if a precise failure occurs, then additive complete calibration/campaign bundles for a new candidate.
   - Acceptance: sealed `PASS`, `FAIL`, or honest `BLOCKED`; no missing/replaced pair, topology-smoke/connection ledger, class-mandatory raw member, `C/A` latency, failed/blocked predecessor, hidden retry, keepalive normalization, or reduced matrix; exact f64/verdict bits reproduce with all derived analysis ignored as input.
   - Rollback impact: failed/blocked evidence and any cited diagnostic remain in the delivery set; candidate rollback is Git/operational selection, not data or ledger editing.

4. **Independent verification and delivery**
   - Scope: raw recomputation and exact recompression from tracked chunks, report/index/receipt links, actual-cap check, ordinary-Git commit/push, independent exact-commit review, merge, fetched durable-base retention proof, then cleanup/branch removal/main refresh.
   - Acceptance: every required calibration/campaign seal, chunk, index, result bit, verdict, and report link reproduces first from the exact PR commit and then from the fetched durable base/merge commit with source `.perf` unavailable; closed/failed/unmerged delivery remains `BLOCKED` with `.perf` and worktree retained.
   - Rollback impact: revert code only with explicit evidence-retention review; committed conclusion evidence is not discarded as routine cleanup.

## 14. Implementation notes

Expected implementation surfaces are a new nested benchmark package, thin campaign/topology-smoke/bundle/verify/delivery-ready/delivery-retained commands, expanded benchmark-only endpoint ledgers, the ignored `.perf` execution/staging/scratch root, and the tracked task artifact root. Production `src/`, root Cargo files, release behavior, and deployment files require no change or benchmark instrumentation; repository tests may only assert the existing shipped behavior.

Keep fixture protocol, load operations/connection policy, topology smoke, sampler, schedule, analyzer, raw schema, source verifier, canonical archive/codec/chunker, bundle schema, bundle verifier, and Git delivery gate as separate modules. The independent bundle verifier may share primitive parsers/hashes but not analyzer decisions or cached derived values. Use integer nanoseconds/ticks/KiB in raw records; centralize no floating-point decision outside the analyzer/verifier. The report must enumerate all 45 hard comparison cells and 190 scalar gates rather than collapse failures into an average, and must hash-link every transitive evidence bundle.

## 15. Open questions and current blockers

**No design question remains open.** Production behavior and the previously approved statistical, clock, lifecycle, noise, rollback, artifact, and security gates remain unchanged; this amendment changes only the prospective benchmark topology and evidence needed to represent shipped behavior. In addition to B1–B3, this Draft closes the implementation-discovered upload blocker: exact baseline and candidate intentionally return `Connection: close` for a fully consumed successful 1 MiB downstream-H1 POST, so `B11`/`C11`/`C12` now measure one fresh connection per operation through close/EOF, matching direct H1 ceilings, while `C21`/`C22` retain persistent H2 multiplexing. Warmup/materialization, operation timing, connection reconciliation, smoke, runtime accounting, fixed endpoint storage, direct mapping, verdict precedence, tests, and threats to validity are updated without a keepalive override or production change. The status remains **Draft — ready for focused review** of §§4.2, 6.4–6.6, 6.8.0–6.9, 6.11–6.14, 7–13.

The only current design gate is that focused review; implementation/delivery must not claim the prior PASS covers this amendment. Empirical blockers for `N=30/50` remain the mandatory exact-binary topology smoke, role-local lifecycle/noise attribution under repeated H1 accept/close work, exact-policy endpoint ceilings, signature stability, 42-hour admission/48-hour completion including `E_smoke`, additional wait, reachable raw/coexistence space with expanded endpoint records, calibration-derived tracked fit, final actual tracked bytes, exact deterministic re-encoding, independent committed-chunk review, and merged durable-base reachability. High-scout exhaustion and selection of `N=70/100` stop without reserving unreachable authoritative data. None justifies forcing keepalive, moving connect/EOF outside an operation, reusing a connection, retrying an operation ID, changing affinity/services/statistical thresholds/protocol matrix/authoritative or calibration samples/thread counts, or weakening mandatory evidence retention.

## 16. References

- Stable contract: `.legion/tasks/prove-http2-performance-regression/plan.md`
- Research: `.legion/tasks/prove-http2-performance-regression/docs/research.md`
- Task decisions: `.legion/tasks/prove-http2-performance-regression/log.md`
- HTTP/2 design/review: `.legion/tasks/enable-http2-proxy/docs/{rfc,review-rfc,review-change,test-report}.md`
- Effective security/ownership decisions: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`, `.legion/wiki/tasks/enable-http2-proxy.md`
- Current source/tests: `Cargo.toml`, `Cargo.lock`, `src/{main,config,db,cookies,server,proxy,capacity,runtime_plan}.rs`, `tests/proxy_integration.rs`, `scripts/e2e-*.sh`
- Git objects: baseline `28a4a273ea9b2725191dce35233f55972beaac6f`; initial candidate `1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad`
