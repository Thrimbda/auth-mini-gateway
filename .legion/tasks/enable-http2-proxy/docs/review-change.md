# Read-only high-risk implementation re-review

> Date: 2026-07-17
> Base: `origin/master` / `28a4a273ea9b2725191dce35233f55972beaac6f`
> Design basis: latest `rfc.md` plus focused `review-rfc.md` **PASS**
> Security lens: **applied** — authentication, protocol, tunnel, identity, and resource-ownership boundaries changed
> Gate: **PASS**

## Blocking findings

**None.** The current source closes all six prior blockers, and the fresh verification evidence exercises the failure-sensitive paths that previously lacked proof.

## Prior blocker disposition

### 1. CLOSED — request/U/stream ownership now waits for Hyper to drop the body wrapper

`TrackedRequestBody::observe_terminal` records clean/error/cancellation state and drops only the inbound body; it does not call `request_done` or release the request-half stream lease (`src/proxy.rs:4198-4241`). Those actions occur only from `TrackedRequestBody::drop` through `finish_on_drop` (`src/proxy.rs:4243-4262`). This is the required witness because pinned Hyper moves the wrapper into its H2 body pipe and can retain a returned DATA frame while waiting for flow-control capacity.

The component test returns a terminal frame and separately exercises cancellation while proving U, the generation stream permit, and the downstream H2 stream lease remain held until wrapper drop (`src/proxy.rs:5089-5215`). The raw upstream integration fixture advertises a zero stream window, sends an early `413`, withholds `WINDOW_UPDATE`, and proves both U and downstream stream admission remain unavailable; only after flow control lets Hyper finish/drop the body do later requests proceed on the same generation (`tests/proxy_integration.rs:2610-2718,4886-5010`). This closes the premature-release defect without aborting siblings or exceeding U.

### 2. CLOSED — the transport witness follows actual inner transport destruction

`H2ProofIo` now stores `inner: Option<T>` (`src/proxy.rs:688-699`). Its destructor takes and synchronously drops that inner TLS/TCP value before calling `mark_transport_dropped` (`src/proxy.rs:830-836`); permit cleanup waits on that persistent witness (`src/proxy.rs:444-463,1668-1677`).

The blocking-drop transport test runs the real wrapper on another thread and proves the witness and U permit remain unavailable while the inner destructor is blocked, then become observable only after it completes (`src/proxy.rs:5217-5280`). The D/U/FD accounting transition is therefore ordered after physical transport ownership ends.

### 3. CLOSED — continuous bounded SETTINGS revocation is linearized with enqueue and exact-generation retirement

The same inbound observer remains attached after initial proof. `ServerFrameScanner` retains fixed 9-byte and 6-byte scratches plus scalar state, skips arbitrary non-SETTINGS payloads without retaining them, preserves fragmentation/coalescing cursors, applies duplicate ID `0x8` last-value semantics, and reports a later effective zero only after the complete frame (`src/proxy.rs:363-389,465-621`). No peer-sized collection exists in this path.

`GenerationControl::revoke_if_enabled` changes `LiveEnabled -> Revoked` and clears selectability while holding the generation mutex, then publishes the persistent retirement signal after unlocking (`src/proxy.rs:252-268`). Every H2 dispatch takes that same mutex around only the final state check, fixed event, and synchronous Hyper enqueue (`src/proxy.rs:289-308,1531-1548`). Therefore update-first performs no send; enqueue-first performs exactly one send before retirement. There is no await, pool operation, callback, driver join, or body poll under the mutex, and pool/state locks are not nested, so the implemented lock graph has no cycle.

Retirement replaces only the matching monotonic generation ID with a nonselectable slot, keeps that slot through the transport-drop witness, and cannot remove a replacement generation (`src/proxy.rs:1207-1233,1259-1322`). Candidate selection closes after an H2 reservation and never re-enters H1/fresh selection (`src/proxy.rs:2081-2151`). The only dispatch sites remain one H1 call and one gate-wrapped H2 call (`src/proxy.rs:1520-1555`).

Evidence now covers every split of a later SETTINGS frame, a chunked 16,384-byte DATA skip, coalescing, duplicate settings, initial-false/later-one behavior, both mutex orders, creator-before-publication, and stale-ID cleanup (`src/proxy.rs:4885-5087`). Protocol fixtures prove selected-H2 no-downgrade, candidate-before-update connection retirement with sibling failure and no replay, and GOAWAY/REFUSED_STREAM before/after dispatch (`tests/proxy_integration.rs:1174-1388,2010-2067,5055-5253`).

### 4. CLOSED — RFC 8441 accepts only absent or consistently zero Content-Length

The validator now mirrors Hyper's decimal, comma/repetition, overflow, and consistency rules and accepts only no value or a consistent numeric zero (`src/proxy.rs:3232-3260`). Unit evidence covers absent, repeated/combined zero, leading-zero, positive, inconsistent, malformed, and signed forms (`src/proxy.rs:4657-4678`).

A real downstream H2 connection establishes tunnels with both `Content-Length: 0` and an absent field while malformed service-observed handshakes remain stream-local `400` responses (`tests/proxy_integration.rs:863-975`). The raw HPACK fixture separately proves the pinned consistent-nonzero case completes/closes before service/auth/U/upstream while the no-length control reaches all of them and leaves the connection open (`tests/proxy_integration.rs:978-1123,5955-6073`).

### 5. CLOSED — adversarial evidence and report claims now match the executable fixtures

The previously missing classes now have concrete tests:

- real fragmented reads, partial vectored/scalar writes, byte transparency, EOF/connection completion, and no pre-proof application frames: `src/proxy.rs:4744-4868`;
- update/enqueue and creator/publication barriers plus stale generation IDs: `src/proxy.rs:4936-5087`;
- idle and 23-byte near-H2-preface expiry plus one-shot deadline disarm for H1/H2: `src/server.rs:2822-2914`;
- zero-window H2 early-final ownership: `tests/proxy_integration.rs:2610-2718`;
- raw GOAWAY and REFUSED_STREAM before/after dispatch/body with connection, HEADERS, and DATA counters: `tests/proxy_integration.rs:2010-2067,5161-5253`.

The command filters and counts in `test-report.md` match the current test names: 19 focused library/component passes, 32 focused protocol/security passes, and 160 full-suite passes (`test-report.md:32-49,167-290`). The report also records strict Clippy, formatting, release build, all-target check, diff check, and all four locally executable E2Es (`test-report.md:221-324`). The report does not claim the unavailable real-auth fixture ran.

### 6. CLOSED — dynamic hooks are absent from release state, request paths, API, and artifacts

All hook fields, `ServeHooks`, the hook-bearing public entrypoint, arguments, state initialization, and invocation sites are guarded by `#[cfg(debug_assertions)]` (`src/server.rs:104-154,650-698,778-828,879-886,1184-1186,1293-1302`). A release-only exhaustive `AppState` destructure prevents fields from silently remaining (`src/server.rs:123-136`).

The source assertion passes (`src/server.rs:3715-3733`). The fresh report records zero forbidden symbols in both the release rlib and binary and an unresolved release import for the hook API (`test-report.md:142-165,253-274`). This review repeated the read-only symbol scan against those current release artifacts and found no hook entrypoint, type, or field symbol.

## Lens assessment

| Lens | Result | Assessment |
|---|---|---|
| Correctness | **PASS** | Ownership witnesses, initial/ongoing SETTINGS handling, enqueue ordering, exact retirement, zero-length CONNECT, streaming, and all tunnel paths match the reviewed design. |
| Maintainability | **PASS** | Protocol selection, generation state, exchange ownership, and WebSocket translation remain typed and separated; bounded cleanup and lock ordering are explicit and tested. |
| Security | **PASS** | Per-stream auth, fixed routing/TLS identity, credential/identity sanitation, bounded resources, strict tunnel classification, and secret-free logs remain fail-closed. |
| Scope | **PASS** | Only existing dependency features, gateway code/tests/docs, and the compatibility E2E setting changed; no infrastructure, deployment, session/SQLite, auth-policy, or external-repository expansion occurred. |
| Verification | **PASS** | Focused adversarial fixtures, full gates, release checks, and local E2Es passed; the sole skip is accurately bounded to the unavailable pinned real-auth fixture. |

## Repeated correctness and security review

- **Protocol selection and TLS:** exact `auto|http1|http2` parsing and cleartext-auto startup rejection are preserved (`src/config.rs:293-318`). HTTPS ALPN is authoritative; forced H2 requires `h2`, auto accepts only `h2`, `http/1.1`, or no ALPN, and selected H2 never falls back (`src/proxy.rs:1048-1099,2191-2247`). Canonical `UpstreamBase` still supplies connector authority, SNI, certificate identity, and the fixed dial target; the first successful TCP connection remains final.
- **Downstream isolation and auth:** one auto H1/H2 connection future uses finite H2 limits and a first-complete-head-only absolute deadline (`src/server.rs:866-966`). Every delivered H2 stream independently enters route classification, syntax validation, Cookie extraction, authentication, allowlist evaluation, and U admission (`src/server.rs:968-1009,1120-1226`). Anonymous, forbidden, malformed, resolver/U-saturated, and gateway-owned requests do not reach the protected upstream.
- **Authority, headers, cookies, and identity:** downstream H2 scheme/authority/Host consistency is validated (`src/server.rs:1316-1415`). H2 upstream URI authority comes only from configured `UpstreamBase`; H1 retains reviewed public-Host compatibility (`src/proxy.rs:3295-3321`). Cookie, Authorization, Proxy-Authorization, forwarding claims, forged identity, connection-nominated fields, and fixed hop fields are removed before verified metadata is injected; responses remove hop/framing/identity fields and gateway cookies (`src/proxy.rs:3379-3531`).
- **Pool, U, streams, FDs, and cancellation:** the combined pool has at most eight live/retiring owners; published H2 generations retain physical ownership in pool slots, private generations retain U through transport destruction, and each application exchange owns U plus its local/downstream stream leases until both halves or the tunnel end (`src/proxy.rs:1135-1677,2081-2330`). H1 retirement still observes its driver before returning U (`src/proxy.rs:2775-3053`). Cancellation guards relay ownership rather than releasing early.
- **No replay:** selection, readiness, capability, handshake, SETTINGS, GOAWAY, REFUSED_STREAM, reset, stale-generation, and send failures return from the selected path. No code reopens owner/address/protocol selection after reservation, and request bodies are neither cloned nor submitted to a second `send_request`.
- **WebSockets:** ordinary CONNECT and non-`websocket` extended protocols remain rejected; H1 and RFC 8441 request/response validation is strict (`src/proxy.rs:3084-3261,3533-3695`). All h1→h1, h1→h2, h2→h1, and h2→h2 bridges retain D/U/applicable stream ownership through opaque bidirectional I/O. Rejected H2 `200` upgrades drop/reset the upgraded stream before releasing leases and do not retire siblings (`src/proxy.rs:3866-4123`).
- **Observability:** connection-selection, dispatch-selection, failure, retirement, and tunnel events contain only fixed classes, protocol/config values, numeric generation IDs, and booleans (`src/proxy.rs:902-950,1101-1123,1313-1321,1558-1565,2211-2221,2277-2284`). No method, path, authority, address, Cookie, token, identity, WebSocket key, body, or raw library error is logged.
- **Dependencies and rollback:** `Cargo.toml` only enables HTTP/2/server-auto features on existing dependencies; lockfile additions are transitive. Upstream-only rollback remains `UPSTREAM_PROTOCOL=http1` plus restart. Downstream parser/RFC 8441 rollback still requires the previous HTTP/1-only binary. There is no migration or persistent capability state.

## Residual risks and accepted gaps

1. Pinned Hyper 1.10.1 can close a downstream H2 connection and its siblings when CONNECT Content-Length is syntactically valid, consistent, and greater than zero. The raw fixture preserves the reviewed boundary: connection completion/EOF, optional wire reset, and zero service/auth/U/upstream dispatch.
2. A later illegal `SETTINGS_ENABLE_CONNECT_PROTOCOL 1 -> 0` intentionally retires the whole affected upstream generation, so unrelated in-flight siblings on that generation can fail. They are not migrated or replayed; other generations remain independent.
3. Initial `ENABLE_CONNECT_PROTOCOL=false` is monotonic-conservative: a later `1` does not make that generation WebSocket-eligible, although ordinary H2 remains usable.
4. `scripts/e2e-real-auth-mini.sh` was not run because `/tmp/opencode/auth-mini-reference/rust-backend/Cargo.toml` is absent (`test-report.md:326-343`). This is an accurately reported, contract-allowed compatibility gap rather than positive evidence.
5. No production rollout or infrastructure validation exists by design. Changes to pinned Hyper/h2 behavior require renewed review of proof parsing, enqueue semantics, CONNECT handling, and transport ownership.

## Verification and scope conclusion

The fresh report is credible and consistent with the current source, tests, command filters, release artifacts, and workspace diff. This review did not rerun the full suite; it inspected the concrete fixtures and production paths, repeated the release-symbol check, and found no claim/source contradiction or remaining blocker.

The tracked diff remains limited to 13 gateway files: feature activation, configuration/operator text, one real-auth E2E compatibility setting, capacity/config/proxy/server implementation, and proxy integration tests. There is no new direct dependency, deployment change, production enablement, external-system mutation, or scope expansion.

## Gate decision

**PASS.** The implementation is ready to proceed to reviewer-facing delivery evidence under the residuals above.

Review artifact: `.legion/tasks/enable-http2-proxy/docs/review-change.md`
