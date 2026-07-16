# Focused RFC re-review: ongoing RFC 8441 SETTINGS revocation

**RFC design gate: PASS**

This is a focused design gate for `review-change.md` finding 3. It approves the latest RFC treatment of a later upstream `SETTINGS_ENABLE_CONNECT_PROTOCOL` effective transition from accepted `1` to `0`. It does not approve the current implementation or clear any other `review-change` finding.

## Review basis

- Stable contract: `../plan.md`
- Current design: `rfc.md`
- Trigger: `review-change.md`, finding 3
- Pinned behavior: Hyper 1.10.1 with h2 0.4.14
  - h2 `frame/settings.rs:128-204` validates SETTINGS framing and values, retains the last duplicate parameter value, and accepts only `0|1` for ID `0x8`.
  - h2 `proto/streams/send.rs:469-479` directly assigns every later effective extended-CONNECT value and does not reject `1 -> 0`.
  - Hyper `client/conn/http2.rs:150-170` implements `send_request` as a synchronous dispatch-channel enqueue that returns a future; response awaiting and body polling happen later.
- Protocol basis: RFC 8441 says a sender MUST NOT send value `0` after previously sending `1`, but does not prescribe a specific receiver action for that violation. Connection retirement is therefore an explicit gateway fail-closed policy, not a claimed automatic Hyper/h2 or RFC-mandated error.

## Finding 3 closure

The prior design was unsafe because it stopped observing inbound frames after initial proof, stored an immutable true capability, and incorrectly assumed pinned h2 would fail a later `1 -> 0`. The corrected RFC no longer relies on that assumption. It keeps the same plaintext-I/O observer attached for the connection lifetime, detects an effective later zero itself, atomically prevents further generation use, and actively retires that exact connection.

This closes the design gap identified by finding 3. Implementation and deterministic evidence are still required before the change can pass `review-change`.

## Continuous observer and memory bound

The scanner is implementable as the specified fixed-cursor state machine:

- It retains one 9-byte frame-header scratch, one 6-byte SETTINGS-pair scratch only while needed, a 24-bit-length-compatible `u32` remaining counter, the frame's last ID `0x8` value, and scalar state. Retained wire data is bounded at 15 bytes and does not grow with peer payload size.
- It parses only newly read plaintext bytes before exposing the unchanged bytes to Hyper. Header and setting-pair cursors naturally survive arbitrary fragmentation; a loop over one read naturally handles arbitrary coalescing.
- Once a non-SETTINGS frame header is complete, the scanner can decrement the remaining count across any number of reads without copying DATA, HEADERS/CONTINUATION, unknown-frame, or padding bytes. The 24-bit wire length is bounded and cannot overflow the `u32` counter.
- For a non-ACK stream-0 SETTINGS frame with length divisible by six, pairs are interpreted incrementally and only the frame's final effective ID `0x8` value is applied after the complete frame. This matches pinned h2's duplicate-setting behavior.
- Frames with illegal size, stream, ACK payload, setting value, or other semantics remain Hyper/h2's responsibility. The observer need not call such a frame legal or duplicate the HTTP/2 state machine; it only preserves framing long enough to obtain the capability witness.
- The scanner begins during initial proof and must consume bytes coalesced after the first SETTINGS in the same read. It therefore has no detach/remainder gap in which a revocation can be lost.

The verification requirement to precede fragmented/coalesced revocation with a large legal non-SETTINGS frame is credible. The test must choose a payload legal under the connection's negotiated frame-size limit; `16_777_215` is the wire-field maximum, not an unconditional peer allowance. This is an implementation/test constraint, not a design blocker.

## Revocation, exact generation, and retirement

The shared `GenerationControl` provides a complete fail-closed transition:

1. Initial true installs `LiveEnabled`. A later complete SETTINGS with effective ID `0x8 = 0` takes the generation mutex, changes `LiveEnabled -> Revoked`, and stores the generation's selectability bit false before releasing the mutex.
2. A candidate that was reserved using a stale true atomic bit must still take the same mutex before dispatch and therefore observes `Revoked`; atomic selectability is an optimization, not the sole authority.
3. After releasing the mutex, the observer publishes the persistent watch signal. The supervisor changes only the matching monotonic generation ID to a nonselectable retiring slot, drops/cancels that generation's master sender and connection future, and retains pool/FD accounting until the physical transport-close witness completes.
4. The I/O wrapper also fails subsequent reads/writes after revocation, so a missed wake or otherwise idle codec cannot keep the transport live indefinitely.
5. Stale completion or notification for G cannot remove or mutate G+1. Other pool generations are not retired.
6. Existing ordinary requests, WebSockets, and siblings on G may fail because the violation is connection-scoped. They clean up through their existing ownership paths and are never migrated, retried, replayed, or sent through idle H1.

This intentionally broad G-local blast radius is consistent with the stable contract: the gateway is choosing connection retirement for a connection-scoped peer capability violation, while gateway-observed and ordinary upstream stream failures remain stream-local.

## Candidate/update linearization

The generation mutex is a valid linearization primitive because every H2 dispatch, not only WebSocket dispatch, checks it immediately before the one enqueue:

- Ordinary H2 is admissible only in `LiveDisabled | LiveEnabled`; Extended CONNECT is admissible only in `LiveEnabled`; all dispatch is rejected in `Revoked | Retiring | Closed`.
- The request, dispatch kind, routing, and sanitized headers are complete before locking.
- While locked, the path performs only the final state check, fixed dispatch-event emission, and Hyper's synchronous `send_request(request)` enqueue. Pinned Hyper source confirms this call places the request on its dispatch channel and constructs the response future; it does not await a response or poll the request body.
- The mutex is released before awaiting the response future and before body, upgrade, cleanup, pool, driver, or transport work.

The two race outcomes are therefore well-defined:

- **Update first:** state becomes `Revoked` and selectability becomes false; the selected WebSocket returns pre-dispatch `502`, emits no dispatch, and cannot inspect or fall through to H1.
- **Candidate first:** exactly one send is enqueued on G while `LiveEnabled`; the later update revokes and retires G, so that stream and G siblings fail normally without replay, migration, or fallback.

No async deadlock or lock cycle is required by the design. Pool selection releases the pool lock before taking the generation mutex. Creator publication uses the no-poll/no-await gap and does not need nested state/pool locks. Revocation releases the state mutex before watch publication, pool mutation, cancellation, join, or transport waiting. A standard mutex is appropriate in the synchronous I/O poll path because every holder is bounded and contains no await. Implementation must keep dispatch-event emission non-reentrant and must not route it through arbitrary release-path callbacks while the gate is held.

## Initial state, creator publication, and normal traffic

- Initial false installs `LiveDisabled`. A later `1` deliberately does not upgrade gateway eligibility, so the generation remains usable for ordinary H2 but cannot carry Extended CONNECT. This is conservative and safe even though pinned h2's current accessor changes.
- Initial true is accepted only after the existing same-connection SETTINGS/ACK proof agrees with Hyper. A revocation coalesced into that proof read is recorded before publication and prevents publication/dispatch.
- Between the creator's final state check, pool insertion, and driver spawn, the private connection is not polled and no await occurs; new peer bytes therefore cannot create an unobserved publication race.
- Creator sender/permit reservation still precedes publication, the published semaphore still exposes only remaining capacity, selected H2 never downgrades to H1, and ordinary H2 traffic retains the existing capacity, exact-ID, streaming, and stream-failure invariants.
- No detached capability cache, second probe connection, new transport stack, or new direct dependency is introduced. `Arc`, `std::sync::Mutex`, atomics, and Tokio watch are available in existing dependencies/features.

## Deterministic verification adequacy

The RFC now requires evidence capable of distinguishing every safety-relevant order:

1. Feed later SETTINGS across every split of the 9-byte header and 6-byte pair, coalesce adjacent frames, place a large legal non-SETTINGS payload before it, and prove byte transparency, final-value semantics, and fixed parser storage.
2. Hold barriers at the shared gate so update-before-candidate deterministically proves G nonselectable, pre-dispatch `502`, zero send, and untouched idle H1.
3. Hold the candidate side first so candidate-before-update deterministically proves one enqueue on G followed by G retirement, with no fallback, migration, or second body/send sequence.
4. Keep controlled siblings on G and traffic on G+1; prove G siblings fail/clean up, G+1 remains live, a retiring slot remains through actual transport close, and stale G signals cannot evict G+1.
5. Exercise revocation coalesced before creator publication and prove no sender becomes pool-visible.
6. Prove initial-false plus later-1 remains ordinary-H2-capable but Extended-CONNECT-ineligible.

These are implementation acceptance requirements, not evidence already supplied by the current test report. Finding 5 remains unresolved until the fixtures are implemented and executed.

## Stable-contract and rollback preservation

- Strict RFC 8441 request/response validation, ordinary CONNECT rejection, authentication, fixed-upstream authority, TLS identity, header/Cookie/credential sanitation, tunnel lifetime, and capacity ownership remain unchanged.
- Candidate selection remains final and there is still exactly one dispatch call. Revocation introduces neither H1 downgrade nor another address/generation attempt.
- Upstream-only rollback remains `UPSTREAM_PROTOCOL=http1` plus restart, which removes upstream H2 generations and this monitor from traffic. Full previous-binary rollback remains available for broader downstream/RFC 8441 regressions. No persistent state or migration is introduced.

## Focused blockers

None.

## Residual risks and implementation watchpoints

1. A violating peer can terminate every in-flight stream on G, including unrelated ordinary requests. This is an intentional connection-local availability cost; unrelated generations must remain live.
2. Initial false is monotonic-conservative: a later legitimate `1` does not enable WebSockets on that generation. This can reduce availability but cannot create unauthorized Extended CONNECT.
3. Correctness depends on retaining the observer for the whole plaintext connection and keeping its frame cursor byte-transparent. Any implementation that stops after initial proof, buffers payload-sized data, or loses coalesced remainder must return to design review.
4. Correctness also depends on the gate covering the actual synchronous enqueue and on transport accounting lasting through physical close. Moving an await/body poll under the mutex, moving enqueue outside it, nesting it with pool/retirement locks, or signaling transport close early is not an allowed implementation variation.
5. Hyper/h2 upgrades require renewed review of SETTINGS parsing, current-capability behavior, send enqueue semantics, and connection cancellation. The RFC correctly does not claim that RFC 8441 mandates the chosen receiver-side close.

## Explicitly unresolved implementation-review findings

This focused PASS does not make the delivery ready. `review-change.md` remains FAIL until all of the following are corrected and re-verified:

- **Finding 1:** request/U/stream ownership can finish before Hyper sends or discards the upload.
- **Finding 2:** the transport-drop witness currently signals before the physical transport field is dropped.
- **Finding 3 implementation:** the approved ongoing observer, shared gate, exact-generation retirement, and tests do not yet exist in the reviewed implementation.
- **Finding 4:** valid consistently parsed `Content-Length: 0` Extended CONNECT is rejected contrary to the RFC.
- **Finding 5:** the verification report overstates evidence and lacks mandatory deterministic fixtures, including the new revocation matrix.
- **Finding 6:** integration-test hooks remain in the release request path.

## Gate result

**PASS — the latest RFC supplies an implementable, bounded, race-linearized, no-replay design for ongoing `SETTINGS_ENABLE_CONNECT_PROTOCOL` revocation. Return to engineer for implementation and all unresolved source findings, then to verify-change; do not treat this focused RFC PASS as delivery approval.**
