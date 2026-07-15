# Security-focused implementation re-review

> Reviewed: 2026-07-15
> Base: `origin/master` / `3e4c273` plus authenticated-proxy changes
> Security lens: applied
> Verdict: **PASS**

## Gate decision

No blocking finding remains. Code inspection confirms that all prior blockers and the plain-HTTP root initialization defect were corrected without weakening authorization, header/cookie policy, fixed-upstream routing, TLS validation, streaming, no-replay behavior, or adapter compatibility.

## Resolved blockers

### Early upstream final cancellation

Each upload now has shared completion/cancellation state. An upstream response before request EOS cancels further downstream body polling, forces downstream close, and makes the upstream lease non-reusable. The focused raw test proves prompt `413`, no later forwarded bytes, no affected-connection reuse, and successful use of a fresh connection.

### Non-ASCII identity parity

Adapter and proxy identity headers use `HeaderValue::from_bytes` after the same safety predicate. `/auth/check` cannot return `204` after accepting an identity without serializing the required user-ID header. Integration coverage proves byte-identical UTF-8 identity headers in adapter and proxy modes.

### WebSocket nominated fields

Client nomination of required WebSocket request fields fails locally with `400` before upstream dispatch. Upstream `101` nomination of required or selected response fields fails with sanitized `502` before downstream `101` commitment or tunnel creation. Canonical authenticated bidirectional WebSockets remain green.

### HTTP root initialization

Plain HTTP upstream initialization no longer loads or requires native TLS roots. HTTPS still requires validated roots and has no insecure verifier or downgrade path. Trusted-certificate success and untrusted-certificate `502` are covered.

## Security view

| Area | Result |
|---|---|
| Shared auth decision, refresh, exact allowlists, touch/clear | **PASS** |
| Safe return target and one-time login state | **PASS** |
| Identity spoofing and verified injection | **PASS** |
| Cookie, Authorization, and token stripping | **PASS** |
| Response cookie namespace and repeated headers | **PASS** |
| Fixed and Connection-nominated hop-by-hop fields | **PASS** |
| Original Host and regenerated forwarding metadata | **PASS** |
| Static upstream URI, DNS/TCP target, TLS and SNI | **PASS** |
| Streaming, backpressure, cancellation and early final | **PASS** |
| Connection reuse and no automatic replay | **PASS** |
| Expect/unread-body close behavior | **PASS** |
| WebSocket validation and tunnel | **PASS** |
| Sanitized errors and secret-free logs | **PASS** |
| Bounded blocking executor | **PASS** |
| Adapter compatibility | **PASS** |
| Fail-closed deployment topology | **PASS with residual deployment evidence** |

## Verification

```text
cargo fmt --check                                        PASS
cargo clippy --all-targets --all-features -- -D warnings PASS
cargo test                                               PASS (55 unit, 13 integration)
cargo build --release --bin auth-mini-gateway            PASS
git diff --check origin/master                            PASS
```

The early-final lifecycle test also passed 20 consecutive focused runs.

## Residual risks

1. The pinned external auth-mini checkout is unavailable, so its composed script was not rerun. Repository refresh/logout/state-machine and real-binary tests are green.
2. Physical Acorn maintenance-deny and FRP `7780`/`7781` switching were not executed. Deployment must prove ports `3000` and `4096` have no public/FRP route.
3. Bytes already written before an early final response is observed cannot be retracted; cancellation prevents subsequent polling and reuse.
4. Established WebSockets remain authorized at handshake and survive later logout, as accepted.
5. `X-Forwarded-For` represents the direct gateway peer, not an asserted browser address through an unconfigured trust chain.
6. Detailed proxy/admission observability remains less complete than RFC recommendations, but logs are secret-safe and client errors are sanitized.

## Final verdict

**PASS.** No remaining exploitable trust-boundary defect or compatibility regression was found.
