# RFC verification-scope re-review

> **Reviewed:** 2026-07-15
> **Inputs:** stable `plan.md`, revised `docs/rfc.md` verification/release sections, retained in-repository tests, and prior RFC review
> **Verdict:** **PASS**

## Gate decision

The scope correction removes the RFC's self-created exhaustive conformance gate without weakening the approved runtime security/protocol design or dropping a user-mandated acceptance outcome. No blocking finding remains.

The mandatory release gate is now correctly limited to:

1. the exact 18 automated outcomes in RFC §16.2;
2. preservation and execution of all existing in-repository tests through mandatory `cargo test`; and
3. the four exact Cargo commands from the stable plan.

Environment-dependent composed systems and completeness of extended adversarial permutations remain valuable evidence, but are no longer hidden additional acceptance outcomes.

## Findings

### 1. The exact 18 user outcomes remain covered — PASS

The mandatory matrix maps to the stable contract without adding a nineteenth outcome:

- adapter unknown-route compatibility: outcome 1;
- `/auth/check` allow/unauthenticated/forbidden behavior: outcome 2;
- authenticated GET and required POST/PUT/PATCH/DELETE preservation: outcomes 3–4;
- unauthenticated and forbidden upstream isolation: outcomes 5–6;
- spoofed identity, Cookie stripping, and verified-session identity source: outcomes 7–9;
- large non-buffered body, chunked response, and SSE: outcomes 10–12;
- authenticated and unauthenticated WebSocket behavior: outcomes 13–14;
- sanitized unreachable-upstream `502`: outcome 15;
- gateway-owned route isolation: outcome 16;
- retained refresh/logout behavior: outcome 17; and
- secret-free logging: outcome 18.

Outcome 16's inline list names five owned routes rather than repeating `/auth/check`. This is not an actual omission because outcome 2 directly exercises `/auth/check`, and mandatory `cargo test` retains `every_gateway_owned_route_and_unsupported_method_isolated_from_proxy`, which covers all six paths with zero upstream hits (`tests/proxy_integration.rs:280-320`). Adding `/auth/check` to outcome 16's prose would improve readability but is not a release blocker or a missing test.

### 2. Existing coverage remains mandatory — PASS

RFC §§16.1, 16.3, 19, and 21 consistently require existing in-repository tests to remain present and passing:

- `cargo test` is mandatory, not advisory.
- Existing defense-in-depth tests cannot be deleted merely because they exceed the 18-outcome matrix.
- Any retained framing, no-retry, admission, WebSocket, compatibility, or race test failure remains a mandatory Cargo-test failure.
- The current integration suite already retains first-chunk large-upload gating, chunked request/response checks, all-six owned-route isolation, Expect timing, framing anti-desynchronization, no-retry pooling, and WebSocket hardening. The scope correction changes release accounting, not those protections.

This preserves runtime assurance while avoiding the prior requirement to automate every cross-product permutation.

### 3. Mandatory commands are exact — PASS

RFC §21 contains exactly the four commands required by `plan.md`, with unchanged arguments:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release --bin auth-mini-gateway
```

No script is presented as a hidden fifth mandatory command. The test report must record all four, the commit, and an evidence mapping for all 18 outcomes.

### 4. Environment-dependent and extended evidence is classified correctly — PASS

- `scripts/e2e-real-auth-mini.sh` depends on the expected external auth-mini checkout/commit. Missing or mismatched `AUTH_MINI_RUST_DIR` is correctly recorded as an environment limitation, not a gateway product failure.
- Proxy-mode, mode-switch, old-binary, WAL, and real-auth-mini scripts should run when their documented prerequisites are present. A runnable script that exposes a defect must still be fixed; it cannot be relabeled as a skip.
- Physical/simulated Acorn maintenance-deny and FRP `7780`/`7781` switching are appropriately composed/deployment evidence rather than universally runnable CI requirements. The rollout and rollback design itself remains normative.
- Exhaustive CL/TE, trailer, pipelining, saturation, stale-connection, WebSocket-malformation, TLS-variant, and failure-provenance cross-products are correctly categorized as extended hardening. Already-retained examples remain mandatory through `cargo test`; only completeness of every additional permutation is non-blocking.

### 5. Runtime security and protocol design are unchanged — PASS

The scope correction changes evidence accounting only. It does not weaken:

- Hyper-owned HTTP parsing/framing and fresh cross-proxy framing;
- hop-by-hop, Cookie, Authorization, forwarding, and spoofed-identity stripping;
- fixed startup-only upstream selection;
- shared authentication/refresh/policy/touch semantics;
- streaming, SSE, chunked reframing, backpressure, cancellation, and unread-body close behavior;
- one-attempt/no-retry pooling;
- strict fallback-only WebSocket validation;
- bounded blocking admission;
- sanitized gateway-visible failures; or
- fail-closed deployment and rollback topology.

## Residual risks

1. Missing external auth-mini or physical FRP prerequisites reduce composed-environment evidence for that run; the limitation must be explicit in the report.
2. The exact 18 outcomes are intentionally not an exhaustive protocol conformance suite. Assurance for broader permutations depends on retained tests, targeted hardening, dependency review, and future regression additions.
3. Outcome 16 should eventually name `/auth/check` explicitly for editorial clarity, even though mandatory outcome 2 and the retained all-six isolation test already cover it.
4. This is a design/scope PASS only. Release still requires actual passing command output and an 18-outcome evidence map.

## Final decision

**PASS.** The revised verification scope matches the stable user contract, preserves all existing mandatory tests, keeps the four commands exact, and correctly separates environment-dependent or extended hardening from product-blocking acceptance.
