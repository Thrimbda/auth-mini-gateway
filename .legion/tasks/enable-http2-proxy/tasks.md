# Enable HTTP/2 proxy support - Task checklist

## Quick Resume

**Current phase**: Review and delivery
**Current item**: Produce walkthrough, wiki writeback, and PR delivery
**Progress**: 7/8 tasks complete
---

## Phase 1: Contract and design

- [x] Materialize the stable HTTP/2 proxy task contract. | Acceptance: plan.md defines goal, acceptance, scope, non-goals, constraints, risks, direction, and phases.
- [x] Inspect current protocol features, downstream serving, upstream handshakes/pool, capacities, headers, WebSockets, and tests. | Acceptance: research evidence identifies concrete ownership and API boundaries without expanding scope.
- [x] Write and adversarially review the high-risk RFC. | Acceptance: RFC resolves ALPN/h2c no-replay selection, protocol-aware pooling, capacities, headers, RFC 8441 bridging, failure semantics, tests, and rollback; review records PASS.
---

## Phase 2: Implementation

- [x] Implement protocol configuration and downstream/upstream HTTP/2 selection. | Acceptance: auto/http1/http2 semantics and h1/h2 protocol paths match the reviewed RFC.
- [x] Implement protocol-aware pooling, capacities, header translation, and WebSocket bridging. | Acceptance: multiplexing, streaming, security, and full-lifetime permit ownership are correct.
- [x] Add focused protocol, streaming, authorization, capacity, and WebSocket regression tests. | Acceptance: tests prove actual selected protocols and all required cross-protocol paths.
---

## Phase 3: Verification

- [x] Run required targeted, full, E2E, formatting, Clippy, and release-build checks. | Acceptance: test-report.md records commands and PASS evidence or a precise blocker.
---

## Phase 4: Review and delivery

- [ ] Complete readiness review, walkthrough, wiki writeback, PR lifecycle, cleanup, and main refresh. | Acceptance: review PASS; delivery evidence exists; PR reaches terminal state; workspace is cleaned and refreshed.
---

## Discovered Tasks

(None)
---

*Last updated: 2026-07-17*
