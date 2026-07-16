# Enable HTTP/2 proxy support

## Goal

Upgrade proxy mode so downstream and protected-upstream traffic supports HTTP/1.1 and HTTP/2, with HTTP/2 preferred by default when the upstream proves that it is available, without weakening authentication, fixed-upstream routing, streaming, or capacity boundaries.

## Problem

The gateway currently compiles Hyper for HTTP/1.1 only, serves downstream connections with the HTTP/1 builder, opens upstream connections with the HTTP/1 handshake, and rewrites every proxied request to HTTP/1.1. This prevents HTTP/2 downstream traffic, HTTP/2 upstream selection, multiplexing, and RFC 8441 WebSocket transport. Adding HTTP/2 also changes connection ownership, protocol negotiation, header rules, and capacity accounting, so a feature-only change would be unsafe.

## Acceptance

- Existing HTTP/1.1 clients and upstreams remain compatible.
- The cleartext listener accepts HTTP/1.1 and HTTP/2 prior-knowledge connections, and every HTTP/2 stream independently passes authentication and allowlist authorization.
- A startup-validated upstream protocol setting supports `auto`, `http1`, and `http2`. HTTPS defaults to `auto` and prefers HTTP/2; cleartext upstreams require an explicit `http1` or `http2` because RFC 9113 provides no side-effect-free in-band discovery.
- HTTPS upstreams select h2 through ALPN and use HTTP/1.1 only when ALPN selects HTTP/1.1 or negotiates no protocol. Certificate and hostname verification remain strict.
- Explicit cleartext `http2` uses h2c prior knowledge and fails closed before application dispatch when HTTP/2 cannot be established. Explicit cleartext `http1` performs no HTTP/2 probe.
- Tests prove the actual protocol used for HTTPS auto h2 and auto h1, forced h2 success/failure, forced h1, cleartext h2c success/failure, and cleartext auto startup rejection.
- Ordinary HTTP covers h1-to-h1, h1-to-h2, h2-to-h1, and h2-to-h2 for existing methods and streaming request/response behavior, including SSE and backpressure.
- HTTP/1.1 WebSocket Upgrade remains compatible; strictly validated RFC 8441 Extended CONNECT works over HTTP/2, including required cross-protocol bridging paths. Ordinary CONNECT remains rejected.
- The upstream pool distinguishes actual protocols and safely supports HTTP/2 multiplexing while bounding TCP connections, active requests, and HTTP/2 streams. `GATEWAY_MAX_ACTIVE_UPSTREAMS` remains an effective upper bound.
- HTTP/1.1 and HTTP/2 hop-by-hop headers, authority, Host, URI, forwarding metadata, credentials, cookies, and forged identity headers are normalized or rejected without allowing client input to change the fixed upstream.
- Anonymous, unauthorized, malformed, or capacity-rejected requests never reach the upstream.
- Logs record the selected upstream protocol without recording sensitive request data.
- Existing tests and relevant E2E scripts remain green; formatting, strict Clippy, full tests, and release build pass.

## Assumptions

- Hyper 1.10.x, hyper-util, hyper-rustls, Tokio, and Rustls expose sufficient HTTP/2, ALPN, h2c prior-knowledge, and extended CONNECT primitives without a new transport stack.
- The gateway continues to proxy to one startup-fixed upstream origin.
- Cleartext protocol choice is operator-provided prior knowledge; the gateway does not attempt in-band h2c discovery.
- Existing downstream, active-upstream, and resolver limits remain the baseline resource controls.

## Constraints

- Keep all existing environment variables compatible; only the new upstream protocol setting defaults to `auto`.
- Reject startup when `auto` is selected for a cleartext upstream, including the default when no explicit protocol value is supplied.
- Do not infer h2c support by sending or replaying an application request, including non-idempotent or streaming requests.
- Do not weaken authentication, authorization, header sanitation, fixed-upstream routing, TLS verification, streaming, or fail-closed behavior.
- Add only the minimum protocol-selection and capacity configuration needed for HTTP/2 correctness.
- Prefer existing Hyper, hyper-util, hyper-rustls, Tokio, and Rustls dependencies; stop before a major dependency or architecture expansion.
- Keep changes inside auth-mini-gateway and do not modify or deploy Nginx, FRP, auth-mini, dotfiles, NixOS, or production infrastructure.

## Risks

- A fallback after dispatch could replay POST, PATCH, uploads, or other non-idempotent requests.
- Treating HTTP/2 like one-request-per-connection could either defeat multiplexing or release capacity before a stream ends.
- Incorrect HTTP/2 authority or hop-by-hop handling could bypass the fixed upstream or leak credentials and identity metadata.
- Extended CONNECT translation could admit generic tunnels, break WebSocket framing, or outlive capacity permits.
- Stale pooled connection generations can evict a healthy replacement or cause unsafe fallback after protocol failure.
- Connection-driver ownership and shutdown changes could strand tasks or terminate active streams.

## Scope

- Cargo HTTP/2 features and the minimum protocol configuration surface.
- Downstream HTTP/1.1 and HTTP/2 prior-knowledge serving.
- Upstream TLS ALPN, explicit cleartext h2c prior knowledge, protocol-aware pooling, and safe connection-generation invalidation.
- HTTP/2-aware request/header translation, streaming bodies, SSE, and capacity ownership.
- HTTP/1.1 Upgrade and RFC 8441 WebSocket validation and bridging.
- Focused unit/integration fixtures plus existing relevant E2E coverage.
- Minimal operator documentation for the new protocol setting; no production enablement.

## Non-goals

- HTTP/3, QUIC, WebTransport, arbitrary TCP tunneling, generic CONNECT proxying, or gRPC-specific authentication.
- Production rollout or changes to Nginx, FRP, auth-mini, OpenCode, NixOS, or external repositories.
- Unrelated session, SQLite, cookie, refresh, DNS, TLS, logging, graceful-shutdown, or trailer refactors.
- Dynamic upstream selection, multi-origin routing, or weakening existing capacity defaults.

## Design Summary

- Use Hyper's protocol-aware downstream server path and protocol-specific upstream handshakes selected before request dispatch.
- Make HTTPS selection authoritative from ALPN and cleartext selection authoritative from explicit operator configuration; require valid peer HTTP/2 SETTINGS before application dispatch.
- Pool HTTP/1.1 as exclusive request connections and HTTP/2 as multiplexed senders with separate connection and stream ownership, while preserving active-request admission.
- Translate request targets and headers according to the selected protocol while deriving authority exclusively from configured upstream data.
- Bridge only validated WebSocket transports and retain permits through the full stream or tunnel lifetime.

## Design Index

> **Design source of truth**: `docs/rfc.md` after adversarial review.

## Phases

1. Contract and design: inspect current protocol, pool, capacity, header, and WebSocket boundaries; specify and review the no-replay design.
2. Implementation: add protocol configuration, downstream/upstream HTTP/2, protocol-aware pooling, and WebSocket bridging with focused tests.
3. Verification: run targeted matrices, existing suites, E2E scripts, strict Clippy, formatting, and release build.
4. Review and delivery: readiness/security review, walkthrough, wiki writeback, PR follow-up, merge, cleanup, and baseline refresh.

---

*Created: 2026-07-16 | Last updated: 2026-07-16*
