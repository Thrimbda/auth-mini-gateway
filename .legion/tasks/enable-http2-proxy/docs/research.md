# Research: HTTP/2 proxy boundaries

> **Scope:** `origin/master` at `28a4a27`; read-only code, test, current crate source, Context7, RFC 8441, and RFC 9113 research. No production code was changed.

## Problem restatement

Proxy mode is HTTP/1.1-only on both sides. The requested change is not a feature-flag-only upgrade: HTTP/2 adds multiplexed request ownership, protocol-specific authority/header rules, per-stream authorization, and RFC 8441 tunnels while the existing pool owns one exclusive HTTP/1 sender and driver per active exchange.

## Current boundaries

| Area | Current behavior | Evidence |
|---|---|---|
| Cargo | Hyper and hyper-rustls enable HTTP/1 only; hyper-util provides Tokio adapters only. | `Cargo.toml:15-17` |
| Downstream | Each accepted socket is served by `http1::Builder` with upgrades, 100 headers, and a 10-second header timeout. | `src/server.rs:669-697` |
| Per-request security | Owned routes are classified first. Every proxy fallback independently performs validation, authentication, allowlist authorization, and identity construction before upstream admission. | `src/server.rs:699-713,807-903,960-989` |
| Upstream request | The fixed path is composed, every request is forced to HTTP/1.1, and browser credentials/identity/forwarding/hop fields are sanitized before one send attempt. | `src/proxy.rs:233-348,1227-1275` |
| Connection | DNS/TCP/TLS and `http1::handshake` run under U/R ownership; hyper-rustls enables only HTTP/1. | `src/proxy.rs:351-414` |
| Pool | One popped `CompleteOwner` contains one exclusive HTTP/1 sender plus driver. Clean EOS parks it in the eight-entry pool; other paths observe driver retirement before U returns. | `src/proxy.rs:104-120,859-1125` |
| Streaming | Request and response bodies are polled frame-by-frame; trailers are dropped; early final responses cancel upload polling. | `src/proxy.rs:1668-1883` |
| WebSocket | Only HTTP/1 GET Upgrade and upstream `101` are accepted; the guarded bridge owns D, U, sender/driver, and both upgraded streams. | `src/proxy.rs:1156-1218,1377-1666` |
| Capacity | D bounds accepted TCP sockets, U bounds active upstream exchanges, R bounds blocking resolution, and the FD budget is `D + U + 8 + listener + reserve`. | `src/capacity.rs`, `src/runtime_plan.rs:56-81` |

The destination boundary is already suitable for protocol work: `UpstreamBase` separately retains canonical configured scheme/authority/path and a typed dial target, so request Host, URI, forwarding data, and HTTP/2 pseudo-fields need not enter DNS, TCP, TLS SNI, or pool keys (`src/config.rs:44-90,267-297`).

## Current API and protocol evidence

- `hyper_util::server::conn::auto::Builder` can distinguish HTTP/1 from an exact HTTP/2 prior-knowledge preface and can serve HTTP/1 upgrades plus HTTP/2 on one cleartext listener.
- Its HTTP/2 builder exposes `enable_connect_protocol()` for RFC 8441. Its 24-byte version detector has no timeout, so a swap must preserve the current 10-second protection against a slowly delivered matching preface.
- Hyper HTTP/2 `SendRequest` is cloneable and one driver serves many streams. Its public `ready()` only checks whether the dispatch channel is closed; it is not peer-protocol proof or a stream-capacity permit.
- Hyper's HTTP/2 client handshake returns after sending the client preface and initial SETTINGS. It explicitly does not wait for the server's initial SETTINGS.
- A polled Hyper HTTP/2 `Connection` exposes peer `SETTINGS_ENABLE_CONNECT_PROTOCOL` and current stream settings. Hyper converts successful Extended CONNECT streams to `Upgraded` I/O, so the existing opaque bidirectional bridge can remain the data path after protocol-specific handshake validation.
- hyper-rustls can offer h2 only or `[h2,http/1.1]`; Rustls exposes the selected ALPN. This provides authoritative HTTPS selection without an application request and without changing certificate or SNI verification.
- RFC 8441 requires peer opt-in through `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`, CONNECT plus `:protocol=websocket`, `:scheme`, `:path`, and `:authority`; it forbids HTTP/1 Connection/Upgrade/Key/Accept fields on the HTTP/2 handshake.
- RFC 9113 section 3.3 states that HTTP/2 support for cleartext `http` origins can only be learned out of band and then used as prior knowledge. The former h2c Upgrade discovery mechanism is deprecated.

Context7 was queried on 2026-07-16 for Hyper 1.10.1, hyper-util, hyper-rustls, Tokio, Rustls, HTTP/2 handshakes, ALPN, h2c, and Extended CONNECT. Pinned crate source confirmed the exact APIs above. Rust LSP was attempted but no LSP server is installed in this workspace.

## Implementable design surfaces

The following parts have no unresolved API blocker:

- Enable the existing crates' HTTP/2 and server-auto features without adding a transport dependency.
- Add strict `auto | http1 | http2` startup configuration.
- Serve downstream HTTP/1 and HTTP/2 prior knowledge while retaining one D lease per TCP connection and one auth decision per stream.
- Use HTTPS ALPN: h2 is authoritative when selected; forced h2 fails closed when not selected; no failure after h2 selection falls back or replays.
- Split the pool into exclusive HTTP/1 owners and bounded shared HTTP/2 owners. U remains per application exchange/stream, while the eight-entry owner budget bounds idle/shared TCP drivers.
- Build HTTP/2 request URI scheme/authority only from `UpstreamBase`; remove regular Host and preserve public authority only in regenerated `X-Forwarded-Host`. HTTP/1 retains its existing external Host behavior.
- Canonically combine repeated HTTP/2 Cookie fields for gateway authentication, then remove them before upstream access.
- Translate and validate all four WebSocket paths: h1/h1, h1/h2, h2/h1, and h2/h2. Ordinary CONNECT and non-WebSocket protocols remain local failures.
- Keep streaming bodies and SSE as Hyper bodies. A shared HTTP/2 driver must never be aborted when one stream ends or fails.
- Preserve one send boundary: protocol selection completes while the user body is unsent and unpolled; exactly one protocol-specific send consumes it; later failures only invalidate future connection use.

## Cleartext auto blocker

No generally safe mechanism satisfies all current cleartext requirements:

1. A client cannot receive HTTP/2 proof before first sending the HTTP/2 prior-knowledge preface.
2. Sending `PRI * HTTP/2.0...` is an optimistic protocol attempt, not RFC 9113 discovery. Most HTTP/1 servers reject it before application dispatch, but the standard does not guarantee that every protected application or intermediary treats it as side-effect-free.
3. Waiting for a valid server SETTINGS/ACK can prove a live peer is HTTP/2 before the user's request is sent, but it cannot remove the probe's possible HTTP/1 application visibility.
4. EOF, reset, timeout, or malformed bytes cannot prove that an origin permanently lacks HTTP/2 rather than experiencing a connection failure or heterogeneous backend selection.
5. A separate probe connection followed by a real connection introduces a time-of-check/time-of-use gap; binding both to one address still cannot prove the next accepted connection has identical protocol support.
6. A synthetic HTTP/1 OPTIONS/h2c Upgrade probe is itself an application request, the upgrade mechanism is deprecated, and prior-knowledge-only HTTP/2 servers need not support it.

Therefore the original strict cleartext-auto contract triggered the stop rule. Implementing an optimistic preface probe would require weakening “side-effect-free and confirmed unsupported.”

## Resolved contract decision

- The user selected the standards-aligned out-of-band policy on 2026-07-16.
- HTTPS defaults to `auto`; ALPN authoritatively selects h2 or HTTP/1.1.
- Cleartext upstreams must explicitly select `http1` or `http2`. `auto`, including an omitted setting that defaults to `auto`, is rejected at startup for a cleartext upstream.
- Explicit cleartext `http2` is operator-provided prior knowledge. The gateway still waits for valid peer HTTP/2 SETTINGS before exposing the application request.
- Explicit cleartext `http1` sends no HTTP/2 preface or probe.

This resolves the design blocker without adding probe traffic or weakening the no-replay boundary. It intentionally replaces the original cleartext-auto acceptance criterion.

## Test baseline and required evidence

The existing integration suite strongly covers HTTP/1 methods, fixed routing, header/cookie sanitation, large streaming uploads, streaming responses, SSE, TLS identity, stale-pool no replay, D/U/R lifetime, and HTTP/1 WebSockets (`tests/proxy_integration.rs`). It records no request version, ALPN, connection identity, or stream concurrency.

If the blocker is resolved, minimum new evidence is:

- actual h1-to-h1, h1-to-h2, h2-to-h1, and h2-to-h2 versions for ordinary methods and streaming;
- HTTPS auto h2, auto h1, forced h1, and forced h2 success/failure;
- explicit cleartext h1/h2 behavior, cleartext-auto startup rejection, and zero user-request replay;
- mixed allowed/anonymous/denied streams on one downstream HTTP/2 connection;
- one multiplexed upstream connection with U saturation and sibling-stream survival;
- HTTP/2 authority, split Cookie, hop-header, credential, forwarding, and identity sanitation;
- all four WebSocket bridges, missing RFC 8441 settings, malformed Extended CONNECT, and ordinary CONNECT rejection;
- slow-preface timeout, GOAWAY/reset no replay, selected-protocol logging, full existing suites, and relevant E2E scripts.

## References

- Contract: `.legion/tasks/enable-http2-proxy/plan.md`
- Historical invariants: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`
- Current implementation: `Cargo.toml`, `src/config.rs`, `src/server.rs`, `src/proxy.rs`, `src/runtime_plan.rs`
- Current integration coverage: `tests/proxy_integration.rs`, `scripts/e2e-*.sh`
- Hyper 1.10.1 and pinned ecosystem source under the local Cargo registry
- RFC 9113 sections 3.3-3.4
- RFC 8441 sections 3-5
