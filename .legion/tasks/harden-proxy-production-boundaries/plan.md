# Harden proxy production boundaries

## 目标

Close the production availability, header-alias, overload, deployment, and trusted-proxy gaps found after the authenticated reverse proxy launch.

## 问题陈述

Moving application proxying from node-local nginx into auth-mini-gateway removed nginx connection limits and exposed new transport and deployment responsibilities. The current gateway has unbounded downstream and active upstream lifetimes, exits on recoverable accept errors, permits underscore header aliases that some applications normalize into protected identity names, maps second-stage login admission overload to a cookie-clearing 500, documents the wrong Acorn/FRP chain without a deployable proxy-mode nginx example, and cannot preserve client IP through a explicitly trusted FRP peer.

## 验收标准

- [ ] Downstream connection concurrency is globally bounded across HTTP keep-alive, request/response streaming, SSE, and the full WebSocket bridge lifetime; saturation cannot create unbounded tasks or file descriptors.
- [ ] Active upstream exchanges/connections are independently bounded through response-body or WebSocket completion, leaving capacity for gateway-owned control routes; saturation returns a sanitized 503 with Retry-After and no automatic request replay.
- [ ] Recoverable listener accept failures including file-descriptor exhaustion use bounded backoff and retry instead of terminating the process or spinning.
- [ ] Proxy fallback rejects request header names containing underscores before authentication or upstream access, returning a sanitized 400; forged underscore aliases cannot reach the application.
- [ ] Unauthenticated proxy handling performs authentication decision and login-state creation under one bounded admission or otherwise maps admission overload to cookie-neutral 503 with Retry-After; overload never becomes a cookie-clearing 500.
- [ ] Optional trusted-proxy configuration defaults to trusting nobody. Inbound X-Forwarded-For is ignored for untrusted direct peers; trusted peers may supply strictly parsed client-IP metadata that is regenerated for the upstream and never affects authentication, authorization, return targets, or upstream selection.
- [ ] Production documentation includes the exact Acorn nginx to Acorn 127.0.0.1:18081 to FRP to Axiom gateway 127.0.0.1:7780 to OpenCode 127.0.0.1:4096 chain and a directly usable proxy-mode nginx configuration.
- [ ] The Acorn nginx example sends every path to the gateway, preserves browser Cookie, forwards Host and external protocol, supports WebSocket, SSE, streaming uploads, and long-running requests, and does not use auth_request or clear Cookie.
- [ ] Existing adapter/proxy authentication, session, refresh, logout, streaming, SSE, WebSocket, no-replay, header sanitation, and cookie-format behavior remains compatible.
- [ ] Automated tests cover connection saturation and release, long-lived permit ownership, accept backoff classification, underscore aliases with zero upstream hits, login overload semantics, trusted/untrusted/malformed forwarding metadata, and documentation-critical configuration.
- [ ] cargo fmt --check, cargo clippy --all-targets --all-features -- -D warnings, cargo test, and cargo build --release --bin auth-mini-gateway pass.

## 假设 / 约束 / 风险

- **假设**: The production gateway remains a single active Rust process with one SQLite database and one fixed optional upstream.
- **假设**: Axiom frpc connects to the loopback gateway, and Acorn nginx can overwrite X-Forwarded-For with its observed client address before traffic enters FRP.
- **假设**: Connection limits are startup configuration with conservative positive defaults documented relative to the process file-descriptor limit.
- **假设**: Public TLS remains terminated by Acorn nginx; OpenCode and adapter-only gateway ports remain loopback-only and absent from FRP/public mappings.
- **约束**: Connection permits must survive spawned WebSocket bridge tasks and streaming response bodies; releasing at HTTP upgrade or response-header time is incorrect.
- **约束**: No forwarded header, including trusted client IP metadata, may influence authentication, allowlists, login return targets, fixed upstream authority, DNS, TCP destination, TLS SNI, or connection-pool keys.
- **约束**: Do not add dynamic upstreams, multi-host routing, RBAC, new authentication methods, or a generic rate-limiting product.
- **约束**: Do not change SQLite schema, gateway cookie/session formats, auth-mini behavior, or existing allowlist semantics.
- **约束**: Do not rely on nginx defaults to drop ambiguous headers; proxy mode must fail closed itself.
- **约束**: Errors and logs must remain free of cookies, tokens, secrets, raw forwarded values, internal addresses, and database paths.
- **风险**: Incorrect semaphore ownership can release capacity before SSE/WebSocket/response completion or deadlock connection progress.
- **风险**: Connection limits that are too low or share one pool can starve login, logout, and health traffic behind long-lived application streams.
- **风险**: Trusting forwarding metadata without validating the direct peer and each IP value can reintroduce spoofing.
- **风险**: Accept error retry can become a CPU spin or hide permanent listener failure if backoff and classification are wrong.
- **风险**: Changing admission flow can regress session cleanup, login-state creation, or authentication-unavailable semantics.

## 要点

- Add separate, startup-validated downstream and active-upstream capacity controls with lifecycle-correct permit ownership.
- Retry only recoverable accept errors with bounded backoff and secret-free observability.
- Reject underscore request-header names on proxy fallback before expensive authentication.
- Keep one shared authentication decision while ensuring login state creation does not require a second independently overloaded admission.
- Add optional explicit trusted-proxy CIDRs; preserve direct-peer behavior by default and canonicalize client-IP metadata only after trust validation.
- Replace the ambiguous proxy deployment text with an exact Acorn/FRP/OpenCode configuration.

## 范围

- Configuration parsing and validation for connection limits and trusted proxy CIDRs.
- Tokio listener lifecycle, downstream connection admission, recoverable accept retry/backoff, and permit handoff to WebSocket bridges.
- Proxy active-upstream admission, response-body/upgrade permit ownership, 503 mapping, underscore-header rejection, and trusted forwarding metadata.
- Unauthenticated proxy admission/login-state flow and overload mapping.
- Integration/unit tests for all new availability and trust-boundary behavior while retaining existing suites.
- README, environment example, production deployment guide, nginx/FRP examples, and operational limit guidance.

## 非目标

- Do not add per-user or per-IP rate limiting, quotas, load balancing, or a general traffic-management subsystem.
- Do not trust Cloudflare, nginx, FRP, or any forwarding chain implicitly; trust is enabled only by explicit direct-peer CIDR configuration.
- Do not use forwarded client IP for authentication, authorization, session lookup, return targets, or upstream routing.
- Do not change public TLS termination, auth-mini, OpenCode, SQLite schema, or gateway cookie/session formats.
- Do not add multiple upstreams, dynamic discovery, HTTP/2 upstream support, or generic CONNECT tunneling.
- Do not add GitHub CI configuration as part of this runtime hardening task.

## 设计索引 (Design Index)

> **Design Source of Truth**: docs/rfc.md

**摘要**:
- Use independent downstream and upstream capacity budgets so long-lived application streams cannot consume every control-plane slot.
- Treat permits as lifecycle resources owned by connection tasks, streaming bodies, or upgrade bridges rather than request-handler stack frames.
- Make listener resource errors recoverable with bounded backoff while preserving fatal-error visibility.
- Reject ambiguous underscore request headers before authentication and forwarding.
- Keep forwarded client IP opt-in and peer-authenticated; regenerate one canonical value rather than forwarding arbitrary raw chains.
- Make the Acorn nginx and FRP boundary executable documentation rather than an abstract topology.

## 阶段概览

1. **Contract and design** - Materialize the production-hardening contract and research the current lifecycle/trust boundaries.
2. **Implementation** - Implement connection/admission hardening and recoverable accept behavior.
3. **Verification** - Run required commands and focused availability/security tests and record evidence.
4. **Review and delivery** - Run readiness/security review, resolve blockers, and produce walkthrough/wiki evidence.

---

*创建于: 2026-07-15 | 最后更新: 2026-07-15*
