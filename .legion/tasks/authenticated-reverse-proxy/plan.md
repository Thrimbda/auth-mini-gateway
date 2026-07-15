# Authenticated reverse proxy mode

## 目标

Add an optional authenticated reverse proxy mode while preserving the existing auth_request adapter behavior when UPSTREAM_URL is unset.

## 问题陈述

The current gateway only answers authentication routes and relies on node-local Nginx to proxy applications. NAT-hosted application nodes need the gateway itself to enforce the existing session and allowlist policy, then stream traffic to one fixed loopback upstream without weakening the authentication boundary.

## 验收标准

- [ ] UPSTREAM_URL is optional, startup-validated, fixed, and limited to absolute http or https URLs without credentials, fragments, or queries.
- [ ] Without UPSTREAM_URL, all existing routes, status codes, cookies, session refresh, logout, and unknown-route 404 behavior remain compatible.
- [ ] With UPSTREAM_URL, non-gateway routes share the same authentication decision as /auth/check and become login redirect, 403 denial, or authenticated streaming proxy responses.
- [ ] The proxy preserves method, path, query, body, external Host, forwarding metadata, HTTP keep-alive, chunking, SSE, WebSocket, connection reuse, and backpressure without full body buffering.
- [ ] Client identity headers and cookies are stripped before proxying; verified identity headers are injected and secrets are not logged.
- [ ] Proxy failures return sanitized 502 responses and internal failures return sanitized 500 responses.
- [ ] Existing tests pass and automated coverage proves compatibility, GET and the required POST/PUT/PATCH/DELETE methods, authorization denials, header and cookie safety, large bodies, chunking, SSE, WebSocket, unreachable upstream, and gateway-owned route isolation.
- [ ] cargo fmt --check, cargo clippy --all-targets --all-features -- -D warnings, cargo test, and cargo build --release --bin auth-mini-gateway pass.
- [ ] README.md, .env.example, and docs/production-deployment.md document adapter and proxy modes plus the OpenCode 7780 to 4096 deployment topology.

## 假设 / 约束 / 风险

- **假设**: Each gateway instance serves one public origin and one optional fixed upstream.
- **假设**: The application binds only to loopback and FRP exposes the gateway port rather than the application port.
- **假设**: Public TLS remains terminated by Acorn Nginx.
- **假设**: Existing auth-mini endpoints, token formats, cookie formats, SQLite schema semantics, and allowlist behavior remain authoritative.
- **约束**: Do not derive upstream selection from Host, headers, query parameters, paths, or any other user input.
- **约束**: Do not duplicate session lookup, refresh, JWT validation, identity resolution, or allowlist logic between /auth/check and proxy mode.
- **约束**: Do not fully buffer proxied request or response bodies.
- **约束**: Do not forward browser cookies, access tokens, refresh tokens, spoofed identity headers, or inappropriate hop-by-hop headers.
- **约束**: Gateway-owned authentication, callback, logout, login, and health routes must never be proxied.
- **约束**: No secret-bearing values or internal error details may appear in logs or client responses.
- **风险**: Authentication and proxy trust-boundary changes can introduce authorization bypass or identity spoofing.
- **风险**: Migrating from the handwritten blocking server to an asynchronous HTTP stack can regress callback, refresh, logout, cookies, and response compatibility.
- **风险**: WebSocket upgrades and hop-by-hop header handling are protocol-sensitive and can leak or break traffic if implemented incorrectly.
- **风险**: SSE, large bodies, and long-running OpenCode requests require real streaming, backpressure, and cancellation behavior.
- **风险**: Forwarded header trust and original Host preservation must support deployment without becoming authentication inputs.

## 要点

- Preserve all current auth-mini behavior and cookie/session formats.
- Use a mature Tokio plus Hyper/Axum-class async stack for the server and proxy transport.
- Represent authentication as one reusable decision returning trusted identity, unauthenticated state, or forbidden state plus cookie cleanup metadata.
- Keep upstream configuration singular and static.
- Treat security, streaming, and rollback compatibility as first-class verification targets.

## 范围

- Refactor the HTTP runtime to an asynchronous streaming server while retaining existing authentication, JWT, SQLite, cookie, policy, and auth-mini integration logic.
- Add UPSTREAM_URL parsing and startup validation.
- Implement shared authentication decisions for /auth/check and proxy traffic.
- Implement HTTP and WebSocket reverse proxying with header sanitation, identity injection, forwarding metadata, and sanitized errors.
- Add focused and integration tests for adapter compatibility, proxy transport, denials, security properties, streaming, and upgrades.
- Update deployment documentation and environment examples.

## 非目标

- Do not modify auth-mini, its login UI, Email OTP, or Passkey policy.
- Do not change gateway cookie/session formats, introduce RBAC, or add new authentication methods.
- Do not support multiple upstreams, host-based routing, path-based routing, or any dynamic upstream selection.
- Do not add generic CONNECT tunneling; fallback CONNECT requests fail closed while gateway-owned path precedence remains unchanged.
- Do not terminate public TLS in the gateway or modify OpenCode.
- Do not remove the existing `/auth/check` adapter capability.

## 设计索引 (Design Index)

> **Design Source of Truth**: docs/rfc.md

**摘要**:
- Keep adapter mode as the rollback-compatible default when UPSTREAM_URL is absent.
- Adopt an asynchronous HTTP runtime and streaming proxy client rather than extending the handwritten TcpListener parser.
- Centralize authentication and authorization before mapping decisions to adapter or proxy responses.
- Compose all proxied URIs from the startup-validated fixed upstream plus the original path and query only.
- Sanitize request headers before adding trusted identity and forwarding metadata; preserve multi-value response headers while filtering transport-specific fields.

## 阶段概览

1. **Contract and design** - Materialize the stable task contract and produce a high-risk RFC with research evidence.
2. **Implementation** - Implement async shared-auth adapter and fixed-upstream proxy mode.
3. **Verification** - Run required formatting, lint, test, and release build commands and record evidence.
4. **Review and delivery** - Run readiness and security review, fix blockers, and produce reviewer handoff artifacts.

---

*创建于: 2026-07-15 | 最后更新: 2026-07-15*
