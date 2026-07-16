# Legion Wiki

## Current Task Summaries

- [enable-http2-proxy](tasks/enable-http2-proxy.md): ALPN-authoritative HTTPS H2, explicit cleartext protocol selection, no-replay multiplexing, and RFC 8441 capability monitoring.
- [harden-proxy-production-boundaries](tasks/harden-proxy-production-boundaries.md): bound downstream/upstream/resolver lifetimes, harden proxy header and forwarding trust, and make Acorn/FRP rollout executable.
- [authenticated-reverse-proxy](tasks/authenticated-reverse-proxy.md): optional fixed-upstream authenticated streaming proxy while preserving the nginx `auth_request` adapter mode.
- [harden-mobile-session-lifecycle](tasks/harden-mobile-session-lifecycle.md): request-driven mobile sessions with 7-day inactivity, 30-day absolute lifetime, resilient refresh, and schema v2 migration.
- [remove-auth-method-policy](tasks/remove-auth-method-policy.md): remove gateway-level Passkey enforcement and authorize verified auth-mini identities only through allowlists.
- [production-deployment-docs](tasks/production-deployment-docs.md): production deployment docs for the Rust/SQLite auth-mini gateway.
- [production-rust-sqlite-gateway](tasks/production-rust-sqlite-gateway.md): production Rust/SQLite gateway adapting real auth-mini sessions to nginx `auth_request` front authentication.
- [auth-mini-gateway-poc](tasks/auth-mini-gateway-poc.md): historical TypeScript PoC superseded for production runtime by `production-rust-sqlite-gateway`.

## Cross-Task Knowledge

- [Decisions](decisions.md)
- [Patterns](patterns.md)
- [Maintenance](maintenance.md)
- [Wiki Log](log.md)
