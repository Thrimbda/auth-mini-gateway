# Legion Wiki

## Current Task Summaries

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
