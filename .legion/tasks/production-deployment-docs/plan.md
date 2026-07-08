# Production Deployment Docs

## Task Contract

- **Task ID:** `production-deployment-docs`
- **Name:** Production deployment documentation for auth-mini-gateway
- **Goal:** create production-ready deployment documentation under `docs/` for the Rust/SQLite auth-mini gateway, with a docs README shaped after auth-mini's README style.
- **Problem:** the gateway now has a production Rust/SQLite runtime, but the repository only has a short root README and examples. Operators need a clear production deployment guide that explains topology, prerequisites, configuration, nginx integration, auth-mini dependencies, checks, rollback, and operational boundaries.

## Acceptance

- A `docs/` directory exists.
- `docs/README.md` serves as a docs entry point, following the high-signal structure of auth-mini's README: positioning, good fit/not fit, quick start, operations pointers, and next docs.
- `docs/production-deployment.md` gives a production deployment guide for Docker/Compose-style deployment and host/systemd-style deployment.
- The guide documents required auth-mini configuration, gateway environment variables, SQLite persistence, nginx `auth_request`, protected upstream isolation, WebSocket support, verification checks, backups, upgrades, rollback, and troubleshooting.
- Root `README.md` links to the new docs.
- Documentation does not introduce new runtime behavior or claim unsupported multi-active SQLite deployment.

## Scope

- Add production deployment docs under `docs/`.
- Update root README only enough to point readers to the docs.
- Add Legion task, verification, review, walkthrough, and wiki evidence.

## Non-Goals

- Do not change gateway runtime behavior.
- Do not change Docker Compose or nginx examples unless a documentation typo makes them inaccurate.
- Do not add Kubernetes manifests or cloud-provider-specific instructions.
- Do not write auth-mini's own deployment manual; reference the required auth-mini setup from the gateway perspective.

## Assumptions

- The supported production topology remains one active gateway instance with durable SQLite WAL storage.
- nginx remains the public reverse proxy, TLS terminator, and `auth_request` caller.
- auth-mini is deployed separately and reachable by the gateway.
- Operators can adapt examples to their own process supervisor, reverse proxy, and upstream service.

## Constraints

- Keep token/cookie/secret handling guidance explicit.
- Do not recommend exposing the protected upstream directly.
- Do not recommend multi-active gateway instances sharing one SQLite DB.
- Keep the docs actionable and concise for operators.

## Risks

- Deployment docs can accidentally overgeneralize example topology into production recommendations.
- Misstating auth-mini issuer/public URL requirements can cause login or JWT verification failures.
- Missing SQLite backup/permissions guidance can create operational risk.

## Design Summary

- Use `docs/README.md` as a reader-oriented docs index and positioning page.
- Use `docs/production-deployment.md` as the detailed execution guide.
- Mirror auth-mini README's clarity and flow, but focus on gateway deployment rather than auth-mini authentication internals.
- Keep examples generic and mark placeholders clearly.

## Phases

- Brainstorm: materialize this documentation task contract.
- Implementation: write `docs/README.md`, `docs/production-deployment.md`, and update root README links.
- Verification: inspect rendered markdown structure and verify referenced files/commands match the repository.
- Review and handoff: record review, walkthrough/PR body, wiki writeback, then complete PR lifecycle.
