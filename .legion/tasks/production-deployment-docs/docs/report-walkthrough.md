# Walkthrough: Production Deployment Docs

## Mode

implementation

## Reviewer Summary

This documentation-only change adds a `docs/` section for production deployment of the Rust/SQLite auth-mini gateway. It gives operators an entry-point README and a detailed production deployment guide covering auth-mini requirements, gateway configuration, nginx `auth_request`, SQLite persistence, verification, rollback, and troubleshooting.

## Main Changes

- Added `docs/README.md` as the docs index and positioning page, following auth-mini README's high-signal style.
- Added `docs/production-deployment.md` as the production deployment guide.
- Updated root `README.md` to link the docs.
- Added Legion task evidence for contract, verification, review, walkthrough, and wiki writeback.

## Deployment Guidance Covered

- target nginx + gateway + auth-mini + protected-upstream topology
- auth-mini issuer and gateway reachability requirements
- gateway production environment variables
- Docker and Docker Compose deployment paths
- host/systemd deployment path and env-file permissions
- nginx `auth_request` pattern with WebSocket support
- pre-rollout verification checklist
- SQLite WAL backup/restore considerations
- upgrade and rollback procedure
- security notes and troubleshooting

## Verification Evidence

- `git add -A && git diff --cached --check`: PASS.
- `cargo test`: PASS with 11 unit tests.
- Readiness/doc review: PASS with no blocking findings.

## Reviewer Pointers

- Start with `docs/README.md` for structure and positioning.
- Review `docs/production-deployment.md` for operational correctness and security-sensitive guidance.
- Check `.legion/tasks/production-deployment-docs/docs/test-report.md` for verification evidence.
- Check `.legion/tasks/production-deployment-docs/docs/review-change.md` for review decision.
