## Summary

- Add `docs/README.md` as the gateway docs entry point, modeled after auth-mini's concise README structure.
- Add `docs/production-deployment.md` with production deployment guidance for Docker, Compose, host/systemd, nginx, SQLite operations, verification, rollback, and troubleshooting.
- Link the new docs from the root README.

## Verification

- `git add -A && git diff --cached --check`
- `cargo test`
- Readiness/doc review: PASS, no blocking findings.

## Notes

- Documentation-only change; no runtime behavior changed.
- The docs preserve the supported single-active SQLite gateway topology and do not recommend exposing protected upstreams directly.
