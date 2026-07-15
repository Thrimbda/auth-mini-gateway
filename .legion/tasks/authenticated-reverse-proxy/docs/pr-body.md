## Summary

> **Labels:** `high-risk`, `security`
> **Risk:** authentication/proxy trust boundary, HTTP streaming/framing, WebSocket upgrades, and deployment switching.

Adds an optional authenticated fixed-upstream reverse-proxy mode while preserving the existing nginx `auth_request` adapter as the default and rollback path.

- `UPSTREAM_URL` unset/empty: existing adapter behavior and unmatched-route `404`.
- Valid fixed `UPSTREAM_URL`: non-owned routes use the same authentication decision as `/auth/check`, then become login `302`, denial `403`, auth-unavailable `503`, or an authenticated streaming proxy response.
- No schema change and no gateway cookie-format change.

## What changed

- Replaced the handwritten one-request server with Tokio + Hyper HTTP/1 streaming and backpressure.
- Centralized session lookup, refresh, exact allowlist policy, identity safety, and touch in one shared authentication decision.
- Added one startup-only fixed HTTP(S) upstream; request input cannot select another destination.
- Added one-attempt fixed-origin connection pooling without automatic replay.
- Stripped browser cookies/authorization, spoofed identity, inbound forwarding, and hop-by-hop fields; regenerated forwarding metadata and injected only verified identity.
- Added validated WebSocket upgrade bridging and early-final upload cancellation.
- Kept all six gateway-owned paths local for every method.
- Documented proxy/adapter topology, rollout, and rollback.

## Security review

- Early upstream final responses cancel remaining upload polling, close downstream, and disable affected-connection reuse.
- `/auth/check` and proxy injection preserve byte-identical verified non-ASCII identity headers.
- `Connection` nomination of required WebSocket fields fails before downstream `101`.
- HTTP no longer depends on TLS roots; HTTPS remains certificate-validated with no insecure fallback.

Final security review: **PASS**, no blocking finding.

## Verification

- [x] `cargo fmt --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test` - **55 unit + 13 integration**, 0 failed/ignored
- [x] `cargo build --release --bin auth-mini-gateway`

All exact 18 acceptance outcomes passed. Repository proxy-mode, mode-switch, old-binary compatibility, and WAL backup/restore drills passed.

## Deployment / rollback

Proxy topology is Acorn nginx `:443` -> FRP -> gateway `127.0.0.1:7780` -> OpenCode `127.0.0.1:4096`. Adapter rollback uses node nginx `127.0.0.1:7781`, adapter gateway `127.0.0.1:3000`, and the same loopback OpenCode.

Only one gateway process may use SQLite. Roll back under maintenance deny by stopping `7780`, restarting with `UPSTREAM_URL` unset on `3000`, verifying `7781`, switching FRP, and removing deny. Never expose `3000` or `4096` publicly.

## Residual evidence

- The externally pinned auth-mini checkout was unavailable, so its composed script was not rerun.
- Physical Acorn maintenance-deny and FRP switching were not executed; production rollout must verify the port boundary.

## Evidence

- [Stable plan](.legion/tasks/authenticated-reverse-proxy/plan.md)
- [Final RFC](.legion/tasks/authenticated-reverse-proxy/docs/rfc.md)
- [Final RFC review](.legion/tasks/authenticated-reverse-proxy/docs/review-rfc.md)
- [Final test report](.legion/tasks/authenticated-reverse-proxy/docs/test-report.md)
- [Final security review](.legion/tasks/authenticated-reverse-proxy/docs/review-change.md)
- [Reviewer walkthrough](.legion/tasks/authenticated-reverse-proxy/docs/report-walkthrough.md)
