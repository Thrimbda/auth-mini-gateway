# authenticated-reverse-proxy

## Metadata

- `task-id`: `authenticated-reverse-proxy`
- `status`: `completed`
- `risk`: `high`
- `schema-version`: `gateway-session-v2` (unchanged)
- `historical`: `false`
- `supersedes`: nginx-only upstream proxy decision
- `superseded-by`: `(none)`

## Outcome Summary

- `UPSTREAM_URL` is optional: absent/empty preserves the nginx `auth_request` adapter and unmatched-route `404`; a valid fixed HTTP(S) URL enables authenticated proxy fallback.
- Tokio + Hyper now provides streaming HTTP/1, large/chunked bodies, SSE, pooled connections, backpressure, sanitized failures, and validated bidirectional WebSocket upgrades.
- `/auth/check` and proxy fallback share one session lookup, refresh, identity, exact allowlist, and touch decision while preserving existing cookie/session/JWT/SQLite behavior.
- Browser cookies/authorization, spoofed identity, inbound forwarding, and hop-by-hop fields never reach the application; only verified user ID/email are injected.
- OpenCode remains loopback-only. FRP exposes gateway `7780`, not OpenCode `4096`; Acorn nginx continues to terminate public TLS.

## Reusable Decisions

- One gateway process serves one public origin and at most one startup-configured upstream.
- Request data cannot alter upstream scheme, authority, TCP destination, or TLS SNI.
- Gateway-owned authentication/control paths are classified before fallback for every method.
- Hyper owns parsing and framing; the gateway regenerates cross-proxy framing and never fully buffers application bodies.
- Upstream sends are not automatically replayed. Early final responses cancel the remaining upload and disable connection reuse.
- WebSocket validation occurs on both sides before downstream `101`; required fields nominated by `Connection` fail closed.
- Adapter rollback is configuration-only and requires no schema or gateway cookie conversion.

## Related Raw Sources

- `plan`: `.legion/tasks/authenticated-reverse-proxy/plan.md`
- `log`: `.legion/tasks/authenticated-reverse-proxy/log.md`
- `tasks`: `.legion/tasks/authenticated-reverse-proxy/tasks.md`
- `research`: `.legion/tasks/authenticated-reverse-proxy/docs/research.md`
- `rfc`: `.legion/tasks/authenticated-reverse-proxy/docs/rfc.md`
- `reviews`: `.legion/tasks/authenticated-reverse-proxy/docs/review-rfc.md`, `.legion/tasks/authenticated-reverse-proxy/docs/review-change.md`
- `test report`: `.legion/tasks/authenticated-reverse-proxy/docs/test-report.md`
- `report`: `.legion/tasks/authenticated-reverse-proxy/docs/report-walkthrough.md`

## Notes

- All four mandatory Cargo commands, 55 unit tests, 13 integration tests, and all exact 18 acceptance outcomes passed.
- Repository proxy-mode, mode-switch, old-binary compatibility, and WAL backup/restore drills passed.
- The external pinned auth-mini checkout and physical Acorn/FRP switch were unavailable; both remain rollout evidence follow-ups.
