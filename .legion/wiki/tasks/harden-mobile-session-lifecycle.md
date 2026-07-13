# harden-mobile-session-lifecycle

## Metadata

- `task-id`: `harden-mobile-session-lifecycle`
- `status`: `active`
- `risk`: `high`
- `schema-version`: `gateway-session-v2`
- `historical`: `false`
- `supersedes`: `(none)`
- `superseded-by`: `(none)`

## Outcome Summary

- Mobile browser sessions now use a 7-day inactivity deadline under a non-sliding 30-day absolute deadline; successful authorization coalesces durable touch to once per hour.
- Gateway session schema v2 preserves legacy deadlines during migration and keeps old binaries fail-closed while refreshed identity is pending.
- Temporary or indeterminate refresh failures return `503` without clearing the session; only exact refresh-endpoint rejection can conditionally revoke it.
- Positive cookies use an absolute `Expires` deadline and nginx propagates renewal cookies from `auth_request` to the browser-facing response.
- Current auth-mini does not support no-interaction redirect SSO; that capability remains an external follow-up rather than a gateway claim.

## Reusable Decisions

- Mobile browsers do not need background token refresh: the gateway refreshes server-side on the next authenticated request.
- Rotating refresh requests use shared-result per-session single-flight plus durable SQLite compare-and-swap.
- Refresh rotation persists a fail-closed identity-pending state before `/me`; `/me` has no authority to revoke a session.
- Auth-mini HTTP calls do not follow redirects and accept only contract-defined exact `200 OK` success responses.
- Local session migration, rollback, old-binary behavior, real auth-mini/nginx composition, and WAL backup/restore are release gates.

## Related Raw Sources

- `plan`: `.legion/tasks/harden-mobile-session-lifecycle/plan.md`
- `log`: `.legion/tasks/harden-mobile-session-lifecycle/log.md`
- `tasks`: `.legion/tasks/harden-mobile-session-lifecycle/tasks.md`
- `research`: `.legion/tasks/harden-mobile-session-lifecycle/docs/research.md`
- `rfc`: `.legion/tasks/harden-mobile-session-lifecycle/docs/rfc.md`
- `reviews`: `.legion/tasks/harden-mobile-session-lifecycle/docs/review-rfc.md`, `.legion/tasks/harden-mobile-session-lifecycle/docs/review-change.md`
- `test report`: `.legion/tasks/harden-mobile-session-lifecycle/docs/test-report.md`
- `report`: `.legion/tasks/harden-mobile-session-lifecycle/docs/report-walkthrough.md`

## Notes

- Accepted residual R-01: a remote refresh rotation committed before a lost response cannot be recovered without auth-mini protocol support; a later exact superseded response may require re-login.
- Accepted residual R-02: the gateway trusts exact auth-mini wire rejections even though auth-mini may currently fold some internal failures into `session_invalidated`.
- No physical mobile Safari run is claimed; real nginx, delayed-response cookie handling, and request-driven recovery were verified.
