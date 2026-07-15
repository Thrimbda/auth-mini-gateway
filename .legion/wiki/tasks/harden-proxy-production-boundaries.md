# harden-proxy-production-boundaries

## Metadata

- `task-id`: `harden-proxy-production-boundaries`
- `status`: `completed`
- `risk`: `high`
- `schema-version`: `gateway-session-v2` (unchanged)
- `historical`: `false`
- `supersedes`: unbounded authenticated-proxy production envelope
- `superseded-by`: `(none)`
- `production-rollout`: `blocked-pending-native-evidence`

## Outcome Summary

- Downstream connections, active upstream work, and blocking DNS resolution now use independent startup-validated capacities with lifecycle-correct ownership through HTTP, SSE, cleanup, and WebSocket completion.
- Complete upstream ownership pairs Hyper sender and driver handle; non-idle retirement observes driver termination before returning capacity.
- Domain resolution is explicit and bounded without starving the 64-worker authentication lane; IPv4/IPv6 literals bypass resolution and retain correct TLS identity.
- Recoverable accept errors retry with bounded backoff; fatal errors exit once without waiting for stuck blocking work. Panic output is static and payload-free.
- Underscore aliases fail before authentication/upstream access. Anonymous login state uses the same admission as authentication, preserving cookie-neutral overload.
- Trusted client IP is opt-in by immediate-peer CIDR, accepts one strict IP, and cannot influence authentication or routing.
- Checked nginx, FRP, systemd, environment, and rollback artifacts describe the exact Acorn `18081` to Axiom `7780` to OpenCode `4096` chain.

## Reusable Decisions

- Default capacities are D/U/R `256/128/8`; proxy headroom is at least 16 and blocking-thread capacity is `64 + R + 16`.
- Default proxy/adapter FD budgets are 905/769; finite effective soft RLIMIT below the applicable budget blocks startup.
- Saturated U or R returns exact retryable `503` before request-body polling and without DNS/connect/application work or replay.
- D, U, and R are lifecycle resources, not request-handler counters; every cancellation and Drop path is part of the security model.
- Implementation PASS does not authorize rollout without native topology, credential, service-limit, and resource evidence.

## Related Raw Sources

- `plan`: `.legion/tasks/harden-proxy-production-boundaries/plan.md`
- `log`: `.legion/tasks/harden-proxy-production-boundaries/log.md`
- `tasks`: `.legion/tasks/harden-proxy-production-boundaries/tasks.md`
- `research`: `.legion/tasks/harden-proxy-production-boundaries/docs/research.md`
- `rfc`: `.legion/tasks/harden-proxy-production-boundaries/docs/rfc.md`
- `reviews`: `.legion/tasks/harden-proxy-production-boundaries/docs/review-rfc.md`, `.legion/tasks/harden-proxy-production-boundaries/docs/review-change.md`
- `test report`: `.legion/tasks/harden-proxy-production-boundaries/docs/test-report.md`
- `report`: `.legion/tasks/harden-proxy-production-boundaries/docs/report-walkthrough.md`

## Verification

- Mandatory format, Clippy, test, and release-build commands passed.
- 90 unit and 27 integration tests passed; repository proxy, mode-switch, old-binary, and WAL drills passed.
- Final security review passed with no code finding.
- Native Acorn/Axiom rollout evidence remains mandatory and outstanding.
