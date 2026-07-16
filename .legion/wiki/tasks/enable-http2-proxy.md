# enable-http2-proxy

## Metadata

- `task-id`: `enable-http2-proxy`
- `status`: `completed`
- `risk`: `high`
- `schema-version`: `gateway-session-v2` (unchanged)
- `historical`: `false`
- `supersedes`: HTTP/1.1-only downstream and upstream proxy transport
- `superseded-by`: `(none)`
- `production-rollout`: `separate-not-performed`
- `delivery-pr`: `https://github.com/Thrimbda/auth-mini-gateway/pull/11`
- `merge-commit`: `5638fb05ee6577818c3bd32541b41ae01d2570f7`

## Outcome Summary

- The cleartext listener now serves HTTP/1.1 and HTTP/2 prior knowledge; every delivered HTTP/2 stream independently passes routing, authentication, authorization, sanitation, and capacity admission.
- `UPSTREAM_PROTOCOL=auto|http1|http2` selects the fixed upstream transport. HTTPS `auto` follows ALPN; cleartext requires explicit `http1` or `http2` and performs no discovery request.
- Ordinary streaming traffic and WebSockets work across H1-to-H1, H1-to-H2, H2-to-H1, and H2-to-H2 while preserving fixed routing, backpressure, and secret stripping.
- Candidate selection closes before one `send_request`; selected H2 never downgrades to H1, and dispatched requests are never replayed.
- Multiplexed H2 uses one U permit per application exchange/stream while the combined eight-owner pool and private-owner accounting continue to bound physical connections.
- RFC 8441 use requires initial SETTINGS/ACK proof on the same connection plus fixed-memory monitoring and exact-generation retirement for later capability revocation.

## Reusable Decisions

- HTTPS `auto` is ALPN-authoritative: selected `h2` is final, while explicit `http/1.1` or no ALPN selects H1. Cleartext protocol choice is operator-provided prior knowledge because safe in-band discovery does not exist.
- No selected path reopens owner, address, generation, or protocol selection. There is exactly one upstream dispatch call and no replay after it.
- Configured `UpstreamBase` alone controls upstream authority, dial target, TLS identity, and pool membership; downstream Host or H2 authority is validation/application metadata only.
- Upload, response, SSE, rejected-upgrade cleanup, tunnel, driver, and transport-drop witnesses retain U and stream/owner permits until the corresponding ownership actually ends.
- An initial false RFC 8441 capability remains WebSocket-ineligible even after a later true value; a later false after accepted true retires that exact generation and never migrates its streams.

## Accepted Residuals

- Pinned Hyper 1.10.1 closes the downstream H2 connection before gateway service for CONNECT with one consistent nonzero Content-Length. The stable guarantee is connection completion/EOF and zero service, authentication, U admission, or upstream dispatch; wire reset and sibling survival are not guaranteed.
- An illegal later `SETTINGS_ENABLE_CONNECT_PROTOCOL` transition from `1` to `0` retires the affected generation, so its in-flight siblings can fail without migration or replay. Other generations remain independent.
- A generation whose initial capability is false ignores a later true value for WebSocket eligibility; ordinary H2 remains usable.
- The real-auth E2E was not run because its pinned external fixture was absent. The four local repository E2Es passed.
- Production rollout and infrastructure validation were not part of this task and remain a separate evidence gate.

## Related Raw Sources

- [Plan](../../tasks/enable-http2-proxy/plan.md)
- [Log](../../tasks/enable-http2-proxy/log.md)
- [Task checklist](../../tasks/enable-http2-proxy/tasks.md)
- [RFC](../../tasks/enable-http2-proxy/docs/rfc.md)
- [Focused RFC review](../../tasks/enable-http2-proxy/docs/review-rfc.md)
- [Implementation and security review](../../tasks/enable-http2-proxy/docs/review-change.md)
- [Test report](../../tasks/enable-http2-proxy/docs/test-report.md)
- [Reviewer walkthrough](../../tasks/enable-http2-proxy/docs/report-walkthrough.md)

## Verification

- Review and verification passed with no blocking finding: 19 focused library/component tests, 32 focused protocol/security tests, and 160 full-suite tests passed.
- Formatting, strict Clippy, release build, all-target check, diff check, release hook exclusion, and four locally executable E2Es passed.
