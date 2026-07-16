# Enable HTTP/2 proxy support - Log

## 2026-07-16 - Contract created

- Legion entry selected the default implementation mode with a high-risk design gate.
- Base ref: `origin/master` at `28a4a27`.
- Branch: `legion/enable-http2-proxy-implementation`.
- Worktree: `.worktrees/enable-http2-proxy`.
- The user-supplied goal, acceptance criteria, constraints, and stop rules were stable enough to materialize without additional assumptions.
- Next: inspect current implementation and current library APIs, then produce `docs/rfc.md` for adversarial review before production-code edits.

## 2026-07-16 - Cleartext auto design blocker

- Repository, test, Context7, pinned crate-source, RFC 9113, and RFC 8441 research is recorded in `docs/research.md`.
- HTTPS ALPN, downstream HTTP/1+HTTP/2 serving, protocol-aware pooling, streaming, and RFC 8441 have viable existing APIs.
- RFC 9113 provides no in-band, generally side-effect-free discovery for cleartext HTTP/2; it requires out-of-band prior knowledge.
- An optimistic HTTP/2 preface can prove h2 after peer SETTINGS but cannot guarantee zero HTTP/1 application visibility or conclusively distinguish every unsupported peer from transport failure.
- The task is blocked before RFC/implementation under the explicit stop rule. Resume requires approval for either optimistic cleartext preface probing or explicit cleartext protocol selection.
- No production code, dependency, test, deployment, or external-system change has been made.

## 2026-07-16 - Cleartext policy resolved

- The user selected explicit cleartext protocol configuration rather than optimistic preface discovery.
- HTTPS keeps default `auto` and ALPN preference for h2.
- A cleartext upstream now requires explicit `http1` or `http2`; `auto` is a startup error for cleartext.
- Explicit `http2` is prior knowledge and must verify peer SETTINGS before any application stream. Explicit `http1` sends no h2 probe.
- The stable contract and research evidence were updated. The design chain may resume at RFC; production code remains unchanged.

## 2026-07-16 - RFC gate passed

- `docs/rfc.md` specifies downstream auto serving, explicit cleartext policy, HTTPS ALPN, same-connection SETTINGS proof, protocol-aware pooling, two-half streaming ownership, header/authority rules, and all four WebSocket bridges.
- The first review failed on creator permit publication, WebSocket H2-to-H1 fallthrough, and first-head deadline verification.
- The RFC now reserves the creator permit before publication, closes protocol selection before capability validation, and races the initial timeout only until a latched first complete request head.
- Repeated `review-rfc` records PASS with no blocking finding.
- Next: bounded implementation under the reviewed design and its stop conditions.

## 2026-07-16 - Implementation milestones complete

- Milestone 1 added strict protocol configuration, downstream H1/H2 prior knowledge, first-head-only timeout, H2 stream admission, authority validation, and split-Cookie support.
- Milestone 2 added HTTPS ALPN, explicit h2c, same-connection SETTINGS proof, combined H1/H2 owner pool, creator-before-publication reservation, two-half exchange ownership, fixed H2 authority, multiplexing, and no-replay behavior.
- Milestone 3 added strict RFC 8441 classification, all four H1/H2 WebSocket bridges, capability-closed candidate selection, rejected-upgrade cleanup, full tunnel leases, and security/rollback documentation.
- Implementation discovery found that Hyper 1.10.1 intercepts consistently parsed non-zero Content-Length H2 CONNECT before gateway service dispatch and completes the connection. The RFC was narrowed and re-reviewed PASS: required behavior is fail-closed EOF with zero auth/U/upstream; wire RST, gateway 400, and sibling survival are not claimed for this exact pre-service form.
- Focused raw-H2 evidence bypasses Hyper's client validation and proves a valid control reaches service while the malformed form reaches no gateway hook or upstream.
- Engineer checks passed: formatting, all-target check, 100 library tests, 45 proxy integration tests, focused protocol/WebSocket/security groups, and diff whitespace.
- Next: independent `verify-change` evidence across mandatory commands and repository E2E scripts.

## 2026-07-16 - Verification passed

- `docs/test-report.md` records PASS after one engineer loop for strict-Clippy and focused evidence gaps.
- Focused evidence passed: 8 library and 29 protocol/security integration tests.
- Full `cargo test` passed 147 tests: 100 library and 47 integration.
- Formatting, strict all-target/all-feature Clippy, release binary build, all-target check, and diff whitespace passed.
- Proxy-mode E2E passed 47 integration tests; mode-switch, old-binary compatibility, and WAL backup/restore E2Es passed.
- `scripts/e2e-real-auth-mini.sh` was not run because `/tmp/opencode/auth-mini-reference/rust-backend/Cargo.toml` is absent; no external repository was fetched.
- Dependency, infrastructure scope, artifact cleanup, and secret-log boundaries passed. No Nix or production command ran.
- Next: high-risk implementation/readiness review with security perspective.

## 2026-07-17 - Readiness and security review passed

- The first implementation review failed on H2 upload ownership, transport-drop ordering, later RFC 8441 SETTINGS revocation, Content-Length zero compatibility, missing adversarial evidence, and release test hooks.
- The RFC was corrected for continuous fixed-memory SETTINGS monitoring and candidate/update linearization, then `review-rfc` passed again.
- Engineering fixes defer upload ownership to the real body-drop witness, order transport close before capacity release, retire exact generations on illegal capability revocation, accept consistent zero length, compile hooks out of release, and add deterministic timeout/IO/race/GOAWAY/REFUSED_STREAM evidence.
- Re-verification passed 19 focused library, 32 focused integration, and 160 full tests; strict Clippy, release, all-target, diff, and four local E2Es passed.
- Repeated `review-change` with the security lens records PASS and no blocking finding.
- Accepted residuals are the pinned Hyper nonzero CONNECT EOF exception, generation-wide failure on illegal revocation, conservative later capability enablement, missing real-auth fixture, and no production rollout in this task.
- Next: reviewer walkthrough, PR body, wiki writeback, then commit/rebase/push/PR lifecycle.

## 2026-07-17 - Delivery completed

- Reviewer walkthrough, PR body, and Legion wiki writeback were included with the implementation.
- Feature commit `edda267` was pushed from `legion/enable-http2-proxy-implementation`.
- PR #11, `https://github.com/Thrimbda/auth-mini-gateway/pull/11`, was mergeable/CLEAN with no repository checks configured and was squash-merged as `5638fb05ee6577818c3bd32541b41ae01d2570f7`.
- The remote and local feature branches were deleted and the feature worktree was removed.
- The primary worktree was refreshed in detached-baseline mode to `origin/master` at `5638fb0` before this docs-only terminal-state closeout.
- No deployment, Nix, production infrastructure, or external-system change was performed.
