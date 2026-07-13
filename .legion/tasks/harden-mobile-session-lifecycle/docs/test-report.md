# Test Report: harden mobile session lifecycle

> Date: 2026-07-13
> Stage: `verify-change`
> Worktree: `/home/c1/Work/auth-mini-gateway/.worktrees/harden-mobile-session-lifecycle`
> Baseline / worktree HEAD: `f0519d1fcfbf49be43602f7a25ad2373434366fe`
> Design gate: third-round `docs/review-rfc.md` verdict **PASS**

## Verdict

**PASS — post-`review-change` re-verification found no remaining implementation blocker in the executed scope.**

The prior report's broad statement that all RFC concurrency/Pending/rollback hard gates were proven by 35 tests was not supportable and is superseded by this report. `review-change` correctly identified missing no-redirect/exact-200 checks, server-level flight/race evidence, and WAL restore evidence. The repaired tree now has 46 passing Rust tests plus an executed WAL-consistent backup/restore drill. The coverage map below names only assertions actually exercised.

All commands requested for this re-verification passed: formatter, full/targeted tests, Clippy, release build, old binary, WAL backup/restore, pinned real auth-mini/nginx E2E, nginx syntax, Compose rendering, diff hygiene, config/docs consistency, and redacted secret scan. No required command was skipped.

The auth-mini silent-SSO capability remains deliberately **unsupported**, as documented in `docs/silent-sso-capability.md`; this is the approved capability-gate outcome, not a regression.

## Inputs and strategy

Read before validation:

- `plan.md`
- approved Heavy RFC: `docs/rfc.md`
- third-round PASS: `docs/review-rfc.md`
- `docs/implementation-plan.md`
- blocking `docs/review-change.md`
- current diff/status, changed implementation/tests, nginx/Compose examples, and all three E2E scripts

Deterministic Rust tests were chosen for redirect-target observation, exact wire status, controlled-time and in-flight state/race invariants. Composed E2E was used for actual pre-change binary behavior, WAL snapshot restore, pinned real auth-mini refresh, nginx `auth_request`, final-response cookies, HTTP/WebSocket behavior, and upstream isolation. These evidence classes are reported separately rather than treated as interchangeable.

## Environment

```text
cargo 1.96.0 (30a34c682 2026-05-25)
rustc 1.96.0 (ac68faa20 2026-05-25)
Docker client/server 29.6.0
Docker Compose 2.40.3
local nginx: unavailable
auth-mini sibling HEAD: 86b4aaa8ca97d1218217a7f6f0144251a5f30c9b
expected auth-mini commit: 86b4aaa8ca97d1218217a7f6f0144251a5f30c9b
auth-mini sibling status: clean
old gateway ref origin/master: f0519d1fcfbf49be43602f7a25ad2373434366fe
```

The real-auth script builds its auth-mini argument in place. To avoid modifying `/home/c1/Work/auth-mini`, its clean pinned contents were cloned to `/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle`; the mirror was passed through `AUTH_MINI_RUST_DIR`. After E2E, the sibling was still clean and its previously absent `rust-backend/target` remained absent.

## Commands and results

### Rust gates

| Command | Result |
|---|---|
| `cargo fmt --check` | **PASS**, exit 0 |
| `cargo test` | **PASS**, 46 passed, 0 failed, 0 ignored; main/doc targets passed |
| `cargo test -- --list` | **PASS**, listed 46 tests, 0 benchmarks |
| `cargo clippy --all-targets -- -D warnings` | **PASS**, exit 0, no warnings |
| `cargo build --release --bin auth-mini-gateway` | **PASS**, optimized release binary built |

Focused tests were also rerun individually with exact names:

```bash
cargo test auth_mini::tests::redirect_responses_are_not_followed_or_replayed -- --exact
cargo test auth_mini::tests::valid_looking_non_200_responses_never_succeed -- --exact
cargo test server::tests::redirect_wire_results_return_503_without_target_hit_or_state_change -- --exact
cargo test server::tests::valid_looking_non_200_wire_results_do_not_advance_database_state -- --exact
cargo test server::tests::handle_auth_check_shares_all_refresh_outcomes_with_joiners -- --exact
cargo test server::tests::pending_alias_joins_the_running_refresh_identity_flight -- --exact
cargo test server::tests::pending_identity_failure_matrix_retries_without_revocation -- --exact
cargo test server::tests::pending_to_pending_refresh_has_no_intermediate_ready_state -- --exact
cargo test server::tests::logout_idle_and_absolute_expiry_win_during_pending_identity_fetch -- --exact
```

**PASS**: each command ran one named test and reported 1 passed, 0 failed.

The full run's newly relevant actual test names were:

- `auth_mini::tests::redirect_responses_are_not_followed_or_replayed`
- `auth_mini::tests::valid_looking_non_200_responses_never_succeed`
- `auth_mini::tests::identity_wire_maps_failures_without_a_rejection_path`
- `auth_mini::tests::refresh_wire_preserves_temporary_and_indeterminate_classes`
- `server::tests::redirect_wire_results_return_503_without_target_hit_or_state_change`
- `server::tests::valid_looking_non_200_wire_results_do_not_advance_database_state`
- `server::tests::handle_auth_check_shares_all_refresh_outcomes_with_joiners`
- `server::tests::pending_alias_joins_the_running_refresh_identity_flight`
- `server::tests::pending_identity_failure_matrix_retries_without_revocation`
- `server::tests::fresh_identity_replaces_policy_input_including_null_email`
- `server::tests::pending_to_pending_refresh_has_no_intermediate_ready_state`
- `server::tests::logout_idle_and_absolute_expiry_win_during_pending_identity_fetch`
- `server::tests::lost_rotation_result_is_shared_before_later_superseded_revoke`

### Actual old-binary gate

```bash
bash scripts/e2e-old-binary-compat.sh
```

**PASS**:

```text
Old-binary compatibility E2E passed: Ready/NULL read, Pending deny/logout/prune, NULL repair, safe re-upgrade.
```

This built and ran actual `origin/master` source rather than simulating old behavior with new code.

### WAL-consistent backup/restore

```bash
bash scripts/e2e-wal-backup-restore.sh
```

**PASS**:

```text
WAL-consistent backup/restore drill passed.
```

The script verified non-empty WAL frames, SQLite backup API snapshot consistency, exclusion of post-backup writes, `integrity_check=ok`, schema version 2, restored Ready invariants, and authorization of the restored fixture by the real gateway binary.

### Pinned real auth-mini + nginx + upstream

Preflight and no-write mirror:

```bash
git -C "/home/c1/Work/auth-mini" rev-parse HEAD
git -C "/home/c1/Work/auth-mini" status --short
test -f "/home/c1/Work/auth-mini/rust-backend/Cargo.toml"
test ! -e "/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle" \
  && git clone --quiet --no-local "/home/c1/Work/auth-mini" "/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle" \
  && git -C "/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle" checkout --quiet 86b4aaa8ca97d1218217a7f6f0144251a5f30c9b \
  && git -C "/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle" rev-parse HEAD
```

Execution:

```bash
AUTH_MINI_RUST_DIR="/tmp/opencode/auth-mini-e2e-harden-mobile-session-lifecycle/rust-backend" \
  bash scripts/e2e-real-auth-mini.sh
```

**PASS**. Final output:

```text
E2E passed: real auth-mini, Rust gateway, nginx, protected HTTP/WebSocket upstream.
```

Observed stages passed: real OTP callback; callback/HTTP/WS absolute Cookie; upstream `500` preservation; gateway-down and auth-mini-down `503` isolation; restart persistence; temporary refresh recovery; real token rotation and Pending finalization; logout; exact rejection; allowlist denial; slow-upstream receipt-time expiry.

This real-service script does **not** inject auth-mini 3xx/201/206, `/me` malformed/error matrices, or in-flight clock races. Those claims rely on the named deterministic Rust wire/handler tests above; the E2E proves the composed nginx/real-auth-mini path listed here only.

### nginx and Compose

```bash
docker run --rm --add-host gateway:127.0.0.1 --add-host upstream:127.0.0.1 \
  -v "$PWD/examples/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:1.27-alpine nginx -t
```

**PASS**: syntax OK; configuration test successful.

```bash
docker compose -f examples/docker-compose.yml config --quiet
```

**PASS**, exit 0.

### Diff and docs/config hygiene

```bash
git diff --check
```

**PASS**, no whitespace errors.

A Python assertion probe checked all four defaults in `.env.example`, `examples/docker-compose.yml`, `README.md`, and `docs/production-deployment.md`:

```text
LOGIN_STATE_TTL_SECONDS=600
SESSION_TTL_SECONDS=604800
SESSION_ABSOLUTE_TTL_SECONDS=2592000
SESSION_TOUCH_INTERVAL_SECONDS=3600
```

**PASS**: 16 assertions, 0 missing. The first auxiliary probe assumed shell-assignment formatting in README and false-reported four missing strings; the corrected probe matched README's prose/backtick format. This was a verifier-command mismatch, not a product failure.

### Non-disclosing sensitive-information scan

Executed against the exact modified/untracked set:

```bash
python3 - <<'PY'
import pathlib, re, subprocess, sys
root = pathlib.Path('.')
raw = subprocess.check_output(
    ['git', 'ls-files', '-z', '--modified', '--others', '--exclude-standard']
)
paths = [pathlib.Path(p.decode()) for p in raw.split(b'\0') if p]
high = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'),
    'aws-access-key': re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
    'github-token': re.compile(r'(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
    'slack-token': re.compile(r'(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}'),
    'google-api-key': re.compile(r'(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])'),
    'stripe-live-key': re.compile(r'(?<![A-Za-z0-9])(?:sk|rk)_live_[0-9A-Za-z]{16,}'),
}
assignment = re.compile(
    r'''(?ix)\b(?:password|passwd|api[_-]?key|client[_-]?secret|cookie[_-]?secret|access[_-]?token|refresh[_-]?token)\b\s*(?:=|:)\s*["']([^"'\n]{4,})["']'''
)
placeholder_words = (
    'test', 'fixture', 'example', 'change-me', 'changeme', 'invalid', 'initial',
    'rotated', 'compat', 'legacy', 'wire', 'pending', 'backup', 'wal-drill',
    'secret-that-is', '${', '$', 'next-', 'old-', 'new-'
)
high_hits = []
reviewed = fixture_literals = unresolved_literals = scanned = 0
for rel in paths:
    path = root / rel
    if not path.is_file():
        continue
    data = path.read_bytes()
    if b'\0' in data:
        continue
    text = data.decode('utf-8', errors='replace')
    scanned += 1
    for label, pattern in high.items():
        if pattern.search(text):
            high_hits.append((str(rel), label))
    for match in assignment.finditer(text):
        reviewed += 1
        value = match.group(1).lower()
        if any(word in value for word in placeholder_words) or len(value) < 12:
            fixture_literals += 1
        else:
            unresolved_literals += 1
print(f'scanned_changed_files={scanned}')
print(f'high_confidence_secret_hits={len(high_hits)}')
print(f'credential_literals_reviewed={reviewed}')
print(f'placeholder_or_fixture_literals={fixture_literals}')
print(f'unresolved_credential_literals={unresolved_literals}')
if high_hits or unresolved_literals:
    print('secret_scan=FAIL (matched values redacted)')
    for path, label in high_hits:
        print(f'redacted_match path={path} category={label}')
    sys.exit(1)
print('secret_scan=PASS (no matched values emitted)')
PY
```

Final output after this report was written:

```text
scanned_changed_files=32
high_confidence_secret_hits=0
credential_literals_reviewed=25
placeholder_or_fixture_literals=25
unresolved_credential_literals=0
secret_scan=PASS (no matched values emitted)
```

The re-verification scan emitted no candidate values. All 25 credential-like literals were classified as fixed test/example fixtures; no unresolved literal or high-confidence provider/private-key pattern remained.

## Coverage map

| Required property | Evidence | Result |
|---|---|---|
| 302/307/308 are not followed or replayed | `auth_mini::tests::redirect_responses_are_not_followed_or_replayed`: source refresh hit exactly once for each status; redirect target accepted no connection; refresh/JWKS returned indeterminate and `/me` unavailable | **PASS** |
| Redirect result is fail-closed at handler | `server::tests::redirect_wire_results_return_503_without_target_hit_or_state_change`: direct `handle_auth_check` returned 503, no session Cookie, target zero hit, Ready generation remained 0 | **PASS** |
| Exact 200 contract | `auth_mini::tests::valid_looking_non_200_responses_never_succeed`: valid-looking 201/206 refresh, `/me`, and JWKS did not succeed | **PASS** |
| 201/206 do not advance DB | `server::tests::valid_looking_non_200_wire_results_do_not_advance_database_state`: refresh 201 left Ready G0; `/me` 206 left the same Pending generation | **PASS** |
| Real `handle_auth_check` shared flight | `server::tests::handle_auth_check_shares_all_refresh_outcomes_with_joiners`: leader + 2 joiners shared success/rejected/temporary/indeterminate; one refresh call; statuses 204/401/503 and Cookie/header/row assertions matched each class | **PASS** |
| Pending alias shares running identity flight | `server::tests::pending_alias_joins_the_running_refresh_identity_flight`: observed G+1 Pending joined the leader; refresh count 1, `/me` count 1, both responses 204 | **PASS** |
| Pending error matrix and recovery | `server::tests::pending_identity_failure_matrix_retries_without_revocation`: 401, 404, temporary-upstream, invalid body, and user mismatch each returned 503/no Cookie and preserved Pending generation/no revoke; sixth fresh matching identity recovered without another refresh | **PASS** |
| Production identity wire classes | `auth_mini::tests::identity_wire_maps_failures_without_a_rejection_path`: 404 unavailable, 503 temporary, malformed/missing-user 200 invalid body; no rejection variant | **PASS** |
| Fresh identity replaces stale policy input | `server::tests::fresh_identity_replaces_policy_input_including_null_email`: changed denied email produced 403/no old header; NULL email with user allowlist produced 204/no email header | **PASS** |
| Pending→Pending has no intermediate Ready | `server::tests::pending_to_pending_refresh_has_no_intermediate_ready_state`: barrier observed Pending generation increment before `/me`; alias joiner shared one refresh/one identity call | **PASS** |
| In-flight logout/idle/absolute win | `server::tests::logout_idle_and_absolute_expiry_win_during_pending_identity_fetch`: each terminal event occurred while `/me` was blocked; late finalize returned 401 clear and row stayed inactive | **PASS** |
| R-01 result-sharing boundary | `server::tests::lost_rotation_result_is_shared_before_later_superseded_revoke`: first flight one call/shared indeterminate/unchanged row; later independent superseded revoked | **PASS** |
| Exact rejection revokes | `refresh_wire_classifies_only_exact_rejections`, `exact_refresh_rejection_conditionally_revokes_local_generation`, and real auth-mini invalid-refresh E2E | **PASS** |
| v1 deadline/migration safety | `migration_is_additive_and_never_extends_legacy_deadline`, NULL repair, malformed rollback, future-version rejection | **PASS** |
| Exact lifecycle/touch boundaries | `exact_idle_and_absolute_boundaries_are_inactive`; `touch_is_merged_at_exact_interval_and_capped_by_absolute` | **PASS** |
| Actual old binary compatibility | `bash scripts/e2e-old-binary-compat.sh`: Ready/NULL read, Pending deny/logout/prune, NULL repair and safe re-upgrade | **PASS** |
| WAL backup/restore | `bash scripts/e2e-wal-backup-restore.sh`: non-empty WAL, consistent snapshot, integrity/schema/Ready invariant, post-backup exclusion, restored authorization | **PASS** |
| Absolute Cookie and nginx composition | Cookie unit tests plus pinned real E2E callback, HTTP 200, WS 101, slow response, two independent cookies | **PASS** |
| Auth failure isolation/temporary recovery | Pinned real E2E gateway-down and auth-mini-down produced no-Location 503 with upstream hit delta 0; same Cookie recovered after auth-mini restart | **PASS** |
| Business upstream status isolation | Pinned real E2E `/upstream-500` remained 500 | **PASS** |
| Persistence failures | `refresh_persistence_failure_cannot_claim_ready`; `identity_finalize_and_touch_fail_closed_on_persistence_errors` | **PASS** |
| Diff/config/secrets | `git diff --check`, 16 config/docs assertions, and redacted scan of 32 changed/untracked files | **PASS** |

## Limits and residuals

- Local nginx was unavailable; both config validation and E2E used `nginx:1.27-alpine` through Docker.
- No physical mobile Safari was run. Receipt-time Cookie behavior used curl's cookie jar after a response delayed beyond expiry; HTTP/WS propagation used real nginx. Silent SSO remains explicitly unsupported.
- The pinned real-service E2E exercises transport outage/recovery, real rotation, exact rejection, Cookie/nginx and upstream isolation. It does not inject 3xx/201/206, 429/5xx, malformed `/me`, or in-flight clock races; those are covered by the named deterministic wire/handler tests and are not mislabeled as real-service evidence.
- The server-level shared-flight and terminal-race tests call the real `handle_auth_check` with barriers and observable call counters, but do not proxy a business request. Upstream-zero assertions come from the separate nginx E2E failure paths.
- The WAL drill restores a transactionally consistent Ready snapshot and proves it is usable by the binary; it does not claim a production-volume or lock-contention/load test.
- The approved topology remains one active gateway with SQLite; distributed single-flight is out of scope.
- Accepted R-01 remains: remote rotation commit plus lost response yields shared `503`; a later independent exact superseded response may revoke. The deterministic test passed and no automatic retry was introduced.

## Failures, skips, blocker

- Historical pre-fix review verdict: **FAIL**, for redirect following, non-exact 2xx acceptance, and overstated evidence. This report supersedes the old PASS report only after rerunning the repaired tree.
- Current product/test failures: **none**.
- Required skipped checks: **none**.
- Verification-stage production-code changes: **none**; only this report was updated.
- **Blocker: none.**
