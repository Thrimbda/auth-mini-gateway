# Fix Audience-Bound Login Callback - 日志

## 会话进展 (2026-07-30)

### ✅ 已完成

- Confirmed the local `~/Work/auth-mini` checkout tracks `Thrimbda/auth-mini` and is eight commits behind the fresh official repository.
- Cloned official `zccz14/auth-mini` at `c4e28f5` and identified `7a9b55f` as the audience-contract change.
- Traced the deployed callback host, gateway verifier, `/me` call, user policy, and generic bridge failure mapping.
- Confirmed the remediation direction with the user: adopt audience validation and `ALLOW_USER_IDS` authorization.
- Passed Heavy RFC review for strict audience validation, user-ID authorization, legacy-session bounds, and rollback.
- Implemented audience-bound callback, refresh, and Pending recovery without downstream `/me`.
- Updated active docs, examples, real-auth E2E, and benchmark identity fixtures for user-ID-only authorization.
- Passed cargo fmt/test, real auth-mini E2E, old-binary compatibility, proxy/mode-switch drills, HTTP/2 benchmark tests, security review, walkthrough, and wiki writeback.

### 🟡 进行中

- Commit, push, PR lifecycle, checks/review follow-up, merge, cleanup, and main refresh.

### ⚠️ 阻塞/待定

- Production rollout remains blocked until exact `ALLOW_USER_IDS` values are provisioned and `ALLOW_EMAILS` is cleared for each gateway service.

---

## 关键文件

- **`src/jwt.rs`** [implemented]
  - 作用: Verifies signature, issuer, type, expiry, identity claims, and exact string audience.
  - 备注: `AudienceRejected` is distinct only after a valid signed token passes all non-audience checks.
- **`src/auth_mini.rs`** [implemented]
  - 作用: Owns JWKS, refresh, logout, and audience-aware token verification.
  - 备注: Downstream `/me` identity lookup is removed.
- **`src/server.rs`** [implemented]
  - 作用: Builds login redirects and establishes/refreshes gateway sessions from signed claims.
  - 备注: Callback and Pending finalization no longer call `/me`; signed audience mismatch uses stale-safe conditional revoke.
- **`src/config.rs`** [implemented]
  - 作用: Derives normalized gateway audience and rejects nonempty `ALLOW_EMAILS` at startup.
  - 备注: Loopback login adds explicit `aud`; production HTTPS lets auth-mini derive it.
- **`scripts/e2e-real-auth-mini.sh`** [verified]
  - 作用: Real current-auth-mini contract drill.
  - 备注: Pins official `c4e28f5`, proves `/me` isolation, refresh audience preservation, and wrong-audience rejection.
- **`.legion/tasks/diagnose-login-callback-failure/docs/test-report.md`** [verified]
  - 作用: Verification evidence.
  - 备注: All selected commands passed.
- **`.legion/tasks/diagnose-login-callback-failure/docs/review-change.md`** [reviewed]
  - 作用: Final security/correctness review.
  - 备注: PASS with no blocking findings.

---

## 关键决策

| 决策 | 原因 | 替代方案 | 日期 |
|------|------|----------|------|
| Target official auth-mini `c4e28f5` rather than the stale local fork | The local `origin` is `Thrimbda/auth-mini` and lacks the audience change | Diagnose against local `86b4aaa` | 2026-07-30 |
| Authorize fresh sessions through exact JWT `sub` / `ALLOW_USER_IDS` | Downstream JWTs contain no email and cannot call self-audience `/me` | Pin old auth-mini or add email to upstream JWTs | 2026-07-30 |
| Validate the gateway hostname `aud` | Official auth-mini treats audience as the relying-party boundary | Continue ignoring `aud` | 2026-07-30 |
| Reject issuer/missing audience for legacy sessions | A compatibility exception would permit cross-client token replay | Persist dual legacy/current token profiles | 2026-07-30 |
| Keep schema v2 unchanged | Existing Pending state already provides the crash-safe rotation barrier | Add audience/profile columns | 2026-07-30 |

---

## 快速交接

**下次继续从这里开始：**

1. Commit the reviewed worktree changes.
2. Fetch/rebase `origin/master`, push the PR branch, create the PR, and enable auto-merge if allowed.
3. Follow checks/review to terminal state, then clean up the worktree and refresh the main workspace.

**注意事项：**

- Never record callback bodies, access/refresh tokens, signed cookies, or identity values in evidence.
- Production rollout is not complete until each service has exact `ALLOW_USER_IDS` and no nonempty `ALLOW_EMAILS`.
- Gateway-only rollback does not restore login against current auth-mini.

---

*最后更新: 2026-07-30 10:45*
