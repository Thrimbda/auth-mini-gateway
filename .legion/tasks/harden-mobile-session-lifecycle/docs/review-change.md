# Review Change：移动端会话生命周期与刷新韧性

> Current review: 第二轮 `review-change` 完整复审
> Date: 2026-07-13
> Review mode: 只读代码/证据审查；已展开认证、令牌、会话、SQLite schema/rollback、DoS/泄密与 nginx 安全视角
> Inputs: stable `plan.md`、approved `docs/rfc.md`、第三轮 PASS `docs/review-rfc.md`、当前完整 diff/untracked files、更新后的 `docs/test-report.md`、46 个 Rust tests 与三个 E2E harness
> Traceability: 文末保留首轮 FAIL findings；本轮 resolution 以当前代码和复验证据为准

## Current verdict

**PASS — ready for the next caller-controlled stage.**

本轮未发现 blocking correctness、scope 或 security finding。首轮发现的 redirect replay/credential disclosure、unexpected 2xx fail-open 和验证证据夸大均已闭合；修复没有引入新的授权绕过、session resurrection、错误 fail-open、Cookie 期限越界、old-binary Pending 绕过或 nginx upstream isolation regression。

本结论只完成 `review-change` readiness 判断；不进入后续阶段。

## Blocking findings

**None.**

## First-round finding resolution

| Historical finding | Resolution evidence | Status |
|---|---|---|
| **RC-01 HIGH — auth-mini redirect 被自动跟随，307/308 可重发 refresh credential** | `src/auth_mini.rs:119-123` 显式设置 `redirect::Policy::none()`；`redirect_responses_are_not_followed_or_replayed` 覆盖 refresh 302/307/308、`/me`/JWKS redirect，source hit=1、target zero-hit；`redirect_wire_results_return_503_without_target_hit_or_state_change` 进一步证明真实 `handle_auth_check` 返回 503、无 Cookie、Ready G0 不推进。 | **CLOSED** |
| **RC-02 HIGH — `is_success()` 接受任意 2xx 并推进 refresh/Pending identity** | `src/auth_mini.rs:147-161,219-239,271-303` 对 JWKS、`/me`、refresh 只接受 exact `200 OK`；201/206 valid-looking body 在 wire tests 中均失败，handler tests 证明 Ready/Pending generation/state 不推进。 | **CLOSED** |
| **RC-03 MEDIUM — 35 tests 无法支撑 concurrency/Pending/rollback hard-gate 声明** | 更新后的 `docs/test-report.md` 明确撤回旧声明；46 tests 增加 server-level shared flight、Pending alias/error/recovery、fresh policy input、Pending→Pending 与 logout/idle/absolute barrier；`scripts/e2e-wal-backup-restore.sh` 已实际执行；real auth-mini/nginx、old binary、secret scan 全部重新通过。 | **CLOSED** |

## Security and correctness review

### Auth-mini protocol boundary — PASS

- HTTP client 全局禁止 redirect，因此 `/session/refresh` 不会把 rotating POST、session id 或 refresh token 发往 `Location`；`/me` 与 JWKS 也不会接受 redirect 后的替代 authority。
- JWKS、`/me` 与 refresh success 均要求 exact `200`。Refresh/identity 的 408/429/5xx/transport 保持 temporary，其他未知 status/body（包括 JWKS contract drift）保持 unavailable/indeterminate；只有 refresh endpoint exact `401 session_invalidated/session_superseded` 能进入 remote rejection。
- Refresh success 在持久化前仍验证 token signature、issuer/type/exp、sid 和 sub；identity 只有 fresh matching `/me` 才 finalize。`/me` 401、其他 HTTP、invalid body 与 mismatch 没有 revoke authority。
- Callback 初始 session 同样经过 exact-200 JWKS/identity client、JWT 和 state/sid/sub 校验；未发现修复对 login state 一次性消费、同源 return target 或 Cookie 签名的回归。

### Session lifecycle / no resurrection — PASS

- `persist_pending`、`finalize_pending`、conditional revoke 与 durable touch 均约束 expected generation/state/token、`revoked_at IS NULL` 和 E/A future；不存在把 `revoked_at` 写回 NULL 的 SQL。
- Pending 持久化在 fresh identity 前把 v1-visible compatibility deadline 固定到过去；新 binary 不运行 policy/header/touch，实际 old binary 只能 deny/delete/revoke。
- In-flight logout、idle expiry 和 absolute expiry barrier tests 在 `/me` 阻塞时终止 session；late fresh identity 无法 finalize，最终 401 clear，row 保持 inactive。
- Fresh identity 会替换旧 email 后再重评 policy；allowed→denied 返回 403，NULL email 仅在 user-id allowlist 下授权，没有 stale email fallback。

### Refresh single-flight / result alias — PASS

- Coordinator 的 join/close 锁序、shared outcome、leader-abort completion guard 和 G+1 Pending alias 保持成立。
- 新 server-level test 通过真实 `handle_auth_check` 证明 leader + 2 joiners 对 success/rejected/temporary/indeterminate 只调用一次 refresh，并共享 204/401/503 结果；temporary/indeterminate 不清 Cookie、不推进 row。
- Pending alias test 证明 rotation 已提交但 identity 尚阻塞时，观察 G+1 Pending 的请求加入现有 flight，refresh 与 `/me` 均只调用一次。
- Pending→Pending test 证明 access 到 refresh boundary 时 generation 原子推进但 state 始终 Pending，fresh `/me` 前没有中间 Ready。
- R-01 仍按批准边界处理：同 flight lost-result 共享 503；close 后独立 exact superseded 才条件撤销，无自动 retry。

### SQLite migration / rollback — PASS

- v1→v2 additive migration 仍在 `BEGIN IMMEDIATE` 内执行；legacy `E <= A <= old_E`、future version reject、malformed timestamp rollback、strict Ready/Pending invariant 与 authoritative prune 未被本轮修复改变。
- Actual old-binary harness 继续覆盖 Ready/NULL read、Pending deny/logout/prune、NULL repair 与 safe re-upgrade。
- 新 WAL drill 在 committed fixture 仍位于非空 WAL frames 时使用 SQLite backup API，验证 snapshot 排除后续写入、`integrity_check=ok`、schema v2、Ready invariant，并由真实 gateway 对 restored copy 完成授权读取。该证据闭合第三轮 PASS 的 backup/restore gate。

### Cookie / nginx boundary — PASS

- Positive session/login-state Cookie 仍只有 DB-derived absolute `Expires`，无 positive `Max-Age`；clear 同时使用 `Max-Age=0` 与 1970 `Expires`。
- nginx 继续将 auth subrequest renewal/clear 传播到主 HTTP/WS response；final 401 redirect 保留独立 `amg_session` clear 与 `amg_login_state` positive headers。
- `auth_request` 非 401/403 error 的主请求 500 映射为 no-store 503；gateway/auth-mini outage 无 Location、upstream hit delta 0；`proxy_intercept_errors off` 保持业务 upstream 500 为 500。
- Real nginx 1.27 container syntax、HTTP 200、WS 101、slow-response expiry、two-cookie redirect 和 failure isolation 证据均 PASS。

### Scope / disclosure / availability — PASS with residuals

- 变更保持在 plan 指定的 gateway source、schema、nginx/examples、tests/scripts、docs 与 Legion task artifacts；未修改 auth-mini，也未重新引入 gateway AMR/Passkey policy。
- Production logs 仍只输出固定低敏感事件；更新后的 changed-file scan 未发现 token/Cookie/private-key/credential 泄漏。Redirect 修复消除了首轮 refresh-token 外送路径。
- 每 session flight 降低重复 remote calls，touch 合并限制写放大。SQLite 未做 production-volume lock/load test，thread-per-connection 与 lock contention 仍可能产生 fail-closed 503，但当前没有授权 fail-open 或 ready blocker 证据。

## Verification assessment

更新后的 `test-report.md` 将 deterministic wire/handler tests、真实 nginx/auth-mini E2E、actual old-binary 和 WAL restore 分开陈述，没有再把 mock/barrier evidence 伪装成 real-service evidence。报告记录：

- 46 Rust tests、fmt、Clippy、release build PASS；
- redirect target zero-hit、exact-200 fail-closed、shared flight 和 terminal races 的 focused tests PASS；
- actual old binary、WAL backup/restore、pinned auth-mini/nginx E2E PASS；
- nginx syntax、Compose、diff hygiene、配置一致性和 non-disclosing secret scan PASS。

证据足以覆盖批准 RFC 和首轮 return conditions；没有 verification blocker。

## Residual risks / test limits

- **R-01 accepted:** remote rotation commit 后 response 丢失仍可能在下一独立 exact superseded 时导致重登。
- **R-02 accepted:** auth-mini 仍可能把内部错误折叠为 exact `session_invalidated`；需依赖 invalidation spike 监控和外部 follow-up。
- Remote logout/revocation 在 access-token refresh boundary 前不可见。
- 仅支持单 active gateway + SQLite；没有 distributed single-flight，也没有 production-volume lock/load evidence。
- SQLite/WAL/backup 保存明文 token；token-at-rest encryption 和 Cookie secret 无损轮换不在范围。
- 未运行实体移动 Safari；receipt-time Cookie 使用 curl jar，HTTP/WS 使用真实 nginx。
- Silent SSO capability 继续正确标记为 **FAIL / unsupported**。

## Readiness

**PASS / READY. Blockers: none.**

---

## Historical first-round `review-change` findings

> 以下为首轮 2026-07-13 FAIL 记录，已由上方 resolution table 闭合；不代表当前 verdict。

### RC-01 HIGH — `src/auth_mini.rs` 默认自动跟随 redirect

首轮实现未禁用 reqwest redirect。`/session/refresh` 的 307/308 可能把 rotating POST 及 `session_id`/`refresh_token` 重发到 `Location`，并把最终响应误当原 endpoint 结果；`/me` 与 JWKS 也可能接受 redirect 后 authority。要求 no-redirect、3xx unavailable、target zero-hit 与单次 source call 证据。

**Resolution:** 当前 `redirect::Policy::none()` 与两层 wire/handler tests 已闭合，见 RC-01。

### RC-02 HIGH — `src/auth_mini.rs` 使用 `is_success()` 接受任意 2xx

首轮实现允许 201/202/206 valid-looking JSON 推进 refresh token generation 或 finalize Pending identity，违反 exact valid `200` 的 fail-closed contract。要求 JWKS、`/me`、refresh exact 200，以及 non-200 2xx 不改变 row/Cookie/header 的证据。

**Resolution:** 当前 exact `StatusCode::OK` checks 与 201/206 wire/DB tests 已闭合，见 RC-02。

### RC-03 MEDIUM — `docs/test-report.md` 对 hard-gate 覆盖声明超过证据

首轮 35 tests 主要覆盖 coordinator primitives 和少量 direct flight tests，缺少真实 `handle_auth_check` shared outcomes、Pending alias/error/recovery、Pending→Pending、logout/idle/absolute barriers 及 WAL-consistent restore；旧 test report 却声称全部通过。

**Resolution:** 旧声明已明确撤回；当前 46 tests、focused server-level barrier evidence、WAL drill 与分层 coverage map 已闭合，见 RC-03。
