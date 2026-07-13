# Walkthrough：移动端会话生命周期与刷新韧性

> **Mode:** `implementation`
> **Risk:** **HIGH — authentication / refresh-token rotation / SQLite migration / nginx auth boundary**
> **Review state:** final `test-report` **PASS**；第二轮 `review-change` **PASS / READY**；blocker none（`docs/test-report.md:9-17,299-305`，`docs/review-change.md:9-19,93-95`）
> **Capability exception:** silent SSO gate **FAIL / unsupported**，不属于本 PR 已实现能力（`docs/silent-sso-capability.md:3-18`）
> **Evidence notation:** `docs/test-report.md`、`docs/review-change.md`、`docs/review-rfc.md` 指当前 task 的 docs 目录；`docs/production-deployment.md`、`docs/silent-sso-capability.md` 指仓库根目录用户文档。

## 1. Reviewer summary

本变更解决移动 Safari/PWA 等休眠型浏览器在没有后台定时器时容易隔夜掉线的问题：access token 改为在恢复后的受保护请求上按需刷新，本地 session 改为 **7 天 idle + 30 天不可滑动 absolute**，成功授权活动最多每 **1 小时**合并 touch 一次；login state 为 **10 分钟**。临时认证依赖故障不再被放大为永久登出，而是当前请求 fail-closed `503`、保留 Cookie，恢复后可重试（问题与目标见 `plan.md:3-19`）。

这不是“永不重新登录”的承诺：absolute deadline、明确撤销和本地 logout 仍是终态；移动系统仍可能清理 Cookie；silent SSO 未获能力证据。没有运行实体移动 Safari，Cookie 收包时过期行为使用真实 nginx + curl cookie jar 验证（`docs/test-report.md:289-298`）。

### 最终行为一览

| 边界 | 最终行为 | 主要实现证据 |
|---|---|---|
| 新 session | idle `604800s`，absolute `2592000s`，absolute 从 callback 创建起不推进 | `src/config.rs:73-79`；`src/db.rs:206-239` |
| 活跃续期 | 仅最终允许的 `204` 可 touch；`3600s` 合并；candidate 截断到 absolute | `src/server.rs:257-288`；`src/db.rs:367-415` |
| login state | `600s`、高熵签名 Cookie、同源 return target、一次性消费 | `src/server.rs:89-145,616-640`；`src/db.rs:153-203` |
| refresh 临时/不确定失败 | 当前请求 `503`，无 redirect、无 Cookie clear、row 保留 | `src/auth_mini.rs:65-85,257-304`；`src/server.rs:237-253,578-584` |
| refresh 明确拒绝 | 仅 exact `401 session_invalidated/session_superseded` 条件撤销，返回 `401` 并 clear | `src/auth_mini.rs:281-298`；`src/server.rs:384-438,573-576` |
| `/me` 非 fresh 结果 | 保持 durable Pending，`503`；包括 `/me` 401 在内均无 revoke authority | `src/auth_mini.rs:72-85,202-255`；`src/server.rs:475-525` |
| nginx 主响应 | 传播 absolute renewal/clear Cookie；认证异常映射无跳转 `503`；业务 upstream `500` 不被改写 | `examples/nginx.conf:46-98` |

## 2. 生命周期、Cookie 与用户体验

配置默认值和约束集中在 `Config::from_env` / `validate_session_lifetimes`：`7d idle / 30d absolute / 1h touch / 10m login state`，并强制 `0 < touch <= idle <= absolute`（`src/config.rs:73-109`）。README 与生产部署基线同步这些值（`README.md:49-52`，`docs/production-deployment.md:56-90`）。

用户恢复页面后的首个受保护请求触发服务端检查和必要 refresh，不依赖浏览器后台执行。授权成功后，`touch_ready` 只在间隔到期时把 idle deadline 推进到 `min(now+7d, absolute)`；`403`、`503`、Pending 和失败持久化都不会续期（`src/server.rs:192-290`，`src/db.rs:367-415`）。接受的精度代价是最后活动最多约 1 小时保守提前过期，而不是越过安全期限（`docs/review-rfc.md:51-54`）。

正向 `amg_session` 和 login-state Cookie 只携带 DB deadline 对应的绝对 `Expires`，不携带 positive `Max-Age`；clear Cookie 同时携带 `Max-Age=0` 与 1970 `Expires`（`src/cookies.rs:18-36,66-90`）。nginx 从 auth subrequest 捕获 `Set-Cookie` 并加到最终 HTTP/WS 主响应；401 internal redirect 还会同时保留 session clear 和 `/login` 产生的独立 login-state Cookie（`examples/nginx.conf:57-89`）。因此慢 upstream 不会按“收包时刻 + 相对时长”把 Cookie 延后。

## 3. Schema v2、legacy 不延长与可回滚性

`SCHEMA_VERSION=2` 是 additive migration，保留 v1 列，并新增 idle/absolute/touch/identity-Pending 字段。迁移在 `BEGIN IMMEDIATE` 中完成，拒绝未来 schema；v1 row 使用：

```text
A = min(old session_expires_at, created_at + 30d)
E = min(old session_expires_at, A)
```

因此始终 `E <= A <= old deadline`，不会给 legacy session 延寿。旧 binary 后续写入的 nullable row 也按同一公式 repair（`src/db.rs:446-568`）。读取时严格校验 Ready 的 compatibility gate 必须镜像 idle deadline，Pending 的 gate 必须为过去时间；未知或不一致状态不能授权（`src/db.rs:600-668`）。

Rotation 后新 token 先由 `persist_pending` 原子写入，generation 增加，`identity_state=pending`，同时把 v1 可见 `session_expires_at` 写为 `COMPAT_DENY_AT`。这样新旧 binary 在 fresh identity 完成前都 fail-closed。`finalize_pending` 只有在 generation/user/state 匹配、未撤销且 E/A 未到期时才恢复 Ready；没有 SQL 会把 `revoked_at` 设回 NULL（`src/db.rs:286-365`）。

真实 pre-change binary 已验证 Ready/NULL read、Pending deny/logout/prune、NULL repair 和安全 re-upgrade；WAL drill 已验证非空 WAL、SQLite backup API snapshot、恢复完整性/schema/Ready invariant 及恢复后真实 gateway 授权（`docs/test-report.md:92-119,279-283`）。

## 4. Refresh authority：typed、exact-200、no-redirect

`AuthMiniClient` 全局设置 `redirect::Policy::none()`，避免 307/308 将 rotation POST、session id 或 refresh token 重放到 `Location`（`src/auth_mini.rs:111-126`）。JWKS、`/me` 与 refresh success 都只接受 exact `200 OK`；201/206 或 3xx 即使 body 看似有效也不能推进 DB（`src/auth_mini.rs:142-171,202-255,257-304`）。

错误边界是显式类型：

- `Temporary`: timeout、transport、429、5xx；
- `Indeterminate`: unexpected status/body、token verification、contract drift、persistence 等；
- `Rejected`: **仅 refresh endpoint** exact `session_invalidated` / `session_superseded`；
- `IdentityFetchOutcome` 没有 `Rejected` variant，因此 `/me` 不能撤销 session（`src/auth_mini.rs:39-85`）。

`handle_auth_check` 将 Temporary/Indeterminate 映射到无跳转 `503`，不 clear Cookie；Rejected 才走 `401` clear。nginx 再把 auth phase 的内部 `500` 映射为最终 `503`，同时保持 protected upstream 零命中（`src/server.rs:237-253,573-584`，`examples/nginx.conf:57-77,95-98`）。

## 5. Shared-result flight 与 durable identity-Pending

`FlightCoordinator` 以 session + observed `(generation,state)` 协调 flight。close 前注册的 joiner 消费 leader 发布的同一个 `Ready / Rejected / Temporary / Indeterminate`；不匹配版本等待当前 flight 关闭后重读；leader drop 会发布 `LeaderAborted`，避免永久等待（`src/flight.rs:15-20,23-49,62-118,142-186`）。Ready G 成功 rotation 前注册 Pending G+1 alias，避免看到已持久化 Pending 的并发请求重复 `/me`（`src/server.rs:351-367`）。

成功 rotation 的持久化顺序为：验证新 JWT/sid/sub → 原子保存新 token 为 Pending → 调用 `/me` → 只有 fresh matching identity 才 finalize Ready。Pending 可以跨 crash/restart 恢复；旧 email 不参与 policy/header。`/me` 401、其他 HTTP、transport、invalid body 或 identity mismatch 都只保持 Pending 并返回 shared `503`；后续独立请求可重试 identity，access 到正常 boundary 后可 Pending→Pending rotation（`src/server.rs:293-381,441-525`）。

Logout 不等待 flight：先 durable local revoke，再 best-effort remote logout。refresh CAS、Pending finalize 与 touch 都要求未撤销且未到期，因此迟到的远端成功不能复活 logout/idle/absolute 终态（`src/server.rs:538-570`；`src/db.rs:277-415`）。

## 6. 首轮 review findings 与修复

### 设计安全门演进

首轮 `review-rfc` 的 B-01/B-02/B-03 分别指出 mutex 不共享失败结果、30 天 email snapshot 弱化授权、relative `Max-Age` 被慢响应平移；第二轮又发现 B-04 把 `/me` 401 错当 revoke authority。第三轮全部闭合并 PASS（`docs/review-rfc.md:43-54,154-218`）。实现对应采用 shared-result flight、durable Pending、absolute `Expires` 和 `/me` non-revocation。

### 首轮 `review-change` 安全/证据 findings

| Finding | 风险 | 修复与复验证据 | 最终状态 |
|---|---|---|---|
| RC-01：auth-mini redirect 自动跟随，307/308 可重放 refresh credential | **HIGH** | `redirect::Policy::none()`；source hit=1、redirect target zero-hit；handler 返回 503 且 state 不推进 | CLOSED |
| RC-02：`is_success()` 接受任意 2xx，201/206 可推进 token/Pending | **HIGH** | JWKS、`/me`、refresh 均 exact 200；valid-looking 201/206 wire + handler tests 证明 DB 不推进 | CLOSED |
| RC-03：旧报告以 35 tests 夸大 concurrency/Pending/rollback 覆盖 | **MEDIUM** | 撤回旧声明；46 tests、server barrier tests、actual old binary、WAL restore、real-service E2E 分层陈述 | CLOSED |

完整 finding 与修复定位见 `docs/review-change.md:21-27,99-119`；最终复审未发现 blocking correctness、scope 或 security finding（`docs/review-change.md:9-19`）。

## 7. 真实验证清单

以下为最终 `verify-change` 已执行结果，不是本 walkthrough 新跑的测试：

- [x] `cargo fmt --check`
- [x] `cargo test` — **46 passed, 0 failed, 0 ignored**
- [x] `cargo clippy --all-targets -- -D warnings`
- [x] `cargo build --release --bin auth-mini-gateway`
- [x] 定向 wire/handler tests：no redirect、exact 200、四类 shared outcome、Pending alias/recovery、Pending→Pending、logout/idle/absolute race（`docs/test-report.md:50-90`）
- [x] `bash scripts/e2e-old-binary-compat.sh` — actual `origin/master` binary（`docs/test-report.md:92-105`）
- [x] `bash scripts/e2e-wal-backup-restore.sh` — WAL-consistent snapshot/restore（`docs/test-report.md:106-119`）
- [x] pinned auth-mini commit `86b4aaa8...` + nginx + protected HTTP/WebSocket upstream E2E：OTP callback、Cookie propagation、outage `503` isolation、restart、temporary recovery、real rotation/Pending finalize、logout、exact rejection、403、slow-upstream expiry（`docs/test-report.md:120-149`）
- [x] nginx `1.27-alpine` syntax；Compose render；`git diff --check`；16 项配置/文档一致性；changed-file redacted secret scan（`docs/test-report.md:151-184,186-260`）
- [ ] **未运行实体移动 Safari。** 真实 nginx 覆盖 HTTP/WS propagation；慢响应收包后 Cookie 行为由 curl jar 覆盖，不得表述为 Safari 实机验证（`docs/test-report.md:289-295`）。

真实 auth-mini/nginx E2E 没有注入 3xx/201/206、malformed `/me` 或 in-flight clock race；这些结论来自具名 deterministic wire/handler tests，而非真实服务注入（`docs/test-report.md:147-149,291-294`）。

## 8. Migration、rollout 与 rollback

### Rollout

1. 保持单 active writer，停止 gateway，做 WAL-consistent backup；保留旧 binary/image、old env、old nginx config。
2. 将 binary、四项生命周期配置和 nginx 作为一个兼容单元部署。
3. 启动并确认 v2 migration；验证 legacy deadline 不增加、Ready mirror、Pending compatibility deny。
4. 开流前重跑 actual old-binary、WAL restore、pinned auth-mini/nginx E2E。
5. 监控 Pending count/age、SQLite errors、flight outcomes、invalidation spike。

操作步骤与发布检查在 `docs/production-deployment.md:349-378`。

### Rollback

1. 始终保留 `auth_request` 或 maintenance deny，不能暴露 protected upstream。
2. 停止新 gateway/active flights 后恢复旧 binary 与 old env；不降低 `user_version`、不 drop v2 columns。
3. Ready row 可由旧 binary 读取；Pending 通过 past compatibility deadline fail-closed，可能被 prune 并要求重登。
4. DB 可疑时恢复 WAL-consistent backup；backup 后已 rotation 的 token 可能 superseded，按 R-01 fail-closed 重登。
5. 禁止手工拼接 Pending token、email 或 revocation state。

详见 `docs/production-deployment.md:380-387`。

## 9. Accepted residuals 与外部 follow-up

- **R-01 — accepted bounded fail-closed:** auth-mini 已提交 rotation、但 response 丢失或 gateway 在 Pending CAS 前 crash 时，gateway 无法恢复新 token。同一 flight 全部共享 `503`；下一独立请求若收到 exact superseded，可条件撤销并要求重登。禁止自动重试 rotating POST（`docs/review-change.md:83-86`；验证见 `docs/test-report.md:277,297`）。外部改进方向是 auth-mini idempotency/recovery contract。
- **R-02 — accepted wire-contract residual:** gateway 只能信任 refresh endpoint exact `session_invalidated/session_superseded`。auth-mini 仍可能把内部错误折叠为 `session_invalidated`，造成不必要重登；需监控 invalidation spike，并在 auth-mini 跟进 internal failure → 5xx（`docs/review-change.md:85-86`，`docs/production-deployment.md:398-405`）。该信任绝不扩展到 `/me`。
- Remote logout/revocation 在 access-token refresh boundary 前不可见；单 active gateway + SQLite、明文 token-at-rest、无 production-volume lock/load evidence 仍是已记录边界（`docs/review-change.md:83-91`）。
- **Silent SSO capability gate: FAIL / unsupported.** 当前 gateway session 的 request-driven refresh 不受影响；但 session 终态后不能承诺顶层 redirect 无交互恢复。外部 auth-mini follow-up 必须先定义 session-reuse contract，再由真实移动 Safari 或等价浏览器流程证明 eligible/no-interaction 与 ineligible/interaction 两条路径（`docs/silent-sso-capability.md:7-18`）。

## 10. 建议 review 顺序

1. **高风险协议边界：** `src/auth_mini.rs:39-85,111-171,202-304`。
2. **状态与 no-resurrection：** `src/db.rs:277-415,446-668`；`src/server.rs:293-570`。
3. **并发结果共享：** `src/flight.rs:15-186`；server-level tests 名单见 `docs/test-report.md:76-90`。
4. **浏览器/nginx 边界：** `src/cookies.rs:18-90`；`examples/nginx.conf:46-98`。
5. **上线/回滚证据：** `docs/test-report.md:92-165,262-305`；`docs/production-deployment.md:349-415`。
