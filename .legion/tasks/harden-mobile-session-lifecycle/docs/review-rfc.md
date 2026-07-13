# Review RFC：移动端会话生命周期与刷新韧性

> Current review: 第三轮 `review-rfc` 对抗复审
> Date: 2026-07-13
> Re-reviewed: B-04 revision of `research.md`, `rfc.md`, `risk-register.md`, `implementation-plan.md`
> Traceability: 本文后续完整保留第二轮 B-04 FAIL 与首轮 B-01/B-02/B-03 FAIL 记录

## Current verdict

**Verdict: PASS**

第三轮修订已经闭合 B-04，且没有发现新的实现前 blocking gap。`/me` 现被明确限制为 identity freshness source，而不是 local revoke authority：只有 fresh valid matching `200` 可以 finalize；所有其他结果保持同 generation Pending、共享 `503`，不 clear/touch/authorize；只有 refresh endpoint exact `session_invalidated/session_superseded` 可以因远端原因执行 expected-version conditional revoke。

设计现在对认证、SQLite migration、rotation/single-flight、old-binary rollback、absolute Cookie/nginx 和验证证据均达到可实现、可验证、可回滚门槛。PASS 只允许交回 `legion-workflow` 进入后续实现阶段；本轮没有实施代码或执行实现工作。

## Third-round B-04 closure

### `/me` has no revoke authority — CLOSED

复审确认四层 design source 一致：

1. **Research evidence:** 固定 auth-mini commit 的 OpenAPI 与实现证明确 `invalid_access_token` 只说明当前 access/profile request 不可用，且可能折叠 profile/SQLite 内部错误；不能证明 refresh credential/session 永久失效。
2. **State machine:** RFC 6.3 删除 `/me` rejection transition。Pending 只有 fresh valid matching `200` 能 CAS Ready；exact 401、其他 HTTP status、transport/timeout、parse/profile failure、malformed success 和 identity mismatch 均 no row change + shared `503`。
3. **Typed boundary:** `IdentityFetchOutcome` 没有 `Rejected` variant；`AnyHttpStatus` 明确包含 exact 401。Flight 的 remote `Rejected` 来源只允许 refresh endpoint exact rejection。
4. **Implementation stop condition:** 任一 `/me` 非 fresh-valid matching 200 路径执行 revoke/clear、构造 Rejected、policy/header/touch 均直接停止实现。

该边界消除了第二轮指出的不可区分错误分类，也没有把不可恢复状态伪装为可用：Pending 全程 fail-closed，protected upstream 命中为零，并继续受 E/A、local logout 和 old-binary compatibility gate 约束。

## Recovery / expiry / logout adversarial closure

| Scenario | Required durable/result behavior | Re-review |
|---|---|---|
| `/me` exact 401 或 internal-fold | generation/token/deadline/revoked state不变；Pending `503`；无 clear/touch/header/upstream | **CLOSED** |
| 多次 non-fresh `/me` 后恢复 | 每个 identity flight 最多一次调用；close 后独立请求可重试；仅第三次 fresh matching 200 finalize | **CLOSED** |
| `/me` 与 access-expiry race | 401 不撤销；到正常 boundary 才 Pending→Pending refresh；refresh success 后 fresh `/me` 可恢复 | **CLOSED** |
| 后续 refresh exact rejection | 只有 refresh flight 可 expected-generation/token revoke并 clear；R-02 范围未扩大 | **CLOSED** |
| New/old binary logout during Pending | logout立即写真实 `revoked_at`；late `/me` finalize CAS=0；无 SQL un-revoke | **CLOSED** |
| Idle/absolute expiry during Pending | refresh/finalize/touch CAS均要求 E/A future；late fresh 200不能恢复 | **CLOSED** |
| Crash/restart / old-binary rollback | Pending token已持久化可由新 binary重试；old binary通过past gate deny/delete/revoke，不能 authorize | **CLOSED** |

对应 barrier、repeated-flight、refresh-success/rejection、new/actual-old logout、E/A expiry 和 upstream-zero tests 已进入 RFC 11.4/11.5 与 implementation plan Milestone 2，足以验证上述状态转换。

## All review findings and decisions

| Item | Final design-gate status |
|---|---|
| **B-01 shared-result flight** | **CLOSED** — same-version joiners共享 four outcomes；failed flight remote count=1；close 后独立请求才重试。 |
| **B-02 durable identity Pending** | **CLOSED** — token先原子持久化；fresh identity前新旧 binary fail-closed；finalize受 generation/revoke/E/A CAS约束。 |
| **B-03 absolute Cookie expiry** | **CLOSED** — positive absolute Expires only；slow upstream、receipt-time jar与two-cookie nginx tests完整。 |
| **B-04 `/me` overreach** | **CLOSED** — `/me` 无 Rejected/revoke/clear authority；全部 non-fresh结果保持 Pending `503`。 |
| **R-01** | **ACCEPTED/CLOSED** — post-commit ambiguity是明确、测试化的 bounded fail-closed residual。 |
| **R-02** | **ACCEPTED/CLOSED** — wire trust严格限于 refresh exact rejection，并保留 invalidation-spike/follow-up。 |
| **R-07** | **ACCEPTED/CLOSED** — 3600 秒 conservative touch及边界测试固定。 |
| **R-12** | **CLOSED** — snapshot永久拒绝；fresh Pending finalize是唯一 identity更新路径。 |

## Remaining conditions after PASS

以下不是 RFC blocker，而是后续 engineer/verify-change/review-change 必须兑现的 hard gates：

1. 用实际 pre-change binary 验证 Ready/Pending/NULL-row/logout/prune，而非新代码模拟。
2. 运行 deterministic flight、B-04 recovery、persistence-failure 和 logout/expiry barrier tests；任何 `/me` 非 fresh 路径出现 revoke/clear 即停止。
3. 用真实 auth-mini/nginx 验证 rotation/exact rejection、HTTP/WebSocket absolute Cookie、两个独立 Set-Cookie、auth `503` 和 protected-upstream zero hit。
4. 验证 v1→v2 deadline 不增加、transaction rollback、WAL-consistent backup restore 和 rollback superseded 边界。
5. 完成日志/指标/CI artifact secret scan；SSO capability 必须继续标记 unsupported。

## Handoff

`review-rfc` 设计门已通过，可交回 `legion-workflow` 安排实现。按用户约束，本轮停在此处，不进入实现。

---

## 第二轮评审记录（历史，以下 FAIL/return condition 仅用于追溯）

> Current review: 第二轮 `review-rfc` 对抗复审
> Date: 2026-07-13
> Re-reviewed: revised `research.md`, `rfc.md`, `risk-register.md`, `implementation-plan.md`
> Historical record: 本文后半保留首轮 FAIL、B-01/B-02/B-03 和原始风险裁决全文

## 第二轮 Verdict（历史）

**Second-round Verdict: FAIL**

首轮 B-01 shared-result flight、B-02 durable identity-pending/old-binary fail-closed、B-03 absolute `Expires` 均已在设计和验证计划中实质闭合；R-01、R-02、R-07、R-12 的首轮裁决也已成为 binding inputs，不再是 open question。

但 B-02 引入的 Pending `/me` 流程新增了一项 blocking authentication gap：RFC 把未定义的“exact `/me` invalid access”作为本地撤销依据。固定 auth-mini 证据表明该响应既不能证明 refresh token 失效，也可能折叠 profile/SQLite 内部错误。按当前设计实现会扩大永久登出类别，违反 plan 的明确撤销边界，因此仍不能进入实现。

## Second-round blocking finding

### B-04 — `/me` 的 `401 invalid_access_token` 不是可撤销本地 session 的明确 refresh/session rejection

**Design evidence:** revised RFC 6.3 把 Pending `/me` 的“exact invalid access”映射为 expected-generation revoke；implementation plan Milestone 2 同样要求 exact `/me` invalid access 条件撤销。但 research、RFC definitions 和 risk register 都没有定义该 exact classifier 或证明它代表 refresh token/session 已永久无效。

**Fixed auth-mini evidence at `86b4aaa8ca97d1218217a7f6f0144251a5f30c9b`:**

- `openapi.yaml:269-285,782-789` 只把 `/me` 的 `401 invalid_access_token` 定义为 access token missing、malformed、expired 或 revoked；它不声明 refresh credential/session 必然不可恢复。
- `rust-backend/src/http.rs:849-857` 不仅对 authentication failure 返回该 `401`，还把 `current_user_response` 的**任意错误**折叠成同一个 `401 invalid_access_token`。
- `rust-backend/src/session.rs:143-165` 又把 access-token verify、session lookup 和相关 DB 错误统一映射为 invalid access。

**Why blocking:**

1. Access token 在 `/me` 请求边界到期时，refresh token 仍可能完全有效；直接 revoke 会把可恢复状态变成永久登出。
2. `/me` profile/SQLite 内部错误也可表现为 exact `401`；直接 revoke 会重新引入本任务要消除的“临时依赖故障导致永久登出”。
3. 首轮 R-02 只裁决了 refresh endpoint 的 exact `session_invalidated/session_superseded` wire contract，不能外推为信任 `/me` 的 `invalid_access_token`。
4. 实现者无法从现有 wire response 区分上述情况，因而当前撤销分支不可安全实现、不可验证。

**Required closure:**

- `/me` 不得成为 local revoke authority。除 fresh `200` 且 identity 与 verified JWT/existing user 一致外，`401 invalid_access_token`、其他 status/body、mismatch 和 profile failure 都应保持 Pending、返回 `503`、不 clear、不 touch、不发送 identity header。
- Pending token 到正常 refresh boundary 后，可按既定 Pending→Pending rotation 流程恢复；只有 refresh endpoint 的 exact `session_invalidated/session_superseded` 才按 R-02 条件撤销。
- research 必须加入上述 `/me` wire/implementation evidence；RFC state table、typed-error boundary、risk register 和 implementation plan 必须删除 `/me` 401→revoke。
- 增加确定性测试：fresh token 的 `/me` exact 401/profile internal failure 保持 Pending+503；access expiry race 不 revoke；后续 refresh success 可恢复，后续 exact refresh rejection 才 revoke；全部 upstream hit=0。

该修订不要求修改 auth-mini，也不改变已经接受的 R-01/R-02/R-07/R-12 裁决。

## 首轮 finding 闭合复核

| Finding | Re-review decision | 对抗复核 |
|---|---|---|
| **B-01** | **CLOSED** | Flight 现在按 observed `(generation,state)` 注册 joiner、共享 four-outcome result；mismatched version 等待 close 后重读；G+1 Pending alias 防止重复 `/me`；panic/poison completion guard 与 four-outcome remote-count=1 tests 已写入 RFC/plan。注册是否发生在 close 前被明确作为线性化边界，足以区分 joiner 与后续独立请求。 |
| **B-02** | **CLOSED for stale-identity and old-binary gate** | Valid rotation 后 token+generation+Pending+past compatibility gate 原子提交；fresh `/me` 前不跑 policy/header/touch；finalize 匹配 generation/Pending/revocation/E/A 且永不清 `revoked_at`；v2 prune 使用 authoritative deadlines；真实旧 binary 的 deny/logout/prune/NULL-row gate 已列为 hard test。B-04 是 Pending error classification 的新增问题，不否定该兼容 gate 本身。 |
| **B-03** | **CLOSED** | Positive session/login-state Cookie 改为 absolute `Expires` only，positive `Max-Age` 被禁止；clear 使用 `Max-Age=0`+past Expires；slow-upstream、receipt-time jar、HTTP/101 和 final redirect two-cookie tests 已闭合主响应延迟问题。客户端异常时钟仅能造成残留 Cookie，server E/A 仍拒绝授权。 |

## R-01 / R-02 / R-07 / R-12 复核

| Risk | Current decision | Closure status |
|---|---|---|
| **R-01** | **ACCEPTED — bounded fail-closed residual** | **CLOSED.** 同一 indeterminate flight one remote call/all joiners 503；close 后第三独立请求 exact superseded 才 expected-version revoke。禁止自动 retry，并有完整确定性 sequence。 |
| **R-02** | **ACCEPTED — refresh wire contract only** | **CLOSED within its original scope.** 只信任 refresh endpoint exact `401 session_invalidated/session_superseded`；其他 refresh status/body 503。B-04 要求明确禁止把该裁决扩展到 `/me`。 |
| **R-07** | **ACCEPTED — 3600s** | **CLOSED.** Ready-only conditional touch、A cap、3599999/3600000ms boundary 和写入上限均已纳入设计/测试。 |
| **R-12** | **SNAPSHOT REJECTED; PENDING REQUIRED** | **CLOSED.** 旧 email 不再 fallback；fresh identity 原子替换后才 policy/header；allowed→denied、NULL/user-id、crash/restart、logout/expiry 和 actual-old-binary 均有 hard gate。 |

## 分领域复审结论

- **认证：FAIL。** Ready-only authorization、Pending fail-closed 和 exact refresh rejection 边界正确；B-04 的 `/me` 撤销 authority 仍越界。
- **SQLite migration：PASS at design gate。** `E<=A<=old_E`、Ready mirror、Pending past gate、strict state validation、atomic rollback、authoritative prune 与 NULL repair 均可实现并可验证。
- **Refresh rotation / single-flight：PASS at design gate。** Shared outcome、close boundary、R-01 sequence、Pending alias、logout/expiry CAS 和 persistence-failure paths 已充分具体。
- **nginx Cookie / 503：PASS at design gate。** Absolute Expires、两个独立 Set-Cookie、auth failure→503/upstream0 与 upstream500 隔离均有真实组合测试。
- **Rollback：PASS at design gate。** Pending 对 actual old binary deny/delete/revoke，Ready 兼容，old logout 后 finalize=0，WAL-consistent restore 接受 superseded 重登。
- **测试：FAIL only on B-04。** 其余首轮 hard gates已进入 implementation plan；缺少 `/me` exact 401/internal failure 不撤销及后续可恢复 sequence。

## Current return condition

退回 `spec-rfc`，只需闭合 B-04 后再次执行 `review-rfc`。重新评审前必须能从 design source 明确证明：

1. `/me` 任意非 fresh-valid identity 结果都不会直接 revoke、clear 或 authorize；
2. Pending 继续 fail-closed，并可在后续 identity retry或 Pending→Pending refresh 后恢复；
3. 唯一远端撤销 authority 仍是 R-02 已裁决的 refresh exact rejection；
4. 对应 research/risk/tests 与该边界一致。

即使后续 review PASS，actual old-binary、真实 nginx/auth-mini、slow-cookie、flight concurrency、persistence failure 和 secret scan 仍是实现后的 rollout hard gates，不能以本设计评审代替。

---

## 首轮评审记录（历史，以下 Verdict/Return condition 不代表本轮新增判断）

> Review stage: `review-rfc`
> Date: 2026-07-13
> Reviewed: `plan.md`, `docs/research.md`, `docs/rfc.md`, `docs/risk-register.md`, `docs/implementation-plan.md`
> Scope: 只审查设计是否可实现、可验证、可回滚；未修改生产代码、`plan.md`、`log.md` 或 `tasks.md`

## 首轮 Verdict（历史）

**First-round Verdict: FAIL**

当前 RFC 不能进入实现。SQLite additive migration、refresh typed-error 矩阵、nginx `503` 隔离和总体 rollback 方向基本成立，但仍有三个会让认证行为不安全或无法按验收标准验证的 blocking finding：当前 mutex 方案不是真正的 single-flight、30 天 email snapshot 会弱化现有授权边界、auth subrequest 计算的相对 `Max-Age` 不能证明浏览器收到的 Cookie 不越过 absolute deadline。

结论应退回 `spec-rfc`，先修订 RFC、风险登记和实现/测试计划；本 review 不授权实现。

## Blocking findings

### B-01 — `Weak<Mutex<()>>` 只做串行化，没有共享一次 flight 的失败结果

**Evidence:** RFC 6.6.1 只定义 `session_id -> Weak<Mutex<()>>`，等待者拿锁后重读 row；RFC 11.3 和 implementation plan Milestone 3 只要求成功 refresh 时远端调用数为 1。

**Failure:** leader 遇到 timeout、transport、429、5xx 或 indeterminate failure 时，数据库 row 不变。已经排队的并发请求随后逐个拿锁，仍判断需要 refresh，并各自再次调用 rotating POST。这会：

1. 违反“同 session 并发 refresh 使用 single-flight”的验收条件；
2. 把一次依赖故障放大为串行请求风暴和累计等待；
3. 在 leader 实际已远端 rotate、但响应丢失时，让 waiter 立即得到 `session_superseded` 并撤销 row，把本应返回 `503` 且保留 session 的同一并发批次转成永久登出。

这不是实现细节。RFC 必须定义同一 observed generation 的 joiner 如何消费 leader 的同一个 success/rejected/temporary/indeterminate 结果，以及一次 temporary flight 完成后何时允许一个**后续新请求**重试。验证必须覆盖：两个并发请求、leader 返回 temporary/indeterminate、远端调用恰好一次、两者均为 `503`、row/Cookie 不变；之后独立请求才可重新发起 refresh。

因此当前设计不可按并发与临时故障验收标准实现和验证。

### B-02 — R-12 的 email snapshot 会把可变身份属性继续作为最长 30 天的授权事实

**Evidence:** RFC 6.5.2 决定 refresh 后不再调用 `/me`，继续把 callback email 同时用于 allowlist 判断和 `X-Auth-Mini-Email`；risk register R-12 已确认 email 变化最长 30 天不可见。

**Failure:** 当前系统 refresh 后会重新取得 `/me`。改成 snapshot 后，已离开允许域、被更名或被重新分配的 email 仍可通过 email allowlist，并继续作为可信身份 header 发送给 protected upstream。每请求重评 allowlist 不能修复这一点，因为被重评的输入本身已经陈旧；“建议使用 user-id allowlist”也不能改变现有 email allowlist 是受支持安全边界的事实。

这会造成授权语义的安全退化，而 plan 没有接受该退化。R-12 不得按当前方案进入实现。修订 RFC 必须二选一：

- 提供可审计的 auth-mini 契约，证明 session lifetime 内 email 不可变且可安全作为 snapshot；或
- 完整设计 rotation 后先持久化 token、在 fresh identity 未确认前不授权的 durable 状态，包括 migration、状态转换、重试、old-binary rollback 的 fail-closed 行为和测试。

在该边界未确定前，设计不安全且 rollback 语义不完整。

### B-03 — auth 时刻计算的相对 `Max-Age` 不能约束浏览器实际收包时刻

**Evidence:** RFC 6.4.2 规定 `Max-Age=floor(E-now)`，RFC 6.7 再由 nginx 把 subrequest 的 `Set-Cookie` 加到 protected upstream 的最终响应，并据此声称 Cookie 不越过 absolute deadline。

**Failure:** `Max-Age` 从用户代理处理最终响应时开始计时，不是从 auth subrequest 的 `now` 开始。若 protected upstream 在 auth 成功后延迟 `d` 才返回 headers，浏览器 Cookie 可存活到约 `E+d`，慢响应或 streaming header delay 下没有可证明上界。现有“Max-Age 不大于 auth 时 DB remaining lifetime”的单测无法证明浏览器边界的声明。

服务端仍会在 `E/A` 后拒绝该 opaque Cookie，因此这不是 session resurrection；但它直接冲突于 plan 中“浏览器收到受 absolute deadline 限制的滑动 Cookie”和 RFC 的绝对声明。RFC 必须明确选择并验证：

- absolute deadline 只约束服务端授权，允许 Cookie 因主响应延迟而短暂残留；或
- 改用能按绝对时间约束用户代理 Cookie 的方案，并给出 Safari/真实 nginx 浏览器流程验证。

在契约未澄清前，该验收项不可验证。

## R-01 / R-02 / R-07 / R-12 裁决

| Risk | Decision | 裁决理由与约束 |
|---|---|---|
| **R-01** | **ACCEPTED — bounded fail-closed residual** | Gateway 单仓无法消除远端 commit 后响应丢失或本地 CAS 前 crash。接受下一次未恢复的 `session_superseded` 导致条件撤销和重登；不接受自动 retry、永久 `503` 或猜测 token。必须补确定性测试：第一次远端已 rotate 但客户端得到 indeterminate，row 不变且返回 `503`；下一次 superseded 执行 expected-generation revoke、清 Cookie、upstream 零命中。该限制必须进入生产文档和 auth-mini idempotency/recovery follow-up。 |
| **R-02** | **ACCEPTED — trust exact wire contract** | Gateway 只把 exact `401 + session_invalidated/session_superseded` 当作 external authority 的明确拒绝，其他 status/body 一律 `503`。接受 auth-mini 当前可能把内部错误折叠为 `session_invalidated` 的残余 UX 风险，因为 gateway 无法从 wire 安全区分，且行为保持 fail-closed。文档不得声称所有 auth-mini 内部临时错误都能保留 session；需监控 invalidation spike，并建立 auth-mini 将内部故障改为 5xx 的 follow-up。 |
| **R-07** | **ACCEPTED — 3600s touch interval** | 接受最多约 1 小时的保守提前到期，换取每 session 每天最多 24 次 durable touch。该误差不得延长 `E/A`，配置必须满足 `0 < touch <= idle <= absolute`，边界测试按 RFC 保留。 |
| **R-12** | **REJECTED — BLOCKING** | 未证明 email 在 session 内不可变时，30 天 snapshot 会弱化 email allowlist 和下游身份 header 的授权语义。必须按 B-02 重新设计或提供不可变契约证据后再审。 |

## 分领域对抗审查

### 认证边界

- `204` 才 touch、`403/503` 不 touch、local logout 先 revoke、失败认证 upstream 零命中的方向正确。
- exact status+error allowlist、未知 body/status 走 `503`，可以避免 gateway 自身把 contract drift 当撤销。
- R-02 按外部 wire contract 接受，但必须收窄文档保证；gateway 不能证明 auth-mini 内部错误分类正确。
- R-12 仍是 blocking authorization regression。

### SQLite migration

- `A/E <= old_E` 的 backfill 证明成立；additive nullable columns 能支持旧 binary 写入并在再次升级时 repair。
- `BEGIN IMMEDIATE`、非法时间全事务失败、future version 拒绝和保留 `session_expires_at` 的 rollback 方向可执行。
- 实现 gate 必须实际验证：v1 fixture deadline 不增加、DDL/DML 故障不半迁移、旧 binary 能以旧 env 启动 `user_version=2` 数据库、旧 binary 新建 NULL row 后再次升级不延长、格式损坏 row 不授权。
- 以上当前不是 RFC blocker，但不能只靠静态公式替代 migration/rollback fixture。

### Refresh rotation

- POST 前准备 JWKS、成功后先验证 sid/sub 再立即 CAS、rotation POST 禁止自动 retry，能缩短但不能消除 R-01 窗口。
- R-01 接受为 fail-closed 重登边界；RFC 11.3 当前明确排除 ambiguous case，导致该已接受 Critical residual 没有验证证据，必须补入测试计划。
- CAS 继续必须同时约束 expected token/generation、未撤销、idle/absolute 未到期；DB 写失败不得伪装成成功。

### Single-flight

- logout 不等待 refresh lock、以 DB revoke 和 CAS 决胜是正确的 no-resurrection 线性化边界。
- 当前 keyed mutex 没有 flight result sharing，B-01 阻塞。
- 除已有 success/logout/expiry 测试外，还需 temporary leader + multiple joiners、indeterminate leader + joiners、不同 session 并行、registry cleanup、poison/fail-closed 测试。

### nginx Cookie / `503`

- `auth_request_set` 捕获 renewal Cookie、`add_header ... always`、认证阶段内部 `500` 映射 `503`、`proxy_intercept_errors off` 并验证业务 upstream `500` 不被改写，设计方向成立。
- E2E 必须分别断言两个 `Set-Cookie`：清除 `amg_session` 与新建 `amg_login_state`，不能只断言存在任意 Cookie；还要覆盖 auth gateway 连接失败、直接 5xx、无 `Location`、失败路径 hit count 为零。
- B-03 的相对 `Max-Age`/最终响应时延问题尚未解决。

### Rollback

- 停 writer、保留 fail-closed nginx、旧 binary+旧 env、必要时恢复 WAL-consistent backup 的顺序合理。
- 恢复旧 DB 后 refresh token 可能 superseded 并触发重登，已作为 fail-closed 边界接受；不得手工拼接 token。
- rollback drill 必须真实运行旧 binary，而不是只验证新 binary 可读 v2；同时证明 restored backup 包含一致的 DB/WAL 状态。
- 如果 R-12 改成新增 durable pending state，必须重新证明旧 binary 不会忽略该状态后授权；当前 rollback 章节尚未覆盖，因此不能先实现后补。

### 测试充分性

现有计划已覆盖大部分 deadline、migration、nginx status/Cookie、logout/expiry race，但以下是 RFC 回炉后的必补 hard gate：

1. 同 generation 的 temporary/indeterminate single-flight 结果共享，remote call count 必须为 1；
2. R-01 post-commit ambiguity 的完整两请求状态转换；
3. R-12 最终方案的身份变化、授权和 old-binary rollback 测试；
4. B-03 最终 Cookie 契约的慢 upstream/真实浏览器或等价可观察验证；
5. refresh CAS 持久化故障、touch DB 故障都返回 unavailable、row 不被错误撤销、upstream hit 为 0；
6. final redirect 同时保留 clear-session 与 login-state 两个独立 Cookie。

## Return condition

退回 `spec-rfc`。只有 B-01、B-02、B-03 均在 RFC、risk register 和 implementation/testing plan 中闭合，并保持上述 R-01/R-02/R-07/R-12 裁决，才可重新执行 `review-rfc`。
