# RFC: 移动端会话生命周期与刷新韧性

> **Profile:** RFC Heavy / High Risk
> **Status:** Revised after second `review-rfc` FAIL — Ready for re-review
> **Created / Updated:** 2026-07-13
> **Review basis:** `docs/review-rfc.md` B-01/B-02/B-03/B-04 与 R-01/R-02/R-07/R-12 裁决
> **Reader:** 负责认证边界、SQLite migration、nginx 部署和最终上线批准的 reviewer

## Executive Summary

- **生命周期：** 新 session 为 7 天 inactivity、30 天 absolute；仅成功 `204` touch，按已接受的 3600 秒间隔合并。
- **迁移：** schema v2 是 additive migration；旧 session 的新 deadline 不晚于旧 `session_expires_at`。
- **B-01：** single-flight 不再只是 mutex 串行化。同一 observed generation/state 的 joiner 订阅同一个 flight，并共享 leader 的 success/rejected/temporary/indeterminate 结果；失败批次只发一次远端请求，flight 关闭后的独立请求才可重试。
- **B-02：** 拒绝 30 天 email snapshot。远端 rotation 后先原子保存新 token 并进入 durable `identity_pending`；该事务同时把 v1 可见的兼容 deadline 设为过去，使新旧 binary 都 fail-closed。只有 `/me` 返回 fresh matching identity 后才能恢复 ready。
- **B-03：** positive `amg_session` 不再使用相对 `Max-Age`，只使用 DB effective deadline 对应的绝对 `Expires`。慢 upstream 不会把 Cookie 到期时间平移到主响应收包之后。
- **B-04：** `/me` 不具备撤销 authority。只有 fresh valid `200` 且 identity 与 verified JWT/existing user 一致才能 finalize；包括 exact `401 invalid_access_token` 在内的所有其他结果都保持 Pending、共享 `503`，不 clear/touch/authorize。
- **刷新错误：** exact `401 session_invalidated/session_superseded` 按 R-02 信任为明确拒绝；其他 status/body 一律 `503` 且不清 Cookie。
- **R-01：** 接受“远端已提交但结果丢失”的 bounded fail-closed residual：同一 flight joiner 都先得到 `503`；下一个独立请求收到 superseded 后条件撤销并重登，不自动 retry 或猜测 token。
- **并发：** logout 不等待 refresh flight，先写 `revoked_at`；pending finalize、refresh CAS、touch 都要求未撤销和未到期，不能 un-revoke。
- **nginx：** 显式传播 renewal/clear Cookie，把 auth phase error 映射为最终 `503`；最终 401 redirect 必须同时含独立的 clear-session 与 login-state 两个 `Set-Cookie`。
- **静默 SSO：** auth-mini 固定证据仍为 capability gate FAIL；本任务不修改 auth-mini。

---

## 1. 背景与 review closure

移动 Safari/PWA 不能依赖后台定时 refresh，可靠入口是恢复后的首个受保护请求。现有 gateway 使用固定 8 小时 session，并把所有 refresh 故障变成 local revoke。首轮 review 的 B-01/B-02/B-03 已闭合；第二轮 B-04 进一步收窄 remote rejection 边界：`/me` 的 access-token/profile 结果不能外推为 refresh credential 或 session 永久失效。

本修订将三项都纳入状态机和确定性验证，不修改 auth-mini，不改变 nginx 作为唯一公网代理的边界，也不恢复 gateway authentication-method policy。

## 2. Goals

1. 新 session 同时执行 7 天 inactivity 与 callback 创建时起算的 30 天 absolute lifetime。
2. v1→v2 自动迁移且任何旧 session 不因升级得到更晚 deadline。
3. 同一 refresh flight 的所有 joiner 共享一个最终结果，包括所有失败分类。
4. 远端 rotation 后，在 fresh `/me` identity 完成前 durable fail-closed，并在 crash/restart 后可继续恢复。
5. `/me` 只有 fresh valid matching `200` 可 finalize；其余任何结果都保留 Pending、返回 `503`，并允许后续独立 identity retry 或正常 Pending→Pending refresh 恢复。
6. logout、idle expiry、absolute expiry、refresh endpoint exact rejection 永远不能被 refresh 或 identity finalize 复活。
7. 临时/不确定故障返回 `503`、不触发登录 redirect、不清 Cookie、不命中 protected upstream。
8. positive session Cookie 使用绝对期限，nginx 主响应延迟不能延后其 expiry。
9. 真实 nginx/auth-mini、实际 old binary、可控时间和 barrier 并发测试共同构成发布 gate。

## 3. Non-goals

- 不修改 auth-mini refresh/login 协议或仓库，不实现 idempotency/recovery endpoint。
- 不实现多 active gateway、分布式 single-flight、共享 SQLite 或跨进程协调。
- 不实现 silent iframe/background auth、浏览器后台 refresh、原生 App SDK 或 OIDC Provider。
- 不实现 token-at-rest encryption、Cookie secret 无损轮换、push revocation。
- 不把 WebSocket 后续 frame 计为活动，也不到期主动断开已有连接。
- 不恢复基于 `amr`/Passkey 的 gateway authorization policy。

## 4. Hard constraints and accepted review decisions

### 4.1 API / status

- `/auth/check`: `204` allow、`401` missing/expired/revoked/explicit rejection、`403` fresh identity but unauthorized、`503` temporary/indeterminate/pending identity unavailable。
- `401/403/503` 都不得命中 protected upstream。
- `SESSION_TTL_SECONDS=604800`、`SESSION_ABSOLUTE_TTL_SECONDS=2592000`、`SESSION_TOUCH_INTERVAL_SECONDS=3600`；校验 `0 < touch <= idle <= absolute`。
- `LOGIN_STATE_TTL_SECONDS=600`。

### 4.2 Review decisions are closed inputs

| Risk | Incorporated decision |
|---|---|
| R-01 | 接受 post-commit ambiguity。禁止自动 retry；同一 flight 共享 indeterminate；下一独立请求若 exact superseded 则条件撤销。 |
| R-02 | 信任 exact wire `401 + session_invalidated/session_superseded`；其他 status/body 一律 unavailable。监控 invalidation spike，并建立 auth-mini internal-error→5xx follow-up。 |
| R-07 | 固定接受 3600 秒 touch interval 和最多约 1 小时保守提前到期。 |
| R-12 | snapshot 方案被拒绝；必须使用 durable identity-pending，fresh `/me` 前不授权、不发送 identity header。 |

R-02 的信任范围严格限于 `POST /session/refresh` 的 exact `session_invalidated/session_superseded`。它不适用于 `/me` 的 `invalid_access_token`，后者无论 status/body 如何都不能直接导致 local revoke/clear。

### 4.3 Security / privacy

- 浏览器只持 opaque HMAC Cookie；token 只存 SQLite。
- 不记录 token、Cookie、secret、callback body、auth-mini 原始 body、email、user/session id 或原始 URI。
- pending identity、DB/CAS 错误、flight coordinator 错误都 fail-closed。
- local logout 先 durable revoke，remote logout 始终 best-effort。

## 5. Definitions

- **`C`**: callback 创建本地 session 的时间。
- **`A`**: absolute deadline，`C + 30d`，永不推进。
- **`E`**: authoritative idle/effective deadline，始终 `E <= A`。
- **Compatibility gate (`session_expires_at`)**: v1 binary 可见的授权 gate。Ready 时镜像 `E`；pending 时写固定过去时间。
- **Observed version**: `(refresh_generation, identity_state)`，请求加入 flight 的版本键。
- **Flight**: 一个 session 上一次有明确注册边界的 refresh/identity recovery 操作及其共享结果。
- **Ready**: fresh identity 与当前 token generation 已一致，可进入 policy evaluation。
- **Identity pending**: 当前 token 已持久化，但当前 generation 的 `/me` 尚未验证；任何 binary 都不得授权。
- **Remote revoke authority**: 只有 refresh endpoint exact `401 session_invalidated/session_superseded` 可因远端原因触发 expected-version conditional revoke；`/me` 永远不是 remote revoke authority。

---

## 6. Proposed design

### 6.1 End-to-end auth check

1. 验证签名 Cookie；失败返回 `401` clear。
2. 读取 session row 并解析 authoritative `E/A`、`identity_state`、generation、revocation。
3. missing/revoked/`now >= E`/`now >= A` 返回 `401` clear。
4. `identity_state=pending` 时进入 identity-recovery flight；不得提前 policy/touch/header。
5. Ready 且 access token 需要 refresh 时进入 refresh flight。
6. Flight success 后重读 DB；只有 Ready row 才评估 allowlist 和 header safety。
7. `403` 不 touch；允许返回 `204` 前执行 3600 秒条件 touch。
8. Touch 推进时返回 absolute-Expires renewal Cookie；nginx 把它加到最终主响应。

### 6.2 Schema v2 and v1-visible fail-closed gate

#### 6.2.1 Added columns

保留全部 v1 列，新增：

| Column | Meaning | Compatibility |
|---|---|---|
| `idle_expires_at TEXT` | v2 authoritative `E` | 物理 nullable，供旧 binary 插入；v2 正常 row 必须有效 |
| `absolute_expires_at TEXT` | immutable `A` | 同上 |
| `last_touched_at TEXT` | last durable touch | 同上 |
| `identity_state TEXT` | `ready` or `pending` | 物理 nullable；v2 启动 repair old-binary row |
| `identity_pending_since TEXT` | pending 开始时间，仅观测/排障 | pending 必须非空；ready 必须为空 |

Existing `session_expires_at` 不再是 v2 authoritative idle source，而是兼容 gate：

- Ready: `session_expires_at == idle_expires_at`。
- Pending: `session_expires_at = 1970-01-01T00:00:00.000Z`（`COMPAT_DENY_AT`）。
- 不一致/未知 state 的 row 返回 `503`，不自动授权。

使用兼容 gate 而不是 `revoked_at` sentinel 的原因：旧 binary 的 logout 只更新 `revoked_at IS NULL`。Pending 必须保持 `revoked_at=NULL`，让旧 binary logout 仍能写入真实 revoke；后续 finalize 始终要求 `revoked_at IS NULL`，因此不能清除明确 logout。

#### 6.2.2 Atomic v1→v2 migration

在 `BEGIN IMMEDIATE` 内：

1. v0 先建立 v1 baseline；v1 添加全部 v2 列。
2. 对每个 v1 row：
   - `old_E = session_expires_at`
   - `A = min(old_E, created_at + 30d)`
   - `E = min(old_E, A)`
   - `idle_expires_at = E`
   - `absolute_expires_at = A`
   - `last_touched_at = created_at`
   - `identity_state = ready`
   - `identity_pending_since = NULL`
   - `session_expires_at = E`
3. 设置 `user_version=2` 并提交。
4. 任一 timestamp/DDL/DML 错误 rollback 全事务并拒绝启动；`user_version>2` 拒绝启动。

每次 v2 启动还要 repair 旧 binary 创建的 nullable row：按同一不延长公式填充 deadline，设为 Ready。当前 old binary 只在成功 `/me` 后原子写 refresh identity，因此它对既有 Ready row 的 generation/email 更新可继续视为 Ready；它不能读取 Pending row。

#### 6.2.3 Old session invariant

Migration 后 `E <= A <= old_E`。Ready touch candidate 为 `min(now+7d,A)`，不会越过 `old_E`。Legacy 默认 8 小时 row 的 `A=old_E`，因此不获得延长或 renewal。

### 6.3 Ready/pending/revoked state machine

| From | Event | Atomic durable action | Result |
|---|---|---|---|
| none | callback `/me` success | Insert current tokens + fresh email as Ready; compat gate=`E` | policy may run |
| Ready G | refresh temporary/indeterminate before valid 200 | No row change | shared `503` |
| Ready G | exact refresh rejection | expected G/token conditional `revoked_at=now` | shared `401` clear |
| Ready G | valid refresh 200 | CAS token pair, generation G+1, state Pending, pending_since=now, compat gate=`COMPAT_DENY_AT` | no authorization; call `/me` |
| Pending G | `/me` success, same user | CAS fresh email, state Ready, pending_since=NULL, compat gate=`idle_expires_at` | re-read then policy |
| Pending G | `/me` 任意非 fresh-valid matching `200`，包括 exact 401 | No row change | shared `503`; later independent request retries `/me` |
| Pending G | access needs refresh | Refresh; valid 200 atomically replaces tokens, generation G+1, remains Pending and compat-denied; then `/me` | no stale authorization |
| Ready/Pending | local logout | `revoked_at=now` without waiting for flight | clear + redirect; terminal |
| Ready/Pending | `now >= E` or `now >= A` | no refresh/finalize/touch allowed; prune eligible | `401` clear |

Fresh `/me` completion rules：

- `user_id` 必须等于 verified JWT `sub` 和 existing session user id。
- Email 可以改变或变为 NULL；finalize 原子替换 DB email。随后用新值重评 allowlist，可能返回 `403`。
- **只有** fresh valid `200`、可解析 profile、matching user 才能 finalize。
- Exact `401 invalid_access_token`、其他 4xx/5xx、transport/timeout、body/parse failure、profile/internal failure、malformed success 和 identity mismatch 全部保持 Pending并返回 `503`；不得 revoke、clear、touch、authorize或用旧 email fallback。
- Identity mismatch 记录固定低敏感 contract/security-drift 告警，但不能伪装成 refresh rejection。
- Finalize SQL 必须匹配 `id + expected generation + identity_state=pending + revoked_at IS NULL + E/A > now`。
- Finalize 只恢复 compatibility gate，不写 `revoked_at=NULL`；因此任何新/旧 binary logout 都不能被 un-revoke。

Repeated `/me` / recovery rules：

- 每个 identity flight 最多调用一次 `/me`；同一 flight joiner共享其 `503`，不在同一请求内循环或改发 refresh。
- Flight 关闭后的独立请求若 access token 尚未到本地 refresh boundary，可创建新的 identity-only flight并重试一次 `/me`。
- 若 access token 已到正常 refresh boundary，先按 Pending→Pending 流程调用 refresh。Refresh success 保存新 generation后再调用 `/me`；refresh exact rejection 才可条件撤销。
- `/me` 401 与本地 access-expiry race 不直接改变 generation/state。它可能在后续正常 refresh success + fresh `/me` 后恢复，也可能在后续 exact refresh rejection 后被撤销。
- Local logout 或 E/A 到期可随时终止 Pending；之后任何 `/me` success/finalize 都必须 CAS 失败。

### 6.4 Pending crash recovery, prune, and rollback

#### Crash points

1. **Remote rotate 后、pending CAS 前 crash:** DB 仍为 Ready G；这是已接受 R-01。下一独立 refresh 可能 superseded 并条件撤销。
2. **Pending CAS 后、`/me` 前 crash:** DB 已保存新 token且 compatibility gate 已过去；重启识别 Pending 并重试 `/me`。
3. **`/me` 成功后、finalize 前 crash:** 仍 Pending；GET `/me` 可安全重试。
4. **Finalize 后 crash:** Ready row 已含 fresh email 和恢复的 gate。

#### Prune

v2 prune 使用 authoritative `idle_expires_at`、`absolute_expires_at` 与 `revoked_at`。它**不能**因为 Pending 的 compatibility gate 在过去就删除 row。Pending 不 touch，故 `/me` 长期失败不会延长 E/A。

旧 binary prune 仍按 `session_expires_at` 删除 Pending；这是安全的 fail-closed session loss，不是授权绕过。再次升级不能恢复已删除 row。

#### Actual old-binary rollback

- Ready row 的 compatibility gate 镜像 E，旧 binary 维持原行为。
- Pending row gate 是过去，旧 binary `get_session` 返回 none，不能 refresh/authorize/forward identity。
- 旧 binary logout 的 UPDATE 不依赖 session expiry，因此会把 Pending 的 `revoked_at` 写成真实时间。
- 新 binary 再上线时，pending finalize 要求 `revoked_at IS NULL`；旧 binary logout 后绝不恢复 Ready。
- 旧 binary prune 可能删除 Pending；接受重登。
- Rollback drill 必须运行真正的 pre-change binary + old env，而不是用新代码模拟。

### 6.5 True per-session single-flight with result sharing

#### 6.5.1 Flight object

Registry 维护 `session_id -> Arc<Flight>` 的当前 entry。Flight 包含：

```text
flight_id                 // process-local random/monotonic, never logged
accepted_versions         // initially {(generation, identity_state)}
phase                     // Running | Completed(Arc<FlightOutcome>)
registered_joiners        // only synchronization bookkeeping
condition/event           // wake every registered joiner
```

`FlightOutcome` 只含低敏感 enum 和 expected DB version，不含 token、Cookie、email：

```text
Ready { generation }
Rejected { reason }
Temporary { class }
Indeterminate { class }
```

`Rejected` 的远端来源只允许 refresh endpoint exact rejection；也可表示 row 已被 local logout/expiry 终止，但 `/me` outcome 永远不能构造 `Rejected`。

#### 6.5.2 Join and close linearization

1. 请求先从 DB 得到 observed `(generation,state)`，立即进入 registry。
2. 若 running flight 的 `accepted_versions` 包含 observed version，请求注册为 joiner，并等待同一个 outcome；它不得在唤醒后再调用远端。
3. 若已有 running flight 但 observed version 尚不匹配，请求不得替换 entry 或并发创建第二个 flight；它等待现有 flight 关闭，不消费不匹配的 outcome，随后重读 DB 并重新进入 registry。
4. 只有 registry 中没有 running entry 时，请求才能创建新 flight并成为 leader。
5. Leader 在 Ready G 的 valid refresh response 即将 CAS 为 Pending G+1 前，先把 `(G+1,pending)` 加入 `accepted_versions`；因此看到已提交 Pending G+1 的请求也加入同一 refresh+identity flight，不会并发重复 `/me`。
6. Leader 发布 outcome 一次，关闭 entry 并唤醒所有已注册 joiner。Joiner共享 exact success/rejected/temporary/indeterminate 分类。
7. 关闭点后到达 registry 的请求是**后续独立请求**：它重新读取 DB 并可创建新 flight。Ready failure 可重新 refresh；Pending failure 先重试 `/me`，仅 token 已到 refresh 条件时才 rotate。

并发批次的线性化边界是“在 flight 关闭前是否成功注册”，而不是请求 TCP 到达时间。已经注册的同 generation joiner 无论 leader 成败都只观察一次远端 operation。

Leader panic/coordination poison 必须通过 completion guard 发布 `Indeterminate::LeaderAborted`、移除当前 entry 并唤醒 joiner；不能让 joiner永久等待或自行串行重试。Registry 仅接受已验证 HMAC session id，并清理 completed/dead entries。

#### 6.5.3 Outcome consumption

- `Ready`: leader 和 joiner都重读 exact DB row；只有 Ready/current generation 才继续 policy/touch。
- `Rejected`: 所有成员返回 `401` clear；条件 revoke 只由 leader执行一次。
- `Temporary/Indeterminate`: 所有成员返回 `503`，不 touch、不 clear、不命中 upstream。Row 可能仍 Ready（rotation 未持久化）或已 Pending（token 已保存但 `/me` 未完成）。
- Joiner 不根据“DB 未变化”自行再 refresh；这是 B-01 的核心约束。

### 6.6 Typed refresh and R-01/R-02 behavior

```text
RefreshError::Rejected(Invalidated | Superseded)
RefreshError::Temporary(Timeout | Transport | RateLimited | Upstream5xx)
RefreshError::Indeterminate(UnexpectedStatus | InvalidErrorBody |
                            InvalidSuccessBody | TokenVerification |
                            IdentityMismatch | ContractDrift)
```

`RefreshError` 仅描述 `POST /session/refresh`。Identity fetch 使用单独且无 rejection variant 的边界：

```text
IdentityFetchOutcome::Fresh(MeResponse)
IdentityFetchOutcome::Unavailable(Transport | AnyHttpStatus |
                                  InvalidBody | IdentityMismatch |
                                  ContractDrift)
```

`AnyHttpStatus` 明确包含 exact `401 invalid_access_token`。只有 `Fresh` 可尝试 finalize；所有 `Unavailable` 共享 `503` 并保持 Pending。

| Wire/local result | Leader action | Shared flight outcome |
|---|---|---|
| exact `401 session_invalidated` | expected version/token conditional revoke | Rejected |
| exact `401 session_superseded`, DB already advanced | use current state | Ready or current pending recovery result |
| exact `401 session_superseded`, DB unchanged | expected conditional revoke | Rejected |
| timeout/transport/408/429/5xx | no automatic retry | Temporary |
| 400, unknown 401, other status/body drift | preserve state | Indeterminate |
| valid 200, pending CAS fails due logout/expiry | discard response; never restore | Rejected/local inactive |
| valid 200, pending CAS DB failure | no success claim; old row preserved if transaction failed | Indeterminate |

`/me` 不出现在 remote rejection table 中。它的任何非 Fresh outcome 都是 Pending identity unavailable，绝不执行 conditional revoke 或 clear。

R-01 deterministic sequence：

1. Two requests register on Ready G flight.
2. Fake auth-mini commits rotation but transport returns indeterminate to leader.
3. One remote call；leader/joiner都 `503`；Ready G row/Cookie unchanged；upstream hit=0。
4. Flight closes.
5. Third independent request creates new G flight，auth-mini exact superseded。
6. Gateway expected-G/token conditional revoke；`401` clear；upstream hit=0。

这正是已接受 residual；不得让第二个 joiner在步骤 3 内触发 superseded，也不得把步骤 5 变成自动 retry。

### 6.7 Logout / expiry races

Logout 不等待 flight：

1. 读取 best-effort remote logout snapshot。
2. 立即 `UPDATE revoked_at=now WHERE id=? AND revoked_at IS NULL`，Ready/Pending 都适用。
3. 返回 clear Cookie/redirect；远端失败不回滚。
4. Refresh pending CAS、identity finalize、touch 都要求 `revoked_at IS NULL` 与 `E/A > now`。

若 finalize 先完成，logout 随后 revoke Ready；若 logout 先完成，finalize CAS=0。没有任何路径写 `revoked_at=NULL`。

### 6.8 Touch merge

R-07 已接受 3600 秒：

```text
due = now - last_touched_at >= 3600s
candidate = min(now + 7d, A)
advance = Ready && due && candidate > E
```

Touch 原子更新 `idle_expires_at`、Ready compatibility gate `session_expires_at`、`last_touched_at`、`updated_at`。Pending/403/503 不 touch。该策略最多约 1 小时保守提前到期，绝不延长 E/A，每 session 每天最多 24 次 durable touch。

### 6.9 Absolute Cookie expiry (B-03)

#### Positive cookies

- Positive `amg_session` **不包含 `Max-Age`**。
- 使用 `Expires=<E as IMF-fixdate GMT>`；E 已是 `min(idle,absolute)`。
- Callback 和 durable touch 都用 DB 中的 absolute timestamp，不从最终 response 时刻重新计算 duration。
- 若 protected upstream 在 auth 后延迟返回 headers，浏览器看到的仍是同一个 E；若收包时已过 E，Cookie 已到期，而不是再存活一个 relative duration。
- Cookie 继续 opaque、`HttpOnly`、`Path=/`、configured `SameSite`、production `Secure`、无 `Domain`。

Login-state 也使用创建时计算的绝对 `Expires=created+600s`，避免正向 Cookie 混用相对语义。

#### Clearing

Clear Cookie 使用两种兼容信号：

```text
Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT
```

正向 Cookie 若同时带 `Max-Age` 会让 user agent优先使用 relative age，因此禁止正向双写。

#### Clock boundary

Absolute `Expires` 消除的是**主响应延迟平移**，不是客户端时钟异常。Gateway/DB 仍是授权 authority；严重客户端时钟偏差可能提前删除或残留 Cookie，但不能在 E/A 后授权。nginx final `Date` 与浏览器标准 Cookie 处理需在真实/等价 jar 测试中验证。

### 6.10 nginx Set-Cookie and `503`

```nginx
location = /_auth {
  internal;
  proxy_pass http://gateway/auth/check;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header Cookie $http_cookie;
}

location / {
  auth_request /_auth;
  auth_request_set $auth_set_cookie $upstream_http_set_cookie;
  auth_request_set $auth_status $upstream_status;
  add_header Set-Cookie $auth_set_cookie always;

  error_page 401 = /__login_redirect;
  error_page 403 = @forbidden;
  error_page 500 = @auth_unavailable;
  proxy_intercept_errors off;
  proxy_pass http://protected_upstream;
}

location = /__login_redirect {
  internal;
  proxy_pass http://gateway/login;
  add_header Set-Cookie $auth_set_cookie always;
}

location @auth_unavailable {
  add_header Cache-Control "no-store" always;
  add_header Retry-After "5" always;
  return 503 "Authentication service temporarily unavailable\n";
}
```

Required observable contract：

- Ready touch 的 positive Cookie 在主 response，且只有 absolute Expires、没有 positive Max-Age。
- Explicit `401` final redirect 有**两个独立 headers**：`amg_session` clear 和 `amg_login_state` positive；按 cookie name/attributes 分别断言，不能只检查任意 `Set-Cookie`。
- Gateway timeout/connection failure/5xx 最终为无 `Location` 的 `503`，Cookie 不清除，upstream hit=0。
- Protected upstream 自己的 `500` 仍为 `500`。
- Access log 不含 `$auth_set_cookie`、`$http_cookie`、Authorization。

### 6.11 Controlled time

进程级 `SystemClock`/`ManualClock` 供 DB deadline、JWT exp、Cookie Expires、server decisions 使用。JWKS elapsed cache 保持单独 monotonic source。Tests 不混用 `Utc::now()` 或 sleep 来证明 deadline。

---

## 7. Alternatives considered

### A. Mutex-only serialization

- **Rejected:** failure leaves row unchanged, queued waiter会逐个重复 remote refresh。必须使用 flight outcome sharing。

### B. 30-day email snapshot

- **Rejected by R-12:** stale email 会继续通过 email allowlist 并发送到 downstream。使用 durable Pending。

### C. Persist tokens after `/me`

- **Rejected:** remote rotation 已发生时 `/me` temporary/crash 会丢失新 refresh token。先持久化 Pending，再 `/me`。

### D. Pending represented by `revoked_at` sentinel

- **Rejected:** old binary logout 只更新 `revoked_at IS NULL`，无法把 pending sentinel 转为真实 logout；后续 finalize 可能 un-revoke。使用过去的 compatibility deadline，同时保留 `revoked_at=NULL`。

### E. Positive `Max-Age=E-auth_now`

- **Rejected by B-03:** user agent 从最终收包时开始 relative age，slow upstream 会到 `E+d`。使用 absolute Expires only。

### F. 每请求 touch / in-memory write-behind

- **Rejected:** 前者写放大，后者 crash 丢活动。按 R-07 使用 3600 秒 conditional durable touch。

### G. Temporary failure as 401

- **Rejected:** 会触发 login redirect/state 风暴。使用 `503`。

### H. Treat exact `/me` 401 as session rejection

- **Rejected by B-04:** `invalid_access_token` 只描述 access-token/profile request failure，且 auth-mini 会把 DB/profile internal errors折叠到同一响应。它不能证明 refresh credential/session永久失效。保持 Pending `503`，仅 refresh exact rejection可撤销。

---

## 8. Migration, rollout, and rollback

### 8.1 Migration rollout

1. 停止唯一 active writer，做 WAL-consistent backup；保存 pre-change binary、old env、old nginx config。
2. 运行 v0/v1→v2、非法 timestamp、transaction failure、old-binary nullable row、Ready/Pending fixture。
3. 部署 binary/env/nginx 为一个兼容单元。
4. 启动原子 migration；只记录 schema from/to、rows、duration、result。
5. 验证 old deadline invariant、Ready mirror、Pending compat deny、NULL repair。
6. 通过真实 nginx/auth-mini 和 actual old-binary rollback drill 后开放流量。

### 8.2 Rollout hard gates

- Single-flight four-outcome sharing 与 R-01 three-request sequence。
- Pending rotation→persist→`/me`→ready，identity change→403/header update，crash recovery。
- `/me` exact 401、其他 status/body/parse/profile failure、identity mismatch全部保持 Pending `503`；repeated identity-only retry可恢复，只有后续 refresh exact rejection可撤销。
- Old binary 对 Pending 401/零 upstream；old binary logout 后新 finalize CAS 失败。
- Positive Cookie Expires/no Max-Age、slow upstream、two Set-Cookie redirect。
- Refresh pending CAS failure、identity finalize failure、touch DB failure 都 unavailable 且 upstream 0。
- SSO capability 仍明确 FAIL。

### 8.3 Rollback

1. nginx 保持 auth_request 或 maintenance deny，绝不暴露 upstream。
2. 停新 gateway，确保无 active writer/flight。
3. 可运行 old binary+old env 读取 additive v2：Ready 可继续，Pending 通过过去 gate fail-closed。
4. Pending 可能被 old prune 删除，接受重登；不得手工恢复 token/email。
5. Old binary logout Pending 后必须写 `revoked_at`；再次升级不得 finalize。
6. DB 可疑时恢复 pre-deploy WAL-consistent backup；已 rotated token 可能 superseded 并按 R-01 重登。
7. 不 downgrade `user_version` 或 drop columns。

Rollback 的目标是恢复安全服务，不承诺保留新 session 或 pending recovery。

---

## 9. Observability without disclosure

Fixed events：`schema_migration`, `auth_check`, `session_touch`, `refresh_flight`, `identity_pending`, `identity_finalize`, `session_logout`。

Fixed outcomes include：`flight_leader`, `flight_joined`, `ready`, `temporary`, `indeterminate`, `rejected_invalidated`, `rejected_superseded`, `pending_entered`, `pending_retried`, `pending_me_401`, `pending_identity_mismatch`, `pending_ready`, `cas_lost`, `expired`。

允许字段：duration、HTTP status、schema version、rows changed、generation delta（只记录 `+1`，不记录值）、joiner count aggregate。禁止 session/flight id、token、Cookie、email/user id、body/URI。

Alerts：migration failure、contract drift/identity mismatch 任意出现、pending age/count 持续增长、repeated `/me` unavailable、invalidation spike、flight remote-call/joiner 比异常、SQLite errors、失败认证 upstream hit 非零。R-02 文档必须说明 exact refresh invalidation 可能包含 auth-mini 内部折叠错误，建立 auth-mini 5xx follow-up；`/me` 401/internal fold只告警 unavailable，不计入 rejection metric。

---

## 10. Security and revocation boundaries

- Ready 才能 authorize；Pending 不使用旧 email，不发 identity header。
- Local logout、idle/absolute expiry、refresh endpoint exact rejection 都是 terminal boundary。
- `/me` 的任何非 Fresh 结果都不是 terminal/revoke boundary，只能维持 Pending `503`。
- 无任何 SQL 把 `revoked_at` 设回 NULL。
- Remote auth-mini logout 无 push/introspection；已有 access JWT 最迟到 refresh boundary 才检测。
- R-01 只接受 fail-closed 重登，不接受自动 retry 或永久猜测恢复。
- Old binary 对 Pending 只能 deny/delete/revoke，不能 authorize。
- Absolute Cookie expiry 不替代 server deadline；server 是最终 authority。

---

## 11. Deterministic testing strategy

### 11.1 Time and migration

- `E/A - 1ms` allow，恰好 deadline deny。
- Touch `3599999ms` skip、`3600000ms` advance；candidate 被 A 截断。
- v1 deadline 不增加；fresh v2；future version 拒绝；故障全事务 rollback。
- Old binary nullable row repair；Ready mirror/Pending compat gate invariant。
- Prune 使用 authoritative idle/absolute：v2 不因 Pending compat past 删除；old binary可删除且 fail-closed。

### 11.2 Single-flight B-01

- Success leader + multiple same-version joiners：one remote refresh，所有请求使用 Ready result。
- Temporary leader + joiners：one remote call，全部 `503`，row/Cookie unchanged；flight 关闭后独立请求才发第二次。
- Indeterminate leader + joiners：同上。
- Refresh-exact rejected leader + joiners：one remote call/one conditional revoke，全部 `401` clear；identity flight没有 rejected branch。
- Different sessions parallel；completed registry cleanup；leader panic/poison 唤醒所有 joiner并共享 indeterminate。
- Pending G+1 请求在 prior refresh flight 尚运行时加入 alias，不重复 `/me`。

### 11.3 R-01 boundary

- 两请求同 Ready G：fake remote commit + lost response；remote count=1；两者 `503`；row/Cookie unchanged；upstream 0。
- Flight close 后第三请求：exact superseded；expected-G revoke；clear Cookie；upstream 0。

### 11.4 Durable identity pending B-02

- Valid rotation 原子保存 new tokens/Pending/compat past；在 `/me` barrier 未释放时新旧 binary 都不能 authorize。
- `/me` temporary：leader/joiner共享 `503`；row Pending；下一独立请求 identity-only retry，不重复 refresh。
- `/me` email changed from allowed→denied：finalize fresh email，然后 `403`，不发送旧 email header、不 touch。
- `/me` email denied→allowed 或 NULL/user-id allow：使用 fresh identity 决策。
- `/me` user mismatch/malformed：保持 Pending `503`。
- Pending access 到 refresh boundary：rotate Pending→Pending，再 `/me`；无中间 Ready。
- Crash after pending CAS / after `/me` before finalize：restart recovery。
- Logout while Pending、expiry while Pending、old binary logout while Pending：finalize CAS=0，绝不 un-revoke。
- Actual old binary against v2 DB：Ready behavior、Pending deny、Pending logout/prune；再次升级安全。

### 11.5 `/me` non-revocation boundary B-04

- Fresh access token调用 `/me` 返回 exact `401 invalid_access_token`：row保持同 generation Pending；shared `503`；无 revoke/clear/touch/identity header；upstream 0。
- Fake auth-mini将 profile/SQLite internal failure折叠为同一 exact 401：行为完全相同。
- `/me` 其他 4xx/5xx、transport timeout、invalid JSON/body、malformed 200：全部保持 Pending `503`。
- `/me` valid profile但 user mismatch：保持 Pending `503`并产生 fixed drift alert；不能构造 refresh Rejected。
- 同一 identity flight多个 joiner只调用一次 `/me`并共享 unavailable；flight关闭后的独立请求可再调用一次。
- 前两次 `/me` unavailable、第三次 fresh valid matching 200：只在第三次 finalize Ready并使用fresh email policy/header。
- Access expiry race：`/me` 401不撤销；到正常 refresh boundary后 Pending→Pending refresh success + fresh `/me` 可恢复。
- 相同起点下若后续 refresh endpoint exact `session_invalidated/superseded`，才执行 expected-version revoke/clear。
- Repeated `/me` 期间 local logout或 E/A expiry：后续 fresh 200 finalize CAS=0；保持 terminal local state。

### 11.6 Cookie/nginx B-03

- Unit：positive session/login-state 有 exact IMF-fixdate Expires 且无 positive Max-Age；clear 有 `Max-Age=0` + past Expires。
- Barrier-controlled slow upstream：auth subrequest先产生固定 E；主 response headers 延迟到 ManualClock > E 后释放；最终 header仍为 E，不变成 `E+delay`。
- Injected-receipt-time Cookie jar或真实浏览器：在 receipt>E 时不保留 positive session Cookie。
- Final 401 redirect 分别断言两个 headers：`amg_session` clear、`amg_login_state` positive，属性各自正确。
- Auth connection failure/direct 5xx 最终 503、无 Location、无 clear、upstream 0；业务 upstream 500 保持 500。
- HTTP response 与 WebSocket 101 均传播 absolute renewal Cookie。

### 11.7 Persistence failures

- Valid refresh response但 pending CAS I/O failure：不能声称 success；shared indeterminate 503；upstream 0。
- `/me` success但 finalize I/O failure：保持 Pending或事务 rollback；503；重试可恢复。
- Touch DB failure：Ready row不撤销，503，upstream 0。
- 所有 test diagnostics 执行 secret scan。

### 11.8 Silent SSO

Gate 维持 **FAIL / unsupported**，固定 auth-mini commit evidence 不变。通过条件是交付 unsupported 证据和 auth-mini follow-up，不是 gateway 内伪造 silent flow。

---

## 12. Milestones

### Milestone 1 — schema/time/compatibility gate

- Add authoritative idle/absolute、identity state、atomic migration、ManualClock。
- Acceptance: old deadline invariant、Ready mirror、Pending old-binary deny、prune/rollback fixtures。

### Milestone 2 — flight coordinator and refresh persistence

- Add shared four-outcome flight、R-01 behavior、Ready→Pending token CAS。
- Acceptance: same-generation failure batches remote count=1；logout/expiry no resurrection。

### Milestone 3 — identity recovery and absolute cookies/nginx

- Add Pending `/me` retry/finalize、absolute Expires、two-cookie/503 nginx behavior。
- Acceptance: only fresh valid matching `/me` finalizes；all other `/me` results remain Pending `503`；identity changes immediately affect policy/header；slow upstream cannot move expiry。

### Milestone 4 — real E2E/old-binary rollback/operations

- Real auth-mini/nginx/HTTP/WebSocket、actual old binary、docs/alerts/rollback drill。
- Acceptance: all hard gates and secret scan pass；SSO remains correctly documented unsupported。

---

## 13. Open questions

No blocking design question remains from B-01/B-02/B-03/B-04 or R-01/R-02/R-07/R-12. Re-review should validate that `/me` has no revoke authority, the specified flight close boundary and Pending compatibility gate remain sound, and the absolute Cookie verification is sufficient before implementation.

## 14. Implementation notes

Expected modules：

- `src/db.rs`: v2 fields, compatibility gate, Ready/Pending APIs, authoritative prune, conditional finalize/revoke/touch。
- `src/server.rs`: flight coordinator, pending recovery, logout/expiry ordering, outcome sharing。
- `src/auth_mini.rs`: typed refresh and `/me` errors, no rotation auto-retry。
- `src/cookies.rs`: positive absolute Expires only；clear dual expiry。
- `src/config.rs`, clock utility, `src/jwt.rs`: defaults and controlled time。
- `examples/nginx.conf`, E2E script: two-cookie, slow upstream, `503`, actual old-binary fixtures。
- Production docs: R-01/R-02 residuals、Pending rollback、Expires semantics、SSO gate。

Detailed sequencing is in `docs/implementation-plan.md`. This RFC still does not authorize production code until `review-rfc` passes.

## 15. References

- Contract: `.legion/tasks/harden-mobile-session-lifecycle/plan.md`
- Research: `.legion/tasks/harden-mobile-session-lifecycle/docs/research.md`
- Failed review and binding decisions: `.legion/tasks/harden-mobile-session-lifecycle/docs/review-rfc.md`
- Risk register: `.legion/tasks/harden-mobile-session-lifecycle/docs/risk-register.md`
- Implementation plan: `.legion/tasks/harden-mobile-session-lifecycle/docs/implementation-plan.md`
- nginx auth_request: <https://nginx.org/en/docs/http/ngx_http_auth_request_module.html>
- Fixed auth-mini evidence: sibling commit `86b4aaa8ca97d1218217a7f6f0144251a5f30c9b`
