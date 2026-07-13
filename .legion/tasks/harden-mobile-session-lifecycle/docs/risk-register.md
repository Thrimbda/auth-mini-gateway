# Risk Register: mobile session lifecycle hardening

> **Date:** 2026-07-13
> **Revision basis:** `docs/review-rfc.md` FAIL
> **Scale:** Likelihood/Impact = Low, Medium, High, Critical
> **Purpose:** 记录已裁决 residual、修订后的控制措施和 re-review hard gates

## Blocking-finding closure

| Finding | Design closure | Verification gate |
|---|---|---|
| **B-01** mutex 不共享失败结果 | Flight 保存 observed version、registered joiners 和一个共享 four-outcome result；joiner 永不在同一请求重发。关闭后的独立请求才能新建 flight。 | success/rejected/temporary/indeterminate 各自 multiple joiners，remote count=1；R-01 两请求+第三独立请求。 |
| **B-02** email snapshot 弱化授权 | Rotation 后 atomic token save→durable Pending；compatibility deadline 置过去让新旧 binary deny；fresh `/me` 后按 generation/revocation/deadline CAS Ready。 | identity change、pending retry/restart、logout/expiry、actual old binary deny/logout/prune、no un-revoke。 |
| **B-03** positive Max-Age 随主响应延迟平移 | Positive session/login-state Cookie 使用 absolute `Expires` only；positive 禁止 Max-Age；clear 使用 Max-Age=0+past Expires。 | slow-upstream barrier、receipt>E cookie jar/browser、exact Expires、两个独立 Set-Cookie。 |
| **B-04** `/me` 401 被误当永久 session rejection | `/me` 无 rejection/revoke authority；只有 fresh valid matching 200可finalize，所有其他结果保持Pending 503。唯一远端撤销 authority是refresh exact rejection。 | exact401/internal fold/access-expiry race/repeated `/me`/later refresh success或exact rejection/logout/expiry matrix。 |

## Summary

| ID | Risk | Likelihood | Impact | Status |
|---|---|---:|---:|---|
| R-01 | Remote rotation commit 后结果丢失，gateway 无法恢复 token | Medium | Critical | **Accepted bounded fail-closed residual** |
| R-02 | auth-mini 可能把内部错误折叠为 exact invalidated | Low/Medium | High | **Accepted wire-contract residual** |
| R-03 | v1→v2/Pending migration 延长、损坏或半迁移 | Low | Critical | Mitigated; must verify |
| R-04 | DB backup rollback 带回 superseded refresh token | Medium | High | Accepted fail-closed |
| R-05 | nginx 丢 Cookie、合并错误或 `503` 映射错误 | Medium | High | Mitigated; must verify |
| R-06 | Refresh/identity finalize 复活 logout/expired session | Medium | Critical | Mitigated; must verify |
| R-07 | 3600 秒 touch 导致保守提前到期 | Medium | Medium | **Accepted** |
| R-08 | 客户端时钟偏差影响 absolute Expires 的浏览器保留时间 | Low/Medium | Medium | Residual; server remains authority |
| R-09 | 30 天 server-side token retention 扩大 DB 泄露影响 | Low/Medium | Critical | Accepted in contract |
| R-10 | Logs/tests 泄露 token/Cookie/identity | Medium | Critical | Mitigated; must verify |
| R-11 | auth-mini 不支持 no-interaction redirect SSO | Certain | Medium | Capability gate FAIL |
| R-12 | Fresh email 未确认前授权或旧 binary 忽略 Pending | Medium | Critical | **Snapshot rejected; Pending design closes** |
| R-13 | Remote revocation 在 access token 到期前不可见 | Medium | High | Known boundary |
| R-14 | Flight join/close/abort 实现错误造成重复调用或永久等待 | Medium | High | Mitigated; must verify |
| R-15 | SQLite touch/pending/finalize 写竞争造成 `503` | Medium | High | Must observe |
| R-16 | Old binary rollback 对 Pending 删除、logout 或 NULL row 处理错误 | Medium | Critical | Mitigated; actual binary drill required |
| R-17 | Pending 长时间无法完成导致可用性下降 | Medium | High | Fail-closed residual; alert/retry bounded by E/A |
| R-18 | `/me` 非 fresh 结果被错误升级为 revoke/clear | Medium | Critical | **B-04 closed by non-revocation boundary** |

---

## Detailed risks

### R-01 — Post-commit refresh ambiguity

- **Binding decision:** Accepted as bounded fail-closed residual。
- **Trigger:** auth-mini 已 rotate，但 response 丢失；或 gateway 在 durable Pending CAS 前 crash。
- **Required behavior:** 同一 running flight 的所有 joiner共享 Indeterminate/`503`，只发一次 remote call；row/Cookie 不变。Flight 关闭后，下一个独立请求若得到 exact superseded，则 expected-generation/token 条件撤销并 clear。
- **Forbidden:** 自动 retry、让 queued joiner马上再 POST、永久 `503`、猜测/拼接 token。
- **Mitigation:** POST 前准备 JWKS；结果后立即 Pending CAS；single-flight result sharing；R-01 sequence 进入 deterministic tests；生产文档和 auth-mini idempotency/recovery follow-up。
- **Residual:** 用户可能在极端网络/crash 窗口重登。

### R-02 — Refresh exact invalidated 可能包含 auth-mini internal error

- **Binding decision:** Trust exact refresh wire contract only。
- **Required classifier:** 只有 **refresh endpoint** exact `401 + session_invalidated/session_superseded` 是 remote rejection；其他 refresh status/body 都是 `503`。该裁决不得扩展到 `/me invalid_access_token`。
- **Effect:** auth-mini 当前内部折叠可能造成永久重登，gateway 无法从 wire 安全区分。
- **Mitigation:** invalidation spike alert；固定 contract tests；文档不声称所有 auth-mini 内部临时错误都保留；auth-mini internal failure→5xx follow-up。
- **Residual:** UX 风险已接受，安全上 fail-closed。

### R-03 — Schema/Pending migration 不安全

- **Trigger:** DDL/DML 中断、非法 timestamp、错误 backfill、state/gate 不一致、future schema downgrade。
- **Effect:** 延长旧 session、Pending 被误当 Ready、旧 binary 绕过。
- **Mitigation:** `BEGIN IMMEDIATE`；`E<=A<=old_E`；Ready gate mirror、Pending gate epoch invariant；错误 rollback；future version 拒绝；old-binary NULL repair；state invariant validation。
- **Hard tests:** v0/v1/failure/future/NULL repair、Pending fixture、format corruption、old deadline proof。

### R-04 — Backup rollback token 不一致

- **Trigger:** auth-mini 在部署后 rotate，gateway 恢复部署前 DB。
- **Effect:** restored token superseded，用户重登。
- **Mitigation:** 保持 fail-closed；不手工修 token；maintenance capacity；按 R-01 exact superseded 撤销。
- **Residual:** 无跨系统一致性 snapshot，不承诺保留部署后 session。

### R-05 — nginx Cookie/503 boundary

- **Trigger:** `auth_request_set` 未传播、internal redirect 丢 clear Cookie、多个 Set-Cookie 被覆盖、auth 500 未映射或业务 500 被误改。
- **Effect:** Cookie 不续期、redirect loop、错误 500/302、upstream hit。
- **Mitigation:** checked-in config/docs 同步；`add_header ... always`；`proxy_intercept_errors off`；按 cookie name分别断言两个 headers；真实 nginx HTTP/WebSocket/503/upstream500 tests。
- **Stop:** 任一失败认证 upstream hit 非零或任一 Cookie header 缺失。

### R-06 — Logout/expiry resurrection

- **Trigger:** Pending `/me` 或 refresh flight in-flight 时 new/old binary logout、idle/absolute 到期。
- **Effect:** 已撤销 session 恢复 Ready。
- **Mitigation:** logout 不等 flight，立即写 `revoked_at`；Pending 使用过去 compatibility gate而非 revoked sentinel；finalize/refresh/touch 都要求 expected generation、`revoked_at IS NULL`、E/A future；没有 SQL 清 `revoked_at`。
- **Hard tests:** logout/expiry at every barrier；old binary logout Pending 后新 finalize CAS=0。

### R-07 — Touch precision/write load

- **Binding decision:** 3600 秒 accepted。
- **Effect:** 最后活动最多约 1 小时保守提前到期；不会延长安全期限。
- **Mitigation:** Ready-only conditional update；`0<touch<=idle<=absolute`；≤24 writes/session/day；fixed boundary tests。

### R-08 — Browser clock and absolute Expires

- **Trigger:** 用户设备 wall clock 严重偏差或非标准 Cookie 处理。
- **Effect:** Cookie 可能提前删除或在客户端残留；absolute Expires 已消除主响应 delay 平移，但不能修复任意客户端时钟。
- **Mitigation:** positive 无 Max-Age；Expires 使用 DB E；final Date/real or injected-time cookie jar validation；server deadline始终 authoritative。
- **Residual:** 客户端残留 Cookie 不能在 E/A 后获得授权。

### R-09 — Token-at-rest exposure

- **Trigger:** SQLite/WAL/backup compromise。
- **Effect:** refresh token 暴露，远端 lifetime 可滑动。
- **Mitigation:** local 30d absolute、private storage/backup/permissions、不记录 token、compromise response/revoke。
- **Residual:** at-rest encryption 不在范围。

### R-10 — Observability leakage

- **Trigger:** 打印 HTTP body、Cookie jar、SQLite token row、email/session/flight id。
- **Effect:** secret/PII 进入日志或 CI artifact。
- **Mitigation:** fixed enums/counts/durations only；flight id不记录；body cap parse without logging；secret scan；nginx log排除 Cookie/Authorization。

### R-11 — Silent SSO unavailable

- **Evidence:** fixed auth-mini commit 的 LoginRoute 不读取 recovered session并自动 callback。
- **Required behavior:** capability gate 维持 FAIL；不在 gateway 模拟；交付 auth-mini allowlisted authorize/resume + browser E2E follow-up。

### R-12 — Fresh identity boundary

- **Binding decision:** 30-day email snapshot rejected。
- **New control:** valid rotation 后 atomic save tokens + state Pending + v1-visible gate epoch；fresh matching `/me` 前新旧 binary都 deny，旧 email不用于 policy/header。
- **Finalize:** replace email and restore Ready gate only with expected generation、Pending、unrevoked、unexpired CAS。
- **Non-fresh rule:** `/me` exact401、其他status/body/transport/parse/profile failure和identity mismatch都保持Pending 503；不revoke/clear/touch/header。
- **Identity change:** allowed→denied 立即 `403`；header 不得携带旧 email。
- **Residual implementation risk:** Pending state machine较复杂，因此 migration/prune/crash/rollback tests 是 hard gate。

### R-13 — Remote revocation visibility

- **Trigger:** auth-mini remote logout，但 gateway access JWT 尚未 refresh。
- **Effect:** 最长到 access-token refresh boundary 才检测。
- **Mitigation:** 60 秒 skew；exact refresh rejection；local logout immediate。
- **Residual:** auth-mini 无 push/introspection。

### R-14 — Flight coordinator correctness

- **Trigger:** Joiner未注册、completed entry过早/过晚清理、leader panic、version alias race。
- **Effect:** duplicate rotation、joiner串行 storm、永久等待、不同 generation错误共享。
- **Mitigation:** observed `(generation,state)`；Pending G+1 alias在 CAS 前注册；不匹配版本等待当前 entry 关闭且不并发替换；single publish；completion guard；join/close linearization；joiner只消费 outcome；completed/dead cleanup。
- **Hard tests:** four outcomes、multiple joiners、different sessions、pending alias、panic/poison、cleanup。

### R-15 — SQLite availability

- **Trigger:** touch、Pending CAS、finalize、logout、prune 并发或 storage failure。
- **Effect:** authentication `503`。
- **Mitigation:** network不在 DB transaction 内；短 CAS；single active；3600s touch；busy/error metrics；failure injection。
- **Residual:** DB failure必须 unavailable，不能绕过。

### R-16 — Actual old-binary rollback

- **Trigger:** old binary 忽略 v2 state、prune Pending、对 NULL row 写入或 logout Pending。
- **Effect:** 最坏风险是 Pending 被误授权或 explicit logout被后续 finalize恢复。
- **Mitigation:** Pending `session_expires_at=1970...`，old read fail；保持 `revoked_at=NULL` 使 old logout可写真实 revoke；new finalize不清 revoke；old prune删除 Pending被接受；NULL row再升级按不延长公式 repair。
- **Hard gate:** 实际 pre-change binary+old env 对 Ready/Pending/NULL/logout/prune fixture，不接受新代码模拟。

### R-17 — Pending availability/liveness

- **Trigger:** `/me` 持续 401/timeout/5xx/parse/profile/internal/contract mismatch。
- **Effect:** session持续 `503`，但不使用 stale identity。
- **Mitigation:** 后续独立 request identity-only retry；access需要时 Pending→Pending refresh；pending不 touch，最终 E/A 到期；pending count/age alerts。
- **Residual:** 选择安全 fail-closed 而非 stale authorization。

### R-18 — `/me` classification overreach

- **Evidence:** `/me 401 invalid_access_token` 只证明当前 access/profile request不可用；auth-mini还会把 `current_user_response` 任意错误折叠为同一401。
- **Effect:** 若直接revoke，会把access expiry race或profile/SQLite temporary failure变成永久登出，越过R-02范围。
- **Control:** Identity fetch outcome没有 Rejected variant。只有 fresh valid matching 200可finalize；所有其他结果维持同generation Pending并共享503。Identity mismatch只发fixed drift alert。
- **Recovery:** 后续独立 identity flight可重复一次 `/me`；到正常access refresh boundary后可Pending→Pending refresh。Refresh success后fresh `/me`可恢复；只有refresh exact rejection可条件撤销。
- **Terminal races:** local logout/E/A expiry可终止Pending；后续`/me` success finalize必须CAS=0。
- **Hard tests:** exact401、folded profile internal error、expiry race、repeated failures→success、repeated failures→refresh exact rejection、logout/expiry；全程upstream0直到fresh identity允许。

---

## Re-review checklist

- [ ] B-01：同 observed version joiners共享 four outcomes；failure flight remote count=1；独立请求重试边界明确。
- [ ] B-02：Pending atomic save/gate/finalize、crash/prune/logout/expiry/actual-old-binary 全闭合，无 un-revoke SQL。
- [ ] B-03：positive Expires only、slow upstream、receipt-time jar/browser、two Set-Cookie 验证完整。
- [ ] B-04：`/me` 所有非 fresh-valid matching 200结果都不revoke/clear/authorize；恢复与后续refresh exact rejection边界完整。
- [ ] R-01/R-02/R-07 已按 binding decision 写入 RFC 与 tests，不再作为 open question。
- [ ] R-12 snapshot 已删除，identity change 立即影响 policy/header。
- [ ] auth-mini 不修改，SSO capability 仍为 FAIL。
