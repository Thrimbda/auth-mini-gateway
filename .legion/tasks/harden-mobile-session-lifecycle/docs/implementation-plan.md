# Implementation Plan: mobile session lifecycle hardening

> 从 revised `docs/rfc.md` 抽取。仅供 re-review PASS 后的 engineer 阶段执行；当前阶段不实现生产代码。
> **Hard stop:** `review-rfc` 未重新 PASS 前，不开始 Milestone 1。

## Milestone 1 — Clock、schema v2 与 old-binary compatibility gate

### Scope

- `src/config.rs`
- `src/util.rs` 或 clock module
- `src/jwt.rs`
- `src/db.rs`
- migration fixtures / preserved pre-change binary fixture

### Steps

- [ ] 引入 `SystemClock`/`ManualClock`，统一 DB、JWT、server、Cookie absolute time；JWKS elapsed 使用独立 monotonic source。
- [ ] 设置 7d/30d/3600s/600s defaults 和 `0 < touch <= idle <= absolute` validation。
- [ ] v2 additive columns：`idle_expires_at`, `absolute_expires_at`, `last_touched_at`, `identity_state`, `identity_pending_since`。
- [ ] 将 existing `session_expires_at` 定义为 compatibility gate：Ready mirror E；Pending fixed past epoch。
- [ ] 实现原子 v0/v1→v2、future-version 拒绝、illegal timestamp rollback、old-binary NULL row repair。
- [ ] Store APIs 分离 authoritative read、Ready read、Pending read；不允许未知/不一致 state 被授权。
- [ ] v2 prune 使用 authoritative idle/absolute/revoked，不因 Pending compat gate past 删除。
- [ ] 实现 conditional Ready touch、conditional revoke、Ready/Pending refresh CAS、Pending finalize；任何 API 都不清 `revoked_at`。

### Deterministic verification

- fresh v0→v2；handmade v1→v2；unknown future version reject。
- old rows `E<=A<=old_session_expires_at`；expired/revoked不复活。
- injected DDL/DML/timestamp failure：version/data不半迁移。
- Ready invariant：compat gate==idle；Pending invariant：gate==epoch、pending_since non-null。
- old binary nullable insert后再次升级：按旧 deadline repair Ready且不延长。
- ManualClock：E/A exact boundary、touch 3599999/3600000ms、absolute cap。
- v2 prune保留未到 authoritative deadline的 Pending；old binary prune删除 Pending仍 fail-closed。

### Actual old-binary gate

- [ ] 在修改前保存/build pre-change binary artifact及 old env。
- [ ] 用实际旧 binary 打开 `user_version=2` fixture：Ready可按旧行为读取；Pending必须 401/clear且 upstream 0。
- [ ] 旧 binary logout Pending 后检查 `revoked_at` 非空；新 finalize CAS必须为0。
- [ ] 旧 binary prune Pending允许删除；再次升级不能恢复。

### Stop conditions

- Pending 可被旧 binary `get_session` 读取。
- 任一 old deadline 增加、state/gate不一致被授权、或 finalize能清 logout。
- Old-binary behavior 只由 mock/new code 模拟。

### Rollback notes

- Additive schema保留 v1 columns；Ready可供 old binary 使用，Pending deliberately fail-closed。
- 数据可疑时恢复 WAL-consistent backup；不手工修 token/state。

---

## Milestone 2 — True flight result sharing 与 durable identity recovery

### Scope

- `src/auth_mini.rs`
- `src/server.rs`
- `src/db.rs`
- flight coordinator module/test fixtures

### Steps: coordinator (B-01)

- [ ] 实现 per-session `Flight`：observed `(generation,state)`、accepted version aliases、Running/Completed、registered joiners、single shared outcome。
- [ ] Outcome 固定为 Ready / Rejected / Temporary / Indeterminate，不携带 token/Cookie/email/id；Rejected远端来源只允许refresh endpoint exact rejection，`/me`不得构造Rejected。
- [ ] Joiner在 flight close前注册；注册后只等待/消费 outcome，禁止同一请求再调用远端。
- [ ] Observed version与当前 running flight不匹配时等待其关闭并重读 DB；禁止替换 entry 或创建同 session 第二个并发 flight。
- [ ] Leader在 Ready G→Pending G+1 CAS前注册 `(G+1,pending)` alias，避免已看到 Pending 的并发请求重复 `/me`。
- [ ] Publish once、remove current entry、wake all；close后的独立请求重读 DB 后才可 new flight。
- [ ] Completion guard覆盖 panic/poison，发布 shared indeterminate并唤醒；清理 completed/dead registry entries。

### Steps: refresh and Pending (B-02/B-04)

- [ ] Typed refresh只识别 exact rejected wire；body size bounded，不记录 raw body，不自动 retry rotation POST。
- [ ] POST前准备 JWKS；valid 200验证 sid/sub/issuer/type/signature/exp/amr。
- [ ] Valid rotation后第一项 durable action是 atomic token CAS + generation+1 + Pending + pending_since + compat gate epoch；不更新/使用旧 email。
- [ ] Pending保存成功后调用 `/me`；success same user原子替换 fresh email、Ready、clear pending_since、restore compat gate。
- [ ] Identity fetch使用无Rejected variant的类型；只有fresh valid matching 200可finalize。
- [ ] `/me` exact401、其他status/body/transport/parse/profile failure和identity mismatch全部保留 Pending并共享503；不revoke/clear/touch/authorize，mismatch只告警。
- [ ] 每个identity flight最多一次`/me`；后续独立请求可再开identity-only flight，禁止同一请求内部循环。
- [ ] Pending access到 refresh boundary时执行 Pending→Pending rotation，再 `/me`，无中间 Ready。
- [ ] 只有refresh endpoint exact `session_invalidated/session_superseded`可因远端原因做 expected-version conditional revoke。
- [ ] Local logout不等待 flight，先 revoke；expiry/revocation使 pending CAS/finalize/touch全部失败。

### Deterministic single-flight tests

- Success leader + ≥2 same-version joiners：remote refresh count=1；所有请求消费同一 Ready result。
- Temporary leader + joiners：count=1，全部503，row/Cookie unchanged；flight close后独立请求才发下一次。
- Indeterminate leader + joiners：同上。
- Refresh-exact Rejected leader + joiners：count=1、conditional revoke一次、全部401 clear；identity flight无Rejected分支。
- Different sessions可并行；registry cleanup；leader panic/poison无永久 waiter。
- Ready G flight提交 Pending G+1 后，观察 G+1 Pending 的请求加入 alias，不重复 `/me`。
- Nonmatching observed version等待当前 flight关闭并重读，不产生同 session并发 remote operation。

### R-01 required sequence

- [ ] Two requests join Ready G flight。
- [ ] Fake auth-mini commits rotation但leader收到 indeterminate。
- [ ] Assert remote count=1；两请求503；Ready G row/token/deadline/Cookie unchanged；upstream hit=0。
- [ ] Flight关闭后第三独立请求收到 exact superseded。
- [ ] Assert expected-G/token revoke、401 clear、upstream hit=0；无自动 retry。

### Pending identity tests

- Rotation CAS后在 `/me` barrier阻塞：DB有new tokens/Pending/gate epoch；new/actual-old binary都不能 authorize。
- `/me` temporary：leader/joiner共享503；next independent identity-only retry；refresh count不增加。
- `/me` exact401/profile-internal-fold/其他status/body/parse/transport：与temporary相同，保持Pending且不clear。
- allowed email→denied：fresh finalize后403；无旧 email header；无 touch/upstream hit。
- denied→allowed、NULL email+allowed user id：只使用 fresh identity决策。
- user mismatch/malformed/unknown status：Pending + 503，不fallback。
- Pending token expiry：Pending→Pending refresh；fresh identity前不Ready。
- Crash/restart after Pending CAS and after `/me` before finalize：可重试恢复。
- New logout/old logout/idle/absolute expiry at each barrier：finalize CAS=0；永不 un-revoke。

### B-04 `/me` non-revocation tests

- Fresh access token + exact `401 invalid_access_token`：Pending generation/token/deadline/revoked state不变；503；no clear/touch/header；upstream0。
- Fake profile/SQLite internal failure折叠为相同401：同样保持Pending503。
- Access expiry race：`/me` 401不revoke；到正常refresh boundary后Pending→Pending refresh success + fresh matching `/me`恢复Ready。
- 重复独立`/me` flights前两次401/5xx、第三次fresh200：每flight一次调用，前两次503，第三次才finalize。
- 重复`/me`后refresh endpoint exact rejection：只有该refresh flight执行conditional revoke/clear。
- Valid200但identity mismatch：Pending503 + fixed alert，不构造Rejected。
- Repeated `/me`期间new/old logout或E/A expiry：后续fresh200 finalize CAS=0，upstream始终0。

### Persistence failure tests

- Valid 200 but Pending CAS failure：shared Indeterminate 503；不能claim success；upstream0。
- `/me` success but finalize transaction failure：Pending/rollback保持；503；later retry可恢复。
- Touch DB failure：Ready不撤销、503、upstream0。

### Stop conditions

- 同一 failed flight remote count>1。
- Joiner醒来后因row unchanged再refresh。
- Pending期间 policy/header/touch运行或旧 email fallback。
- 任一 `/me` 非fresh-valid matching200路径执行revoke/clear或构造Rejected。
- 任一路径把 `revoked_at` 设为NULL。

### Rollback notes

- Old binary对Pending deny/delete/revoke；不承诺Pending恢复。
- R-01/R-02 residual必须进入生产文档，不得用 retry隐藏。

---

## Milestone 3 — Absolute Cookie Expires 与 nginx composed boundary

### Scope

- `src/cookies.rs`
- `src/http.rs`
- `src/server.rs`
- `examples/nginx.conf`
- controlled slow-upstream / cookie-jar fixtures

### Steps (B-03)

- [ ] Positive `amg_session` 使用 DB E 的 IMF-fixdate `Expires`，禁止 positive `Max-Age`。
- [ ] Positive `amg_login_state` 使用 created+600s absolute Expires。
- [ ] Clear Cookie同时使用 `Max-Age=0` 和 past Expires。
- [ ] Callback和durable Ready touch才发positive session Cookie；Pending/403/503不发renewal/clear。
- [ ] nginx捕获 auth Set-Cookie并传播至main response；401 internal redirect同时保留clear-session与proxied login-state Cookie。
- [ ] Auth phase internal error映射最终503；`proxy_intercept_errors off`保持业务upstream500。

### Unit and deterministic tests

- Positive session/login-state：exact absolute Expires、无 Max-Age、安全属性/opaque签名不变。
- Clear：`Max-Age=0` + epoch Expires。
- Barrier slow upstream：auth先生成fixed E；延迟main headers；ManualClock推进到>E后release；最终Set-Cookie仍是E而非E+delay。
- Injected receipt-time cookie jar：receipt>E不存positive session Cookie；receipt<E存到E。
- Response ordering：迟到的旧renewal只能保守缩短，不能越过自身E/A。

### Real nginx tests

- HTTP 200和WebSocket 101传播absolute renewal Cookie。
- Final explicit-401 redirect按name分别存在：
  - `amg_session` clear（Max-Age=0 + past Expires）；
  - `amg_login_state` positive（absolute Expires，no positive Max-Age）。
- Auth timeout、gateway connection failure、direct5xx：final503、no Location、no clear、upstream0。
- Unauthorized403 no touch/upstream0。
- Protected upstream500仍500。

### Stop conditions

- 任一positive session Cookie包含Max-Age。
- Slow upstream导致expiry变成relative receipt+remaining。
- 两个Set-Cookie被合并、覆盖或只验证“任意一个存在”。
- Auth failure命中upstream或变成login redirect。

### Rollback notes

- Old binary仍可能发positive Max-Age；回滚时这是已知功能退化，server deadline仍fail-closed。
- 保持new nginx config时，old binary空renewal header应no-op，必须smoke验证。

---

## Milestone 4 — Real E2E、operations、rollback and delivery evidence

### Scope

- `scripts/e2e-real-auth-mini.sh`
- `README.md`, `.env.example`, `docs/production-deployment.md`
- `examples/docker-compose.yml` as needed
- subsequent test/review/walkthrough artifacts

### Steps

- [ ] 固定并报告 real auth-mini commit/version；覆盖real200 rotation和exact401 outcomes。
- [ ] Fault fixture可控制 pre-commit temporary、post-commit lost response、`/me` exact401/internal-fold/其他failure/identity change，不打印secrets。
- [ ] Observable upstream hit counter覆盖401/403/503/Pending。
- [ ] Actual old-binary rollback drill覆盖Ready/Pending/logout/prune/NULL rows和old env。
- [ ] WAL-consistent backup restore drill；记录superseded/relogin boundary。
- [ ] Production docs写入：R-01 accepted residual、R-02仅限refresh wire trust、B-04 `/me` non-revocation、R-07 3600s、Pending state/rollback、absolute Expires、two-cookie/nginx503、SSO FAIL。
- [ ] Logs/artifacts secret scan；pending count/age、flight outcome/joiner、invalidation spike alerts。

### Verification commands

- `cargo fmt --check`
- `cargo test`
- `cargo build --release --bin auth-mini-gateway`
- `bash scripts/e2e-real-auth-mini.sh`
- nginx config validation in actual/container nginx
- actual pre-change binary compatibility harness
- docs/config consistency and secret scan

### Expected report matrix

每个case记录但不泄密：observed state/generation delta、flight role/outcome、remote call count、DB state transition、direct gateway status、final nginx status、Cookie names/expiry mode、upstream hit delta。

必须单列：

- B-01 four outcomes and independent-retry boundary；
- R-01 lost-response→third-request superseded；
- B-02 Pending identity changes/restart/old-binary logout；
- B-03 slow upstream/receipt-time jar/two Set-Cookie；
- B-04 `/me` exact401/internal fold/retry recovery/access-expiry/later refresh rejection/logout-expiry；
- persistence failures and zero upstream hit；
- SSO capability FAIL evidence。

### Stop conditions

- 任何 blocking-finding hard gate缺证据或由mock-only替代真实nginx/old-binary boundary。
- Docs仍提30-day email snapshot或positive session Max-Age。
- Docs或代码计划仍允许 `/me` 非fresh结果revoke/clear。
- auth-mini被修改或SSO被宣称支持。
- Secret scan命中token/Cookie/body/identity。

### Rollback notes

- 发布前保留old binary/image、old env、old nginx config、WAL-consistent DB backup。
- Rollback始终保持auth_request/maintenance fail-closed；Pending可能丢失并重登，不直连upstream。
