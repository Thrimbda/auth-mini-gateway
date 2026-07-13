# 优化移动端会话生命周期与刷新韧性

## 目标

让移动 Safari 等休眠型浏览器无需后台刷新即可稳定保持登录，同时保持认证请求 fail-closed、显式撤销及时生效，并为静默 SSO 建立可验证的能力门。

## 问题陈述

当前 gateway 使用固定 8 小时本地 session 和 5 分钟 login state，活跃请求与 token refresh 均不延长本地期限；任何 refresh 故障都会撤销 session，且 nginx 未传播 auth subrequest 的续期 Cookie。这会让移动浏览器隔夜返回时频繁重新登录，并把临时认证服务故障放大为永久登出。

## 验收标准

- [ ] LOGIN_STATE_TTL_SECONDS 默认值、样例和生产文档统一为 600 秒，并保留高熵、签名、同源和一次性消费约束。
- [ ] 新建 gateway session 同时实施 7 天 inactivity timeout 和从本地 callback 创建时起算的 30 天 absolute lifetime；成功授权活动只能延长 idle deadline，绝不能延长 absolute deadline。
- [ ] schema v1 到新版本的迁移可自动执行且不延长旧 session 的既有有效期；重启后未过期的新 session 保持有效。
- [ ] 浏览器经 nginx 主响应收到受 absolute deadline 限制的滑动 amg_session Cookie，Cookie 继续保持 opaque、HttpOnly、SameSite 和 Secure 约束。
- [ ] access token 过期后由 gateway 按请求刷新，不依赖 Safari 后台定时器；并发 refresh 使用每 session single-flight，logout/expiry 不能被刷新复活。
- [ ] timeout、网络故障、429、5xx 及其他非确定性 refresh 故障拒绝本次访问且不命中上游、不撤销 session；恢复后同一 Cookie 可重试。
- [ ] 只有 auth-mini 明确判定 refresh token 或 session 无效、过期或撤销时才撤销本地 session 并清 Cookie；临时故障不得触发登录重定向风暴。
- [ ] 本地 logout 继续立即撤销并清 Cookie，远端 logout 失败不恢复本地访问。
- [ ] 验证当前 auth-mini 是否支持顶层重定向下的无交互 session 复用；支持则接入并以浏览器流程验证，不支持则将证据和后续 auth-mini 任务写入交付物，不在本 PR 修改 auth-mini。
- [ ] 单元、迁移、并发和真实 nginx/auth-mini E2E 覆盖 idle/absolute 边界、Cookie 续期、临时故障恢复、明确拒绝撤销以及受保护上游零命中。

## 假设 / 约束 / 风险

- **假设**: 目标客户端是移动浏览器或 PWA，而非原生 App。
- **假设**: 30 天 absolute lifetime 从 gateway callback 创建本地 session 时起算。
- **假设**: 只有返回 204 的成功授权检查重置 inactivity；403 不续期，WebSocket 仅在握手时计为活动。
- **假设**: 部署保持单 active gateway、SQLite WAL 和 nginx 唯一公网入口。
- **假设**: auth-mini 的浏览器 SSO 能力未知，必须通过能力门验证。
- **约束**: auth-mini 作为外部身份服务，本任务不修改其仓库或协议。
- **约束**: 浏览器只持有签名 opaque Cookie，access/refresh token 继续只存 SQLite，日志不得包含 token、Cookie、secret 或 callback body。
- **约束**: 所有认证不确定性保持 fail-closed，受保护 upstream 不得在认证失败时收到请求。
- **约束**: 以最新 origin/master 为实现基线，不重新引入由 gateway 检查 amr/Passkey 的已删除策略。
- **约束**: nginx 继续负责 HTTP/WebSocket 反向代理，gateway 不代理业务流量。
- **风险**: 持久化 schema 迁移和长期 token 保存扩大回滚及泄露影响。
- **风险**: 错误分类若与 auth-mini 实际状态码契约不符，可能错误保留已撤销 session 或制造不必要登出。
- **风险**: 并行 refresh 的 token rotation 竞态可能把成功推进的 session 错误撤销。
- **风险**: 每请求 touch 会放大 SQLite 写入和锁竞争，需要合并写入频率。
- **风险**: auth subrequest 的 Set-Cookie 传播与 503 映射若配置错误，可能导致 Cookie 不续期或登录重定向循环。

## 要点

- 生命周期分层: 7 天 inactivity 与不可延长的 30 天 absolute deadline。
- 请求驱动刷新: 移动浏览器无需后台运行，返回后的首个请求触发服务端 refresh。
- 故障分级: 临时故障保留 session 并返回不可用，明确认证拒绝才撤销。
- 并发安全: per-session single-flight 配合数据库条件更新，避免 refresh/logout 竞态。
- 静默 SSO: 作为 auth-mini 能力门验证，不越界修改外部服务。
- 迁移安全: 旧 8 小时 session 不因升级被延长。

## 范围

- src/ - 配置、Cookie、HTTP、auth-mini client、session 生命周期、SQLite migration 与并发控制。
- examples/nginx.conf 与部署样例 - 续期 Cookie 和临时认证故障传播。
- scripts/ 与 Rust tests - 生命周期、迁移、并发和真实集成验证。
- README.md、.env.example、docs/ - 配置、运维、迁移、风险和静默 SSO 能力说明。
- .legion/tasks/harden-mobile-session-lifecycle/ 与 .legion/wiki/ - 设计、验证、评审和 durable writeback。

## 非目标

- 不修改 auth-mini 仓库、协议或认证方式策略，也不在 gateway 中实现 Passkey、OTP 或 OIDC Provider。
- 不支持原生移动 App token SDK、多 active gateway、跨域共享 Cookie 或新增管理配置页面。
- 不依赖浏览器后台定时 refresh，也不承诺移动系统永不清理第一方 Cookie。
- 不把已建立 WebSocket 的后续帧计为活动，也不在 deadline 到达时主动断开已有连接。
- 不在本任务中实现 SQLite token-at-rest 加密、Cookie secret 无损轮换或跨应用全局 logout。

## 设计索引 (Design Index)

> **Design Source of Truth**: .legion/tasks/harden-mobile-session-lifecycle/docs/rfc.md

**摘要**:
- 核心流程: 认证成功后按合并频率更新 idle deadline 并经 nginx 续期 Cookie；absolute deadline 始终为硬上限。
- 刷新策略: 每 session 串行刷新并保留错误类型；临时错误返回非重定向 503，明确凭据拒绝返回 401 并撤销。
- 迁移策略: schema 升级保留旧 session 原有 deadline 作为上限，新语义仅完整应用于新 session。
- 能力门: 使用固定 auth-mini 版本验证顶层重定向是否无交互；不支持时记录边界而不伪装已实现。
- 验证策略: 可控时间单测、schema migration、并发竞态测试以及真实 nginx/auth-mini HTTP/WebSocket E2E。

## 阶段概览

1. **设计与能力验证** - 形成 research、Heavy RFC 与风险登记
2. **会话生命周期实现** - 实现 schema migration、idle/absolute deadline 与合并 touch
3. **刷新韧性实现** - 实现 typed refresh errors、503/401 分流与 per-session single-flight
4. **验证与审查** - 运行单元、迁移、并发及真实 E2E 验证
5. **交付与收口** - 生成 walkthrough、PR body 与 wiki writeback

---

*创建于: 2026-07-13 | 最后更新: 2026-07-13*
