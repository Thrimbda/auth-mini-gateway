# 优化移动端会话生命周期与刷新韧性 - 日志

## 会话进展 (2026-07-13)

### ✅ 已完成

- 已收敛并确认任务契约。
- 已从最新 origin/master 创建隔离 worktree。
- 完成现状 research、Heavy RFC、风险登记与 implementation plan。
- 确认当前 auth-mini 不支持 redirect 登录的无交互 SSO。
- Heavy RFC 经三轮对抗评审收敛并 PASS。
- 关闭 shared-result single-flight、durable identity-pending、absolute Expires 和 /me 无撤销权设计缺口。
- 实现 schema v2、7/30 天 lifecycle、1 小时合并 touch 和 absolute Expires Cookie。
- 实现 durable identity-pending、shared-result single-flight、typed refresh errors 和 401/503 分流。
- 同步 nginx、E2E、旧 binary 兼容脚本、部署文档与 SSO 能力说明。
- verify-change PASS：fmt、35 tests、clippy、release、旧 binary、真实 auth-mini/nginx E2E、Compose/nginx、diff 与 secret scan 全通过。
- 修复 auth-mini HTTP redirect 与 unexpected 2xx fail-open：禁止 redirect、只接受 exact 200。
- 新增 server-level shared-flight/Pending/竞态测试和 WAL backup/restore drill；46 tests 与完整 E2E 复验 PASS。
- review-change 复审 PASS / READY，首轮三个阻塞项全部闭合且无新增安全 finding。
- 生成 reviewer walkthrough 与 PR body。
- 完成 Legion wiki task summary、decisions、patterns、maintenance 和 log writeback。
- Primary PR https://github.com/Thrimbda/auth-mini-gateway/pull/5 merged as 26c42aa9b91b24059acd8b3c676776cfab40a4e2。
- GitHub reported no required checks and no blocking review; auto-merge attempt reached immediate merged state。
- Closeout metadata prepared; worktree deletion and main baseline refresh follow immediately after this writeback lands。
### 🟡 进行中

(暂无)
### ⚠️ 阻塞/待定

(暂无)
---

## 关键文件

- **`.legion/tasks/harden-mobile-session-lifecycle/plan.md`** [completed]
  - 作用: 稳定任务契约与授权范围
  - 备注: 11/11 checklist 完成
- **`.legion/tasks/harden-mobile-session-lifecycle/docs/rfc.md`** [completed]
  - 作用: High-risk Heavy RFC 设计真源
  - 备注: 三轮 review-rfc 后 PASS
- **`.legion/tasks/harden-mobile-session-lifecycle/docs/test-report.md`** [completed]
  - 作用: 独立验证证据与验收覆盖映射
  - 备注: 最终 46 tests 与完整 E2E PASS
- **`.legion/tasks/harden-mobile-session-lifecycle/docs/review-change.md`** [completed]
  - 作用: 代码与安全 readiness 评审
  - 备注: 最终 PASS / READY
- **`.legion/tasks/harden-mobile-session-lifecycle/docs/report-walkthrough.md`** [completed]
  - 作用: 评审者交付 walkthrough
  - 备注: 包含迁移、风险、验证与 SSO 能力门
- **`.legion/wiki/tasks/harden-mobile-session-lifecycle.md`** [completed]
  - 作用: 长期可查询任务摘要
  - 备注: status completed
---

## 关键决策

| 决策 | 原因 | 替代方案 | 日期 |
|------|------|----------|------|
| 静默 SSO 采用能力门且不修改 auth-mini | 当前 auth-mini LoginRoute 不复用已恢复 session | 强制跨仓实现；伪装 gateway 已支持 | 2026-07-13 |
| 旧 session 升级时不延长 | 避免升级隐式扩大既有授权窗口 | 全部重登；直接转换为 7/30 天 | 2026-07-13 |
| 只有 refresh endpoint 精确拒绝可触发远端原因撤销 | `/me` 非成功响应不能证明 refresh session 永久失效 | `/me` 401 直接撤销；所有远端错误都保留 | 2026-07-13 |
| auth-mini client 禁止 redirect 且只接受 exact 200 | 防止 refresh token 被 307/308 重发并拒绝 contract drift | reqwest 默认 redirect；接受任意 2xx | 2026-07-13 |
| PR #5 merged with no repository-reported checks | GitHub merged immediately after auto-merge attempt; `gh pr checks` reported no checks | 等待不存在的 required checks | 2026-07-13 |
---

## 快速交接

**下次继续从这里开始：**

1. Merge closeout metadata PR。
2. Delete `.worktrees/harden-mobile-session-lifecycle`。
3. Fetch origin and refresh the main workspace to `origin/master`。

**注意事项：**

- Primary implementation PR is merged; remaining actions are repository lifecycle cleanup only。
---

*最后更新: 2026-07-13 12:13 by Legion CLI*
