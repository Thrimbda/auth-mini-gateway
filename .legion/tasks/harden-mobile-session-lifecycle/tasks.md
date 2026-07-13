# 优化移动端会话生命周期与刷新韧性 - 任务清单

## 快速恢复

**当前阶段**: (none)
**当前检查项**: (none)
**进度**: 11/11 任务完成
---

## 阶段 1: 设计与能力验证 ✅ COMPLETE

- [x] 形成 research、Heavy RFC 与风险登记 | 验收: 现状证据、生命周期语义、错误矩阵、迁移/回滚和 SSO 能力门完整落盘
- [x] 完成 RFC 对抗评审并收敛 | 验收: review-rfc PASS 后方可进入实现
---

## 阶段 2: 会话生命周期实现 ✅ COMPLETE

- [x] 实现 schema migration、idle/absolute deadline 与合并 touch | 验收: 旧 session 不延长，新 session 满足 7/30 天边界且并发不复活
- [x] 实现受限滑动 Cookie 与 nginx 传播 | 验收: 浏览器主响应收到正确 Max-Age 且保留安全属性
---

## 阶段 3: 刷新韧性实现 ✅ COMPLETE

- [x] 实现 typed refresh errors、503/401 分流与 per-session single-flight | 验收: 临时故障可恢复、明确拒绝撤销、并发 refresh/logout 安全
- [x] 执行 auth-mini 静默 SSO 能力门 | 验收: 支持则完成接入验证；不支持则记录证据与后续任务
---

## 阶段 4: 验证与审查 ✅ COMPLETE

- [x] 运行单元、迁移、并发及真实 E2E 验证 | 验收: test-report 覆盖所有关键验收且无失败
- [x] 完成代码、安全与交付 readiness review | 验收: review-change PASS，无未解决安全阻塞项
- [x] 修复并复验 review-change 认证边界阻塞项 | 验收: 禁止 redirect、exact 200、扩展竞态与 WAL restore 验证全部通过
---

## 阶段 5: 交付与收口 ✅ COMPLETE

- [x] 生成 walkthrough、PR body 与 wiki writeback | 验收: 评审者材料和 durable knowledge 完整
- [x] 创建、跟进并合并 PR，清理 worktree 并刷新主工作区 | 验收: PR merged、checks/review 完成、worktree 删除、主工作区刷新
---

## 发现的新任务

(暂无)
---

*最后更新: 2026-07-13 12:13*
