# Fix Audience-Bound Login Callback

## 目标

Restore gateway login compatibility with the current official auth-mini audience-bound token contract while enforcing the gateway hostname audience and user-ID authorization.

## 问题陈述

Official auth-mini commit 7a9b55f binds redirect logins to a hostname JWT audience and reserves /me for self-audience tokens. The gateway ignores aud, then calls /me with a downstream token, so valid callback sessions are rejected as Invalid auth-mini session and the bridge displays a generic login failure.

## 验收标准

- [ ] A token issued by current official auth-mini for the configured gateway hostname can complete the callback without a /me call.
- [ ] Initial and refreshed access tokens fail closed when aud is missing under the current profile, malformed, or does not match the configured gateway hostname, with any explicitly retained legacy behavior documented and tested.
- [ ] Fresh sessions authorize exact JWT sub values through ALLOW_USER_IDS and do not depend on email lookup; unknown users remain denied.
- [ ] Existing durable sessions and rollback behavior have an explicit migration policy that does not silently broaden access.
- [ ] Targeted unit/integration tests and a real current-auth-mini contract drill pass without logging tokens, cookies, callback bodies, or identities.
- [ ] Active README, deployment guidance, examples, and environment documentation explain the user-ID migration and audience contract.

## 假设 / 约束 / 风险

- **假设**: The fresh official checkout at c4e28f5 represents the target auth-mini contract.
- **假设**: For a non-loopback HTTPS redirect, auth-mini emits aud as the normalized redirect_uri hostname and preserves it on refresh.
- **假设**: Auth-mini remains external and unmodified.
- **约束**: Never log access tokens, refresh tokens, signed cookies, callback bodies, or identity values.
- **约束**: Preserve gateway-owned routes, adapter/proxy mode behavior, opaque browser cookies, server-side token storage, and deny-by-default authorization.
- **约束**: Use ALLOW_USER_IDS for fresh audience-bound sessions; email may only remain as bounded legacy session data, not a new-login dependency.
- **约束**: Do not change production infrastructure or secrets as part of the repository implementation.
- **风险**: Legacy sessions refreshed after auth-mini migration may carry the issuer hostname audience rather than the gateway hostname.
- **风险**: Two deployed gateway hostnames require distinct expected audiences even though they share one auth-mini issuer.
- **风险**: An incorrect compatibility exception could permit cross-client token replay.
- **风险**: Deployments configured only with ALLOW_EMAILS will continue to deny fresh logins until user IDs are provisioned.

## 要点

- Audience binding: derive and validate the exact normalized hostname represented by GATEWAY_PUBLIC_BASE_URL.
- Identity boundary: trust verified JWT sub for downstream authorization and stop using /me for audience-bound sessions.
- Migration: preserve fail-closed behavior and document the ALLOW_EMAILS to ALLOW_USER_IDS operational transition.
- Evidence: reproduce against the fresh official auth-mini checkout rather than the stale local fork.

## 范围

- src/jwt.rs and src/auth_mini.rs - parse and enforce the audience contract for initial and refreshed tokens.
- src/server.rs, src/db.rs, and src/policy.rs - establish sessions and refresh identity without downstream /me dependency while preserving bounded legacy behavior.
- src/config.rs, .env.example, README.md, docs/, examples/, and scripts/ - configuration, migration guidance, and current-auth-mini contract verification.
- Tests covering callback, refresh, audience mismatch, allowlist denial, and secret boundaries.
- .legion/tasks/diagnose-login-callback-failure/ - design, verification, review, and delivery evidence.

## 非目标

- Do not modify auth-mini or add email to its downstream JWT contract.
- Do not redesign gateway cookies, session lifetimes, proxy transport, or nginx routing.
- Do not make email a trusted claim when the signed access token does not contain it.
- Do not deploy infrastructure or edit production secrets within this repository task.

## 设计索引 (Design Index)

> **Design Source of Truth**: .legion/tasks/diagnose-login-callback-failure/docs/rfc.md

**摘要**:
- Core flow: derive the expected hostname audience from the gateway public URL, verify aud with issuer/signature/expiry, create and refresh sessions from signed claims, and authorize exact sub allowlists without calling /me.
- Migration and rollback: the RFC must explicitly bound legacy no-audience or issuer-audience sessions and prevent any exception from admitting a token minted for another downstream hostname.
- Verification: deterministic signed-token tests plus a real fresh official auth-mini issuance/refresh drill, followed by security-focused review.

## 阶段概览

1. **Contract and design** - Record upstream and runtime evidence, then specify audience, identity, migration, rollback, and verification behavior.
2. **Implementation** - Implement audience-bound verification and user-ID session authorization with focused regression coverage.
3. **Verification and delivery** - Run formatting, tests, current-auth-mini E2E, security review, walkthrough, and wiki writeback.

---

*创建于: 2026-07-30 | 最后更新: 2026-07-30*
