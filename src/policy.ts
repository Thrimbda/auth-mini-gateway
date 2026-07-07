import type { AppConfig, GatewaySession } from './types.js';

export type PolicyDecision =
  | { allowed: true }
  | { allowed: false; status: 403; reason: 'not_allowlisted' | 'passkey_required' };

export function evaluatePolicy(session: Pick<GatewaySession, 'userId' | 'email' | 'amr'>, config: AppConfig): PolicyDecision {
  const emailAllowed = session.email ? config.allowEmails.has(session.email.toLowerCase()) : false;
  const userAllowed = config.allowUserIds.has(session.userId);

  if (!emailAllowed && !userAllowed) {
    return { allowed: false, status: 403, reason: 'not_allowlisted' };
  }

  if (config.requirePasskey && !session.amr.includes('webauthn')) {
    return { allowed: false, status: 403, reason: 'passkey_required' };
  }

  return { allowed: true };
}
