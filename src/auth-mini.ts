import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { AppConfig, AuthMiniTokenResponse, MeResponse, VerifiedAccessToken } from './types.js';

export class AuthMiniClient {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly config: AppConfig) {
    this.jwks = createRemoteJWKSet(new URL('/jwks', config.authMiniIssuer));
  }

  async verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.config.authMiniIssuer,
      algorithms: ['EdDSA'],
    });

    if (payload.typ !== 'access') throw new Error('invalid token type');
    if (typeof payload.sub !== 'string') throw new Error('missing subject');
    if (typeof payload.sid !== 'string') throw new Error('missing session id');
    if (typeof payload.exp !== 'number') throw new Error('missing expiration');
    if (!Array.isArray(payload.amr) || !payload.amr.every((item) => typeof item === 'string')) {
      throw new Error('missing amr');
    }

    return {
      userId: payload.sub,
      authSessionId: payload.sid,
      amr: payload.amr,
      exp: payload.exp,
    };
  }

  async fetchMe(accessToken: string): Promise<MeResponse> {
    const response = await this.fetchJson('/me', {
      headers: { authorization: `Bearer ${accessToken}` },
    });

    if (typeof response.user_id !== 'string') throw new Error('invalid /me user id');
    if (response.email !== null && typeof response.email !== 'string') {
      throw new Error('invalid /me email');
    }

    return { userId: response.user_id, email: response.email };
  }

  async refresh(sessionId: string, refreshToken: string): Promise<AuthMiniTokenResponse> {
    const response = await this.fetchJson('/session/refresh', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, refresh_token: refreshToken }),
    });

    return parseTokenResponse(response);
  }

  async logout(accessToken: string): Promise<void> {
    await this.fetchJson('/session/logout', {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  private async fetchJson(path: string, init: RequestInit): Promise<Record<string, unknown>> {
    const response = await fetch(new URL(path, this.config.authMiniIssuer), init);
    if (!response.ok) throw new Error('auth-mini request failed');
    const parsed = (await response.json()) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('auth-mini response was not an object');
    }
    return parsed as Record<string, unknown>;
  }
}

export function parseTokenResponse(response: Record<string, unknown>): AuthMiniTokenResponse {
  if (
    typeof response.session_id !== 'string' ||
    typeof response.access_token !== 'string' ||
    typeof response.refresh_token !== 'string'
  ) {
    throw new Error('invalid token response');
  }

  if (response.token_type !== undefined && response.token_type !== 'Bearer') {
    throw new Error('invalid token type');
  }

  return {
    sessionId: response.session_id,
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
  };
}
