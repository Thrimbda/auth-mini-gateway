import type { AppConfig } from './types.js';

export function normalizeReturnTo(input: string | null | undefined, config: AppConfig): string | null {
  const raw = input?.trim() || '/';
  if (raw.includes('\n') || raw.includes('\r')) return null;

  if (raw.startsWith('/') && !raw.startsWith('//')) {
    try {
      const parsed = new URL(raw, config.publicBaseUrl);
      return `${parsed.pathname}${parsed.search}${parsed.hash}`;
    } catch {
      return null;
    }
  }

  try {
    const parsed = new URL(raw);
    const publicOrigin = new URL(config.publicBaseUrl).origin;
    if (parsed.origin !== publicOrigin) return null;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return null;
  }
}

export function buildAuthMiniLoginUrl(state: string, config: AppConfig): string {
  const redirectUri = new URL('/auth/callback', config.publicBaseUrl).toString();
  const params = new URLSearchParams({ redirect_uri: redirectUri, state });

  if (config.authMiniLoginUrl) {
    const separator = config.authMiniLoginUrl.includes('?') ? '&' : '?';
    return `${config.authMiniLoginUrl}${separator}${params.toString()}`;
  }

  return `${config.authMiniPublicBaseUrl}/web/#/login?${params.toString()}`;
}
