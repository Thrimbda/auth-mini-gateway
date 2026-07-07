import type { AppConfig, SameSite } from './types.js';

const DEFAULT_AUTH_MINI = 'http://127.0.0.1:7777';
const DEFAULT_PUBLIC_BASE = 'http://localhost:8080';

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const authMiniIssuer = normalizeBaseUrl(
    env.AUTH_MINI_ISSUER ?? DEFAULT_AUTH_MINI,
    'AUTH_MINI_ISSUER',
  );
  const publicBaseUrl = normalizeBaseUrl(
    env.GATEWAY_PUBLIC_BASE_URL ?? DEFAULT_PUBLIC_BASE,
    'GATEWAY_PUBLIC_BASE_URL',
  );
  const authMiniPublicBaseUrl = normalizeBaseUrl(
    env.AUTH_MINI_PUBLIC_BASE_URL ?? authMiniIssuer,
    'AUTH_MINI_PUBLIC_BASE_URL',
  );
  const cookieSecret = env.GATEWAY_COOKIE_SECRET ?? '';

  if (cookieSecret.length < 32) {
    throw new Error('GATEWAY_COOKIE_SECRET must be at least 32 characters');
  }

  return {
    host: env.HOST ?? '127.0.0.1',
    port: parseInteger(env.PORT, 3000, 'PORT'),
    publicBaseUrl,
    authMiniIssuer,
    authMiniPublicBaseUrl,
    authMiniLoginUrl: env.AUTH_MINI_LOGIN_URL,
    cookieSecret,
    cookieSecure: parseBoolean(env.COOKIE_SECURE, true),
    cookieSameSite: parseSameSite(env.COOKIE_SAME_SITE),
    sessionTtlMs: parseInteger(env.SESSION_TTL_SECONDS, 8 * 60 * 60, 'SESSION_TTL_SECONDS') * 1000,
    loginStateTtlMs: parseInteger(env.LOGIN_STATE_TTL_SECONDS, 5 * 60, 'LOGIN_STATE_TTL_SECONDS') * 1000,
    refreshSkewMs: parseInteger(env.REFRESH_SKEW_SECONDS, 60, 'REFRESH_SKEW_SECONDS') * 1000,
    maxLoginStates: parseInteger(env.MAX_LOGIN_STATES, 10_000, 'MAX_LOGIN_STATES'),
    maxSessions: parseInteger(env.MAX_SESSIONS, 10_000, 'MAX_SESSIONS'),
    allowEmails: parseCsv(env.ALLOW_EMAILS, true),
    allowUserIds: parseCsv(env.ALLOW_USER_IDS, false),
    requirePasskey: parseBoolean(env.REQUIRE_PASSKEY, true),
    logoutRedirect: env.LOGOUT_REDIRECT ?? '/',
  };
}

export function normalizeBaseUrl(value: string, name: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid URL`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${name} must use http or https`);
  }

  parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString().replace(/\/$/, '');
}

function parseInteger(value: string | undefined, fallback: number, name: string): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback;
  const normalized = value.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new Error('boolean values must be true or false');
}

function parseSameSite(value: string | undefined): SameSite {
  const normalized = (value ?? 'lax').toLowerCase();
  if (normalized === 'lax' || normalized === 'strict' || normalized === 'none') {
    return normalized;
  }
  throw new Error('COOKIE_SAME_SITE must be lax, strict, or none');
}

function parseCsv(value: string | undefined, lowercase: boolean): Set<string> {
  return new Set(
    (value ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => (lowercase ? entry.toLowerCase() : entry)),
  );
}
