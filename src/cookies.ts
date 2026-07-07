import { createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { AppConfig } from './types.js';

export const SESSION_COOKIE = 'amg_session';
export const LOGIN_STATE_COOKIE = 'amg_login_state';

export function parseCookies(header: string | undefined): Map<string, string> {
  const result = new Map<string, string>();
  if (!header) return result;

  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    try {
      result.set(name, decodeURIComponent(value));
    } catch {
      // Treat malformed cookie values as absent instead of failing auth checks.
    }
  }

  return result;
}

export function readSignedCookie(req: IncomingMessage, name: string, secret: string): string | null {
  const signed = parseCookies(req.headers.cookie).get(name);
  if (!signed) return null;
  return unsignValue(signed, secret);
}

export function signValue(value: string, secret: string): string {
  return `${value}.${mac(value, secret)}`;
}

export function unsignValue(signed: string, secret: string): string | null {
  const index = signed.lastIndexOf('.');
  if (index <= 0) return null;
  const value = signed.slice(0, index);
  const signature = signed.slice(index + 1);
  const expected = mac(value, secret);

  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (signatureBuffer.length !== expectedBuffer.length) return null;
  if (!timingSafeEqual(signatureBuffer, expectedBuffer)) return null;
  return value;
}

export function serializeSignedCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
  config: AppConfig,
): string {
  return serializeCookie(name, signValue(value, config.cookieSecret), maxAgeSeconds, config);
}

export function clearCookie(name: string, config: AppConfig): string {
  return serializeCookie(name, '', 0, config);
}

function serializeCookie(name: string, value: string, maxAgeSeconds: number, config: AppConfig): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    `SameSite=${formatSameSite(config.cookieSameSite)}`,
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];

  if (config.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

function mac(value: string, secret: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function formatSameSite(value: AppConfig['cookieSameSite']): string {
  if (value === 'none') return 'None';
  if (value === 'strict') return 'Strict';
  return 'Lax';
}
