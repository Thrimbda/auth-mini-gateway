import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createGatewayServer } from '../src/app.js';
import { normalizeReturnTo } from '../src/returns.js';
import { InMemoryStore } from '../src/store.js';
import type { AppConfig } from '../src/types.js';

const cookieSecret = 'test-cookie-secret-with-more-than-32-chars';

describe('auth-mini gateway', () => {
  let mock: MockAuthMini;
  let gateway: TestGateway | undefined;

  beforeEach(async () => {
    mock = await MockAuthMini.start();
  });

  afterEach(async () => {
    await gateway?.close();
    await mock.close();
    gateway = undefined;
  });

  test('normalizes safe relative returns and rejects open redirects', () => {
    const config = makeConfig('http://auth.local');
    expect(normalizeReturnTo('/app?x=1', config)).toBe('/app?x=1');
    expect(normalizeReturnTo('http://gateway.local/app', config)).toBe('/app');
    expect(normalizeReturnTo('https://evil.example/app', config)).toBeNull();
    expect(normalizeReturnTo('//evil.example/app', config)).toBeNull();
    expect(normalizeReturnTo('/ok\r\nlocation:https://evil.example', config)).toBeNull();
  });

  test('creates a gateway session and rejects replayed login state', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl));
    const started = await startLogin(gateway.baseUrl, '/app');
    const token = await mock.mint({ email: 'allowed@example.com', amr: ['webauthn'] });

    const callback = await postCallback(gateway.baseUrl, started.cookie, started.state, token);
    expect(callback.response.status).toBe(200);
    expect(await callback.response.json()).toEqual({ returnTo: '/app' });

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: callback.cookie },
    });
    expect(check.status).toBe(204);
    expect(check.headers.get('x-auth-mini-email')).toBe('allowed@example.com');

    const replay = await postCallback(gateway.baseUrl, started.cookie, started.state, token);
    expect(replay.response.status).toBe(400);
  });

  test('rejects tampered gateway session cookies', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
    });
    const tampered = sessionCookie.replace(/.$/, (char) => (char === 'a' ? 'b' : 'a'));

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: tampered },
    });
    expect(check.status).toBe(401);
  });

  test('denies users outside the allowlist after valid auth-mini login', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl));
    const started = await startLogin(gateway.baseUrl, '/');
    const token = await mock.mint({ email: 'blocked@example.com', amr: ['webauthn'] });
    const callback = await postCallback(gateway.baseUrl, started.cookie, started.state, token);

    expect(callback.response.status).toBe(403);
    expect(callback.cookie).toContain('amg_session=');

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: callback.cookie },
    });
    expect(check.status).toBe(403);
  });

  test('enforces passkey requirement with auth-mini amr', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl, { requirePasskey: true }));
    const started = await startLogin(gateway.baseUrl, '/');
    const token = await mock.mint({ email: 'allowed@example.com', amr: ['email_otp'] });
    const callback = await postCallback(gateway.baseUrl, started.cookie, started.state, token);

    expect(callback.response.status).toBe(403);

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: callback.cookie },
    });
    expect(check.status).toBe(403);
  });

  test('refreshes near-expiry access tokens during auth check', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl, { refreshSkewMs: 10 * 60 * 1000 }));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
      expirationTime: '30s',
    });

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    expect(check.status).toBe(204);
    expect(mock.refreshCount).toBe(1);
  });

  test('serializes concurrent refresh for the same gateway session', async () => {
    mock.refreshDelayMs = 50;
    gateway = await TestGateway.start(makeConfig(mock.baseUrl, { refreshSkewMs: 10 * 60 * 1000 }));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
      expirationTime: '30s',
    });

    const [first, second] = await Promise.all([
      fetch(`${gateway.baseUrl}/auth/check`, { headers: { cookie: sessionCookie } }),
      fetch(`${gateway.baseUrl}/auth/check`, { headers: { cookie: sessionCookie } }),
    ]);

    expect(first.status).toBe(204);
    expect(second.status).toBe(204);
    expect(mock.refreshCount).toBe(1);
  });

  test('clears gateway session when refresh fails', async () => {
    mock.refreshFails = true;
    gateway = await TestGateway.start(makeConfig(mock.baseUrl, { refreshSkewMs: 10 * 60 * 1000 }));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
      expirationTime: '30s',
    });

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    expect(check.status).toBe(401);

    const secondCheck = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    expect(secondCheck.status).toBe(401);
  });

  test('logout revokes the gateway session and attempts auth-mini logout', async () => {
    gateway = await TestGateway.start(makeConfig(mock.baseUrl));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
    });

    const logout = await fetch(`${gateway.baseUrl}/logout`, {
      method: 'POST',
      headers: { cookie: sessionCookie },
      redirect: 'manual',
    });
    expect(logout.status).toBe(302);
    expect(mock.logoutCount).toBe(1);

    const check = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    expect(check.status).toBe(401);
  });

  test('in-flight refresh cannot resurrect a logged-out session', async () => {
    mock.refreshDelayMs = 75;
    gateway = await TestGateway.start(makeConfig(mock.baseUrl, { refreshSkewMs: 10 * 60 * 1000 }));
    const sessionCookie = await login(gateway.baseUrl, mock, {
      email: 'allowed@example.com',
      amr: ['webauthn'],
      expirationTime: '30s',
    });

    const inFlightCheck = fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    await waitFor(() => mock.refreshCount === 1);

    const logout = await fetch(`${gateway.baseUrl}/logout`, {
      method: 'POST',
      headers: { cookie: sessionCookie },
      redirect: 'manual',
    });
    expect(logout.status).toBe(302);

    const refreshCheck = await inFlightCheck;
    expect(refreshCheck.status).toBe(401);

    const afterLogout = await fetch(`${gateway.baseUrl}/auth/check`, {
      headers: { cookie: sessionCookie },
    });
    expect(afterLogout.status).toBe(401);
  });

  test('prunes expired store entries and caps abandoned public state', () => {
    let now = 0;
    const store = new InMemoryStore(() => now, { maxLoginStates: 2, maxSessions: 2 });

    store.createLoginState('/expired', 1);
    now = 2;
    store.createLoginState('/fresh-a', 100);
    expect(store.stats().loginStates).toBe(1);

    store.createLoginState('/fresh-b', 100);
    store.createLoginState('/fresh-c', 100);
    expect(store.stats().loginStates).toBe(2);

    store.createSession(sessionInput(1));
    now = 2;
    store.createSession(sessionInput(100));
    expect(store.stats().sessions).toBe(1);

    store.createSession(sessionInput(100));
    store.createSession(sessionInput(100));
    expect(store.stats().sessions).toBe(2);
  });
});

async function login(
  baseUrl: string,
  mock: MockAuthMini,
  options: MintOptions,
): Promise<string> {
  const started = await startLogin(baseUrl, '/');
  const token = await mock.mint(options);
  const callback = await postCallback(baseUrl, started.cookie, started.state, token);
  expect(callback.response.status).toBe(200);
  return callback.cookie;
}

async function startLogin(baseUrl: string, returnTo: string): Promise<{ cookie: string; state: string }> {
  const response = await fetch(`${baseUrl}/login?return_to=${encodeURIComponent(returnTo)}`, {
    redirect: 'manual',
  });
  expect(response.status).toBe(302);
  const location = response.headers.get('location');
  expect(location).toBeTruthy();
  const hash = new URL(location ?? '').hash;
  const state = new URLSearchParams(hash.slice(hash.indexOf('?') + 1)).get('state');
  expect(state).toBeTruthy();
  return { cookie: collectCookies(response.headers), state: state ?? '' };
}

async function postCallback(
  baseUrl: string,
  cookie: string,
  state: string,
  token: AuthMiniWireToken,
): Promise<{ response: Response; cookie: string }> {
  const response = await fetch(`${baseUrl}/auth/callback/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ ...token, state }),
  });
  return { response, cookie: mergeCookies(cookie, collectCookies(response.headers)) };
}

function makeConfig(authMiniIssuer: string, overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    host: '127.0.0.1',
    port: 0,
    publicBaseUrl: 'http://gateway.local',
    authMiniIssuer,
    authMiniPublicBaseUrl: authMiniIssuer,
    cookieSecret,
    cookieSecure: false,
    cookieSameSite: 'lax',
    sessionTtlMs: 60 * 60 * 1000,
    loginStateTtlMs: 5 * 60 * 1000,
    refreshSkewMs: 60 * 1000,
    maxLoginStates: 10_000,
    maxSessions: 10_000,
    allowEmails: new Set(['allowed@example.com']),
    allowUserIds: new Set(),
    requirePasskey: true,
    logoutRedirect: '/',
    ...overrides,
  };
}

class TestGateway {
  private constructor(
    readonly server: ReturnType<typeof createGatewayServer>['server'],
    readonly baseUrl: string,
  ) {}

  static async start(config: AppConfig): Promise<TestGateway> {
    const { server } = createGatewayServer(config);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as AddressInfo;
    return new TestGateway(server, `http://127.0.0.1:${address.port}`);
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

type MintOptions = {
  email: string;
  userId?: string;
  amr: string[];
  sessionId?: string;
  expirationTime?: string;
};

type AuthMiniWireToken = {
  session_id: string;
  access_token: string;
  token_type: 'Bearer';
  refresh_token: string;
  expires_in: number;
};

class MockAuthMini {
  private readonly server: ReturnType<typeof createServer>;
  private privateKey!: CryptoKey | Uint8Array;
  private publicJwk!: Record<string, unknown>;
  private readonly sessions = new Map<string, { userId: string; email: string; amr: string[] }>();
  baseUrl = '';
  refreshCount = 0;
  logoutCount = 0;
  refreshFails = false;
  refreshDelayMs = 0;

  private constructor() {
    this.server = createServer((req, res) => {
      this.handle(req, res).catch(() => sendJson(res, 500, { error: 'server_error' }));
    });
  }

  static async start(): Promise<MockAuthMini> {
    const mock = new MockAuthMini();
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    mock.privateKey = privateKey;
    mock.publicJwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'EdDSA', use: 'sig' };
    await new Promise<void>((resolve) => mock.server.listen(0, '127.0.0.1', resolve));
    const address = mock.server.address() as AddressInfo;
    mock.baseUrl = `http://127.0.0.1:${address.port}`;
    return mock;
  }

  async mint(options: MintOptions): Promise<AuthMiniWireToken> {
    const userId = options.userId ?? `user-${options.email}`;
    const sessionId = options.sessionId ?? crypto.randomUUID();
    const refreshToken = crypto.randomUUID();
    const accessToken = await new SignJWT({ sid: sessionId, amr: options.amr, typ: 'access' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key', typ: 'JWT' })
      .setIssuer(this.baseUrl)
      .setSubject(userId)
      .setIssuedAt()
      .setExpirationTime(options.expirationTime ?? '15m')
      .sign(this.privateKey);

    this.sessions.set(accessToken, { userId, email: options.email, amr: options.amr });
    this.sessions.set(refreshToken, { userId, email: options.email, amr: options.amr });
    return {
      session_id: sessionId,
      access_token: accessToken,
      token_type: 'Bearer',
      refresh_token: refreshToken,
      expires_in: 900,
    };
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', this.baseUrl);

    if (req.method === 'GET' && url.pathname === '/jwks') {
      sendJson(res, 200, { keys: [this.publicJwk] });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/me') {
      const token = req.headers.authorization?.replace(/^Bearer /, '');
      const session = token ? this.sessions.get(token) : null;
      if (!session) {
        sendJson(res, 401, { error: 'invalid_token' });
        return;
      }
      sendJson(res, 200, { user_id: session.userId, email: session.email });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/session/refresh') {
      this.refreshCount += 1;
      if (this.refreshFails) {
        sendJson(res, 401, { error: 'invalid_refresh' });
        return;
      }
      if (this.refreshDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.refreshDelayMs));
      }
      const body = (await readJson(req)) as { session_id?: string; refresh_token?: string };
      const session = body.refresh_token ? this.sessions.get(body.refresh_token) : null;
      if (!body.session_id || !session) {
        sendJson(res, 401, { error: 'invalid_refresh' });
        return;
      }
      sendJson(
        res,
        200,
        await this.mint({
          email: session.email,
          userId: session.userId,
          amr: session.amr,
          sessionId: body.session_id,
        }),
      );
      return;
    }

    if (req.method === 'POST' && url.pathname === '/session/logout') {
      this.logoutCount += 1;
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function collectCookies(headers: Headers): string {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const values = getSetCookie ? getSetCookie.call(headers) : splitSetCookie(headers.get('set-cookie') ?? '');
  return values.map((value) => value.split(';')[0]).filter(Boolean).join('; ');
}

function mergeCookies(existing: string, next: string): string {
  const jar = new Map<string, string>();
  for (const source of [existing, next]) {
    for (const pair of source.split(';')) {
      const trimmed = pair.trim();
      if (!trimmed) continue;
      const index = trimmed.indexOf('=');
      if (index <= 0) continue;
      jar.set(trimmed.slice(0, index), trimmed.slice(index + 1));
    }
  }
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function splitSetCookie(value: string): string[] {
  if (!value) return [];
  return value.split(/,(?=\s*[^;]+=)/g).map((entry) => entry.trim());
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('condition was not met before timeout');
}

function sessionInput(ttlMs: number) {
  return {
    authSessionId: crypto.randomUUID(),
    accessToken: 'access-token',
    refreshToken: crypto.randomUUID(),
    userId: 'user-id',
    email: 'allowed@example.com',
    amr: ['webauthn'],
    accessExpiresAt: Date.now() + ttlMs,
    expiresAt: ttlMs,
  };
}
