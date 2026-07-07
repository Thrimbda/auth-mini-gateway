import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { AuthMiniClient } from './auth-mini.js';
import {
  clearCookie,
  LOGIN_STATE_COOKIE,
  readSignedCookie,
  serializeSignedCookie,
  SESSION_COOKIE,
} from './cookies.js';
import { evaluatePolicy } from './policy.js';
import { buildAuthMiniLoginUrl, normalizeReturnTo } from './returns.js';
import { InMemoryStore } from './store.js';
import type { AppConfig, AuthMiniTokenResponse, GatewaySession } from './types.js';

type GatewayDeps = {
  authMini?: AuthMiniClient;
  store?: InMemoryStore;
  now?: () => number;
};

type CallbackBody = {
  access_token?: unknown;
  refresh_token?: unknown;
  session_id?: unknown;
  token_type?: unknown;
  state?: unknown;
};

export function createGatewayServer(config: AppConfig, deps: GatewayDeps = {}) {
  const now = deps.now ?? (() => Date.now());
  const store = deps.store ?? new InMemoryStore(now, {
    maxLoginStates: config.maxLoginStates,
    maxSessions: config.maxSessions,
  });
  const authMini = deps.authMini ?? new AuthMiniClient(config);
  const refreshes = new Map<string, Promise<GatewaySession>>();

  async function handler(req: IncomingMessage, res: ServerResponse) {
    try {
      const url = new URL(req.url ?? '/', config.publicBaseUrl);

      if (req.method === 'GET' && url.pathname === '/healthz') {
        res.writeHead(204).end();
        return;
      }

      if (req.method === 'GET' && url.pathname === '/login') {
        handleLogin(req, url, res);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/auth/callback') {
        sendCallbackPage(res);
        return;
      }

      if (req.method === 'POST' && url.pathname === '/auth/callback/session') {
        await handleCallbackSession(req, res);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/auth/check') {
        await handleAuthCheck(req, res);
        return;
      }

      if ((req.method === 'POST' || req.method === 'GET') && url.pathname === '/logout') {
        await handleLogout(req, res, url);
        return;
      }

      sendText(res, 404, 'Not found');
    } catch {
      sendText(res, 500, 'Internal server error');
    }
  }

  function handleLogin(req: IncomingMessage, url: URL, res: ServerResponse) {
    const originalUri = typeof req.headers['x-original-uri'] === 'string' ? req.headers['x-original-uri'] : null;
    const returnTo = normalizeReturnTo(url.searchParams.get('return_to') ?? originalUri, config);
    if (!returnTo) {
      sendText(res, 400, 'Invalid return_to');
      return;
    }

    const state = store.createLoginState(returnTo, config.loginStateTtlMs);
    res.setHeader('Set-Cookie', [
      serializeSignedCookie(
        LOGIN_STATE_COOKIE,
        state.id,
        Math.ceil(config.loginStateTtlMs / 1000),
        config,
      ),
    ]);
    redirect(res, buildAuthMiniLoginUrl(state.id, config));
  }

  async function handleCallbackSession(req: IncomingMessage, res: ServerResponse) {
    const stateIdFromCookie = readSignedCookie(req, LOGIN_STATE_COOKIE, config.cookieSecret);
    let body: CallbackBody;
    try {
      body = (await readJson(req)) as CallbackBody;
    } catch {
      sendText(res, 400, 'Invalid JSON');
      return;
    }
    const consumedState = stateIdFromCookie ? store.consumeLoginState(stateIdFromCookie) : null;
    const clearState = clearCookie(LOGIN_STATE_COOKIE, config);

    if (!consumedState || body.state !== stateIdFromCookie) {
      res.setHeader('Set-Cookie', [clearState]);
      sendText(res, 400, 'Invalid login state');
      return;
    }

    if (
      body.token_type !== 'Bearer' ||
      typeof body.access_token !== 'string' ||
      typeof body.refresh_token !== 'string' ||
      typeof body.session_id !== 'string'
    ) {
      res.setHeader('Set-Cookie', [clearState]);
      sendText(res, 400, 'Invalid login callback');
      return;
    }

    let session: GatewaySession;
    let policy = { allowed: true } as ReturnType<typeof evaluatePolicy>;
    try {
      session = await createSessionFromTokens({
        sessionId: body.session_id,
        accessToken: body.access_token,
        refreshToken: body.refresh_token,
      });
      policy = evaluatePolicy(session, config);
    } catch (error) {
      res.setHeader('Set-Cookie', [clearState]);
      sendText(res, 401, 'Invalid auth-mini session');
      return;
    }

    res.setHeader('Set-Cookie', [
      clearState,
      serializeSignedCookie(
        SESSION_COOKIE,
        session.id,
        Math.ceil((session.expiresAt - now()) / 1000),
        config,
      ),
    ]);

    if (!policy.allowed) {
      sendText(res, policy.status, 'Forbidden');
      return;
    }

    sendJson(res, 200, { returnTo: consumedState.returnTo });
  }

  async function createSessionFromTokens(tokens: AuthMiniTokenResponse) {
    const verified = await authMini.verifyAccessToken(tokens.accessToken);
    if (verified.authSessionId !== tokens.sessionId) {
      throw new Error('session id mismatch');
    }

    const me = await authMini.fetchMe(tokens.accessToken);
    if (me.userId !== verified.userId) {
      throw new Error('user mismatch');
    }

    const candidate = {
      id: 'pending',
      authSessionId: tokens.sessionId,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      userId: verified.userId,
      email: me.email,
      amr: verified.amr,
      accessExpiresAt: verified.exp * 1000,
      expiresAt: now() + config.sessionTtlMs,
    } satisfies GatewaySession;

    return store.createSession({
      authSessionId: candidate.authSessionId,
      accessToken: candidate.accessToken,
      refreshToken: candidate.refreshToken,
      userId: candidate.userId,
      email: candidate.email,
      amr: candidate.amr,
      accessExpiresAt: candidate.accessExpiresAt,
      expiresAt: candidate.expiresAt,
    });
  }

  async function handleAuthCheck(req: IncomingMessage, res: ServerResponse) {
    const sessionId = readSignedCookie(req, SESSION_COOKIE, config.cookieSecret);
    if (!sessionId) {
      sendText(res, 401, 'Unauthenticated');
      return;
    }

    let session = store.getSession(sessionId);
    if (!session) {
      res.setHeader('Set-Cookie', [clearCookie(SESSION_COOKIE, config)]);
      sendText(res, 401, 'Unauthenticated');
      return;
    }

    if (session.accessExpiresAt - now() <= config.refreshSkewMs) {
      try {
        session = await refreshGatewaySession(session);
      } catch {
        const current = store.getSession(session.id);
        if (
          current &&
          (current.refreshToken !== session.refreshToken || current.accessExpiresAt > session.accessExpiresAt)
        ) {
          session = current;
        } else {
          store.deleteSession(session.id);
          res.setHeader('Set-Cookie', [clearCookie(SESSION_COOKIE, config)]);
          sendText(res, 401, 'Session refresh failed');
          return;
        }
      }
    }

    const policy = evaluatePolicy(session, config);
    if (!policy.allowed) {
      sendText(res, policy.status, 'Forbidden');
      return;
    }

    res.setHeader('X-Auth-Mini-User-Id', session.userId);
    if (session.email) res.setHeader('X-Auth-Mini-Email', session.email);
    res.writeHead(204).end();
  }

  async function refreshGatewaySession(session: GatewaySession): Promise<GatewaySession> {
    const existing = refreshes.get(session.id);
    if (existing) return existing;

    const refresh = refreshGatewaySessionOnce(session).finally(() => {
      if (refreshes.get(session.id) === refresh) refreshes.delete(session.id);
    });
    refreshes.set(session.id, refresh);
    return refresh;
  }

  async function refreshGatewaySessionOnce(session: GatewaySession): Promise<GatewaySession> {
    const refreshed = await authMini.refresh(session.authSessionId, session.refreshToken);
    if (refreshed.sessionId !== session.authSessionId) {
      throw new Error('refresh session id mismatch');
    }

    const verified = await authMini.verifyAccessToken(refreshed.accessToken);
    if (verified.authSessionId !== session.authSessionId) {
      throw new Error('refreshed token session id mismatch');
    }

    const me = await authMini.fetchMe(refreshed.accessToken);
    if (me.userId !== verified.userId) {
      throw new Error('refreshed user mismatch');
    }

    const next: GatewaySession = {
      ...session,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      userId: verified.userId,
      email: me.email,
      amr: verified.amr,
      accessExpiresAt: verified.exp * 1000,
    };

    const current = store.getSession(session.id);
    if (!current || current.refreshToken !== session.refreshToken) {
      throw new Error('session changed during refresh');
    }

    store.updateSession(next);
    return next;
  }

  async function handleLogout(req: IncomingMessage, res: ServerResponse, url: URL) {
    const sessionId = readSignedCookie(req, SESSION_COOKIE, config.cookieSecret);
    const session = sessionId ? store.getSession(sessionId) : null;
    if (sessionId) store.deleteSession(sessionId);

    if (session) {
      try {
        await authMini.logout(session.accessToken);
      } catch {
        // Local logout must be deterministic even if remote revocation fails.
      }
    }

    const returnTo = normalizeReturnTo(url.searchParams.get('return_to') ?? config.logoutRedirect, config) ?? '/';
    res.setHeader('Set-Cookie', [clearCookie(SESSION_COOKIE, config)]);
    redirect(res, returnTo);
  }

  return { server: createServer(handler), store };
}

function sendCallbackPage(res: ServerResponse) {
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Completing login</title></head>
<body>
<p>Completing login...</p>
<script>
(async () => {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const payload = Object.fromEntries(params.entries());
  window.history.replaceState(null, '', '/auth/callback');
  const response = await fetch('/auth/callback/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error('Login failed');
  const body = await response.json();
  window.location.assign(body.returnTo || '/');
})().catch(() => {
  document.body.textContent = 'Login failed. Please try again.';
});
</script>
</body>
</html>`;

  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  res.end(html);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 64 * 1024) throw new Error('request body too large');
    chunks.push(buffer);
  }

  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

function redirect(res: ServerResponse, location: string) {
  res.writeHead(302, { location, 'cache-control': 'no-store' }).end();
}

function sendText(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
