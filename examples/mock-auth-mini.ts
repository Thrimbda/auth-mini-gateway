import { createServer } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const issuer = process.env.ISSUER ?? 'http://127.0.0.1:7777';
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const publicJwk = await exportJWK(publicKey);
const kid = 'mock-current';
const jwks = { keys: [{ ...publicJwk, kid, alg: 'EdDSA', use: 'sig' }] };

const sessions = new Map<string, { userId: string; email: string | null; amr: string[] }>();
let logoutCount = 0;

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', issuer);

    if (req.method === 'GET' && url.pathname === '/jwks') {
      sendJson(res, 200, jwks);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/__mint') {
      const email = url.searchParams.get('email') || 'allowed@example.com';
      const userId = url.searchParams.get('user_id') || `user-${email}`;
      const amr = (url.searchParams.get('amr') || 'webauthn').split(',').filter(Boolean);
      const token = await mintSession(userId, email, amr);
      sendJson(res, 200, token);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/me') {
      const token = bearer(req.headers.authorization);
      const session = token ? sessions.get(token) : null;
      if (!session) {
        sendJson(res, 401, { error: 'invalid_token' });
        return;
      }
      sendJson(res, 200, { user_id: session.userId, email: session.email });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/session/refresh') {
      const body = (await readJson(req)) as { session_id?: string; refresh_token?: string };
      const existing = body.refresh_token ? sessions.get(body.refresh_token) : null;
      if (!body.session_id || !existing) {
        sendJson(res, 401, { error: 'invalid_refresh' });
        return;
      }
      const token = await mintSession(existing.userId, existing.email, existing.amr, body.session_id);
      sendJson(res, 200, token);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/session/logout') {
      logoutCount += 1;
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/__stats') {
      sendJson(res, 200, { logoutCount });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  } catch {
    sendJson(res, 500, { error: 'server_error' });
  }
});

async function mintSession(
  userId: string,
  email: string | null,
  amr: string[],
  sessionId: string = crypto.randomUUID(),
) {
  const refreshToken = crypto.randomUUID();
  const accessToken = await new SignJWT({ sid: sessionId, amr, typ: 'access' })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
    .setIssuer(issuer)
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(privateKey);

  sessions.set(accessToken, { userId, email, amr });
  sessions.set(refreshToken, { userId, email, amr });
  return {
    session_id: sessionId,
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    refresh_token: refreshToken,
  };
}

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length);
}

async function readJson(req: NodeJS.ReadableStream): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

function sendJson(res: import('node:http').ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

const port = Number.parseInt(process.env.PORT ?? '7777', 10);
const host = process.env.HOST ?? '127.0.0.1';
server.listen(port, host, () => {
  console.log(`mock auth-mini listening on ${host}:${port}`);
});
