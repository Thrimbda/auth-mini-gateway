import { execFileSync } from 'node:child_process';
import WebSocket from 'ws';

const baseUrl = process.env.SMOKE_BASE_URL ?? 'http://127.0.0.1:8080';
const mockAuthUrl = process.env.SMOKE_AUTH_URL ?? 'http://127.0.0.1:7777';
const upstreamUrl = process.env.SMOKE_UPSTREAM_URL;
const composeFile = process.env.SMOKE_COMPOSE_FILE ?? 'examples/docker-compose.yml';

let cookie = '';

await waitForGateway();
await resetHits();

const unauth = await fetch(`${baseUrl}/`, { redirect: 'manual' });
assert(unauth.status === 302, 'unauthenticated request should redirect');
assert((await hits()) === 0, 'unauthenticated request must not reach upstream');

await loginAs('blocked@example.com', 'webauthn');
const forbidden = await fetch(`${baseUrl}/`, { headers: { cookie }, redirect: 'manual' });
assert(forbidden.status === 403, 'unauthorized allowlist user should be forbidden');
assert((await hits()) === 0, 'forbidden request must not reach upstream');

cookie = '';
await loginAs('allowed@example.com', 'webauthn');
const allowed = await fetch(`${baseUrl}/`, { headers: { cookie } });
assert(allowed.status === 200, 'authorized request should reach upstream');
assert((await hits()) === 1, 'authorized HTTP request should increment upstream hits');

await websocketCheck();
assert((await hits()) === 2, 'authorized WebSocket should increment upstream hits');

if (!process.env.SKIP_DOCKER_PORT_CHECK) {
  let directPortFailed = false;
  try {
    execFileSync('docker', ['compose', '-f', composeFile, 'port', 'upstream', '4000'], {
      stdio: 'pipe',
    });
  } catch {
    directPortFailed = true;
  }
  assert(directPortFailed, 'upstream service must not publish a direct host port');
}

console.log('nginx smoke passed');

async function loginAs(email, amr) {
  const login = await fetch(`${baseUrl}/login?return_to=%2F`, { redirect: 'manual' });
  assert(login.status === 302, 'login should redirect to auth-mini');
  mergeCookie(login.headers.get('set-cookie'));
  const location = login.headers.get('location');
  assert(location, 'login response must include location');
  const state = new URL(location.replace('/web/#/login?', '/web/?')).searchParams.get('state');
  assert(state, 'login location must include state');

  const minted = await fetch(`${mockAuthUrl}/__mint?email=${encodeURIComponent(email)}&amr=${encodeURIComponent(amr)}`);
  assert(minted.ok, 'mock auth-mini should mint token');
  const token = await minted.json();
  const callback = await fetch(`${baseUrl}/auth/callback/session`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ ...token, state }),
  });
  mergeCookie(callback.headers.get('set-cookie'));
}

async function websocketCheck() {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(baseUrl.replace('http:', 'ws:').replace('https:', 'wss:') + '/ws', {
      headers: { cookie },
    });
    ws.once('message', () => {
      ws.close();
      resolve();
    });
    ws.once('error', reject);
    setTimeout(() => reject(new Error('websocket timeout')), 5000).unref();
  });
}

async function resetHits() {
  if (upstreamUrl) {
    await fetch(`${upstreamUrl}/reset`);
    return;
  }

  execFileSync('docker', ['compose', '-f', composeFile, 'exec', '-T', 'upstream', 'wget', '-qO-', 'http://127.0.0.1:4000/reset'], {
    stdio: 'pipe',
  });
}

async function hits() {
  if (upstreamUrl) {
    const response = await fetch(`${upstreamUrl}/hits`);
    return (await response.json()).hits;
  }

  const output = execFileSync('docker', ['compose', '-f', composeFile, 'exec', '-T', 'upstream', 'wget', '-qO-', 'http://127.0.0.1:4000/hits'], {
    encoding: 'utf8',
  });
  return JSON.parse(output).hits;
}

function mergeCookie(setCookie) {
  if (!setCookie) return;
  const existing = new Map(
    cookie
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => part.split('=')),
  );
  for (const raw of splitSetCookie(setCookie)) {
    const [pair] = raw.split(';');
    const index = pair.indexOf('=');
    if (index > 0) existing.set(pair.slice(0, index), pair.slice(index + 1));
  }
  cookie = [...existing.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function splitSetCookie(value) {
  return value.split(/,(?=\s*[^;]+=)/g).map((entry) => entry.trim());
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function waitForGateway() {
  const deadline = Date.now() + 15_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.status === 204) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw lastError ?? new Error('gateway did not become ready');
}
