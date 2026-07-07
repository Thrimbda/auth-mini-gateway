import { randomBytes } from 'node:crypto';
import type { GatewaySession, LoginState } from './types.js';

export class InMemoryStore {
  private readonly loginStates = new Map<string, LoginState>();
  private readonly sessions = new Map<string, GatewaySession>();

  constructor(
    private readonly now: () => number = () => Date.now(),
    private readonly limits: { maxLoginStates?: number; maxSessions?: number } = {},
  ) {}

  createLoginState(returnTo: string, ttlMs: number): LoginState {
    this.pruneExpiredLoginStates();
    const state: LoginState = {
      id: randomId(),
      returnTo,
      expiresAt: this.now() + ttlMs,
    };
    this.loginStates.set(state.id, state);
    enforceLimit(this.loginStates, this.limits.maxLoginStates ?? 10_000);
    return state;
  }

  consumeLoginState(id: string): LoginState | null {
    const state = this.loginStates.get(id);
    this.loginStates.delete(id);
    if (!state || state.expiresAt <= this.now()) return null;
    return state;
  }

  createSession(input: Omit<GatewaySession, 'id'>): GatewaySession {
    this.pruneExpiredSessions();
    const session = { ...input, id: randomId() };
    this.sessions.set(session.id, session);
    enforceLimit(this.sessions, this.limits.maxSessions ?? 10_000);
    return session;
  }

  getSession(id: string): GatewaySession | null {
    const session = this.sessions.get(id);
    if (!session) return null;
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(id);
      return null;
    }
    return session;
  }

  updateSession(session: GatewaySession): void {
    this.pruneExpiredSessions();
    this.sessions.set(session.id, session);
    enforceLimit(this.sessions, this.limits.maxSessions ?? 10_000);
  }

  deleteSession(id: string): void {
    this.sessions.delete(id);
  }

  stats(): { loginStates: number; sessions: number } {
    this.pruneExpiredLoginStates();
    this.pruneExpiredSessions();
    return { loginStates: this.loginStates.size, sessions: this.sessions.size };
  }

  private pruneExpiredLoginStates(): void {
    const now = this.now();
    for (const [id, state] of this.loginStates) {
      if (state.expiresAt <= now) this.loginStates.delete(id);
    }
  }

  private pruneExpiredSessions(): void {
    const now = this.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(id);
    }
  }
}

function randomId(): string {
  return randomBytes(32).toString('base64url');
}

function enforceLimit<T>(map: Map<string, T>, max: number): void {
  while (map.size > max) {
    const oldest = map.keys().next().value as string | undefined;
    if (!oldest) return;
    map.delete(oldest);
  }
}
