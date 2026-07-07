export type SameSite = 'lax' | 'strict' | 'none';

export type AppConfig = {
  host: string;
  port: number;
  publicBaseUrl: string;
  authMiniIssuer: string;
  authMiniPublicBaseUrl: string;
  authMiniLoginUrl?: string;
  cookieSecret: string;
  cookieSecure: boolean;
  cookieSameSite: SameSite;
  sessionTtlMs: number;
  loginStateTtlMs: number;
  refreshSkewMs: number;
  maxLoginStates: number;
  maxSessions: number;
  allowEmails: Set<string>;
  allowUserIds: Set<string>;
  requirePasskey: boolean;
  logoutRedirect: string;
};

export type VerifiedAccessToken = {
  userId: string;
  authSessionId: string;
  amr: string[];
  exp: number;
};

export type MeResponse = {
  userId: string;
  email: string | null;
};

export type AuthMiniTokenResponse = {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
};

export type GatewaySession = {
  id: string;
  authSessionId: string;
  accessToken: string;
  refreshToken: string;
  userId: string;
  email: string | null;
  amr: string[];
  accessExpiresAt: number;
  expiresAt: number;
};

export type LoginState = {
  id: string;
  returnTo: string;
  expiresAt: number;
};
