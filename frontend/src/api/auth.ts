import { AuthSession, AuthState, UserProfile } from '../types/auth';

const SESSION_STORAGE_KEY = 'vulnguard_auth_session';
const PKCE_STORAGE_KEY = 'vulnguard_pkce';
const cognitoDomain = (import.meta.env.VITE_COGNITO_DOMAIN || '').replace(/\/$/, '');
const cognitoClientId = import.meta.env.VITE_COGNITO_CLIENT_ID || '';

function callbackUrl(): string {
  return `${window.location.origin}/callback`;
}

export function isCognitoConfigured(): boolean {
  return Boolean(cognitoDomain && cognitoClientId);
}

export async function beginCognitoLogin(signUp = false): Promise<void> {
  if (!isCognitoConfigured()) throw new Error('Cognito is not configured for this deployment.');
  const { verifier, challenge } = await generatePkcePair();
  const state = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');
  sessionStorage.setItem(PKCE_STORAGE_KEY, JSON.stringify({ verifier, state }));
  const url = new URL(`${cognitoDomain}/${signUp ? 'signup' : 'login'}`);
  url.search = new URLSearchParams({
    response_type: 'code', client_id: cognitoClientId,
    redirect_uri: callbackUrl(), scope: 'openid email profile',
    code_challenge_method: 'S256', code_challenge: challenge, state,
  }).toString();
  window.location.assign(url.toString());
}

export async function completeCognitoLogin(): Promise<AuthSession | null> {
  if (window.location.pathname !== '/callback') return null;
  const params = new URLSearchParams(window.location.search);
  const stored = sessionStorage.getItem(PKCE_STORAGE_KEY);
  sessionStorage.removeItem(PKCE_STORAGE_KEY);
  window.history.replaceState({}, '', '/');
  if (params.has('error')) throw new Error(params.get('error_description') || 'Sign-in was cancelled.');
  if (!stored || !params.get('code') || !isCognitoConfigured()) throw new Error('Sign-in session is missing or expired.');
  const { verifier, state } = JSON.parse(stored) as { verifier: string; state: string };
  if (!state || params.get('state') !== state) throw new Error('Invalid sign-in state.');
  const response = await fetch(`${cognitoDomain}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: cognitoClientId,
      redirect_uri: callbackUrl(), code: params.get('code')!, code_verifier: verifier,
    }),
  });
  if (!response.ok) throw new Error('Cognito could not complete sign-in. Please try again.');
  const result = await response.json();
  if (!result.access_token || !result.id_token) throw new Error('Cognito returned an incomplete session.');
  const session = authManager.loginWithTokens(result.access_token, result.id_token);
  session.refreshToken = result.refresh_token;
  authManager.setSession(session);
  return session;
}

// Decode JWT payload without external library
function parseJwt(token: string): any {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

// Generate PKCE code verifier and challenge
export async function generatePkcePair(): Promise<{ verifier: string; challenge: string }> {
  const array = new Uint8Array(32);
  window.crypto.getRandomValues(array);
  const verifier = Array.from(array, (dec) => ('0' + dec.toString(16)).slice(-2)).join('');
  
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return { verifier, challenge };
}

export const authManager = {
  getSession(): AuthSession | null {
    if (typeof window === 'undefined' || !window.sessionStorage) return null;
    const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    try {
      const session = JSON.parse(raw) as AuthSession;
      // Check expiration with 30-second buffer
      if (session.expiresAt && session.expiresAt <= Math.floor(Date.now() / 1000) + 30) {
        this.clearSession();
        return null;
      }
      return session;
    } catch {
      return null;
    }
  },

  setSession(session: AuthSession): void {
    if (typeof window === 'undefined' || !window.sessionStorage) return;
    window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  },

  clearSession(): void {
    if (typeof window === 'undefined' || !window.sessionStorage) return;
    window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  },

  getAccessToken(): string | null {
    const session = this.getSession();
    return session ? session.accessToken : null;
  },

  getCurrentUser(): UserProfile | null {
    const session = this.getSession();
    return session ? session.user : null;
  },

  getInitialState(): AuthState {
    const session = this.getSession();
    return {
      isAuthenticated: !!session,
      isLoading: false,
      user: session?.user || null,
      session: session,
      error: null,
    };
  },

  isSessionExpired(): boolean {
    if (typeof window === 'undefined' || !window.sessionStorage) return true;
    const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return true;
    try {
      const session = JSON.parse(raw) as AuthSession;
      return session.expiresAt ? session.expiresAt <= Math.floor(Date.now() / 1000) : false;
    } catch {
      return true;
    }
  },

  // Log in using standard Cognito User Pools JWT tokens
  loginWithTokens(accessToken: string, idToken?: string): AuthSession {
    const claims = parseJwt(accessToken);
    const profile = idToken ? parseJwt(idToken) : null;
    if (!claims?.sub || !claims?.exp || claims.token_use !== 'access') {
      throw new Error('An unexpired Cognito access token is required.');
    }
    if (claims.exp <= Math.floor(Date.now() / 1000)) throw new Error('The access token has expired.');
    if (cognitoClientId && claims.client_id !== cognitoClientId) throw new Error('Token belongs to another application.');
    const sub = claims.sub;
    const email = profile?.email || claims.email || `${sub.slice(0, 8)}@cognito.local`;
    const exp = claims.exp || Math.floor(Date.now() / 1000) + 3600;
    const username = claims['cognito:username'] || email.split('@')[0];

    const user: UserProfile = {
      sub,
      email,
      username,
      name: profile?.name || claims.name || username,
      isDemo: false,
      clientType: 'cognito_user',
    };

    const session: AuthSession = {
      accessToken,
      idToken,
      expiresAt: exp,
      user,
    };

    this.setSession(session);
    return session;
  },

  // Instant pre-configured persona login for local testing / multi-tenant demo
  loginAsDemoAnalyst(persona: 'analyst-a' | 'analyst-b'): AuthSession {
    if (!import.meta.env.DEV) throw new Error('Demo identities are available only in local development.');
    const isA = persona === 'analyst-a';
    const sub = isA ? 'usr-a-edge-analyst' : 'usr-b-core-analyst';
    const email = isA ? 'analyst-a@vulnguard.io' : 'analyst-b@vulnguard.io';
    const username = isA ? 'Analyst A (Edge Ops)' : 'Analyst B (Core Sec)';
    const token = `user-${isA ? 'a' : 'b'}-token`;

    const user: UserProfile = {
      sub,
      email,
      username,
      name: username,
      isDemo: true,
      clientType: 'demo_analyst',
    };

    const session: AuthSession = {
      accessToken: token,
      expiresAt: Math.floor(Date.now() / 1000) + 7200, // 2 hours
      user,
    };

    this.setSession(session);
    return session;
  },

  signOut(): void {
    const wasDemo = this.getCurrentUser()?.isDemo;
    this.clearSession();
    if (isCognitoConfigured() && !wasDemo) {
      const url = new URL(`${cognitoDomain}/logout`);
      url.search = new URLSearchParams({ client_id: cognitoClientId, logout_uri: window.location.origin }).toString();
      window.location.assign(url.toString());
    }
  },
};

export const authService = authManager;
