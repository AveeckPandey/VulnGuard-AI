import { AuthSession, AuthState, UserProfile } from '../types/auth';

const SESSION_STORAGE_KEY = 'vulnguard_auth_session';

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
    const claims = parseJwt(accessToken) || (idToken ? parseJwt(idToken) : {}) || {};
    const sub = claims.sub || `usr-${Math.random().toString(36).substring(2, 10)}`;
    const email = claims.email || claims.username || `${sub.slice(0, 8)}@cognito.local`;
    const exp = claims.exp || Math.floor(Date.now() / 1000) + 3600;
    const username = claims['cognito:username'] || email.split('@')[0];

    const user: UserProfile = {
      sub,
      email,
      username,
      name: claims.name || username,
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
};

export const authService = authManager;
