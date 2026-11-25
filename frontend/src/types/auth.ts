export interface UserProfile {
  sub: string;
  email: string;
  username: string;
  name?: string;
  isDemo?: boolean;
  clientType: 'cognito_user' | 'service_account' | 'demo_analyst' | 'anonymous';
}

export interface AuthSession {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number; // Unix timestamp in seconds
  viaHostedUi?: boolean;
  user: UserProfile;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: UserProfile | null;
  session?: AuthSession | null;
  error: string | null;
}
