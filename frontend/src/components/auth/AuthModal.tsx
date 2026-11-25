import React, { useState } from 'react';
import ElectricLogo from '@/components/ui/ElectricLogo';
import { authManager, beginCognitoLogin, isCognitoConfigured } from '../../api/auth';
import { UserProfile } from '../../types/auth';
import { Shield, X } from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserProfile) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onAuthSuccess }) => {
  const [error, setError] = useState<string | null>(null);
  if (!isOpen) return null;

  const start = async (signUp: boolean) => {
    setError(null);
    try {
      await beginCognitoLogin(signUp);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start sign-in.');
    }
  };

  const demo = (persona: 'analyst-a' | 'analyst-b') => {
    try {
      const session = authManager.loginAsDemoAnalyst(persona);
      onAuthSuccess(session.user);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Demo login failed.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#070709]/90 p-4 backdrop-blur-md">
      {/* Interactive Sign-In Page Background */}
      <div aria-hidden="true" className="fixed inset-0 z-0 opacity-65">
        <ElectricLogo
          src="/logo.svg"
          color="#e0f2fe"
          glowColor="#38bdf8"
          scale={0.72}
          strands={6}
          bend={0.6}
          crackle={1.5}
          arcs={2}
          speed={2.8}
          interactive={true}
          cursorIntensity={0.85}
          cursorRadius={120}
          intensity={1.5}
          glow={1.8}
          flicker={0.75}
          fill={0.12}
          theme="dark"
        />
      </div>

      <div
        className="relative z-10 w-full max-w-md rounded-2xl border border-white/[0.14] bg-[#131316]/95 p-6 shadow-2xl backdrop-blur-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="auth-modal-title" className="flex items-center gap-2 text-lg font-semibold text-foreground">
              <Shield className="size-4 text-sky-400" />
              <span>Your private workspace</span>
            </h2>
            <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
              Sign in with Amazon Cognito to save and view your assessments.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close sign-in dialog"
            className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-white/[0.08] hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {error && (
          <p role="alert" className="mt-4 rounded-xl border border-red-500/35 bg-red-500/15 p-3 text-sm text-red-200">
            {error}
          </p>
        )}

        {!isCognitoConfigured() && (
          <p role="status" className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs leading-relaxed text-amber-200">
            Cognito sign-in is not configured for this environment.
          </p>
        )}

        <div className="mt-5 grid gap-2.5">
          <button
            type="button"
            disabled={!isCognitoConfigured()}
            onClick={() => start(false)}
            className="h-10 rounded-xl bg-primary px-4 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            Sign in
          </button>
          <button
            type="button"
            disabled={!isCognitoConfigured()}
            onClick={() => start(true)}
            className="h-10 rounded-xl border border-border bg-white/[0.04] px-4 text-sm font-medium text-foreground transition-colors hover:bg-white/[0.08] disabled:opacity-50"
          >
            Create account
          </button>
        </div>

        {import.meta.env.DEV && !isCognitoConfigured() && (
          <div className="mt-5 border-t border-border pt-4">
            <p className="mb-2.5 text-xs text-muted-foreground">Local development personas (no real account)</p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => demo('analyst-a')}
                className="flex-1 rounded-xl border border-border bg-white/[0.04] px-3 py-2 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08]"
              >
                Analyst A
              </button>
              <button
                type="button"
                onClick={() => demo('analyst-b')}
                className="flex-1 rounded-xl border border-border bg-white/[0.04] px-3 py-2 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08]"
              >
                Analyst B
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
