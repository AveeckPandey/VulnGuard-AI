import React, { useState } from 'react';
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-[#0c1322] p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="auth-modal-title">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="auth-modal-title" className="flex items-center gap-2 text-lg font-bold text-white"><Shield className="h-5 w-5 text-cyan-400" />Your private workspace</h2>
            <p className="mt-2 text-sm text-slate-400">Sign in with Amazon Cognito to save and view your assessments.</p>
          </div>
          <button onClick={onClose} aria-label="Close sign-in dialog" className="text-slate-400 hover:text-white"><X className="h-5 w-5" /></button>
        </div>
        {error && <p role="alert" className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">{error}</p>}
        {!isCognitoConfigured() && <p role="status" className="mt-4 text-sm text-amber-300">Cognito sign-in is not configured for this environment.</p>}
        <div className="mt-6 grid gap-3">
          <button disabled={!isCognitoConfigured()} onClick={() => start(false)} className="rounded-lg bg-cyan-500 px-4 py-2.5 font-semibold text-slate-950 disabled:opacity-50">Sign in</button>
          <button disabled={!isCognitoConfigured()} onClick={() => start(true)} className="rounded-lg border border-slate-600 px-4 py-2.5 font-semibold text-white disabled:opacity-50">Create account</button>
        </div>
        {import.meta.env.DEV && !isCognitoConfigured() && <div className="mt-6 border-t border-slate-700 pt-4">
          <p className="mb-2 text-xs text-slate-400">Local development personas (no real account)</p>
          <div className="flex gap-2">
            <button onClick={() => demo('analyst-a')} className="rounded-lg border border-slate-600 px-3 py-2 text-xs text-white">Analyst A</button>
            <button onClick={() => demo('analyst-b')} className="rounded-lg border border-slate-600 px-3 py-2 text-xs text-white">Analyst B</button>
          </div>
        </div>}
      </div>
    </div>
  );
};
