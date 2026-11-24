import React, { useState } from 'react';
import { authManager } from '../../api/auth';
import { UserProfile } from '../../types/auth';
import { Shield, Lock, Mail, CheckCircle2, AlertCircle, X, Sparkles } from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserProfile) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onAuthSuccess }) => {
  const [tab, setTab] = useState<'signin' | 'signup' | 'demo'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [customToken, setCustomToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDemoLogin = (persona: 'analyst-a' | 'analyst-b') => {
    setError(null);
    try {
      const session = authManager.loginAsDemoAnalyst(persona);
      setSuccessMsg(`Signed in as ${session.user.username}`);
      setTimeout(() => {
        onAuthSuccess(session.user);
        onClose();
      }, 500);
    } catch (e: any) {
      setError(e.message || 'Demo login failed');
    }
  };

  const handleCustomTokenLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!customToken.trim()) {
      setError('Please provide a valid Cognito JWT token or bearer string.');
      return;
    }
    try {
      const session = authManager.loginWithTokens(customToken.trim());
      setSuccessMsg(`Authenticated session for ${session.user.email}`);
      setTimeout(() => {
        onAuthSuccess(session.user);
        onClose();
      }, 500);
    } catch (e: any) {
      setError(e.message || 'Token parsing failed');
    }
  };

  const handleCognitoSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!email || !password) {
      setError('Email and password are required.');
      return;
    }
    // Simulate / execute standard Cognito user session creation
    try {
      const pseudoSub = `usr-${Math.random().toString(36).substring(2, 10)}`;
      const pseudoToken = `cognito-jwt-${pseudoSub}`;
      const session = authManager.loginWithTokens(pseudoToken);
      session.user.email = email;
      session.user.username = email.split('@')[0];
      authManager.setSession(session);
      setSuccessMsg(`Welcome, ${session.user.username}!`);
      setTimeout(() => {
        onAuthSuccess(session.user);
        onClose();
      }, 500);
    } catch (e: any) {
      setError(e.message || 'Sign in failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="w-full max-w-md bg-[#0c1322] border border-border/80 rounded-2xl shadow-2xl overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
      >
        {/* Header */}
        <div className="p-5 border-b border-border flex items-center justify-between bg-card/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 id="auth-modal-title" className="text-base font-bold text-white tracking-tight">
                VulnGuard Workspace Access
              </h3>
              <p className="text-[11px] text-slate-400">Multi-tenant personal testing workspace</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-border text-xs bg-slate-950/40">
          <button
            onClick={() => { setTab('signin'); setError(null); }}
            className={`flex-1 py-2.5 text-center font-semibold transition-all border-b-2 ${
              tab === 'signin'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            onClick={() => { setTab('signup'); setError(null); }}
            className={`flex-1 py-2.5 text-center font-semibold transition-all border-b-2 ${
              tab === 'signup'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign Up
          </button>
          <button
            onClick={() => { setTab('demo'); setError(null); }}
            className={`flex-1 py-2.5 text-center font-semibold transition-all border-b-2 flex items-center justify-center space-x-1 ${
              tab === 'demo'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Multi-Tenant Demo</span>
          </button>
        </div>

        <div className="p-6 space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* TAB 1 & 2: Sign In / Sign Up */}
          {(tab === 'signin' || tab === 'signup') && (
            <form onSubmit={handleCognitoSubmit} className="space-y-3.5">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@organization.com"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    required
                  />
                </div>
                {tab === 'signup' && (
                  <p className="text-[10px] text-slate-500 mt-1">
                    Password must be at least 8 characters with uppercase, lowercase, and numbers.
                  </p>
                )}
              </div>

              <button
                type="submit"
                className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs tracking-wide shadow-lg shadow-cyan-500/20 transition-all"
              >
                {tab === 'signin' ? 'Sign In to Workspace' : 'Create Free Workspace Account'}
              </button>

              <div className="relative my-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-800" />
                </div>
                <div className="relative flex justify-center text-[10px] uppercase font-mono">
                  <span className="bg-[#0c1322] px-2 text-slate-500">Or use Bearer Token</span>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] font-medium text-slate-400">
                    Existing Cognito JWT / Access Token
                  </label>
                </div>
                <input
                  type="text"
                  value={customToken}
                  onChange={(e) => setCustomToken(e.target.value)}
                  placeholder="Paste Bearer JWT token..."
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-[11px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={handleCustomTokenLogin}
                  className="w-full mt-2 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-all"
                >
                  Apply Token & Authorize
                </button>
              </div>
            </form>
          )}

          {/* TAB 3: Multi-Tenant Demo Personas */}
          {tab === 'demo' && (
            <div className="space-y-3">
              <div className="p-3 rounded-xl bg-cyan-950/20 border border-cyan-800/30 text-xs text-slate-300">
                <p className="font-semibold text-cyan-400 mb-1">Multi-Tenant Isolation Testing</p>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Test tenant isolation by switching between Analyst A and Analyst B. Each analyst maintains a strictly isolated workspace, independent assessments, and private system contexts.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-2.5 pt-1">
                <button
                  onClick={() => handleDemoLogin('analyst-a')}
                  className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-cyan-500/50 hover:bg-cyan-500/5 text-left transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-7 h-7 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center font-bold text-xs">
                        A
                      </div>
                      <div>
                        <p className="text-xs font-bold text-white group-hover:text-cyan-400 transition-colors">
                          Analyst A (Edge Ops Workspace)
                        </p>
                        <p className="text-[10px] font-mono text-slate-400">analyst-a@vulnguard.io</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded-full">
                      Tenant A
                    </span>
                  </div>
                </button>

                <button
                  onClick={() => handleDemoLogin('analyst-b')}
                  className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-purple-500/50 hover:bg-purple-500/5 text-left transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-7 h-7 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold text-xs">
                        B
                      </div>
                      <div>
                        <p className="text-xs font-bold text-white group-hover:text-purple-400 transition-colors">
                          Analyst B (Core Sec Workspace)
                        </p>
                        <p className="text-[10px] font-mono text-slate-400">analyst-b@vulnguard.io</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded-full">
                      Tenant B
                    </span>
                  </div>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
