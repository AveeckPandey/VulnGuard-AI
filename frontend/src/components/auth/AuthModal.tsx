import React, { useMemo, useState } from 'react';
import ElectricLogo from '@/components/ui/ElectricLogo';
import {
  authManager,
  confirmPasswordReset,
  confirmSignUpCode,
  evaluatePasswordRules,
  isCognitoConfigured,
  requestPasswordReset,
  resendSignUpCode,
  signInWithEmail,
  signUpWithEmail,
} from '../../api/auth';
import { UserProfile } from '../../types/auth';
import { ArrowLeft, Check, Circle, Eye, EyeOff, Loader2, Shield, X } from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserProfile) => void;
}

type AuthMode = 'signin' | 'signup' | 'verify' | 'forgot' | 'forgot_confirm';

function PasswordRulesChecklist({ password }: { password: string }) {
  const rules = useMemo(() => evaluatePasswordRules(password), [password]);
  return (
    <ul className="space-y-1.5 rounded-xl border border-border bg-[#0d0d10] p-3 text-xs">
      {rules.map((rule) => (
        <li
          key={rule.id}
          className={`flex items-center gap-2 transition-colors ${
            rule.met ? 'text-emerald-400' : 'text-muted-foreground'
          }`}
        >
          {rule.met ? (
            <Check className="size-3.5 shrink-0 text-emerald-400" />
          ) : (
            <Circle className="size-3 shrink-0 text-zinc-600" />
          )}
          <span>{rule.label}</span>
        </li>
      ))}
    </ul>
  );
}

const INPUT_CLASS =
  'h-10 w-full rounded-xl border border-white/[0.12] bg-[#0d0d10] px-3.5 text-sm text-foreground placeholder:text-zinc-500 transition-colors focus:border-white/40 focus:outline-none';

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onAuthSuccess }) => {
  const [mode, setMode] = useState<AuthMode>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [destination, setDestination] = useState<string | undefined>(undefined);
  const [pendingPassword, setPendingPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  if (!isOpen) return null;

  const authConfigured = isCognitoConfigured();
  const passwordValid = evaluatePasswordRules(password).every((rule) => rule.met);

  const switchMode = (nextMode: AuthMode) => {
    setMode(nextMode);
    setError(null);
    setNotice(null);
    setShowPassword(false);
    if (nextMode === 'signin' || nextMode === 'signup') {
      setCode('');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setError('Please enter your email address.');
      return;
    }

    setIsSubmitting(true);
    try {
      if (mode === 'signin') {
        const session = await signInWithEmail(trimmedEmail, password);
        onAuthSuccess(session.user);
        onClose();
        return;
      }

      if (mode === 'signup') {
        if (!passwordValid) {
          setError('Password does not meet all requirements.');
          return;
        }
        const res = await signUpWithEmail(trimmedEmail, password);
        if (res.userConfirmed) {
          const session = await signInWithEmail(trimmedEmail, password);
          onAuthSuccess(session.user);
          onClose();
          return;
        }
        setPendingPassword(password);
        setDestination(res.deliveryDestination || trimmedEmail);
        setCode('');
        setMode('verify');
        setNotice('Check your email for a 6-digit verification code.');
        return;
      }

      if (mode === 'verify') {
        if (!code.trim()) {
          setError('Enter the verification code sent to your email.');
          return;
        }
        await confirmSignUpCode(trimmedEmail, code);
        const signInPass = pendingPassword || password;
        if (signInPass) {
          const session = await signInWithEmail(trimmedEmail, signInPass);
          onAuthSuccess(session.user);
          onClose();
          return;
        }
        setPassword('');
        setCode('');
        setMode('signin');
        setNotice('Email verified. Sign in with your password to continue.');
        return;
      }

      if (mode === 'forgot') {
        const dest = await requestPasswordReset(trimmedEmail);
        setDestination(dest || trimmedEmail);
        setPassword('');
        setCode('');
        setMode('forgot_confirm');
        setNotice('Password reset code sent to your email.');
        return;
      }

      if (mode === 'forgot_confirm') {
        if (!code.trim()) {
          setError('Enter the reset code from your email.');
          return;
        }
        if (!passwordValid) {
          setError('New password does not meet all requirements.');
          return;
        }
        await confirmPasswordReset(trimmedEmail, code, password);
        setPassword('');
        setCode('');
        setMode('signin');
        setNotice('Password updated. Sign in with your new password.');
      }
    } catch (err: any) {
      if (err?.code === 'UserNotConfirmedException') {
        setPendingPassword(password);
        setDestination(trimmedEmail);
        setMode('verify');
        setNotice('Your email is not verified yet. Enter your verification code or resend a new one.');
        return;
      }
      setError(err instanceof Error ? err.message : 'Authentication failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResendCode = async () => {
    setError(null);
    setNotice(null);
    setIsSubmitting(true);
    try {
      const dest = await resendSignUpCode(email);
      setDestination(dest || email.trim());
      setNotice(`Verification code resent to ${dest || email.trim()}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not resend code.');
    } finally {
      setIsSubmitting(false);
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

  const headers: Record<AuthMode, { title: string; subtitle: string }> = {
    signin: {
      title: 'Sign in to VulnGuard AI',
      subtitle: 'Access your private assessment workspace and triage history.',
    },
    signup: {
      title: 'Create your account',
      subtitle: 'Save vulnerability assessments to a private, isolated workspace.',
    },
    verify: {
      title: 'Verify your email',
      subtitle: `Enter the verification code sent to ${destination || email || 'your email'}.`,
    },
    forgot: {
      title: 'Reset your password',
      subtitle: 'Enter your account email and we will send a recovery code.',
    },
    forgot_confirm: {
      title: 'Choose a new password',
      subtitle: `Enter the recovery code sent to ${destination || email || 'your email'}.`,
    },
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#070709]/92 p-4 backdrop-blur-md">
      {/* Subtle Electric Shield Backdrop */}
      <div aria-hidden="true" className="fixed inset-0 z-0 opacity-45">
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
          intensity={1.35}
          glow={1.6}
          flicker={0.75}
          fill={0.1}
          theme="dark"
        />
      </div>

      <div
        className="relative z-10 w-full max-w-[440px] rounded-2xl border border-white/[0.14] bg-[#131316]/95 p-6 shadow-2xl backdrop-blur-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div>
            {(mode === 'verify' || mode === 'forgot' || mode === 'forgot_confirm') && (
              <button
                type="button"
                onClick={() => switchMode('signin')}
                className="mb-2 inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
              >
                <ArrowLeft className="size-3.5" />
                <span>Back to sign in</span>
              </button>
            )}
            <h2 id="auth-modal-title" className="flex items-center gap-2 text-lg font-semibold text-foreground">
              <Shield className="size-4 text-sky-400" />
              <span>{headers[mode].title}</span>
            </h2>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {headers[mode].subtitle}
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

        {/* Sign In / Create Account Tabs */}
        {(mode === 'signin' || mode === 'signup') && (
          <div className="mt-4 grid grid-cols-2 rounded-xl border border-border bg-[#0d0d10] p-1">
            <button
              type="button"
              onClick={() => switchMode('signin')}
              className={`h-8 rounded-lg text-xs font-medium transition-colors ${
                mode === 'signin'
                  ? 'bg-[#1c1c21] text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => switchMode('signup')}
              className={`h-8 rounded-lg text-xs font-medium transition-colors ${
                mode === 'signup'
                  ? 'bg-[#1c1c21] text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Create account
            </button>
          </div>
        )}

        {/* Alerts */}
        {error && (
          <p role="alert" className="mt-4 rounded-xl border border-red-500/35 bg-red-500/15 px-3.5 py-2.5 text-xs text-red-200">
            {error}
          </p>
        )}

        {notice && (
          <p role="status" className="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 text-xs text-emerald-200">
            {notice}
          </p>
        )}

        {!authConfigured && (
          <p role="status" className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs leading-relaxed text-amber-200">
            Account sign-in is not configured in this local environment.
          </p>
        )}

        {/* Native Dark Auth Form */}
        {authConfigured && (
          <form onSubmit={handleSubmit} className="mt-4 space-y-3.5">
            {mode !== 'verify' && (
              <div>
                <label htmlFor="auth-email" className="mb-1.5 block text-xs font-medium text-zinc-300">
                  Email address
                </label>
                <input
                  id="auth-email"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className={INPUT_CLASS}
                />
              </div>
            )}

            {(mode === 'verify' || mode === 'forgot_confirm') && (
              <div>
                <label htmlFor="auth-code" className="mb-1.5 block text-xs font-medium text-zinc-300">
                  Verification code
                </label>
                <input
                  id="auth-code"
                  type="text"
                  inputMode="numeric"
                  required
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Enter 6-digit code"
                  className={`${INPUT_CLASS} font-mono tracking-widest`}
                />
              </div>
            )}

            {(mode === 'signin' || mode === 'signup' || mode === 'forgot_confirm') && (
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <label htmlFor="auth-password" className="text-xs font-medium text-zinc-300">
                    {mode === 'forgot_confirm' ? 'New password' : 'Password'}
                  </label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => switchMode('forgot')}
                      className="text-[11px] font-medium text-sky-400 transition-colors hover:text-sky-300"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <input
                    id="auth-password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    className={`${INPUT_CLASS} pr-10`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground transition-colors hover:text-foreground"
                  >
                    {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </div>
              </div>
            )}

            {(mode === 'signup' || mode === 'forgot_confirm') && (
              <PasswordRulesChecklist password={password} />
            )}

            <button
              type="submit"
              disabled={isSubmitting || ((mode === 'signup' || mode === 'forgot_confirm') && !passwordValid)}
              className="flex h-10 w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isSubmitting && <Loader2 className="size-4 animate-spin" />}
              <span>
                {mode === 'signin' && (isSubmitting ? 'Signing in...' : 'Sign in')}
                {mode === 'signup' && (isSubmitting ? 'Creating account...' : 'Create account')}
                {mode === 'verify' && (isSubmitting ? 'Verifying...' : 'Verify email')}
                {mode === 'forgot' && (isSubmitting ? 'Sending code...' : 'Send reset code')}
                {mode === 'forgot_confirm' && (isSubmitting ? 'Updating password...' : 'Update password')}
              </span>
            </button>

            {mode === 'verify' && (
              <div className="text-center">
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={handleResendCode}
                  className="text-xs font-medium text-sky-400 transition-colors hover:text-sky-300 disabled:opacity-50"
                >
                  Didn&apos;t receive a code? Resend verification email
                </button>
              </div>
            )}
          </form>
        )}

        {/* Local Dev Demo Personas */}
        {import.meta.env.DEV && !authConfigured && (
          <div className="mt-5 border-t border-border pt-4">
            <p className="mb-2.5 text-xs text-muted-foreground">Local development personas</p>
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
