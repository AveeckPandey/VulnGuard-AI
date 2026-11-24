import React from 'react';
import { Shield, ArrowRight, Database, TrendingUp, AlertTriangle, Sparkles, Lock, Flame } from 'lucide-react';

interface LandingHeroProps {
  onNavigateToAnalyzer: () => void;
  onExploreFeedsClick?: () => void;
  onSelectPreset?: (cveId: string, criticality: any, exposure: any, context: string) => void;
  onOpenAuthModal?: () => void;
  isAuthenticated?: boolean;
}

export const LandingHero: React.FC<LandingHeroProps> = ({
  onNavigateToAnalyzer,
  onExploreFeedsClick,
  onSelectPreset,
  onOpenAuthModal,
  isAuthenticated = false,
}) => {
  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-[#0c162e] via-[#091024] to-[#080d1a] border border-cyan-500/20 p-8 sm:p-10 shadow-2xl">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/3 -mb-12 w-64 h-64 bg-blue-600/10 rounded-full blur-2xl pointer-events-none" />

        <div className="relative z-10 max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-semibold">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Autonomous Cybersecurity Intelligence Platform</span>
          </div>

          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black text-white tracking-tight leading-tight">
            Prioritize Vulnerabilities with <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">Ground-Truth Evidence</span>
          </h1>

          <p className="text-sm sm:text-base text-slate-300 leading-relaxed max-w-2xl">
            VulnGuard combines official CVSS metrics, real-time EPSS weaponization probabilities, and CISA KEV exploitation catalogs into an evidence-grounded risk score with verified generative AI remediation roadmaps.
          </p>

          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              onClick={onNavigateToAnalyzer}
              className="inline-flex items-center space-x-2.5 px-6 py-3 rounded-2xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm tracking-wide shadow-xl shadow-cyan-500/25 transition-all transform hover:-translate-y-0.5"
            >
              <span>Analyze a CVE</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            {onExploreFeedsClick && (
              <button
                onClick={onExploreFeedsClick}
                className="inline-flex items-center space-x-2 px-5 py-3 rounded-2xl bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 text-slate-200 text-sm font-semibold transition-all"
              >
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Threat Intel Status</span>
              </button>
            )}

            {!isAuthenticated && onOpenAuthModal && (
              <button
                onClick={onOpenAuthModal}
                className="inline-flex items-center space-x-2 px-5 py-3 rounded-2xl bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 text-slate-200 text-sm font-semibold transition-all"
              >
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Sign In / Demo Personas</span>
              </button>
            )}
          </div>

          {/* Preset Quick Actions */}
          {onSelectPreset && (
            <div className="pt-3 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-400">Quick Test Cases:</span>
              <button
                onClick={() =>
                  onSelectPreset(
                    'CVE-2021-44228',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Public Edge API Gateway with Log4j 2.14.0'
                  )
                }
                className="px-2.5 py-1 rounded-lg bg-slate-900/90 border border-slate-700/80 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 flex items-center space-x-1"
              >
                <Flame className="w-3 h-3 text-red-400" />
                <span>Log4Shell</span>
              </button>
              <button
                onClick={() =>
                  onSelectPreset(
                    'CVE-2024-3094',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Linux Production SSH Build Servers'
                  )
                }
                className="px-2.5 py-1 rounded-lg bg-slate-900/90 border border-slate-700/80 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 flex items-center space-x-1"
              >
                <Sparkles className="w-3 h-3 text-cyan-400" />
                <span>XZ Utils</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* 3 Real Data Sources Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Source 1: NIST NVD */}
        <div className="p-6 rounded-2xl bg-card border border-border shadow-sm hover:border-cyan-500/30 transition-all space-y-3">
          <div className="flex items-center justify-between">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono uppercase bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded-full font-bold">
              Baseline Metrics
            </span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">NIST NVD API 2.0</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Ingests authoritative CVSS v4.0 & v3.1 base scores, attack vector telemetry (AV/AC/PR/UI), and CWE weakness categorizations directly from NIST.
            </p>
          </div>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-cyan-400/90 flex justify-between">
            <span>Score Standard:</span>
            <span>CVSS 0.0 – 10.0</span>
          </div>
        </div>

        {/* Source 2: FIRST EPSS */}
        <div className="p-6 rounded-2xl bg-card border border-border shadow-sm hover:border-blue-500/30 transition-all space-y-3">
          <div className="flex items-center justify-between">
            <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400">
              <TrendingUp className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono uppercase bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded-full font-bold">
              Probability
            </span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">FIRST.org EPSS v3</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Calculates daily empirical exploitation probabilities and honeypot percentiles, forecasting the likelihood of weaponization over the next 30 days.
            </p>
          </div>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-blue-400/90 flex justify-between">
            <span>Exploit Prediction:</span>
            <span>0.0% – 100.0%</span>
          </div>
        </div>

        {/* Source 3: CISA KEV */}
        <div className="p-6 rounded-2xl bg-card border border-border shadow-sm hover:border-red-500/30 transition-all space-y-3">
          <div className="flex items-center justify-between">
            <div className="p-2.5 rounded-xl bg-red-500/10 text-red-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono uppercase bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full font-bold">
              In-the-Wild
            </span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">CISA KEV Catalog</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Validates whether the vulnerability is actively weaponized by threat actors and cross-references federal mandatory remediation deadlines.
            </p>
          </div>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-red-400/90 flex justify-between">
            <span>Known Exploited:</span>
            <span>1,790+ Active CVEs</span>
          </div>
        </div>
      </div>
    </div>
  );
};
