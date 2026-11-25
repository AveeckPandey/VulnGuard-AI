import React, { useState, useEffect } from 'react';
import { Search, Loader2, Globe, Server, AlertCircle, Sparkles, CheckCircle2, Shield, Database, Cpu, Activity } from 'lucide-react';
import { AssetCriticality, InternetExposure, AssessmentRequest } from '../../types/assessment';

interface CveSearchBarProps {
  onAnalyze: (request: AssessmentRequest) => Promise<void>;
  isLoading: boolean;
  isLiveMode: boolean;
  selectedCve: string;
  setSelectedCve: (cve: string) => void;
  criticality: AssetCriticality;
  setCriticality: (crit: AssetCriticality) => void;
  exposure: InternetExposure;
  setExposure: (expo: InternetExposure) => void;
  systemContext: string;
  setSystemContext: (ctx: string) => void;
}

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

const EXECUTION_PHASES = [
  { id: 1, label: 'Threat Intel Ingestion', detail: 'Querying NVD 2.0, EPSS v3, CISA KEV', icon: Shield },
  { id: 2, label: 'Deterministic Scoring', detail: 'Computing 0–100 risk heuristic matrix', icon: Activity },
  { id: 3, label: 'AI Remediation Engine', detail: 'Generating evidence-grounded remediation roadmap', icon: Cpu },
  { id: 4, label: 'Workspace Persistence', detail: 'Saving assessment to workspace history', icon: Database },
];

export const CveSearchBar: React.FC<CveSearchBarProps> = ({
  onAnalyze,
  isLoading,
  isLiveMode,
  selectedCve,
  setSelectedCve,
  criticality,
  setCriticality,
  exposure,
  setExposure,
  systemContext,
  setSystemContext,
}) => {
  const [validationError, setValidationError] = useState<string | null>(null);
  const [activePhaseIndex, setActivePhaseIndex] = useState<number>(0);

  useEffect(() => {
    if (!isLoading) {
      setActivePhaseIndex(0);
      return;
    }

    const interval = setInterval(() => {
      setActivePhaseIndex((prev) => (prev < EXECUTION_PHASES.length - 1 ? prev + 1 : prev));
    }, 1200);

    return () => clearInterval(interval);
  }, [isLoading]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCve = selectedCve.trim().toUpperCase();

    if (!cleanCve) {
      setValidationError('Please enter a CVE identifier (e.g. CVE-2021-44228).');
      return;
    }

    if (!CVE_REGEX.test(cleanCve)) {
      setValidationError('Invalid format. Must match standard CVE pattern: CVE-YYYY-NNNN+');
      return;
    }

    setValidationError(null);
    onAnalyze({
      cve_id: cleanCve,
      asset_criticality: criticality,
      internet_exposure: exposure,
      system_context: systemContext.trim() || undefined,
      simulate_offline: !isLiveMode,
    });
  };

  return (
    <div className="surface-panel space-y-4 rounded-2xl p-5">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Top Row: Search Input & Action Button */}
        <div>
          <label className="mb-2 block text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Target Vulnerability Identifier
          </label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5">
                <Search className="size-4 text-muted-foreground" />
              </div>
              <input
                type="text"
                value={selectedCve}
                onChange={(e) => {
                  setSelectedCve(e.target.value.toUpperCase());
                  if (validationError) setValidationError(null);
                }}
                placeholder="e.g. CVE-2021-44228, CVE-2024-3094..."
                className={`h-10 w-full rounded-xl border bg-background pl-10 pr-4 font-mono text-sm text-foreground placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-ring ${
                  validationError ? 'border-red-500/60 ring-1 ring-red-500/40' : 'border-border'
                }`}
                disabled={isLoading}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-xl bg-primary px-5 text-xs font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  <span>Analyzing Vulnerability...</span>
                </>
              ) : (
                <>
                  <Sparkles className="size-3.5" />
                  <span>Analyze Vulnerability</span>
                </>
              )}
            </button>
          </div>

          {validationError && (
            <div className="mt-2 flex items-center gap-1.5 text-xs text-red-400">
              <AlertCircle className="size-4 shrink-0" />
              <span>{validationError}</span>
            </div>
          )}
        </div>

        {/* Environmental Context Controls */}
        <div className="grid grid-cols-1 gap-4 border-t border-border pt-4 md:grid-cols-3">
          {/* Asset Criticality */}
          <div>
            <label className="mb-1.5 block text-[11px] font-medium text-muted-foreground">
              Asset Business Criticality (Weight: 10%)
            </label>
            <div className="grid grid-cols-4 gap-1 rounded-xl border border-border bg-background p-1">
              {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as AssetCriticality[]).map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setCriticality(level)}
                  className={`rounded-lg py-1.5 text-[11px] font-semibold transition-colors ${
                    criticality === level
                      ? level === 'CRITICAL'
                        ? 'border border-red-500/30 bg-red-500/15 text-red-400'
                        : level === 'HIGH'
                        ? 'border border-orange-500/30 bg-orange-500/15 text-orange-400'
                        : level === 'MEDIUM'
                        ? 'border border-yellow-500/30 bg-yellow-500/15 text-yellow-400'
                        : 'border border-sky-500/30 bg-sky-500/15 text-sky-400'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>

          {/* Internet Exposure */}
          <div>
            <label className="mb-1.5 block text-[11px] font-medium text-muted-foreground">
              Network Perimeter Exposure (Weight: 10%)
            </label>
            <div className="grid grid-cols-2 gap-1 rounded-xl border border-border bg-background p-1">
              <button
                type="button"
                onClick={() => setExposure('INTERNAL')}
                className={`flex items-center justify-center gap-1.5 rounded-lg px-2 py-1.5 text-[11px] font-semibold transition-colors ${
                  exposure === 'INTERNAL'
                    ? 'border border-white/[0.12] bg-white/[0.08] text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Server className="size-3.5" />
                <span>Internal / Isolated</span>
              </button>
              <button
                type="button"
                onClick={() => setExposure('PUBLIC_FACING')}
                className={`flex items-center justify-center gap-1.5 rounded-lg px-2 py-1.5 text-[11px] font-semibold transition-colors ${
                  exposure === 'PUBLIC_FACING'
                    ? 'border border-red-500/30 bg-red-500/15 text-red-400'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Globe className="size-3.5" />
                <span>Public Facing</span>
              </button>
            </div>
          </div>

          {/* System Context Notes */}
          <div>
            <label className="mb-1.5 block text-[11px] font-medium text-muted-foreground">
              Deployment / System Context (Optional)
            </label>
            <input
              type="text"
              value={systemContext}
              onChange={(e) => setSystemContext(e.target.value)}
              placeholder="e.g. Core Payment Auth Gateway"
              className="h-[38px] w-full rounded-xl border border-border bg-background px-3 text-xs text-foreground placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
        </div>
      </form>

      {/* 4-Phase Pipeline Execution Stepper when Loading */}
      {isLoading && (
        <div className="space-y-3 rounded-xl border border-border bg-background p-4">
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2 font-medium text-foreground">
              <Loader2 className="size-3.5 animate-spin text-sky-400" />
              <span>Analysis in Progress: Step {activePhaseIndex + 1} of 4</span>
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">
              {EXECUTION_PHASES[activePhaseIndex].label}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            {EXECUTION_PHASES.map((phase, idx) => {
              const Icon = phase.icon;
              const isPast = idx < activePhaseIndex;
              const isCurrent = idx === activePhaseIndex;

              return (
                <div
                  key={phase.id}
                  className={`rounded-lg border p-2.5 text-xs transition-colors ${
                    isCurrent
                      ? 'border-white/[0.15] bg-white/[0.06] text-foreground'
                      : isPast
                      ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
                      : 'border-border bg-white/[0.01] text-zinc-500'
                  }`}
                >
                  <div className="mb-1 flex items-center gap-2">
                    {isPast ? (
                      <CheckCircle2 className="size-3.5 shrink-0 text-emerald-400" />
                    ) : isCurrent ? (
                      <Loader2 className="size-3.5 shrink-0 animate-spin text-sky-400" />
                    ) : (
                      <Icon className="size-3.5 shrink-0 text-zinc-500" />
                    )}
                    <span className="truncate text-[11px] font-semibold">{phase.label}</span>
                  </div>
                  <p className="line-clamp-1 text-[10px] text-muted-foreground">{phase.detail}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
