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
  { id: 3, label: 'AI Remediation Engine', detail: 'NVIDIA Nemotron synthesis with guardrails', icon: Cpu },
  { id: 4, label: 'Workspace Persistence', detail: 'Storing in DynamoDB UserHistoryIndex', icon: Database },
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

  // Animate the pipeline execution phase when loading
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
    <div className="p-5 rounded-2xl bg-card border border-border shadow-lg space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Top Row: Search Input & Action Button */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Target Vulnerability Identifier
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Search className="w-5 h-5 text-slate-400" />
              </div>
              <input
                type="text"
                value={selectedCve}
                onChange={(e) => {
                  setSelectedCve(e.target.value.toUpperCase());
                  if (validationError) setValidationError(null);
                }}
                placeholder="e.g. CVE-2021-44228, CVE-2024-3094..."
                className={`w-full pl-11 pr-4 py-3 bg-[#0b1120] rounded-xl border text-slate-100 font-mono text-sm placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 transition-all ${
                  validationError ? 'border-red-500/60 ring-1 ring-red-500/50' : 'border-slate-700/80'
                }`}
                disabled={isLoading}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-sm shadow-md shadow-sky-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2 shrink-0 transition-all active:scale-[0.98]"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Executing LangGraph Pipeline...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-cyan-200" />
                  <span>Analyze Vulnerability</span>
                </>
              )}
            </button>
          </div>

          {validationError && (
            <div className="flex items-center space-x-1.5 text-xs text-red-400 mt-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{validationError}</span>
            </div>
          )}
        </div>

        {/* Environmental Context Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80">
          {/* Asset Criticality */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5">
              Asset Business Criticality (Weight: 10%)
            </label>
            <div className="grid grid-cols-4 gap-1 p-1 bg-[#0b1120] rounded-lg border border-slate-800">
              {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as AssetCriticality[]).map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setCriticality(level)}
                  className={`py-1.5 text-xs font-bold rounded transition-all ${
                    criticality === level
                      ? level === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : level === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                        : level === 'MEDIUM'
                        ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>

          {/* Internet Exposure */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5">
              Network Perimeter Exposure (Weight: 10%)
            </label>
            <div className="grid grid-cols-2 gap-1 p-1 bg-[#0b1120] rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() => setExposure('INTERNAL')}
                className={`py-1.5 px-2 text-xs font-bold rounded flex items-center justify-center space-x-1.5 transition-all ${
                  exposure === 'INTERNAL'
                    ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>Internal / Isolated</span>
              </button>
              <button
                type="button"
                onClick={() => setExposure('PUBLIC_FACING')}
                className={`py-1.5 px-2 text-xs font-bold rounded flex items-center justify-center space-x-1.5 transition-all ${
                  exposure === 'PUBLIC_FACING'
                    ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Public Facing</span>
              </button>
            </div>
          </div>

          {/* System Context Notes */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5">
              Deployment / System Context (Optional)
            </label>
            <input
              type="text"
              value={systemContext}
              onChange={(e) => setSystemContext(e.target.value)}
              placeholder="e.g. Core Payment Auth Gateway"
              className="w-full px-3 py-1.5 bg-[#0b1120] rounded-lg border border-slate-800 text-slate-200 text-xs placeholder:text-slate-500 focus:outline-none focus:border-slate-600"
            />
          </div>
        </div>
      </form>

      {/* 4-Phase LangGraph Pipeline Execution Stepper when Loading */}
      {isLoading && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30 space-y-3 animate-in fade-in duration-200">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-cyan-300 flex items-center space-x-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              <span>LangGraph Execution in Progress: Phase {activePhaseIndex + 1} of 4</span>
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              {EXECUTION_PHASES[activePhaseIndex].label}
            </span>
          </div>

          {/* Stepper Dots & Bars */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {EXECUTION_PHASES.map((phase, idx) => {
              const Icon = phase.icon;
              const isPast = idx < activePhaseIndex;
              const isCurrent = idx === activePhaseIndex;

              return (
                <div
                  key={phase.id}
                  className={`p-2.5 rounded-lg border text-xs transition-all ${
                    isCurrent
                      ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200 shadow-sm shadow-cyan-500/10'
                      : isPast
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                      : 'bg-slate-800/40 border-slate-800 text-slate-500'
                  }`}
                >
                  <div className="flex items-center space-x-2 mb-1">
                    {isPast ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400 shrink-0" />
                    ) : (
                      <Icon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    )}
                    <span className="font-bold text-[11px] truncate">{phase.label}</span>
                  </div>
                  <p className="text-[10px] text-slate-400 line-clamp-1">{phase.detail}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
