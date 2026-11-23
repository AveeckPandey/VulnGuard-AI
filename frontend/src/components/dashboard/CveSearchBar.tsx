import React, { useState } from 'react';
import { Search, Loader2, Globe, Server, AlertCircle, Sparkles } from 'lucide-react';
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

const CVE_REGEX = /^CVE-\d{4}-\d{4,8}$/i;

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
    <div className="p-5 rounded-2xl bg-card border border-border shadow-lg">
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
                placeholder="e.g. CVE-2021-44228, CVE-2023-38606..."
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
                  <span>Executing LangGraph...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-sky-200" />
                  <span>Analyze & Prioritize</span>
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

        {/* Bottom Row: Environmental Context Controls */}
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
    </div>
  );
};
