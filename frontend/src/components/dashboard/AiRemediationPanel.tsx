import React from 'react';
import { Sparkles, ShieldCheck, Wrench, Cpu, CheckSquare } from 'lucide-react';
import { AiRemediation } from '../../types/assessment';

interface AiRemediationPanelProps {
  remediation: AiRemediation;
  cveId: string;
}

export const AiRemediationPanel: React.FC<AiRemediationPanelProps> = ({
  remediation,
}) => {
  return (
    <div className="p-6 rounded-2xl bg-card border border-border shadow-xl space-y-6">
      {/* Header & Model Used Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 text-white shadow-md shadow-sky-500/20">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-tight">
              AI-Assisted Remediation & Threat Analysis
            </h3>
            <p className="text-xs text-slate-400">
              Evidence-grounded vulnerability response recommendations
            </p>
          </div>
        </div>

        {/* Model Indicator Badge */}
        <div className="flex items-center space-x-2 text-xs">
          <span className="text-slate-400">Inference Engine:</span>
          {remediation.is_fallback_deterministic ? (
            <span className="px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30 font-mono text-[11px] flex items-center space-x-1.5">
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              <span>Rule-Based Remediation — AI Unavailable</span>
            </span>
          ) : remediation.model_used && remediation.model_used.toLowerCase().includes('nemotron') ? (
            <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono text-[11px] flex items-center space-x-1.5 shadow-sm shadow-emerald-500/20">
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold">Powered by NVIDIA Nemotron</span>
              <span className="text-emerald-500/80 hidden sm:inline">({remediation.model_used})</span>
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/30 font-mono text-[11px] flex items-center space-x-1.5">
              <Cpu className="w-3.5 h-3.5 text-sky-400" />
              <span>Amazon Bedrock ({remediation.model_used})</span>
            </span>
          )}
        </div>
      </div>

      {/* 1. Executive Summary */}
      <div className="p-4 rounded-xl bg-sky-500/5 border border-sky-500/20 text-slate-200">
        <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 mb-1 flex items-center space-x-1.5">
          <ShieldCheck className="w-4 h-4" />
          <span>Executive Summary (CISO & Leadership)</span>
        </h4>
        <p className="text-xs sm:text-sm leading-relaxed text-slate-300">
          {remediation.executive_summary}
        </p>
      </div>

      {/* 2-Column: Technical Impact & Exploitation Assessment */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Technical Impact */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
            Technical Vulnerability Mechanism
          </h4>
          <p className="text-xs leading-relaxed text-slate-400">
            {remediation.technical_impact}
          </p>
        </div>

        {/* Exploitation Assessment */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
            Threat & In-The-Wild Exploitation
          </h4>
          <p className="text-xs leading-relaxed text-slate-400">
            {remediation.exploitation_assessment}
          </p>
        </div>
      </div>

      {/* 3. Actionable Remediation Steps */}
      <div>
        <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-3 flex items-center space-x-2">
          <CheckSquare className="w-4 h-4" />
          <span>Prioritized Remediation Roadmap</span>
        </h4>
        <div className="space-y-2">
          {remediation.remediation_steps.map((step, idx) => (
            <div
              key={idx}
              className="p-3 rounded-xl bg-[#0b1120] border border-slate-800 flex items-start space-x-3 text-xs text-slate-300"
            >
              <span className="w-5 h-5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center font-mono font-bold shrink-0 mt-0.5">
                {idx + 1}
              </span>
              <p className="leading-relaxed">{step}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Mitigation Workarounds */}
      <div>
        <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-3 flex items-center space-x-2">
          <Wrench className="w-4 h-4" />
          <span>Compensating Controls & Workarounds</span>
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {remediation.mitigation_workarounds.map((mit, idx) => (
            <div
              key={idx}
              className="p-3 rounded-xl bg-[#0b1120] border border-slate-800 text-xs text-slate-400 leading-relaxed"
            >
              <span className="text-amber-400 font-bold mr-1.5">•</span>
              {mit}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
