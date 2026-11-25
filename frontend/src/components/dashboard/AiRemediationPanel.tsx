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
    <div className="surface-panel space-y-5 rounded-2xl p-6">
      {/* Header & Model Used Badge */}
      <div className="flex flex-col justify-between gap-3 border-b border-border pb-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-foreground">
            <Sparkles className="size-4 text-sky-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold tracking-tight text-foreground">
              AI-Assisted Remediation & Threat Analysis
            </h3>
            <p className="text-xs text-muted-foreground">
              Evidence-grounded vulnerability response recommendations
            </p>
          </div>
        </div>

        {/* Mode Indicator Badge */}
        <div className="flex items-center gap-2 text-xs">
          {remediation.is_fallback_deterministic ? (
            <span className="flex items-center gap-1.5 rounded-md border border-amber-500/25 bg-amber-500/10 px-2.5 py-1 font-mono text-[11px] text-amber-400">
              <Cpu className="size-3.5 text-amber-400" />
              <span>Rule-Based Remediation (Fallback)</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1 font-mono text-[11px] text-emerald-400">
              <Sparkles className="size-3.5 text-emerald-400" />
              <span className="font-semibold">AI-Generated Guidance</span>
            </span>
          )}
        </div>
      </div>

      {/* 1. Executive Summary */}
      <div className="rounded-xl border border-white/[0.1] bg-white/[0.03] p-4">
        <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-foreground">
          <ShieldCheck className="size-4 text-sky-400" />
          <span>Executive Summary (CISO & Leadership)</span>
        </h4>
        <p className="text-sm leading-relaxed text-zinc-200">
          {remediation.executive_summary}
        </p>
      </div>

      {/* 2-Column: Technical Impact & Exploitation Assessment */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="surface-subpanel rounded-xl p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-200">
            Technical Vulnerability Mechanism
          </h4>
          <p className="text-[13.5px] leading-relaxed text-zinc-300">
            {remediation.technical_impact}
          </p>
        </div>

        <div className="surface-subpanel rounded-xl p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-200">
            Threat & In-The-Wild Exploitation
          </h4>
          <p className="text-[13.5px] leading-relaxed text-zinc-300">
            {remediation.exploitation_assessment}
          </p>
        </div>
      </div>

      {/* 3. Actionable Remediation Steps */}
      <div>
        <h4 className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400">
          <CheckSquare className="size-4" />
          <span>Prioritized Remediation Roadmap</span>
        </h4>
        <div className="space-y-2.5">
          {remediation.remediation_steps.map((step, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 rounded-xl border border-border bg-background p-3.5 text-[13.5px] text-zinc-200"
            >
              <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-md border border-emerald-500/30 bg-emerald-500/15 font-mono text-xs font-semibold text-emerald-300">
                {idx + 1}
              </span>
              <p className="leading-relaxed">{step}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Mitigation Workarounds */}
      <div>
        <h4 className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-amber-400">
          <Wrench className="size-4" />
          <span>Compensating Controls & Workarounds</span>
        </h4>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
          {remediation.mitigation_workarounds.map((mit, idx) => (
            <div
              key={idx}
              className="rounded-xl border border-border bg-background p-3.5 text-[13.5px] leading-relaxed text-zinc-300"
            >
              <span className="mr-1.5 font-bold text-amber-400">•</span>
              {mit}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
