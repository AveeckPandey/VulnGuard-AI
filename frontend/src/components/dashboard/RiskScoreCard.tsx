import React from 'react';
import { AlertTriangle, Clock, Hash, Info } from 'lucide-react';
import { AssessmentResponse } from '../../types/assessment';
import { getPriorityStyles, formatDate } from '../../utils/formatters';

interface RiskScoreCardProps {
  assessment: AssessmentResponse;
}

export const RiskScoreCard: React.FC<RiskScoreCardProps> = ({ assessment }) => {
  const { risk_score, id, execution_time_ms, created_at, cve_id } = assessment;
  const styles = getPriorityStyles(risk_score.priority_level);

  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (risk_score.total_score / 100) * circumference;

  return (
    <div className={`surface-panel rounded-2xl p-6 ${styles.border}`}>
      <div className="flex flex-col items-center justify-between gap-6 md:flex-row">
        {/* Left: Score Gauge & Classification */}
        <div className="flex flex-col items-center gap-5 sm:flex-row">
          <div className="relative flex shrink-0 items-center justify-center">
            <svg className="size-32 -rotate-90 transform">
              <circle
                cx="64"
                cy="64"
                r={radius}
                className="text-white/[0.07]"
                strokeWidth="8"
                stroke="currentColor"
                fill="transparent"
              />
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={progressOffset}
                strokeLinecap="round"
                className={`transition-all duration-1000 ease-out ${styles.text}`}
                fill="transparent"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="font-mono text-3xl font-semibold tracking-tight text-foreground tabular-nums">
                {risk_score.total_score}
              </span>
              <span className="text-[10px] font-medium uppercase text-muted-foreground">/ 100</span>
            </div>
          </div>

          <div className="text-center sm:text-left">
            <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Prioritization Tier
              </span>
              <span
                className={`rounded-md border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${styles.badge}`}
              >
                {risk_score.priority_level} PRIORITY
              </span>
            </div>

            <h2 className="mt-1.5 font-mono text-2xl font-semibold tracking-tight text-foreground">
              {cve_id}
            </h2>

            <p className="mt-1.5 max-w-lg text-[13.5px] leading-relaxed text-zinc-300">
              {risk_score.summary}
            </p>
          </div>
        </div>

        {/* Right: Meta Details */}
        <div className="flex w-full justify-between gap-2 border-t border-border pt-4 text-[13px] text-zinc-300 md:w-auto md:flex-col md:items-end md:border-t-0 md:pt-0">
          <div className="flex items-center gap-1.5 font-mono">
            <Hash className="size-3.5 text-zinc-400" />
            <span className="font-medium text-zinc-200">{id}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="size-3.5 text-zinc-400" />
            <span>
              Triage time: <strong className="font-mono text-foreground">{execution_time_ms} ms</strong>
            </span>
          </div>
          <div className="text-xs text-muted-foreground">{formatDate(created_at)}</div>
        </div>
      </div>

      {/* Provisional Flag Warning */}
      {risk_score.is_provisional && (
        <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-[13px] text-amber-200">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-400" />
          <div>
            <span className="font-semibold">Provisional Assessment Notice:</span>
            <ul className="mt-1 list-inside list-disc space-y-0.5 text-amber-200/90">
              {risk_score.provisional_reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Formula Disclaimer */}
      <div className="mt-4 flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <Info className="size-3.5 shrink-0 text-zinc-400" />
          <span>{risk_score.formula_disclaimer}</span>
        </div>
      </div>
    </div>
  );
};
