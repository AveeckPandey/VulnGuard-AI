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

  // SVG circular gauge calculation
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (risk_score.total_score / 100) * circumference;

  return (
    <div className={`p-6 rounded-2xl bg-card border ${styles.border} shadow-xl relative overflow-hidden`}>
      {/* Background glow */}
      <div
        className={`absolute -top-24 -right-24 w-64 h-64 rounded-full opacity-15 blur-3xl pointer-events-none ${styles.bg}`}
      />

      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Left: Score Gauge & Classification */}
        <div className="flex items-center space-x-6">
          <div className="relative flex items-center justify-center shrink-0">
            <svg className="w-32 h-32 transform -rotate-90">
              <circle
                cx="64"
                cy="64"
                r={radius}
                className="text-slate-800"
                strokeWidth="10"
                stroke="currentColor"
                fill="transparent"
              />
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke="currentColor"
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={progressOffset}
                strokeLinecap="round"
                className={`transition-all duration-1000 ease-out ${styles.text}`}
                fill="transparent"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-3xl font-extrabold font-mono text-white tracking-tighter">
                {risk_score.total_score}
              </span>
              <span className="text-[10px] text-slate-400 uppercase font-semibold">/ 100</span>
            </div>
          </div>

          <div>
            <div className="flex items-center space-x-2.5">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Prioritization Tier
              </span>
              <span
                className={`text-xs font-extrabold px-3 py-1 rounded-full border tracking-wide uppercase ${styles.badge}`}
              >
                {risk_score.priority_level} PRIORITY
              </span>
            </div>

            <h2 className="text-2xl font-black text-white mt-1.5 font-mono">
              {cve_id}
            </h2>

            <p className="text-xs text-slate-400 mt-1 max-w-md leading-relaxed">
              {risk_score.summary}
            </p>
          </div>
        </div>

        {/* Right: Meta Details */}
        <div className="w-full md:w-auto flex md:flex-col justify-between items-end gap-2 text-xs text-slate-400 pt-4 md:pt-0 border-t md:border-t-0 border-slate-800/80">
          <div className="flex items-center space-x-1.5 font-mono">
            <Hash className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-300 font-semibold">{id}</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <Clock className="w-3.5 h-3.5 text-sky-400" />
            <span>Triage time: <strong className="text-slate-200">{execution_time_ms} ms</strong></span>
          </div>
          <div className="text-[11px] text-slate-500">
            {formatDate(created_at)}
          </div>
        </div>
      </div>

      {/* Provisional Flag Warning */}
      {risk_score.is_provisional && (
        <div className="mt-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start space-x-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold">Provisional Assessment Notice:</span>
            <ul className="list-disc list-inside mt-1 space-y-0.5 text-amber-200/90">
              {risk_score.provisional_reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Formula Disclaimer */}
      <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
        <div className="flex items-center space-x-1.5">
          <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span>{risk_score.formula_disclaimer}</span>
        </div>
      </div>
    </div>
  );
};
