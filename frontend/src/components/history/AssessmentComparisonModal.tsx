import React from 'react';
import { X, ArrowRightLeft, Flame, CheckCircle, Cpu } from 'lucide-react';
import { AssessmentSummary } from '../../types/assessment';
import { formatDate, formatProbability, getPriorityStyles } from '../../utils/formatters';

interface AssessmentComparisonModalProps {
  assessmentA: AssessmentSummary;
  assessmentB: AssessmentSummary;
  onClose: () => void;
  onSelectForAnalyzer?: (item: AssessmentSummary) => void;
}

export const AssessmentComparisonModal: React.FC<AssessmentComparisonModalProps> = ({
  assessmentA,
  assessmentB,
  onClose,
  onSelectForAnalyzer,
}) => {
  const stylesA = getPriorityStyles(assessmentA.priority_level);
  const stylesB = getPriorityStyles(assessmentB.priority_level);

  const scoreDiff = assessmentA.total_score - assessmentB.total_score;

  const renderColumn = (
    label: string,
    item: AssessmentSummary,
    styles: ReturnType<typeof getPriorityStyles>
  ) => (
    <div className="surface-subpanel space-y-4 rounded-xl p-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div>
          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
          <h4 className="font-mono text-base font-semibold text-foreground">{item.cve_id}</h4>
        </div>
        <span className={`rounded-md border px-2.5 py-0.5 text-[11px] font-semibold ${styles.badge}`}>
          {item.priority_level}
        </span>
      </div>

      <div className="space-y-2.5 text-xs">
        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">Deterministic Total Score:</span>
          <span className="font-mono text-sm font-semibold text-foreground">{item.total_score} / 100</span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">CVSS v3.1 Base Score:</span>
          <span className="font-mono text-zinc-200">
            {item.cvss_base_score !== null ? item.cvss_base_score.toFixed(1) : 'N/A'}
          </span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">EPSS Exploit Likelihood:</span>
          <span className="font-mono text-zinc-200">
            {formatProbability(item.epss_probability)}
          </span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">CISA KEV Catalog:</span>
          <span>
            {item.is_known_exploited ? (
              <span className="flex items-center gap-1 font-semibold text-red-400">
                <Flame className="size-3.5" />
                <span>Active Weaponization</span>
              </span>
            ) : (
              <span className="flex items-center gap-1 text-emerald-400">
                <CheckCircle className="size-3.5" />
                <span>Not in KEV</span>
              </span>
            )}
          </span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">Asset Criticality:</span>
          <span className="font-medium text-zinc-200">{item.asset_criticality}</span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">Perimeter Exposure:</span>
          <span className="font-medium text-zinc-200">{item.internet_exposure}</span>
        </div>

        <div className="flex justify-between border-b border-border py-1.5">
          <span className="text-muted-foreground">Triage Date:</span>
          <span className="text-zinc-400">{formatDate(item.created_at)}</span>
        </div>

        <div className="flex justify-between py-1.5">
          <span className="text-muted-foreground">Assessment ID:</span>
          <span className="max-w-[150px] truncate font-mono text-[10px] text-zinc-500">
            {item.id}
          </span>
        </div>
      </div>

      {onSelectForAnalyzer && (
        <button
          type="button"
          onClick={() => onSelectForAnalyzer(item)}
          className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg border border-border bg-white/[0.04] py-2 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08]"
        >
          <Cpu className="size-3.5" />
          <span>Load {item.cve_id} into Analyzer</span>
        </button>
      )}
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm sm:p-6">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-border bg-card shadow-2xl">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border bg-background/60 p-5">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-sky-400">
              <ArrowRightLeft className="size-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-foreground">
                Assessment Comparison Matrix
              </h3>
              <p className="text-xs text-muted-foreground">
                Side-by-side telemetry differential between two vulnerability assessments
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 space-y-5 overflow-y-auto p-6">
          <div className="surface-subpanel flex items-center justify-between rounded-xl px-4 py-3 text-xs">
            <span className="text-muted-foreground">Risk Score Differential:</span>
            <span className="font-mono font-semibold text-foreground">
              {scoreDiff === 0 ? (
                'Identical Risk Scores (0 pt delta)'
              ) : scoreDiff > 0 ? (
                <span className="text-red-400">{assessmentA.cve_id} is +{scoreDiff} pts higher risk</span>
              ) : (
                <span className="text-red-400">{assessmentB.cve_id} is +{Math.abs(scoreDiff)} pts higher risk</span>
              )}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {renderColumn('Assessment A', assessmentA, stylesA)}
            {renderColumn('Assessment B', assessmentB, stylesB)}
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end border-t border-border bg-background/60 p-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-border bg-white/[0.04] px-4 py-2 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08]"
          >
            Close Matrix
          </button>
        </div>
      </div>
    </div>
  );
};
