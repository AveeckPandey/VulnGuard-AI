import React from 'react';
import {
  X,
  Calendar,
  Database,
  ArrowLeft,
  ExternalLink,
} from 'lucide-react';
import { AssessmentResponse } from '../../types/assessment';
import { RiskScoreCard } from '../dashboard/RiskScoreCard';
import { ThreatIntelCards } from '../dashboard/ThreatIntelCards';
import { FactorBreakdownChart } from '../dashboard/FactorBreakdownChart';
import { AiRemediationPanel } from '../dashboard/AiRemediationPanel';
import { EvidenceCitations } from '../dashboard/EvidenceCitations';
import { formatUtcTimestamp } from '../../utils/formatters';

interface AssessmentDetailModalProps {
  assessment: AssessmentResponse | null;
  onClose: () => void;
  onLoadIntoAnalyzer: (assessment: AssessmentResponse) => void;
}

export const AssessmentDetailModal: React.FC<AssessmentDetailModalProps> = ({
  assessment,
  onClose,
  onLoadIntoAnalyzer,
}) => {
  if (!assessment) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/75 p-3 backdrop-blur-sm sm:p-6">
      <div className="flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-border bg-background shadow-2xl">
        {/* Header Bar */}
        <div className="flex items-center justify-between border-b border-border bg-card p-4 sm:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border bg-white/[0.03] p-2 text-muted-foreground transition-colors hover:bg-white/[0.07] hover:text-foreground"
              title="Return"
            >
              <ArrowLeft className="size-4" />
            </button>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-base font-semibold text-foreground">
                  {assessment.cve_id}
                </span>
                <span className="rounded-md border border-border bg-white/[0.04] px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
                  {assessment.id}
                </span>
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Calendar className="size-3.5 text-zinc-500" />
                  <span>{formatUtcTimestamp(assessment.created_at)}</span>
                </span>
                <span className="flex items-center gap-1 text-emerald-400">
                  <Database className="size-3.5" />
                  <span>Saved Assessment</span>
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onLoadIntoAnalyzer(assessment)}
              className="hidden items-center gap-1.5 rounded-lg border border-border bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08] sm:flex"
            >
              <span>Load in Analyzer</span>
              <ExternalLink className="size-3.5" />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border bg-white/[0.03] p-2 text-muted-foreground transition-colors hover:bg-white/[0.07] hover:text-foreground"
            >
              <X className="size-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 space-y-5 overflow-y-auto p-4 sm:p-6">
          {/* Target Environment Context Header */}
          <div className="surface-panel grid grid-cols-1 gap-3 rounded-2xl p-4 text-xs sm:grid-cols-3">
            <div>
              <span className="block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Target System Context
              </span>
              <span className="mt-0.5 block truncate font-medium text-foreground">
                {assessment.system_context || 'Standard Corporate Infrastructure'}
              </span>
            </div>
            <div>
              <span className="block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Asset Criticality Tier
              </span>
              <span className="mt-0.5 block font-mono font-semibold text-foreground">
                {assessment.asset_criticality} (Weight: 10%)
              </span>
            </div>
            <div>
              <span className="block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Network Exposure
              </span>
              <span className="mt-0.5 block font-mono font-semibold text-foreground">
                {assessment.internet_exposure} (Weight: 10%)
              </span>
            </div>
          </div>

          <RiskScoreCard assessment={assessment} />
          <ThreatIntelCards intel={assessment.intelligence} />
          <FactorBreakdownChart
            components={assessment.risk_score.components}
            totalScore={assessment.risk_score.total_score}
          />
          <AiRemediationPanel
            remediation={assessment.remediation}
            cveId={assessment.cve_id}
          />
          <EvidenceCitations citations={assessment.remediation.evidence_citations} />
        </div>
      </div>
    </div>
  );
};
