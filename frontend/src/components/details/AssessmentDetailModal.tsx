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
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-6 animate-in fade-in duration-200">
      <div className="bg-[#080d19] border border-slate-800 rounded-3xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl shadow-cyan-500/10 overflow-hidden">
        {/* Header Bar */}
        <div className="p-4 sm:p-6 border-b border-slate-800 flex items-center justify-between bg-card/80">
          <div className="flex items-center space-x-3">
            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
              title="Return"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-extrabold text-white font-mono">
                  {assessment.cve_id}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono">
                  {assessment.id}
                </span>
              </div>
              <div className="flex items-center space-x-3 text-xs text-slate-400 mt-0.5">
                <span className="flex items-center space-x-1">
                  <Calendar className="w-3.5 h-3.5 text-slate-500" />
                  <span>{formatUtcTimestamp(assessment.created_at)}</span>
                </span>
                <span className="flex items-center space-x-1 text-emerald-400">
                  <Database className="w-3.5 h-3.5" />
                  <span>Persisted in Amazon DynamoDB</span>
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onLoadIntoAnalyzer(assessment)}
              className="px-3 py-1.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 text-xs font-semibold transition-all hidden sm:flex items-center space-x-1.5"
            >
              <span>Load in Analyzer</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          {/* Target Environment Context Header */}
          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block">Target System Context</span>
              <span className="text-slate-200 font-medium mt-0.5 block truncate">
                {assessment.system_context || 'Standard Corporate Infrastructure'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block">Asset Criticality Tier</span>
              <span className="text-cyan-400 font-mono font-bold mt-0.5 block">
                {assessment.asset_criticality} (Weight: 10%)
              </span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block">Network Exposure</span>
              <span className="text-slate-200 font-mono font-bold mt-0.5 block">
                {assessment.internet_exposure} (Weight: 10%)
              </span>
            </div>
          </div>

          {/* Risk Score Summary Banner */}
          <RiskScoreCard assessment={assessment} />

          {/* 3 Real Threat Intel Cards (NVD, EPSS, CISA KEV) */}
          <ThreatIntelCards intel={assessment.intelligence} />

          {/* Factor Breakdown Chart */}
          <FactorBreakdownChart
            components={assessment.risk_score.components}
            totalScore={assessment.risk_score.total_score}
          />

          {/* NVIDIA AI Remediation Panel */}
          <AiRemediationPanel
            remediation={assessment.remediation}
            cveId={assessment.cve_id}
          />

          {/* Citations */}
          <EvidenceCitations
            citations={assessment.remediation.evidence_citations}
          />
        </div>
      </div>
    </div>
  );
};
