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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0e172a] border border-slate-700/80 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              <ArrowRightLeft className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Assessment Comparison Matrix
              </h3>
              <p className="text-xs text-slate-400">
                Side-by-side telemetry differential between two vulnerability assessments
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Delta Summary Pill */}
          <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-400">Risk Score Differential:</span>
            <span className="font-mono font-bold text-slate-200">
              {scoreDiff === 0 ? (
                'Identical Risk Scores (0 pt delta)'
              ) : scoreDiff > 0 ? (
                <span className="text-red-400">{assessmentA.cve_id} is +{scoreDiff} pts higher risk</span>
              ) : (
                <span className="text-red-400">{assessmentB.cve_id} is +{Math.abs(scoreDiff)} pts higher risk</span>
              )}
            </span>
          </div>

          {/* Grid Side-by-Side Comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Assessment A Column */}
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Assessment A</span>
                  <h4 className="text-base font-mono font-bold text-cyan-300">{assessmentA.cve_id}</h4>
                </div>
                <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${stylesA.badge}`}>
                  {assessmentA.priority_level}
                </span>
              </div>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Deterministic Total Score:</span>
                  <span className="font-mono font-bold text-white text-sm">{assessmentA.total_score} / 100</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">CVSS v3.1 Base Score:</span>
                  <span className="font-mono text-slate-200">
                    {assessmentA.cvss_base_score !== null ? assessmentA.cvss_base_score.toFixed(1) : 'N/A'}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">EPSS Exploit Likelihood:</span>
                  <span className="font-mono text-slate-200">
                    {formatProbability(assessmentA.epss_probability)}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">CISA KEV Catalog:</span>
                  <span>
                    {assessmentA.is_known_exploited ? (
                      <span className="text-red-400 font-bold flex items-center space-x-1">
                        <Flame className="w-3.5 h-3.5" />
                        <span>Active Weaponization</span>
                      </span>
                    ) : (
                      <span className="text-emerald-400 flex items-center space-x-1">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Not in KEV</span>
                      </span>
                    )}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Asset Criticality:</span>
                  <span className="font-semibold text-slate-200">{assessmentA.asset_criticality}</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Perimeter Exposure:</span>
                  <span className="font-semibold text-slate-200">{assessmentA.internet_exposure}</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Triage Date:</span>
                  <span className="text-slate-400">{formatDate(assessmentA.created_at)}</span>
                </div>

                <div className="flex justify-between py-1.5">
                  <span className="text-slate-400">Assessment ID:</span>
                  <span className="font-mono text-[10px] text-slate-500 truncate max-w-[150px]">
                    {assessmentA.id}
                  </span>
                </div>
              </div>

              {onSelectForAnalyzer && (
                <button
                  onClick={() => onSelectForAnalyzer(assessmentA)}
                  className="w-full mt-2 py-2 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-400 font-medium text-xs transition-all flex items-center justify-center space-x-1.5"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Load {assessmentA.cve_id} into Analyzer</span>
                </button>
              )}
            </div>

            {/* Assessment B Column */}
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Assessment B</span>
                  <h4 className="text-base font-mono font-bold text-cyan-300">{assessmentB.cve_id}</h4>
                </div>
                <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${stylesB.badge}`}>
                  {assessmentB.priority_level}
                </span>
              </div>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Deterministic Total Score:</span>
                  <span className="font-mono font-bold text-white text-sm">{assessmentB.total_score} / 100</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">CVSS v3.1 Base Score:</span>
                  <span className="font-mono text-slate-200">
                    {assessmentB.cvss_base_score !== null ? assessmentB.cvss_base_score.toFixed(1) : 'N/A'}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">EPSS Exploit Likelihood:</span>
                  <span className="font-mono text-slate-200">
                    {formatProbability(assessmentB.epss_probability)}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">CISA KEV Catalog:</span>
                  <span>
                    {assessmentB.is_known_exploited ? (
                      <span className="text-red-400 font-bold flex items-center space-x-1">
                        <Flame className="w-3.5 h-3.5" />
                        <span>Active Weaponization</span>
                      </span>
                    ) : (
                      <span className="text-emerald-400 flex items-center space-x-1">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Not in KEV</span>
                      </span>
                    )}
                  </span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Asset Criticality:</span>
                  <span className="font-semibold text-slate-200">{assessmentB.asset_criticality}</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Perimeter Exposure:</span>
                  <span className="font-semibold text-slate-200">{assessmentB.internet_exposure}</span>
                </div>

                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Triage Date:</span>
                  <span className="text-slate-400">{formatDate(assessmentB.created_at)}</span>
                </div>

                <div className="flex justify-between py-1.5">
                  <span className="text-slate-400">Assessment ID:</span>
                  <span className="font-mono text-[10px] text-slate-500 truncate max-w-[150px]">
                    {assessmentB.id}
                  </span>
                </div>
              </div>

              {onSelectForAnalyzer && (
                <button
                  onClick={() => onSelectForAnalyzer(assessmentB)}
                  className="w-full mt-2 py-2 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-400 font-medium text-xs transition-all flex items-center justify-center space-x-1.5"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Load {assessmentB.cve_id} into Analyzer</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-all"
          >
            Close Matrix
          </button>
        </div>
      </div>
    </div>
  );
};
