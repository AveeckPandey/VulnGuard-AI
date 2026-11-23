import React, { useState } from 'react';
import { History, Search, ArrowRight, Flame, CheckCircle, RefreshCw } from 'lucide-react';
import { AssessmentSummary } from '../../types/assessment';
import { formatDate, formatProbability, getPriorityStyles } from '../../utils/formatters';

interface AssessmentHistoryTableProps {
  history: AssessmentSummary[];
  onSelectAssessment: (id: string) => void;
  onRefresh: () => void;
  isLoading: boolean;
}

export const AssessmentHistoryTable: React.FC<AssessmentHistoryTableProps> = ({
  history,
  onSelectAssessment,
  onRefresh,
  isLoading,
}) => {
  const [filter, setFilter] = useState('');

  const filtered = history.filter(
    (h) =>
      h.cve_id.toLowerCase().includes(filter.toLowerCase()) ||
      h.priority_level.toLowerCase().includes(filter.toLowerCase()) ||
      h.id.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="p-6 rounded-2xl bg-card border border-border shadow-xl space-y-4">
      {/* Table Header Controls */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-2">
        <div className="flex items-center space-x-2">
          <History className="w-5 h-5 text-sky-400" />
          <h3 className="text-base font-bold text-white tracking-tight">
            Vulnerability Investigation History
          </h3>
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search CVE or Priority..."
              className="w-full pl-9 pr-3 py-1.5 bg-[#0b1120] rounded-lg border border-slate-800 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-slate-700"
            />
          </div>

          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-2 rounded-lg bg-[#0b1120] border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-all disabled:opacity-50"
            title="Refresh from DynamoDB / SQLite"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* History Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center text-slate-400 text-xs">
          No assessments match your criteria. Analyze a CVE to generate records.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-3">CVE Identifier</th>
                <th className="py-3 px-3">Priority</th>
                <th className="py-3 px-3">Risk Score</th>
                <th className="py-3 px-3">CVSS</th>
                <th className="py-3 px-3">EPSS</th>
                <th className="py-3 px-3">KEV Status</th>
                <th className="py-3 px-3">Criticality / Exposure</th>
                <th className="py-3 px-3">Triage Date</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filtered.map((item) => {
                const styles = getPriorityStyles(item.priority_level);
                return (
                  <tr
                    key={item.id}
                    className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                    onClick={() => onSelectAssessment(item.id)}
                  >
                    <td className="py-3 px-3 font-mono font-bold text-slate-200 group-hover:text-sky-300">
                      {item.cve_id}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full border ${styles.badge}`}>
                        {item.priority_level}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-white">
                      {item.total_score}
                      <span className="text-[10px] text-slate-400 font-normal">/100</span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {item.cvss_base_score !== null ? item.cvss_base_score.toFixed(1) : 'N/A'}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {formatProbability(item.epss_probability)}
                    </td>
                    <td className="py-3 px-3">
                      {item.is_known_exploited ? (
                        <span className="inline-flex items-center space-x-1 text-red-400 font-bold text-[10px]">
                          <Flame className="w-3.5 h-3.5 text-red-500" />
                          <span>Active</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 text-emerald-400 text-[10px]">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                          <span>Negative</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      <span className="font-semibold text-slate-300">{item.asset_criticality}</span>
                      <span className="text-slate-400 mx-1">/</span>
                      <span className="text-[11px]">{item.internet_exposure}</span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                      {formatDate(item.created_at)}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAssessment(item.id);
                        }}
                        className="p-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 transition-all"
                        title="Inspect Assessment"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
