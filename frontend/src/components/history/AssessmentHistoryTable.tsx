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
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [kevFilter, setKevFilter] = useState<string>('ALL');

  const filtered = history.filter((h) => {
    const matchesSearch =
      h.cve_id.toLowerCase().includes(filter.toLowerCase()) ||
      h.priority_level.toLowerCase().includes(filter.toLowerCase()) ||
      h.id.toLowerCase().includes(filter.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' || h.priority_level === severityFilter;

    const matchesKev =
      kevFilter === 'ALL' ||
      (kevFilter === 'KEV_YES' && h.is_known_exploited) ||
      (kevFilter === 'KEV_NO' && !h.is_known_exploited);

    return matchesSearch && matchesSeverity && matchesKev;
  });

  return (
    <div className="p-6 rounded-2xl bg-card border border-border shadow-xl space-y-4">
      {/* Table Header Controls */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-tight">
              Vulnerability Investigation History
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 border border-slate-700 font-mono">
              {filtered.length} of {history.length}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Historical vulnerability triage records persisted in Amazon DynamoDB
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
          {/* Search Input */}
          <div className="relative flex-1 sm:w-56">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by CVE or ID..."
              className="w-full pl-8 pr-3 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical (≥85)</option>
            <option value="HIGH">High (70–84)</option>
            <option value="MEDIUM">Medium (40–69)</option>
            <option value="LOW">Low (0–39)</option>
          </select>

          {/* KEV Filter */}
          <select
            value={kevFilter}
            onChange={(e) => setKevFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Exploits</option>
            <option value="KEV_YES">Active in KEV</option>
            <option value="KEV_NO">Not in KEV</option>
          </select>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-2 rounded-xl bg-[#0b1120] border border-slate-800 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-all disabled:opacity-50"
            title="Refresh from DynamoDB"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
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
