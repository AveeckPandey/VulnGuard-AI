import React, { useState, useMemo } from 'react';
import {
  History,
  Search,
  ArrowRight,
  Flame,
  CheckCircle,
  RefreshCw,
  ArrowRightLeft,
  ChevronLeft,
  ChevronRight,
  CheckSquare,
  Square,
} from 'lucide-react';
import { AssessmentSummary } from '../../types/assessment';
import { formatDate, formatProbability, getPriorityStyles } from '../../utils/formatters';
import { AssessmentComparisonModal } from './AssessmentComparisonModal';

interface AssessmentHistoryTableProps {
  history: AssessmentSummary[];
  onSelectAssessment: (id: string) => void;
  onRefresh: () => void;
  isLoading: boolean;
  onLoadIntoAnalyzer?: (item: AssessmentSummary) => void;
}

const PAGE_SIZE = 10;

export const AssessmentHistoryTable: React.FC<AssessmentHistoryTableProps> = ({
  history,
  onSelectAssessment,
  onRefresh,
  isLoading,
  onLoadIntoAnalyzer,
}) => {
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [kevFilter, setKevFilter] = useState<string>('ALL');
  const [exposureFilter, setExposureFilter] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [comparisonOpen, setComparisonOpen] = useState<boolean>(false);

  // Filter items based on user criteria
  const filtered = useMemo(() => {
    return history.filter((h) => {
      const matchesSearch =
        h.cve_id.toLowerCase().includes(filter.toLowerCase()) ||
        h.priority_level.toLowerCase().includes(filter.toLowerCase()) ||
        h.id.toLowerCase().includes(filter.toLowerCase());

      const matchesSeverity =
        severityFilter === 'ALL' || h.priority_level === severityFilter;

      const matchesKev =
        kevFilter === 'ALL' ||
        (kevFilter === 'KEV_YES' && h.is_known_exploited) ||
        (kevFilter === 'KEV_NO' && h.is_known_exploited === false);

      const matchesExposure =
        exposureFilter === 'ALL' || h.internet_exposure === exposureFilter;

      return matchesSearch && matchesSeverity && matchesKev && matchesExposure;
    });
  }, [history, filter, severityFilter, kevFilter, exposureFilter]);

  // Reset page when filter changes
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);

  const paginatedItems = useMemo(() => {
    const startIndex = (safePage - 1) * PAGE_SIZE;
    return filtered.slice(startIndex, startIndex + PAGE_SIZE);
  }, [filtered, safePage]);

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((item) => item !== id));
    } else {
      if (selectedIds.length < 2) {
        setSelectedIds([...selectedIds, id]);
      } else {
        // Replace oldest selection
        setSelectedIds([selectedIds[1], id]);
      }
    }
  };

  const selectedAssessments = useMemo(() => {
    return history.filter((h) => selectedIds.includes(h.id));
  }, [history, selectedIds]);

  return (
    <div className="p-6 rounded-2xl bg-card border border-border shadow-xl space-y-4">
      {/* Table Header Controls */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-tight">
              My Assessment Audit History
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 border border-slate-700 font-mono">
              {filtered.length} {filtered.length === 1 ? 'record' : 'records'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Personal triage records persisted in DynamoDB UserHistoryIndex (isolated to your session)
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
          {/* Compare Button if selected */}
          {selectedIds.length === 2 && (
            <button
              onClick={() => setComparisonOpen(true)}
              className="px-3 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-xs shadow-md shadow-cyan-500/20 flex items-center space-x-1.5 transition-all animate-pulse"
            >
              <ArrowRightLeft className="w-3.5 h-3.5" />
              <span>Compare Selected (2)</span>
            </button>
          )}

          {/* Search Input */}
          <div className="relative flex-1 sm:w-52">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Filter by CVE or ID..."
              className="w-full pl-8 pr-3 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
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
            onChange={(e) => {
              setKevFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-2.5 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Exploits</option>
            <option value="KEV_YES">Active in KEV</option>
            <option value="KEV_NO">Not in KEV</option>
          </select>

          {/* Exposure Filter */}
          <select
            value={exposureFilter}
            onChange={(e) => {
              setExposureFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-2.5 py-1.5 bg-[#0b1120] rounded-xl border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Exposure</option>
            <option value="PUBLIC_FACING">Public Facing</option>
            <option value="INTERNAL">Internal</option>
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

      {/* Select instructions helper if 1 selected */}
      {selectedIds.length === 1 && (
        <div className="text-xs text-cyan-400/90 bg-cyan-500/10 border border-cyan-500/20 px-3 py-1.5 rounded-lg flex items-center justify-between">
          <span>Select 1 more assessment using the checkbox to enable side-by-side comparison.</span>
          <button
            onClick={() => setSelectedIds([])}
            className="text-[11px] underline hover:text-white"
          >
            Clear selection
          </button>
        </div>
      )}

      {/* History Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center text-slate-400 text-xs">
          No assessments match your criteria. Analyze a CVE to generate records in your private workspace.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-2 w-8 text-center">Diff</th>
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
              {paginatedItems.map((item) => {
                const styles = getPriorityStyles(item.priority_level);
                const isSelected = selectedIds.includes(item.id);

                return (
                  <tr
                    key={item.id}
                    className={`hover:bg-slate-800/30 transition-colors group cursor-pointer ${
                      isSelected ? 'bg-cyan-500/10' : ''
                    }`}
                    onClick={() => onSelectAssessment(item.id)}
                  >
                    <td className="py-3 px-2 text-center">
                      <button
                        onClick={(e) => toggleSelect(item.id, e)}
                        className="text-slate-400 hover:text-cyan-400"
                        title={isSelected ? 'Deselect for comparison' : 'Select for comparison'}
                      >
                        {isSelected ? (
                          <CheckSquare className="w-4 h-4 text-cyan-400" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-600 group-hover:text-slate-400" />
                        )}
                      </button>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-slate-200 group-hover:text-cyan-300">
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
                      ) : item.is_known_exploited === false ? (
                        <span className="inline-flex items-center space-x-1 text-emerald-400 text-[10px]">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                          <span>Negative</span>
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[10px]">Unknown</span>
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

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-3 border-t border-border text-xs text-slate-400">
          <div>
            Showing {(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length} assessments
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              className="p-1.5 rounded-lg bg-[#0b1120] border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-slate-300">
              Page {safePage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              className="p-1.5 rounded-lg bg-[#0b1120] border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Comparison Modal */}
      {comparisonOpen && selectedAssessments.length === 2 && (
        <AssessmentComparisonModal
          assessmentA={selectedAssessments[0]}
          assessmentB={selectedAssessments[1]}
          onClose={() => setComparisonOpen(false)}
          onSelectForAnalyzer={onLoadIntoAnalyzer}
        />
      )}
    </div>
  );
};
