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
  FolderPlus,
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
  onMoveToWorkspace?: (id: string) => void;
}

const PAGE_SIZE = 10;

export const AssessmentHistoryTable: React.FC<AssessmentHistoryTableProps> = ({
  history,
  onSelectAssessment,
  onRefresh,
  isLoading,
  onLoadIntoAnalyzer,
  onMoveToWorkspace,
}) => {
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [kevFilter, setKevFilter] = useState<string>('ALL');
  const [exposureFilter, setExposureFilter] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [comparisonOpen, setComparisonOpen] = useState<boolean>(false);

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
        setSelectedIds([selectedIds[1], id]);
      }
    }
  };

  const selectedAssessments = useMemo(() => {
    return history.filter((h) => selectedIds.includes(h.id));
  }, [history, selectedIds]);

  return (
    <div className="surface-panel space-y-4 rounded-2xl p-6">
      {/* Table Header Controls */}
      <div className="flex flex-col items-start justify-between gap-3 border-b border-border pb-4 lg:flex-row lg:items-center">
        <div>
          <div className="flex items-center gap-2">
            <History className="size-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold tracking-tight text-foreground">
              Assessment Audit History
            </h3>
            <span className="rounded-md bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground tabular-nums">
              {filtered.length} {filtered.length === 1 ? 'record' : 'records'}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Standalone triage audit log · Assessments assigned to My Workspace are excluded
          </p>
        </div>

        <div className="flex w-full flex-wrap items-center gap-2 lg:w-auto">
          {selectedIds.length === 2 && (
            <button
              type="button"
              onClick={() => setComparisonOpen(true)}
              className="flex h-8 items-center gap-1.5 rounded-lg bg-primary px-3 text-xs font-semibold text-primary-foreground transition-opacity hover:opacity-90"
            >
              <ArrowRightLeft className="size-3.5" />
              <span>Compare Selected (2)</span>
            </button>
          )}

          <div className="relative flex-1 sm:w-52">
            <Search className="pointer-events-none absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
            <input
              type="text"
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Filter by CVE or ID..."
              className="h-8 w-full rounded-lg border border-border bg-background pl-8 pr-3 text-xs text-foreground placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-8 rounded-lg border border-border bg-background px-2.5 text-xs text-zinc-300 focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical (≥85)</option>
            <option value="HIGH">High (70–84)</option>
            <option value="MEDIUM">Medium (40–69)</option>
            <option value="LOW">Low (0–39)</option>
          </select>

          <select
            value={kevFilter}
            onChange={(e) => {
              setKevFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-8 rounded-lg border border-border bg-background px-2.5 text-xs text-zinc-300 focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="ALL">All Exploits</option>
            <option value="KEV_YES">Active in KEV</option>
            <option value="KEV_NO">Not in KEV</option>
          </select>

          <select
            value={exposureFilter}
            onChange={(e) => {
              setExposureFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-8 rounded-lg border border-border bg-background px-2.5 text-xs text-zinc-300 focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="ALL">All Exposure</option>
            <option value="PUBLIC_FACING">Public Facing</option>
            <option value="INTERNAL">Internal</option>
          </select>

          <button
            type="button"
            onClick={onRefresh}
            disabled={isLoading}
            className="flex size-8 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground disabled:opacity-50"
            title="Refresh assessment history"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? 'animate-spin text-foreground' : ''}`} />
          </button>
        </div>
      </div>

      {selectedIds.length === 1 && (
        <div className="flex items-center justify-between rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 py-2 text-xs text-zinc-300">
          <span>Select 1 more assessment using the checkbox to enable side-by-side comparison.</span>
          <button
            type="button"
            onClick={() => setSelectedIds([])}
            className="text-[11px] text-muted-foreground underline hover:text-foreground"
          >
            Clear selection
          </button>
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="py-12 text-center text-xs text-muted-foreground">
          No assessments match your criteria. Analyze a CVE to generate records in your private workspace.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-[13px]">
            <thead>
              <tr className="border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <th className="w-8 px-2 py-3 text-center">Diff</th>
                <th className="px-3 py-3">CVE Identifier</th>
                <th className="px-3 py-3">Priority</th>
                <th className="px-3 py-3">Risk Score</th>
                <th className="px-3 py-3">CVSS</th>
                <th className="px-3 py-3">EPSS</th>
                <th className="px-3 py-3">KEV Status</th>
                <th className="px-3 py-3">Criticality / Exposure</th>
                <th className="px-3 py-3">Triage Date</th>
                <th className="px-3 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.07] font-sans">
              {paginatedItems.map((item) => {
                const styles = getPriorityStyles(item.priority_level);
                const isSelected = selectedIds.includes(item.id);

                return (
                  <tr
                    key={item.id}
                    className={`group cursor-pointer transition-colors hover:bg-white/[0.04] ${
                      isSelected ? 'bg-white/[0.06]' : ''
                    }`}
                    onClick={() => onSelectAssessment(item.id)}
                  >
                    <td className="px-2 py-3.5 text-center">
                      <button
                        type="button"
                        onClick={(e) => toggleSelect(item.id, e)}
                        className="text-muted-foreground hover:text-foreground"
                        title={isSelected ? 'Deselect for comparison' : 'Select for comparison'}
                      >
                        {isSelected ? (
                          <CheckSquare className="size-4 text-foreground" />
                        ) : (
                          <Square className="size-4 text-zinc-500 group-hover:text-zinc-300" />
                        )}
                      </button>
                    </td>
                    <td className="px-3 py-3.5 font-mono font-semibold text-foreground group-hover:text-sky-400">
                      {item.cve_id}
                    </td>
                    <td className="px-3 py-3.5">
                      <span className={`rounded-md border px-2.5 py-0.5 text-[11px] font-semibold ${styles.badge}`}>
                        {item.priority_level}
                      </span>
                    </td>
                    <td className="px-3 py-3.5 font-mono font-semibold text-foreground">
                      {item.total_score}
                      <span className="text-[11px] font-normal text-muted-foreground">/100</span>
                    </td>
                    <td className="px-3 py-3.5 font-mono text-zinc-200">
                      {item.cvss_base_score !== null ? item.cvss_base_score.toFixed(1) : 'N/A'}
                    </td>
                    <td className="px-3 py-3.5 font-mono text-zinc-200">
                      {formatProbability(item.epss_probability)}
                    </td>
                    <td className="px-3 py-3.5">
                      {item.is_known_exploited ? (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-400">
                          <Flame className="size-3.5 text-red-500" />
                          <span>Active</span>
                        </span>
                      ) : item.is_known_exploited === false ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <CheckCircle className="size-3.5 text-emerald-500" />
                          <span>Negative</span>
                        </span>
                      ) : (
                        <span className="text-xs text-zinc-300">Unknown</span>
                      )}
                    </td>
                    <td className="px-3 py-3.5 text-zinc-300">
                      <span className="font-medium text-foreground">{item.asset_criticality}</span>
                      <span className="mx-1 text-zinc-500">/</span>
                      <span className="text-xs">{item.internet_exposure}</span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3.5 text-xs text-zinc-300">
                      {formatDate(item.created_at)}
                    </td>
                    <td className="px-3 py-3.5 text-right">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        {onMoveToWorkspace && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onMoveToWorkspace(item.id);
                            }}
                            className="rounded-lg border border-border bg-white/[0.04] p-1.5 text-muted-foreground transition-colors hover:bg-white/[0.08] hover:text-foreground"
                            title="Move to My Workspace"
                            aria-label={`Move ${item.cve_id} to My Workspace`}
                          >
                            <FolderPlus className="size-3.5" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAssessment(item.id);
                          }}
                          className="rounded-lg border border-border bg-white/[0.04] p-1.5 text-zinc-200 transition-colors hover:bg-white/[0.08] hover:text-foreground"
                          title="Inspect Assessment"
                        >
                          <ArrowRight className="size-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
          <div>
            Showing {(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length} assessments
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              className="rounded-lg border border-border bg-background p-1.5 text-zinc-300 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft className="size-4" />
            </button>
            <span className="font-mono text-zinc-300">
              Page {safePage} of {totalPages}
            </span>
            <button
              type="button"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              className="rounded-lg border border-border bg-background p-1.5 text-zinc-300 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronRight className="size-4" />
            </button>
          </div>
        </div>
      )}

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
