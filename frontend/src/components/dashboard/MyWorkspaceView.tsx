import React from 'react';
import {
  Shield,
  UserCheck,
  AlertTriangle,
  Flame,
  ArrowRight,
  PlusCircle,
  Database,
  Lock,
  Layers,
  Sparkles,
  History,
} from 'lucide-react';
import { UserWorkspaceSummary } from '../../types/assessment';
import { UserProfile } from '../../types/auth';
import { formatDate, formatProbability, getPriorityStyles } from '../../utils/formatters';

interface MyWorkspaceViewProps {
  user: UserProfile | null;
  workspace: UserWorkspaceSummary | null;
  intelFeeds: any;
  onNavigateToAnalyzer: () => void;
  onSelectAssessment: (id: string) => void;
  onSelectPreset: (cveId: string, criticality: any, exposure: any, context: string) => void;
  onOpenAuthModal: () => void;
  onMoveToHistory?: (id: string) => void;
}

export const MyWorkspaceView: React.FC<MyWorkspaceViewProps> = ({
  user,
  workspace,
  intelFeeds,
  onNavigateToAnalyzer,
  onSelectAssessment,
  onSelectPreset,
  onOpenAuthModal,
  onMoveToHistory,
}) => {
  const isAnonymous = !user;
  const total = workspace?.total_assessments ?? 0;
  const dist = workspace?.priority_distribution ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const recent = workspace?.recent_assessments ?? [];

  const kevCount = intelFeeds?.feeds?.cisa_kev?.known_exploited_cves_count || 1790;
  const nvdStatus = intelFeeds?.feeds?.nist_nvd?.status || 'operational';
  const epssStatus = intelFeeds?.feeds?.first_epss?.status || 'operational';
  const kevStatus = intelFeeds?.feeds?.cisa_kev?.status || 'operational';

  return (
    <div className="space-y-5">
      {/* Workspace Header / Identity Card */}
      <div className="surface-panel rounded-2xl p-6">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-foreground">
                <UserCheck className="size-4" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold tracking-tight text-foreground">
                    {user ? `${user.name || user.username}'s Personal Workspace` : 'Guest Security Workspace'}
                  </h2>
                  <span className="rounded-md border border-border bg-white/[0.04] px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                    {user ? (user.isDemo ? 'Demo' : 'Active Account') : 'Guest'}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {user?.email ? `Signed in as ${user.email}` : 'Guest session · Assessments are not saved'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Lock className="size-3.5 shrink-0 text-emerald-400" />
              <span>
                Isolated Workspace: Your triage records are scoped privately to your account with zero cross-user visibility.
              </span>
            </div>
          </div>

          <div className="flex shrink-0 items-center">
            {isAnonymous ? (
              <button
                type="button"
                onClick={onOpenAuthModal}
                className="inline-flex h-9 items-center gap-2 rounded-xl bg-primary px-4 text-xs font-semibold text-primary-foreground transition-opacity hover:opacity-90"
              >
                <Lock className="size-3.5" />
                <span>Sign In to Save Assessments</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={onNavigateToAnalyzer}
                className="inline-flex h-9 items-center gap-2 rounded-xl bg-primary px-4 text-xs font-semibold text-primary-foreground transition-opacity hover:opacity-90"
              >
                <PlusCircle className="size-3.5" />
                <span>New CVE Assessment</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 gap-3.5 md:grid-cols-4">
        <div className="surface-panel rounded-2xl p-4">
          <div className="mb-1 flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium">Recent Triages</span>
            <Layers className="size-4 text-zinc-400" />
          </div>
          <div className="font-mono text-2xl font-semibold text-foreground tabular-nums">{total}</div>
          <p className="mt-1 text-[11px] text-zinc-500">Up to 100 recent assessments in your workspace</p>
        </div>

        <div className="surface-panel rounded-2xl p-4">
          <div className="mb-1 flex items-center justify-between text-red-400">
            <span className="text-xs font-medium">Critical Risk (≥85)</span>
            <Flame className="size-4 text-red-400" />
          </div>
          <div className="font-mono text-2xl font-semibold text-red-400 tabular-nums">{dist.CRITICAL}</div>
          <p className="mt-1 text-[11px] text-zinc-500">
            {total > 0 ? `${((dist.CRITICAL / total) * 100).toFixed(0)}% of your triage` : '0% of total'}
          </p>
        </div>

        <div className="surface-panel rounded-2xl p-4">
          <div className="mb-1 flex items-center justify-between text-orange-400">
            <span className="text-xs font-medium">High Risk (70–84)</span>
            <AlertTriangle className="size-4 text-orange-400" />
          </div>
          <div className="font-mono text-2xl font-semibold text-orange-400 tabular-nums">{dist.HIGH}</div>
          <p className="mt-1 text-[11px] text-zinc-500">
            {total > 0 ? `${((dist.HIGH / total) * 100).toFixed(0)}% of your triage` : '0% of total'}
          </p>
        </div>

        <div className="surface-panel rounded-2xl p-4">
          <div className="mb-1 flex items-center justify-between text-yellow-400">
            <span className="text-xs font-medium">Med & Low (0–69)</span>
            <Shield className="size-4 text-yellow-400" />
          </div>
          <div className="font-mono text-2xl font-semibold text-yellow-400 tabular-nums">{dist.MEDIUM + dist.LOW}</div>
          <p className="mt-1 text-[11px] text-zinc-500">
            {dist.MEDIUM} Medium, {dist.LOW} Low
          </p>
        </div>
      </div>

      {/* Threat Feed Health & Pipeline Telemetry */}
      <div className="grid grid-cols-1 gap-3.5 md:grid-cols-3">
        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <div className="text-xs font-semibold text-foreground">NIST NVD 2.0 API</div>
            <div className="mt-0.5 text-[11px] text-zinc-500">CVSS v3.1 vector & severity metrics</div>
          </div>
          <span className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] font-medium text-emerald-400">
            {nvdStatus}
          </span>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <div className="text-xs font-semibold text-foreground">FIRST.Org EPSS v3</div>
            <div className="mt-0.5 text-[11px] text-zinc-500">Empirical exploit likelihood probability</div>
          </div>
          <span className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] font-medium text-emerald-400">
            {epssStatus}
          </span>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <div className="text-xs font-semibold text-foreground">CISA KEV Catalog</div>
            <div className="mt-0.5 text-[11px] text-zinc-500">{kevCount} weaponized CVEs tracked</div>
          </div>
          <span className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] font-medium text-emerald-400">
            {kevStatus}
          </span>
        </div>
      </div>

      {/* Recent Personal Assessments Table */}
      <div className="surface-panel space-y-4 rounded-2xl p-5">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Database className="size-4 text-muted-foreground" />
              <span>Workspace Assessments</span>
            </h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Assessments created from or pinned to My Workspace (kept separate from Assessment History)
            </p>
          </div>
          {recent.length > 0 && (
            <button
              type="button"
              onClick={onNavigateToAnalyzer}
              className="flex items-center gap-1 text-xs font-medium text-zinc-300 transition-colors hover:text-foreground"
            >
              <span>Launch Analyzer</span>
              <ArrowRight className="size-3.5" />
            </button>
          )}
        </div>

        {recent.length === 0 ? (
          <div className="space-y-3 py-12 text-center">
            <div className="mx-auto flex size-11 items-center justify-center rounded-xl border border-border bg-white/[0.03] text-muted-foreground">
              <Shield className="size-5" />
            </div>
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-foreground">No assessments in your workspace yet</h4>
              <p className="mx-auto max-w-md text-xs text-muted-foreground">
                Run your first vulnerability triage with our multi-factor scoring model and evidence-grounded AI remediation.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
              <button
                type="button"
                onClick={() =>
                  onSelectPreset(
                    'CVE-2021-44228',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Public Edge API Gateway with Log4j 2.14.0'
                  )
                }
                className="flex items-center gap-1.5 rounded-lg border border-border bg-white/[0.03] px-3 py-1.5 text-xs text-zinc-200 transition-colors hover:bg-white/[0.06]"
              >
                <Flame className="size-3.5 text-red-400" />
                <span>Test Log4Shell (CVE-2021-44228)</span>
              </button>
              <button
                type="button"
                onClick={() =>
                  onSelectPreset(
                    'CVE-2024-3094',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Linux Production SSH Build Servers'
                  )
                }
                className="flex items-center gap-1.5 rounded-lg border border-border bg-white/[0.03] px-3 py-1.5 text-xs text-zinc-200 transition-colors hover:bg-white/[0.06]"
              >
                <Sparkles className="size-3.5 text-sky-400" />
                <span>Test XZ Utils (CVE-2024-3094)</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-[13px]">
              <thead>
                <tr className="border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-3">CVE Identifier</th>
                  <th className="px-3 py-3">Priority</th>
                  <th className="px-3 py-3">Risk Score</th>
                  <th className="px-3 py-3">CVSS</th>
                  <th className="px-3 py-3">EPSS</th>
                  <th className="px-3 py-3">Environment Context</th>
                  <th className="px-3 py-3">Triage Date</th>
                  <th className="px-3 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.07] font-sans">
                {recent.map((item) => {
                  const styles = getPriorityStyles(item.priority_level);
                  return (
                    <tr
                      key={item.id}
                      className="group cursor-pointer transition-colors hover:bg-white/[0.04]"
                      onClick={() => onSelectAssessment(item.id)}
                    >
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
                          {onMoveToHistory && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onMoveToHistory(item.id);
                              }}
                              className="rounded-lg border border-border bg-white/[0.04] p-1.5 text-muted-foreground transition-colors hover:bg-white/[0.08] hover:text-foreground"
                              title="Move to Assessment History"
                              aria-label={`Move ${item.cve_id} to Assessment History`}
                            >
                              <History className="size-3.5" />
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
      </div>
    </div>
  );
};
