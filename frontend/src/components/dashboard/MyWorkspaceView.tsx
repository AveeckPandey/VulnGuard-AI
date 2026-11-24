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
}

export const MyWorkspaceView: React.FC<MyWorkspaceViewProps> = ({
  user,
  workspace,
  intelFeeds,
  onNavigateToAnalyzer,
  onSelectAssessment,
  onSelectPreset,
  onOpenAuthModal,
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
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Workspace Header / Identity Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2.5">
              <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-300">
                <UserCheck className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-white tracking-tight">
                    {user ? `${user.name || user.username}'s Personal Workspace` : 'Guest Security Workspace'}
                  </h2>
                  <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    {user ? (user.isDemo ? 'Demo Persona' : 'Cognito User') : 'Unauthenticated'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Tenant ID (sub): <span className="text-slate-300">{user?.sub || 'anonymous-session'}</span>
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-2 text-xs text-slate-400 pt-1">
              <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>
                Isolated Workspace: Records are indexed under your partition key in DynamoDB UserHistoryIndex. Zero cross-user visibility.
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            {isAnonymous ? (
              <button
                onClick={onOpenAuthModal}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs shadow-md shadow-sky-500/20 flex items-center space-x-2 transition-all"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Sign In to Save Assessments</span>
              </button>
            ) : (
              <button
                onClick={onNavigateToAnalyzer}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs shadow-md shadow-sky-500/20 flex items-center space-x-2 transition-all active:scale-[0.98]"
              >
                <PlusCircle className="w-4 h-4" />
                <span>New CVE Assessment</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-medium">My Total Triages</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-white">{total}</div>
          <p className="text-[11px] text-slate-500 mt-1">Saved in private partition</p>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-red-400 mb-1">
            <span className="text-xs font-medium">Critical Risk (≥85)</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-red-400">{dist.CRITICAL}</div>
          <p className="text-[11px] text-slate-500 mt-1">
            {total > 0 ? `${((dist.CRITICAL / total) * 100).toFixed(0)}% of your triage` : '0% of total'}
          </p>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-orange-400 mb-1">
            <span className="text-xs font-medium">High Risk (70–84)</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-orange-400">{dist.HIGH}</div>
          <p className="text-[11px] text-slate-500 mt-1">
            {total > 0 ? `${((dist.HIGH / total) * 100).toFixed(0)}% of your triage` : '0% of total'}
          </p>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-yellow-400 mb-1">
            <span className="text-xs font-medium">Med & Low (0–69)</span>
            <Shield className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-yellow-400">{dist.MEDIUM + dist.LOW}</div>
          <p className="text-[11px] text-slate-500 mt-1">
            {dist.MEDIUM} Medium, {dist.LOW} Low
          </p>
        </div>
      </div>

      {/* Threat Feed Health & Pipeline Telemetry */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-300">NIST NVD 2.0 API</div>
            <div className="text-[11px] text-slate-500 mt-0.5">CVSS v3.1 vector & severity metrics</div>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
            {nvdStatus}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-300">FIRST.Org EPSS v3</div>
            <div className="text-[11px] text-slate-500 mt-0.5">Empirical exploit likelihood probability</div>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
            {epssStatus}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-300">CISA KEV Catalog</div>
            <div className="text-[11px] text-slate-500 mt-0.5">{kevCount} weaponized CVEs tracked</div>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
            {kevStatus}
          </span>
        </div>
      </div>

      {/* Recent Personal Assessments Table */}
      <div className="p-5 rounded-2xl bg-card border border-border shadow-lg space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>My Recent Assessments</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Vulnerabilities analyzed and saved under your user account
            </p>
          </div>
          {recent.length > 0 && (
            <button
              onClick={onNavigateToAnalyzer}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
            >
              <span>Launch Analyzer</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {recent.length === 0 ? (
          <div className="py-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-2xl bg-slate-800/80 border border-slate-700/80 flex items-center justify-center mx-auto text-slate-500">
              <Shield className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-slate-200">No assessments in your workspace yet</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Run your first vulnerability triage with our multi-factor scoring model and NVIDIA Nemotron AI remediation.
              </p>
            </div>
            <div className="pt-2 flex flex-wrap items-center justify-center gap-2">
              <button
                onClick={() =>
                  onSelectPreset(
                    'CVE-2021-44228',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Public Edge API Gateway with Log4j 2.14.0'
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 transition-all flex items-center space-x-1.5"
              >
                <Flame className="w-3.5 h-3.5 text-red-400" />
                <span>Test Log4Shell (CVE-2021-44228)</span>
              </button>
              <button
                onClick={() =>
                  onSelectPreset(
                    'CVE-2024-3094',
                    'CRITICAL',
                    'PUBLIC_FACING',
                    'Linux Production SSH Build Servers'
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 transition-all flex items-center space-x-1.5"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Test XZ Utils (CVE-2024-3094)</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3">CVE Identifier</th>
                  <th className="py-2.5 px-3">Priority</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">CVSS</th>
                  <th className="py-2.5 px-3">EPSS</th>
                  <th className="py-2.5 px-3">Environment Context</th>
                  <th className="py-2.5 px-3">Triage Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {recent.map((item) => {
                  const styles = getPriorityStyles(item.priority_level);
                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                      onClick={() => onSelectAssessment(item.id)}
                    >
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
    </div>
  );
};
