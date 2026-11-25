import React from 'react';
import {
  ShieldAlert,
  AlertOctagon,
  Flame,
  Activity,
  Layers,
  ArrowRight,
  TrendingUp,
  PieChart as PieIcon,
  BarChart2,
  Calendar,
  ExternalLink,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  BarChart,
  Bar,
  CartesianGrid,
} from 'recharts';
import { AssessmentSummary } from '../../types/assessment';
import { formatUtcTimestamp } from '../../utils/formatters';

interface OverviewViewProps {
  history: AssessmentSummary[];
  onSelectAssessment: (id: string) => void;
  onNavigateToAnalyzer: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export const OverviewView: React.FC<OverviewViewProps> = ({
  history,
  onSelectAssessment,
  onNavigateToAnalyzer,
}) => {
  const total = history.length;
  const criticalCount = history.filter((h) => h.priority_level === 'CRITICAL').length;
  const highCount = history.filter((h) => h.priority_level === 'HIGH').length;
  const mediumCount = history.filter((h) => h.priority_level === 'MEDIUM').length;
  const lowCount = history.filter((h) => h.priority_level === 'LOW').length;
  const kevCount = history.filter((h) => h.is_known_exploited).length;
  const avgScore = total > 0 ? (history.reduce((acc, h) => acc + h.total_score, 0) / total).toFixed(1) : '0.0';

  const severityData = [
    { name: 'Critical', value: criticalCount, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: highCount, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: mediumCount, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: lowCount, color: SEVERITY_COLORS.LOW },
  ].filter((d) => d.value > 0);

  const displaySeverityData = severityData.length > 0 ? severityData : [{ name: 'None', value: 1, color: '#27272a' }];

  const trendData = [...history]
    .reverse()
    .slice(-10)
    .map((h, i) => ({
      index: i + 1,
      cve: h.cve_id,
      score: h.total_score,
      date: new Date(h.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' }),
    }));

  const bands = [
    { name: '0–39 Low', count: history.filter((h) => h.total_score < 40).length, fill: '#22c55e' },
    { name: '40–69 Med', count: history.filter((h) => h.total_score >= 40 && h.total_score < 70).length, fill: '#eab308' },
    { name: '70–84 High', count: history.filter((h) => h.total_score >= 70 && h.total_score < 85).length, fill: '#f97316' },
    { name: '85–100 Crit', count: history.filter((h) => h.total_score >= 85).length, fill: '#ef4444' },
  ];

  const tooltipStyle = {
    backgroundColor: '#18181c',
    borderColor: 'rgba(255,255,255,0.14)',
    borderRadius: '0.625rem',
    fontSize: '12px',
    color: '#fafafa',
  };
  const tooltipItemStyle = { color: '#fafafa' };
  const tooltipLabelStyle = { color: '#fafafa', fontWeight: 600 };

  return (
    <div className="space-y-5">
      {/* 5 KPI Cards */}
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-5">
        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Recent Evaluated</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-foreground tabular-nums">{total}</p>
            <p className="mt-0.5 text-xs text-zinc-400">Showing recent (limit 50)</p>
          </div>
          <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-zinc-200">
            <Layers className="size-4" />
          </div>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Critical Severity</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-red-400 tabular-nums">{criticalCount}</p>
            <p className="mt-0.5 text-xs text-zinc-400">Score ≥ 85 (Urgent SLA)</p>
          </div>
          <div className="flex size-9 items-center justify-center rounded-xl border border-red-500/25 bg-red-500/10 text-red-400">
            <AlertOctagon className="size-4" />
          </div>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">High Risk</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-orange-400 tabular-nums">{highCount}</p>
            <p className="mt-0.5 text-xs text-zinc-400">Score 70–84</p>
          </div>
          <div className="flex size-9 items-center justify-center rounded-xl border border-orange-500/25 bg-orange-500/10 text-orange-400">
            <ShieldAlert className="size-4" />
          </div>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">In CISA KEV</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-amber-400 tabular-nums">{kevCount}</p>
            <p className="mt-0.5 text-xs text-zinc-400">Weaponized in the wild</p>
          </div>
          <div className="flex size-9 items-center justify-center rounded-xl border border-amber-500/25 bg-amber-500/10 text-amber-400">
            <Flame className="size-4" />
          </div>
        </div>

        <div className="surface-panel flex items-center justify-between rounded-2xl p-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Avg Priority</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-sky-400 tabular-nums">{avgScore}</p>
            <p className="mt-0.5 text-xs text-zinc-400">Composite 0–100 score</p>
          </div>
          <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-sky-400">
            <Activity className="size-4" />
          </div>
        </div>
      </div>

      {/* Visual Analytics Row: 3 Recharts Panels */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Panel 1: Severity Distribution Donut */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <PieIcon className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Severity Breakdown
              </h3>
            </div>
            <span className="font-mono text-[10.5px] text-muted-foreground">By Priority Tier</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={displaySeverityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={38}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {displaySeverityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} formatter={(value: any, name: any) => [`${value} CVEs`, name]} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 border-t border-border pt-2.5 text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-red-400" />
              <span className="text-muted-foreground">Critical:</span>
              <span className="ml-auto font-mono font-semibold text-foreground">{criticalCount}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-orange-400" />
              <span className="text-muted-foreground">High:</span>
              <span className="ml-auto font-mono font-semibold text-foreground">{highCount}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-yellow-400" />
              <span className="text-muted-foreground">Medium:</span>
              <span className="ml-auto font-mono font-semibold text-foreground">{mediumCount}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-emerald-400" />
              <span className="text-muted-foreground">Low:</span>
              <span className="ml-auto font-mono font-semibold text-foreground">{lowCount}</span>
            </div>
          </div>
        </div>

        {/* Panel 2: Priority Score Trend Area Chart */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <TrendingUp className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Recent Triage Timeline
              </h3>
            </div>
            <span className="font-mono text-[10.5px] text-muted-foreground">Last 10 triaged</span>
          </div>

          <div className="h-44 w-full">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.28} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="cve" tick={{ fontSize: 10, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} formatter={(val: any) => [`${val}/100`, 'Priority Score']} />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="#38bdf8"
                    strokeWidth={1.75}
                    fillOpacity={1}
                    fill="url(#scoreGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                No recent assessments to plot
              </div>
            )}
          </div>
          <p className="text-center text-[10.5px] text-zinc-500">Score progression across consecutive assessments</p>
        </div>

        {/* Panel 3: Score Distribution Bars */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <BarChart2 className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Risk Classification Bands
              </h3>
            </div>
            <span className="font-mono text-[10.5px] text-muted-foreground">0 to 100 Scale</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bands} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} formatter={(val: any) => [`${val} assessments`, 'Count']} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {bands.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-center text-[10.5px] text-zinc-500">Volume of triaged CVEs grouped by portfolio severity tier</p>
        </div>
      </div>

      {/* Recent Assessments Table Card */}
      <div className="surface-panel space-y-4 rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold tracking-tight text-foreground">
              <span>Recently Triaged Vulnerabilities</span>
              <span className="rounded-md bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground tabular-nums">
                {history.length}
              </span>
            </h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Saved vulnerability assessments enriched with multi-source threat intelligence
            </p>
          </div>
          <button
            type="button"
            onClick={onNavigateToAnalyzer}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-white/[0.03] px-3 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.06]"
          >
            <span>Analyze New CVE</span>
            <ArrowRight className="size-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-3">CVE Identifier</th>
                <th className="px-3 py-3">Severity & Score</th>
                <th className="px-3 py-3">CVSS Base</th>
                <th className="px-3 py-3">FIRST EPSS</th>
                <th className="px-3 py-3">CISA KEV</th>
                <th className="px-3 py-3">Exposure</th>
                <th className="px-3 py-3">Triaged Date</th>
                <th className="px-3 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.07] font-mono">
              {history.slice(0, 7).map((item) => {
                const priorityColor = SEVERITY_COLORS[item.priority_level] || '#b4b4bd';
                return (
                  <tr key={item.id} className="group transition-colors hover:bg-white/[0.04]">
                    <td className="px-3 py-3.5 font-semibold text-foreground">
                      <span
                        onClick={() => onSelectAssessment(item.id)}
                        className="cursor-pointer text-foreground hover:text-sky-400 hover:underline"
                      >
                        {item.cve_id}
                      </span>
                    </td>
                    <td className="px-3 py-3.5">
                      <span
                        className="inline-flex items-center gap-1 rounded-md px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider"
                        style={{
                          backgroundColor: `${priorityColor}1a`,
                          color: priorityColor,
                          border: `1px solid ${priorityColor}40`,
                        }}
                      >
                        <span>{item.priority_level}</span>
                        <span className="text-foreground">({item.total_score.toFixed(1)})</span>
                      </span>
                    </td>
                    <td className="px-3 py-3.5 text-zinc-200">
                      {item.cvss_base_score !== null ? item.cvss_base_score.toFixed(1) : 'N/A'}
                    </td>
                    <td className="px-3 py-3.5 text-zinc-200">
                      {item.epss_probability !== null ? `${(item.epss_probability * 100).toFixed(1)}%` : 'N/A'}
                    </td>
                    <td className="px-3 py-3.5">
                      {item.is_known_exploited ? (
                        <span className="rounded-md border border-red-500/30 bg-red-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-red-300">
                          YES (Active)
                        </span>
                      ) : (
                        <span className="text-xs text-zinc-300">
                          {item.is_known_exploited === false ? 'No' : 'Unknown'}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-3.5 font-sans text-xs text-zinc-300">
                      {item.internet_exposure === 'PUBLIC_FACING' ? (
                        <span className="text-zinc-100">Public</span>
                      ) : (
                        <span className="text-zinc-400">Internal</span>
                      )}
                    </td>
                    <td className="px-3 py-3.5 font-sans text-xs text-zinc-300">
                      <div className="flex items-center gap-1.5">
                        <Calendar className="size-3.5 text-zinc-400" />
                        <span>{formatUtcTimestamp(item.created_at)}</span>
                      </div>
                    </td>
                    <td className="px-3 py-3.5 text-right">
                      <button
                        type="button"
                        onClick={() => onSelectAssessment(item.id)}
                        className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-border bg-white/[0.04] px-3 py-1.5 font-sans text-xs font-medium text-zinc-200 transition-colors hover:bg-white/[0.08] hover:text-foreground"
                      >
                        <span>Details</span>
                        <ExternalLink className="size-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
