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

  // 1. Severity Distribution Data for Pie Chart
  const severityData = [
    { name: 'Critical', value: criticalCount, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: highCount, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: mediumCount, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: lowCount, color: SEVERITY_COLORS.LOW },
  ].filter((d) => d.value > 0);

  // Fallback if empty
  const displaySeverityData = severityData.length > 0 ? severityData : [{ name: 'None', value: 1, color: '#334155' }];

  // 2. Trend Data for Area Chart (Chronological order)
  const trendData = [...history]
    .reverse()
    .slice(-10)
    .map((h, i) => ({
      index: i + 1,
      cve: h.cve_id,
      score: h.total_score,
      date: new Date(h.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' }),
    }));

  // 3. Score Distribution Bands
  const bands = [
    { name: '0–39 Low', count: history.filter((h) => h.total_score < 40).length, fill: '#22c55e' },
    { name: '40–69 Med', count: history.filter((h) => h.total_score >= 40 && h.total_score < 70).length, fill: '#eab308' },
    { name: '70–84 High', count: history.filter((h) => h.total_score >= 70 && h.total_score < 85).length, fill: '#f97316' },
    { name: '85–100 Crit', count: history.filter((h) => h.total_score >= 85).length, fill: '#ef4444' },
  ];

  return (
    <div className="space-y-6">
      {/* 5 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        <div className="p-4 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Recent Evaluated</p>
            <p className="text-2xl font-extrabold text-white mt-1 font-mono">{total}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Showing recent (limit 50)</p>
          </div>
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Layers className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Critical Severity</p>
            <p className="text-2xl font-extrabold text-red-400 mt-1 font-mono">{criticalCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Score ≥ 85 (Urgent SLA)</p>
          </div>
          <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <AlertOctagon className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">High Risk</p>
            <p className="text-2xl font-extrabold text-orange-400 mt-1 font-mono">{highCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Score 70–84</p>
          </div>
          <div className="p-2.5 rounded-xl bg-orange-500/10 border border-orange-500/20 text-orange-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">In CISA KEV</p>
            <p className="text-2xl font-extrabold text-amber-400 mt-1 font-mono">{kevCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Weaponized in the wild</p>
          </div>
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <Flame className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Avg Priority</p>
            <p className="text-2xl font-extrabold text-cyan-400 mt-1 font-mono">{avgScore}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Composite 0–100 score</p>
          </div>
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Visual Analytics Row: 3 Recharts Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Panel 1: Severity Distribution Donut */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Severity Breakdown
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">By Priority Tier</span>
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
                >
                  {displaySeverityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b1120',
                    borderColor: '#1e293b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                  }}
                  formatter={(value: any, name: any) => [`${value} CVEs`, name]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Custom Legend */}
          <div className="grid grid-cols-2 gap-2 pt-1 border-t border-border/60 text-[11px]">
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-red-400" />
              <span className="text-slate-400">Critical:</span>
              <span className="font-mono font-bold text-white ml-auto">{criticalCount}</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-orange-400" />
              <span className="text-slate-400">High:</span>
              <span className="font-mono font-bold text-white ml-auto">{highCount}</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-yellow-400" />
              <span className="text-slate-400">Medium:</span>
              <span className="font-mono font-bold text-white ml-auto">{mediumCount}</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span className="text-slate-400">Low:</span>
              <span className="font-mono font-bold text-white ml-auto">{lowCount}</span>
            </div>
          </div>
        </div>

        {/* Panel 2: Priority Score Trend Area Chart */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Recent Triage Timeline
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Last 10 triaged</span>
          </div>

          <div className="h-44 w-full">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="cve" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0b1120',
                      borderColor: '#1e293b',
                      borderRadius: '0.75rem',
                      fontSize: '11px',
                    }}
                    formatter={(val: any) => [`${val}/100`, 'Priority Score']}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#scoreGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No recent assessments to plot
              </div>
            )}
          </div>
          <p className="text-[10px] text-slate-500 text-center">Score progression across consecutive assessments</p>
        </div>

        {/* Panel 3: Score Distribution Bars */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Risk Classification Bands
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">0 to 100 Scale</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bands} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b1120',
                    borderColor: '#1e293b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                  }}
                  formatter={(val: any) => [`${val} assessments`, 'Count']}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {bands.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[10px] text-slate-500 text-center">Volume of triaged CVEs grouped by portfolio severity tier</p>
        </div>
      </div>

      {/* Recent Assessments Table Card */}
      <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center space-x-2">
              <span>Recently Triaged Vulnerabilities</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 border border-slate-700 font-mono">
                {history.length}
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Live assessments persisted in Amazon DynamoDB with multi-source intelligence
            </p>
          </div>
          <button
            onClick={onNavigateToAnalyzer}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 text-xs font-semibold transition-all"
          >
            <span>Analyze New CVE</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="py-2.5 px-3">CVE Identifier</th>
                <th className="py-2.5 px-3">Severity & Score</th>
                <th className="py-2.5 px-3">CVSS Base</th>
                <th className="py-2.5 px-3">FIRST EPSS</th>
                <th className="py-2.5 px-3">CISA KEV</th>
                <th className="py-2.5 px-3">Exposure</th>
                <th className="py-2.5 px-3">Triaged Date</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {history.slice(0, 7).map((item) => {
                const priorityColor =
                  SEVERITY_COLORS[item.priority_level] || '#94a3b8';
                return (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors group">
                    <td className="py-3 px-3 font-bold text-white flex items-center space-x-2">
                      <span className="text-cyan-400 group-hover:underline cursor-pointer" onClick={() => onSelectAssessment(item.id)}>
                        {item.cve_id}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider inline-flex items-center space-x-1"
                        style={{
                          backgroundColor: `${priorityColor}15`,
                          color: priorityColor,
                          border: `1px solid ${priorityColor}35`,
                        }}
                      >
                        <span>{item.priority_level}</span>
                        <span className="text-white">({item.total_score.toFixed(1)})</span>
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {item.cvss_base_score !== null ? item.cvss_base_score.toFixed(1) : 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {item.epss_probability !== null ? `${(item.epss_probability * 100).toFixed(1)}%` : 'N/A'}
                    </td>
                    <td className="py-3 px-3">
                      {item.is_known_exploited ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 font-bold">
                          YES (Active)
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">{item.is_known_exploited === false ? 'No' : 'Unknown'}</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400 font-sans text-[11px]">
                      {item.internet_exposure === 'PUBLIC_FACING' ? (
                        <span className="text-cyan-400">Public</span>
                      ) : (
                        <span className="text-slate-500">Internal</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-500 font-sans text-[11px]">
                      <div className="flex items-center space-x-1">
                        <Calendar className="w-3 h-3 text-slate-600" />
                        <span>{formatUtcTimestamp(item.created_at)}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => onSelectAssessment(item.id)}
                        className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 text-[11px] font-sans transition-all flex items-center space-x-1 ml-auto"
                      >
                        <span>Details</span>
                        <ExternalLink className="w-3 h-3" />
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
