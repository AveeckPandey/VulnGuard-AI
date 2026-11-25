import React from 'react';
import {
  BarChart3,
  Flame,
  Globe,
  Shield,
  Activity,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ScatterChart,
  Scatter,
  ZAxis,
} from 'recharts';
import { AssessmentSummary } from '../../types/assessment';

interface AnalyticsDashboardProps {
  history: AssessmentSummary[];
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({ history }) => {
  const total = history.length;
  const inKev = history.filter((h) => h.is_known_exploited).length;
  const absentFromKev = history.filter((h) => h.is_known_exploited === false).length;
  const publicFacing = history.filter((h) => h.internet_exposure === 'PUBLIC_FACING').length;
  const internal = total - publicFacing;

  const exposureData = [
    { name: 'Public Facing', count: publicFacing, fill: '#38bdf8' },
    { name: 'Internal / Isolated', count: internal, fill: '#6366f1' },
  ];

  const scoredHistory = history.filter(
    (h) => h.cvss_base_score !== null && h.cvss_base_score !== undefined
  );
  const unindexedCount = history.length - scoredHistory.length;

  const scatterData = scoredHistory.map((h) => ({
    cve: h.cve_id,
    cvss: h.cvss_base_score,
    priority: h.total_score,
    epss: Number(((h.epss_probability ?? 0) * 100).toFixed(2)),
  }));

  const criticalityData = [
    { tier: 'Critical', count: history.filter((h) => h.asset_criticality === 'CRITICAL').length, fill: '#ef4444' },
    { tier: 'High', count: history.filter((h) => h.asset_criticality === 'HIGH').length, fill: '#f97316' },
    { tier: 'Medium', count: history.filter((h) => h.asset_criticality === 'MEDIUM').length, fill: '#eab308' },
    { tier: 'Low', count: history.filter((h) => h.asset_criticality === 'LOW').length, fill: '#22c55e' },
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
      {/* Header Banner */}
      <div className="surface-panel rounded-2xl p-6">
        <div className="flex items-center gap-2">
          <BarChart3 className="size-4 text-sky-400" />
          <h2 className="text-base font-semibold tracking-tight text-foreground">
            Enterprise Risk &amp; Intelligence Analytics
          </h2>
        </div>
        <p className="mt-1.5 max-w-2xl text-[13px] leading-relaxed text-muted-foreground">
          Statistical correlation across multi-source cybersecurity telemetry, asset criticality tiers, and deterministic risk weights.
        </p>
      </div>

      {/* Grid of 4 Analytic Cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Chart 1: CVSS vs Calculated Priority Correlation */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <Activity className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                CVSS Base vs Composite Priority Score
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {unindexedCount > 0 && (
                <span className="rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-400">
                  {unindexedCount} missing CVSS excluded
                </span>
              )}
              <span className="font-mono text-[10.5px] text-muted-foreground">Correlation Matrix</span>
            </div>
          </div>
          <div className="h-56 w-full">
            {scatterData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis
                    type="number"
                    dataKey="cvss"
                    name="CVSS"
                    domain={[0, 10]}
                    unit=""
                    tick={{ fontSize: 11, fill: '#a1a1aa' }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    type="number"
                    dataKey="priority"
                    name="Priority"
                    domain={[0, 100]}
                    unit=""
                    tick={{ fontSize: 11, fill: '#a1a1aa' }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <ZAxis type="number" dataKey="epss" range={[60, 300]} name="EPSS %" />
                  <Tooltip
                    cursor={{ strokeDasharray: '3 3', stroke: 'rgba(255,255,255,0.25)' }}
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload as {
                          cve: string;
                          cvss: number;
                          priority: number;
                          epss: number;
                        };
                        return (
                          <div className="space-y-1.5 rounded-xl border border-white/[0.14] bg-[#18181c] p-3 text-xs text-foreground shadow-2xl">
                            <p className="font-mono font-semibold text-sky-400">{data.cve}</p>
                            <p className="text-zinc-200">
                              CVSS: <strong className="font-mono text-foreground">{data.cvss}</strong>
                            </p>
                            <p className="text-zinc-200">
                              Priority: <strong className="font-mono text-foreground">{data.priority}/100</strong>
                            </p>
                            <p className="text-zinc-200">
                              EPSS: <strong className="font-mono text-foreground">{data.epss.toFixed(2)}%</strong>
                            </p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Scatter name="CVEs" data={scatterData} fill="#38bdf8" />
                </ScatterChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                No data available
              </div>
            )}
          </div>
          <p className="text-center text-xs text-zinc-400">
            Bubble size indicates FIRST EPSS exploitation likelihood
          </p>
        </div>

        {/* Chart 2: Asset Criticality Distribution */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Asset Criticality Breakdown
              </h3>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground">Business Tiers</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={criticalityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="tier" tick={{ fontSize: 11, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {criticalityData.map((entry, index) => (
                    <Cell key={`bar-crit-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-center text-xs text-zinc-400">
            Distribution of assessed systems by business operational criticality tier
          </p>
        </div>

        {/* Chart 3: Perimeter Exposure Ratio */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <Globe className="size-4 text-muted-foreground" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Internet Exposure Analysis
              </h3>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground">Perimeter vs Internal</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={exposureData} layout="vertical" margin={{ top: 10, right: 20, left: 20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#a1a1aa' }} tickLine={false} axisLine={false} />
                <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: '#d4d4d8' }} width={105} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {exposureData.map((entry, index) => (
                    <Cell key={`bar-expo-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-center text-xs text-zinc-400">
            Public-facing systems carry a 10% exposure risk multiplier in the heuristic model
          </p>
        </div>

        {/* Chart 4: CISA KEV Weaponization Status */}
        <div className="surface-panel space-y-3 rounded-2xl p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <Flame className="size-4 text-red-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Active Weaponization Ratio
              </h3>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground">CISA KEV Presence</span>
          </div>
          <div className="flex h-56 items-center justify-center">
            <div className="grid w-full grid-cols-2 gap-4 text-center">
              <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-5">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-red-400">
                  Active Weaponization
                </span>
                <p className="mt-2 font-mono text-3xl font-semibold text-foreground tabular-nums">{inKev}</p>
                <p className="mt-1 text-xs text-red-300/90">Confirmed in CISA Catalog</p>
              </div>
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-5">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
                  Absent from KEV
                </span>
                <p className="mt-2 font-mono text-3xl font-semibold text-foreground tabular-nums">{absentFromKev}</p>
                <p className="mt-1 text-xs text-emerald-300/90">Not Listed in Catalog</p>
              </div>
            </div>
          </div>
          <p className="text-center text-xs text-zinc-400">
            Unverified KEV status: {total - inKev - absentFromKev}
          </p>
        </div>
      </div>
    </div>
  );
};
