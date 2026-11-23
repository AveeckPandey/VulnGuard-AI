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
  const publicFacing = history.filter((h) => h.internet_exposure === 'PUBLIC_FACING').length;
  const internal = total - publicFacing;

  // Exposure Comparison Data
  const exposureData = [
    { name: 'Public Facing', count: publicFacing, fill: '#06b6d4' },
    { name: 'Internal / Isolated', count: internal, fill: '#3b82f6' },
  ];

  // Scatter plot: CVSS Base Score (x) vs Priority Score (y) vs EPSS (size)
  const scatterData = history.map((h) => ({
    cve: h.cve_id,
    cvss: h.cvss_base_score || 0,
    priority: h.total_score,
    epss: (h.epss_probability || 0) * 100,
  }));

  // Criticality Hierarchy count
  const criticalityData = [
    { tier: 'Critical', count: history.filter((h) => h.asset_criticality === 'CRITICAL').length, fill: '#ef4444' },
    { tier: 'High', count: history.filter((h) => h.asset_criticality === 'HIGH').length, fill: '#f97316' },
    { tier: 'Medium', count: history.filter((h) => h.asset_criticality === 'MEDIUM').length, fill: '#eab308' },
    { tier: 'Low', count: history.filter((h) => h.asset_criticality === 'LOW').length, fill: '#22c55e' },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-card via-[#0c1427] to-card border border-border shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white tracking-tight">
              Enterprise Risk & Intelligence Analytics
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Statistical correlation across multi-source cybersecurity telemetry, asset criticality tiers, and deterministic risk weights.
          </p>
        </div>

        <div className="flex items-center space-x-4 text-xs">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Dataset</span>
            <span className="font-mono font-bold text-cyan-400 text-sm">{total} Assessments</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Storage</span>
            <span className="font-mono font-bold text-emerald-400 text-sm">AWS DynamoDB</span>
          </div>
        </div>
      </div>

      {/* Grid of 4 Analytic Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: CVSS vs Calculated Priority Correlation */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                CVSS Base vs Composite Priority Score
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Correlation Matrix</span>
          </div>
          <div className="h-56 w-full">
            {scatterData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    type="number"
                    dataKey="cvss"
                    name="CVSS"
                    domain={[0, 10]}
                    unit=""
                    tick={{ fontSize: 10, fill: '#64748b' }}
                  />
                  <YAxis
                    type="number"
                    dataKey="priority"
                    name="Priority"
                    domain={[0, 100]}
                    unit=""
                    tick={{ fontSize: 10, fill: '#64748b' }}
                  />
                  <ZAxis type="number" dataKey="epss" range={[60, 300]} name="EPSS %" />
                  <Tooltip
                    cursor={{ strokeDasharray: '3 3' }}
                    contentStyle={{
                      backgroundColor: '#0b1120',
                      borderColor: '#1e293b',
                      borderRadius: '0.75rem',
                      fontSize: '11px',
                    }}
                    formatter={(val: any, name: any) => [`${val}`, name]}
                  />
                  <Scatter name="CVEs" data={scatterData} fill="#06b6d4" />
                </ScatterChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No data available
              </div>
            )}
          </div>
          <p className="text-[10px] text-slate-500 text-center">
            Bubble size indicates FIRST EPSS exploitation likelihood
          </p>
        </div>

        {/* Chart 2: Asset Criticality Distribution */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Asset Criticality Breakdown
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Business Tiers</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={criticalityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="tier" tick={{ fontSize: 10, fill: '#64748b' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#64748b' }} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b1120',
                    borderColor: '#1e293b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {criticalityData.map((entry, index) => (
                    <Cell key={`bar-crit-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[10px] text-slate-500 text-center">
            Distribution of assessed systems by business operational criticality tier
          </p>
        </div>

        {/* Chart 3: Perimeter Exposure Ratio */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Internet Exposure Analysis
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Perimeter vs Internal</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={exposureData} layout="vertical" margin={{ top: 10, right: 20, left: 20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: '#94a3b8' }} width={100} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b1120',
                    borderColor: '#1e293b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {exposureData.map((entry, index) => (
                    <Cell key={`bar-expo-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[10px] text-slate-500 text-center">
            Public-facing systems carry a 10% exposure risk multiplier in the heuristic model
          </p>
        </div>

        {/* Chart 4: CISA KEV Weaponization Status */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Flame className="w-4 h-4 text-red-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Active Weaponization Ratio
              </h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">CISA KEV Presence</span>
          </div>
          <div className="h-56 flex items-center justify-center">
            <div className="grid grid-cols-2 gap-4 w-full text-center">
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Active Weaponization</span>
                <p className="text-3xl font-extrabold text-white mt-2 font-mono">{inKev}</p>
                <p className="text-[11px] text-red-400/80 mt-1">Confirmed in CISA Catalog</p>
              </div>
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">No Active Exploit</span>
                <p className="text-3xl font-extrabold text-white mt-2 font-mono">{total - inKev}</p>
                <p className="text-[11px] text-emerald-400/80 mt-1">Not Listed in Catalog</p>
              </div>
            </div>
          </div>
          <p className="text-[10px] text-slate-500 text-center">
            CISA KEV status adds 20 weighted contribution points to the composite score
          </p>
        </div>
      </div>
    </div>
  );
};
