import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { ScoreComponent } from '../../types/assessment';
import { BarChart3 } from 'lucide-react';

interface FactorBreakdownChartProps {
  components: ScoreComponent[];
  totalScore: number;
}

const FACTOR_COLORS = [
  '#38bdf8', // sky-400 (CVSS)
  '#818cf8', // indigo-400 (EPSS)
  '#ef4444', // red-500 (KEV)
  '#f59e0b', // amber-500 (Criticality)
  '#10b981', // emerald-500 (Exposure)
];

export const FactorBreakdownChart: React.FC<FactorBreakdownChartProps> = ({
  components,
  totalScore,
}) => {
  const chartData = components.map((c, i) => ({
    name: c.name.split(' ')[0], // Short name
    fullName: c.name,
    contribution: c.weighted_contribution,
    normalized: c.normalized_score,
    weight: `${(c.weight * 100).toFixed(0)}%`,
    raw: String(c.raw_value),
    description: c.description,
    color: FACTOR_COLORS[i % FACTOR_COLORS.length],
  }));

  return (
    <div className="p-5 rounded-2xl bg-card border border-border shadow-lg">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <BarChart3 className="w-4 h-4 text-sky-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Risk Factor Contribution Breakdown
          </h3>
        </div>
        <span className="text-xs text-slate-400">
          Composite Score: <strong className="text-sky-400 font-mono">{totalScore} / 100</strong>
        </span>
      </div>

      {/* Recharts Bar Visualization */}
      <div className="h-52 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
            <XAxis type="number" domain={[0, 30]} stroke="#475569" fontSize={11} tickFormatter={(v) => `${v} pts`} />
            <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={80} />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="p-3 bg-slate-900 border border-slate-700 rounded-xl shadow-xl text-xs space-y-1">
                      <p className="font-bold text-white">{data.fullName}</p>
                      <p className="text-slate-300">
                        Weight: <strong className="text-sky-300">{data.weight}</strong>
                      </p>
                      <p className="text-slate-300">
                        Normalized Score: <strong className="text-white">{data.normalized}/100</strong>
                      </p>
                      <p className="text-slate-300">
                        Points Contributed: <strong className="text-emerald-400">+{data.contribution} pts</strong>
                      </p>
                      <p className="text-slate-400 text-[11px] pt-1">{data.description}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="contribution" radius={[0, 6, 6, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Summary Table of Components */}
      <div className="mt-4 grid grid-cols-2 sm:grid-cols-5 gap-2 pt-3 border-t border-slate-800">
        {components.map((comp, idx) => (
          <div key={idx} className="p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
            <p className="text-[10px] text-slate-400 truncate" title={comp.name}>
              {comp.name}
            </p>
            <p className="text-sm font-bold font-mono text-white mt-0.5">
              +{comp.weighted_contribution.toFixed(1)} <span className="text-[10px] text-slate-400 font-normal">pts</span>
            </p>
            <p className="text-[10px] text-slate-400">
              Weight: {(comp.weight * 100).toFixed(0)}%
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
