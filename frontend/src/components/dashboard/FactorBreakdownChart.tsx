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
  '#38bdf8',
  '#818cf8',
  '#ef4444',
  '#f59e0b',
  '#10b981',
];

export const FactorBreakdownChart: React.FC<FactorBreakdownChartProps> = ({
  components,
  totalScore,
}) => {
  const chartData = components.map((c, i) => ({
    name: c.name.split(' ')[0],
    fullName: c.name,
    contribution: c.weighted_contribution,
    normalized: c.normalized_score,
    weight: `${(c.weight * 100).toFixed(0)}%`,
    raw: String(c.raw_value),
    description: c.description,
    color: FACTOR_COLORS[i % FACTOR_COLORS.length],
  }));

  return (
    <div className="surface-panel rounded-2xl p-5">
      <div className="mb-4 flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="size-4 text-muted-foreground" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Risk Factor Contribution Breakdown
          </h3>
        </div>
        <span className="text-xs text-muted-foreground">
          Composite Score: <strong className="font-mono text-foreground">{totalScore} / 100</strong>
        </span>
      </div>

      <div className="h-52 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
            <XAxis type="number" domain={[0, 30]} stroke="#71717a" fontSize={11} tickLine={false} tickFormatter={(v) => `${v} pts`} />
            <YAxis type="category" dataKey="name" stroke="#a1a1aa" fontSize={11} width={80} tickLine={false} />
            <Tooltip
              cursor={{ fill: 'rgba(255,255,255,0.03)' }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="space-y-1 rounded-xl border border-border bg-popover p-3 text-xs shadow-xl">
                      <p className="font-semibold text-foreground">{data.fullName}</p>
                      <p className="text-zinc-300">
                        Weight: <strong className="text-foreground">{data.weight}</strong>
                      </p>
                      <p className="text-zinc-300">
                        Normalized Score: <strong className="text-foreground">{data.normalized}/100</strong>
                      </p>
                      <p className="text-zinc-300">
                        Points Contributed: <strong className="text-emerald-400">+{data.contribution} pts</strong>
                      </p>
                      <p className="pt-1 text-[11px] text-muted-foreground">{data.description}</p>
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

      <div className="mt-4 grid grid-cols-2 gap-2 border-t border-border pt-4 sm:grid-cols-5">
        {components.map((comp, idx) => (
          <div key={idx} className="surface-subpanel rounded-xl p-2.5">
            <p className="truncate text-[10.5px] text-muted-foreground" title={comp.name}>
              {comp.name}
            </p>
            <p className="mt-0.5 font-mono text-sm font-semibold text-foreground">
              +{comp.weighted_contribution.toFixed(1)}{' '}
              <span className="text-[10px] font-normal text-muted-foreground">pts</span>
            </p>
            <p className="text-[10px] text-zinc-500">Weight: {(comp.weight * 100).toFixed(0)}%</p>
          </div>
        ))}
      </div>
    </div>
  );
};
