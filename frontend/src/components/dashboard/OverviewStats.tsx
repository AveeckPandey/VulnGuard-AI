import React from 'react';
import { ShieldAlert, AlertOctagon, Flame, Activity } from 'lucide-react';
import { AssessmentSummary } from '../../types/assessment';

interface OverviewStatsProps {
  history: AssessmentSummary[];
}

export const OverviewStats: React.FC<OverviewStatsProps> = ({ history }) => {
  const total = history.length;
  const criticalCount = history.filter((h) => h.priority_level === 'CRITICAL').length;
  const highCount = history.filter((h) => h.priority_level === 'HIGH').length;
  const kevCount = history.filter((h) => h.is_known_exploited).length;
  const avgScore = total > 0 ? (history.reduce((acc, h) => acc + h.total_score, 0) / total).toFixed(1) : '0.0';

  const stats = [
    {
      title: 'Recent Assessments',
      value: total,
      label: 'Showing recent (limit 50)',
      icon: Activity,
      color: 'text-sky-400',
      bg: 'bg-white/[0.03] border-border',
    },
    {
      title: 'Critical Severity',
      value: criticalCount,
      label: 'Score >= 85 requiring immediate SLA',
      icon: AlertOctagon,
      color: 'text-red-400',
      bg: 'bg-red-500/10 border-red-500/20',
    },
    {
      title: 'Active CISA KEV Exploits',
      value: kevCount,
      label: 'Confirmed weaponized in wild',
      icon: Flame,
      color: 'text-orange-400',
      bg: 'bg-orange-500/10 border-orange-500/20',
    },
    {
      title: 'Average Risk Score',
      value: `${avgScore}/100`,
      label: `${highCount} High Priority assets`,
      icon: ShieldAlert,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10 border-yellow-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat, idx) => {
        const Icon = stat.icon;
        return (
          <div key={idx} className="surface-panel flex items-center justify-between rounded-2xl p-4">
            <div>
              <p className="text-xs font-medium text-muted-foreground">{stat.title}</p>
              <p className="mt-1 font-mono text-2xl font-semibold text-foreground tabular-nums">{stat.value}</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">{stat.label}</p>
            </div>
            <div className={`rounded-xl border p-2.5 ${stat.bg} ${stat.color}`}>
              <Icon className="size-5" />
            </div>
          </div>
        );
      })}
    </div>
  );
};
