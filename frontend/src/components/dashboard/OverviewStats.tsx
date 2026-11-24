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
      bg: 'bg-sky-500/10 border-sky-500/20',
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
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat, idx) => {
        const Icon = stat.icon;
        return (
          <div
            key={idx}
            className="p-4 rounded-xl bg-card border border-border shadow-sm flex items-center justify-between"
          >
            <div>
              <p className="text-xs font-medium text-slate-400">{stat.title}</p>
              <p className="text-2xl font-extrabold text-white mt-1 font-mono">{stat.value}</p>
              <p className="text-[11px] text-slate-400 mt-0.5">{stat.label}</p>
            </div>
            <div className={`p-3 rounded-xl border ${stat.bg} ${stat.color}`}>
              <Icon className="w-5 h-5" />
            </div>
          </div>
        );
      })}
    </div>
  );
};
