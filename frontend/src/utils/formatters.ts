import { PriorityLevel } from '../types/assessment';

export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return 'N/A';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}

export function formatProbability(prob: number | null | undefined): string {
  if (prob === null || prob === undefined) return 'N/A';
  return `${(prob * 100).toFixed(2)}%`;
}

export function formatPercentile(pct: number | null | undefined): string {
  if (pct === null || pct === undefined) return 'N/A';
  return `${(pct * 100).toFixed(1)}th`;
}

export function getPriorityStyles(priority: PriorityLevel) {
  switch (priority) {
    case 'CRITICAL':
      return {
        badge: 'bg-red-500/10 text-red-400 border-red-500/30',
        text: 'text-red-400',
        border: 'border-red-500/30',
        bg: 'bg-red-500',
        glow: 'shadow-[0_0_20px_rgba(239,68,68,0.25)]',
      };
    case 'HIGH':
      return {
        badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
        text: 'text-orange-400',
        border: 'border-orange-500/30',
        bg: 'bg-orange-500',
        glow: 'shadow-[0_0_20px_rgba(249,115,22,0.25)]',
      };
    case 'MEDIUM':
      return {
        badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
        text: 'text-yellow-400',
        border: 'border-yellow-500/30',
        bg: 'bg-yellow-500',
        glow: 'shadow-[0_0_20px_rgba(234,179,8,0.25)]',
      };
    case 'LOW':
    default:
      return {
        badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
        text: 'text-blue-400',
        border: 'border-blue-500/30',
        bg: 'bg-blue-500',
        glow: 'shadow-[0_0_20px_rgba(59,130,246,0.25)]',
      };
  }
}
