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
        badge: 'bg-red-500/10 text-red-400 border-red-500/25',
        text: 'text-red-400',
        border: 'border-red-500/25',
        bg: 'bg-red-500',
        glow: '',
      };
    case 'HIGH':
      return {
        badge: 'bg-orange-500/10 text-orange-400 border-orange-500/25',
        text: 'text-orange-400',
        border: 'border-orange-500/25',
        bg: 'bg-orange-500',
        glow: '',
      };
    case 'MEDIUM':
      return {
        badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25',
        text: 'text-yellow-400',
        border: 'border-yellow-500/25',
        bg: 'bg-yellow-500',
        glow: '',
      };
    case 'LOW':
    default:
      return {
        badge: 'bg-sky-500/10 text-sky-400 border-sky-500/25',
        text: 'text-sky-400',
        border: 'border-sky-500/25',
        bg: 'bg-sky-500',
        glow: '',
      };
  }
}

export function formatUtcTimestamp(isoString: string | null | undefined): string {
  if (!isoString) return 'N/A';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch {
    return isoString;
  }
}
