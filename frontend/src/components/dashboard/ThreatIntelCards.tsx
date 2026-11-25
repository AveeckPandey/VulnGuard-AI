import React from 'react';
import { TrendingUp, Flame, ExternalLink, CheckCircle, HelpCircle } from 'lucide-react';
import { AggregatedIntel } from '../../types/assessment';
import { formatProbability, formatPercentile } from '../../utils/formatters';

interface ThreatIntelCardsProps {
  intel: AggregatedIntel;
}

export const ThreatIntelCards: React.FC<ThreatIntelCardsProps> = ({ intel }) => {
  const { nvd, epss, cisa_kev } = intel;

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {/* 1. NIST NVD Card */}
      <div className="surface-panel flex flex-col justify-between rounded-2xl p-5 transition-colors hover:border-white/[0.14]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              NIST NVD Intelligence
            </span>
            <a
              href={nvd.source_url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 text-xs text-zinc-300 transition-colors hover:text-foreground"
            >
              <span>NVD 2.0</span>
              <ExternalLink className="size-3 text-muted-foreground" />
            </a>
          </div>

          <div className="mt-4 flex flex-wrap items-baseline gap-2.5">
            <span className="font-mono text-3xl font-semibold text-foreground tabular-nums">
              {nvd.cvss_base_score !== null ? nvd.cvss_base_score.toFixed(1) : 'N/A'}
            </span>
            <span
              className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                nvd.cvss_severity === 'CRITICAL'
                  ? 'border-red-500/25 bg-red-500/10 text-red-400'
                  : nvd.cvss_severity === 'HIGH'
                  ? 'border-orange-500/25 bg-orange-500/10 text-orange-400'
                  : nvd.cvss_severity === 'MEDIUM'
                  ? 'border-yellow-500/25 bg-yellow-500/10 text-yellow-400'
                  : 'border-sky-500/25 bg-sky-500/10 text-sky-400'
              }`}
            >
              {nvd.cvss_severity || 'UNKNOWN'}
            </span>
            <span className="text-xs text-muted-foreground">
              {nvd.cvss_version ? `CVSS v${nvd.cvss_version}` : 'CVSS unavailable'}
            </span>
          </div>

          <p className="mt-3 line-clamp-3 text-[13.5px] leading-relaxed text-zinc-200">
            {nvd.description || 'No description available from upstream feed.'}
          </p>

          {nvd.weaknesses.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {Array.from(new Set(nvd.weaknesses)).map((cwe, idx) => (
                <span
                  key={`${cwe}-${idx}`}
                  className="rounded-md border border-border bg-white/[0.04] px-2 py-0.5 font-mono text-[11px] text-zinc-200"
                >
                  {cwe}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="mt-4 flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
          <span>Vector:</span>
          <span className="max-w-[180px] truncate font-mono text-zinc-300" title={nvd.cvss_vector_string || 'N/A'}>
            {nvd.cvss_vector_string || 'N/A'}
          </span>
        </div>
      </div>

      {/* 2. FIRST EPSS Card */}
      <div className="surface-panel flex flex-col justify-between rounded-2xl p-5 transition-colors hover:border-white/[0.14]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              FIRST EPSS Probability
            </span>
            <a
              href={epss.source_url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 text-xs text-zinc-300 transition-colors hover:text-foreground"
            >
              <span>FIRST.org</span>
              <ExternalLink className="size-3 text-muted-foreground" />
            </a>
          </div>

          <div className="mt-4 flex items-baseline gap-2">
            <span className="font-mono text-3xl font-semibold text-foreground tabular-nums">
              {formatProbability(epss.epss_probability)}
            </span>
            <span className="text-xs text-muted-foreground">next 30-day exploit likelihood</span>
          </div>

          <div className="mt-3 h-2 w-full overflow-hidden rounded-full border border-border bg-white/[0.04]">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                (epss.epss_probability || 0) > 0.5
                  ? 'bg-red-500'
                  : (epss.epss_probability || 0) > 0.15
                  ? 'bg-orange-500'
                  : 'bg-sky-400'
              }`}
              style={{ width: `${Math.min(100, (epss.epss_probability || 0) * 100)}%` }}
            />
          </div>

          <div className="surface-subpanel mt-4 flex items-center justify-between rounded-xl p-3">
            <div className="flex items-center gap-2">
              <TrendingUp className="size-4 text-sky-400" />
              <span className="text-xs font-medium text-zinc-300">Percentile Ranking</span>
            </div>
            <span className="font-mono text-xs font-semibold text-foreground">
              {formatPercentile(epss.epss_percentile)}
            </span>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between border-t border-border pt-3 text-[11px] text-muted-foreground">
          <span>Model Date:</span>
          <span className="font-mono text-zinc-300">{epss.model_date || 'Unknown'}</span>
        </div>
      </div>

      {/* 3. CISA KEV Card */}
      <div className="surface-panel flex flex-col justify-between rounded-2xl p-5 transition-colors hover:border-white/[0.14]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              CISA KEV Exploitation
            </span>
            <a
              href={cisa_kev.source_url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 text-xs text-zinc-300 transition-colors hover:text-foreground"
            >
              <span>CISA.gov</span>
              <ExternalLink className="size-3 text-muted-foreground" />
            </a>
          </div>

          <div className="mt-4">
            {cisa_kev.is_known_exploited ? (
              <div className="flex items-center gap-2.5 rounded-xl border border-red-500/25 bg-red-500/10 p-3 text-red-400">
                <Flame className="size-5 shrink-0 text-red-500" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider">Actively Weaponized in Wild</p>
                  <p className="text-[11px] text-red-300/80">Listed in Federal KEV Catalog</p>
                </div>
              </div>
            ) : cisa_kev.status === 'CONFIRMED_NEGATIVE' ? (
              <div className="flex items-center gap-2.5 rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 text-emerald-400">
                <CheckCircle className="size-5 shrink-0 text-emerald-500" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider">Confirmed Negative</p>
                  <p className="text-[11px] text-emerald-300/80">Not listed in active KEV catalog</p>
                </div>
              </div>
            ) : (
              <div className="surface-subpanel flex items-center gap-2.5 rounded-xl p-3 text-zinc-300">
                <HelpCircle className="size-5 shrink-0 text-muted-foreground" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider">Status Unverified</p>
                  <p className="text-[11px] text-muted-foreground">Catalog unreachable or pending sync</p>
                </div>
              </div>
            )}
          </div>

          {cisa_kev.is_known_exploited && (
            <div className="mt-3 space-y-1.5 text-xs">
              {cisa_kev.vulnerability_name && (
                <p className="line-clamp-1 font-medium text-foreground">
                  {cisa_kev.vulnerability_name}
                </p>
              )}
              {cisa_kev.required_action && (
                <p className="line-clamp-2 text-[11px] text-muted-foreground">
                  <strong className="text-zinc-300">Mandate:</strong> {cisa_kev.required_action}
                </p>
              )}
              {cisa_kev.known_ransomware_use && (
                <div className="flex items-center gap-1.5 text-[11px]">
                  <span className="text-muted-foreground">Ransomware Use:</span>
                  <span
                    className={`font-semibold ${
                      cisa_kev.known_ransomware_use.toLowerCase().includes('known')
                        ? 'text-red-400'
                        : 'text-zinc-400'
                    }`}
                  >
                    {cisa_kev.known_ransomware_use}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-4 flex items-center justify-between border-t border-border pt-3 text-[11px] text-muted-foreground">
          <span>Due Date:</span>
          <span className="font-mono text-zinc-300">{cisa_kev.due_date || 'N/A'}</span>
        </div>
      </div>
    </div>
  );
};
