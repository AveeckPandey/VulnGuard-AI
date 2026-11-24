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
    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      {/* 1. NIST NVD Card */}
      <div className="p-5 rounded-2xl bg-card border border-border flex flex-col justify-between hover:border-slate-700 transition-all shadow-md">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              NIST NVD Intelligence
            </span>
            <a
              href={nvd.source_url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1"
            >
              <span>NVD 2.0</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <div className="mt-4 flex items-baseline space-x-3">
            <span className="text-3xl font-extrabold font-mono text-white">
              {nvd.cvss_base_score !== null ? nvd.cvss_base_score.toFixed(1) : 'N/A'}
            </span>
            <span
              className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                nvd.cvss_severity === 'CRITICAL'
                  ? 'bg-red-500/10 text-red-400 border-red-500/30'
                  : nvd.cvss_severity === 'HIGH'
                  ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                  : nvd.cvss_severity === 'MEDIUM'
                  ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                  : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
              }`}
            >
              {nvd.cvss_severity || 'UNKNOWN'}
            </span>
            <span className="text-xs text-slate-400">{nvd.cvss_version ? `CVSS v${nvd.cvss_version}` : 'CVSS unavailable'}</span>
          </div>

          <p className="text-xs text-slate-300 mt-3 line-clamp-3 leading-relaxed">
            {nvd.description || 'No description available from upstream feed.'}
          </p>

          {/* Weaknesses */}
          {nvd.weaknesses.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1">
              {Array.from(new Set(nvd.weaknesses)).map((cwe, idx) => (
                <span
                  key={`${cwe}-${idx}`}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
                >
                  {cwe}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
          <span>Vector:</span>
          <span className="font-mono text-slate-400 truncate max-w-[180px]" title={nvd.cvss_vector_string || 'N/A'}>
            {nvd.cvss_vector_string || 'N/A'}
          </span>
        </div>
      </div>

      {/* 2. FIRST EPSS Card */}
      <div className="p-5 rounded-2xl bg-card border border-border flex flex-col justify-between hover:border-slate-700 transition-all shadow-md">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              FIRST EPSS Probability
            </span>
            <a
              href={epss.source_url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1"
            >
              <span>FIRST.org</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <div className="mt-4 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono text-white">
              {formatProbability(epss.epss_probability)}
            </span>
            <span className="text-xs text-slate-400">next 30-day exploit likelihood</span>
          </div>

          {/* Progress Bar for EPSS */}
          <div className="mt-3 w-full bg-slate-800 h-2.5 rounded-full overflow-hidden border border-slate-700">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                (epss.epss_probability || 0) > 0.5
                  ? 'bg-red-500'
                  : (epss.epss_probability || 0) > 0.15
                  ? 'bg-orange-500'
                  : 'bg-sky-500'
              }`}
              style={{ width: `${Math.min(100, (epss.epss_probability || 0) * 100)}%` }}
            />
          </div>

          {/* Separate Percentile Display */}
          <div className="mt-4 p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-sky-400" />
              <span className="text-xs text-slate-300 font-medium">Percentile Ranking</span>
            </div>
            <span className="text-xs font-mono font-bold text-sky-300">
              {formatPercentile(epss.epss_percentile)}
            </span>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
          <span>Model Date:</span>
          <span className="text-slate-300 font-mono">{epss.model_date || 'Unknown'}</span>
        </div>
      </div>

      {/* 3. CISA KEV Card */}
      <div className="p-5 rounded-2xl bg-card border border-border flex flex-col justify-between hover:border-slate-700 transition-all shadow-md">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              CISA KEV Exploitation
            </span>
            <a
              href={cisa_kev.source_url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1"
            >
              <span>CISA.gov</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          {/* Status Badge */}
          <div className="mt-4">
            {cisa_kev.is_known_exploited ? (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 flex items-center space-x-2.5 shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-pulse">
                <Flame className="w-5 h-5 text-red-500 shrink-0" />
                <div>
                  <p className="text-xs font-black uppercase tracking-wider">Actively Weaponized in Wild</p>
                  <p className="text-[11px] text-red-300/80">Listed in Federal KEV Catalog</p>
                </div>
              </div>
            ) : cisa_kev.status === 'CONFIRMED_NEGATIVE' ? (
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center space-x-2.5">
                <CheckCircle className="w-5 h-5 text-emerald-500 shrink-0" />
                <div>
                  <p className="text-xs font-bold uppercase tracking-wider">Confirmed Negative</p>
                  <p className="text-[11px] text-emerald-300/80">Not listed in active KEV catalog</p>
                </div>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-slate-800/80 border border-slate-700 text-slate-400 flex items-center space-x-2.5">
                <HelpCircle className="w-5 h-5 text-slate-400 shrink-0" />
                <div>
                  <p className="text-xs font-bold uppercase tracking-wider">Status Unverified</p>
                  <p className="text-[11px] text-slate-400">Catalog unreachable or pending sync</p>
                </div>
              </div>
            )}
          </div>

          {/* KEV Metadata if available */}
          {cisa_kev.is_known_exploited && (
            <div className="mt-3 space-y-1.5 text-xs">
              {cisa_kev.vulnerability_name && (
                <p className="text-slate-300 font-medium line-clamp-1">
                  {cisa_kev.vulnerability_name}
                </p>
              )}
              {cisa_kev.required_action && (
                <p className="text-slate-400 text-[11px] line-clamp-2">
                  <strong className="text-slate-300">Mandate:</strong> {cisa_kev.required_action}
                </p>
              )}
              {cisa_kev.known_ransomware_use && (
                <div className="flex items-center space-x-1.5 text-[11px]">
                  <span className="text-slate-400">Ransomware Use:</span>
                  <span
                    className={`font-semibold ${
                      cisa_kev.known_ransomware_use.toLowerCase().includes('known')
                        ? 'text-red-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {cisa_kev.known_ransomware_use}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
          <span>Due Date:</span>
          <span className="text-slate-300 font-mono">{cisa_kev.due_date || 'N/A'}</span>
        </div>
      </div>
    </div>
  );
};
