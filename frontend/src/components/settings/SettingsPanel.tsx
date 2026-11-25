import React, { useState } from 'react';
import { apiClient } from '../../api/client';
import { UserProfile } from '../../types/auth';
import {
  Settings,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  UserCheck,
  Lock,
  LogOut,
  Activity,
  Sliders,
  Wifi,
} from 'lucide-react';

interface SettingsPanelProps {
  systemHealth: any;
  intelFeeds: any;
  onRefresh: () => void;
  isRefreshing: boolean;
  user: UserProfile | null;
  isLiveMode: boolean;
  setIsLiveMode: (live: boolean) => void;
  onOpenAuthModal: () => void;
  onSignOut: () => void;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({
  systemHealth,
  intelFeeds,
  onRefresh,
  isRefreshing,
  user,
  isLiveMode,
  setIsLiveMode,
  onOpenAuthModal,
  onSignOut,
}) => {
  const [testResult, setTestResult] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState<boolean>(false);

  const feeds = intelFeeds?.feeds || {};
  const nvd = feeds.nist_nvd || {};
  const epss = feeds.first_epss || {};
  const kev = feeds.cisa_kev || {};

  const isHealthy = systemHealth?.status === 'healthy';
  const isConnecting = !systemHealth?.status;

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult('Checking service availability...');
    const start = performance.now();
    try {
      const data = await apiClient.getHealth();
      const latency = Math.round(performance.now() - start);
      setTestResult(`Connected (${latency} ms) · Service status: ${data.status}`);
    } catch (e: any) {
      setTestResult(`Connection failed: ${e.message}`);
    } finally {
      setIsTesting(false);
    }
  };

  const scoringWeights = [
    { label: 'CVSS Base Severity', weight: '30%' },
    { label: 'FIRST EPSS Probability', weight: '30%' },
    { label: 'CISA KEV Exploitation Status', weight: '20%' },
    { label: 'Asset Business Criticality', weight: '10%' },
    { label: 'Network Perimeter Exposure', weight: '10%' },
  ];

  return (
    <div className="space-y-5">
      {/* Top Banner */}
      <div className="surface-panel flex flex-col items-start justify-between gap-4 rounded-2xl p-6 md:flex-row md:items-center">
        <div>
          <div className="flex items-center gap-2">
            <Settings className="size-4 text-sky-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              Workspace &amp; Feed Settings
            </h2>
          </div>
          <p className="mt-1.5 max-w-2xl text-[13px] leading-relaxed text-muted-foreground">
            Manage your workspace session, analysis feed mode, and live threat intelligence source health.
          </p>
        </div>

        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl border border-border bg-white/[0.04] px-4 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08] disabled:opacity-50"
        >
          <RefreshCw className={`size-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh Feed Status</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Card 1: Workspace Session */}
        <div className="surface-panel flex flex-col justify-between space-y-5 rounded-2xl p-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.04] text-sky-400">
                  {user ? <UserCheck className="size-4" /> : <Lock className="size-4" />}
                </div>
                <h3 className="text-sm font-semibold text-foreground">Workspace Account</h3>
              </div>
              <span
                className={`rounded-md border px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                  user
                    ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
                    : 'border-border bg-white/[0.04] text-muted-foreground'
                }`}
              >
                {user ? (user.isDemo ? 'DEMO' : 'SIGNED IN') : 'GUEST'}
              </span>
            </div>

            {user ? (
              <div className="surface-subpanel flex items-center gap-3.5 rounded-xl p-4">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
                  {(user.name || user.username).charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-foreground">
                    {user.name || user.username}
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {user.email || 'Authenticated session'}
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-[13.5px] leading-relaxed text-zinc-300">
                Sign in to save vulnerability assessments and access your private assessment history across sessions.
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2.5 border-t border-border pt-4">
            {user ? (
              <>
                <button
                  type="button"
                  onClick={onOpenAuthModal}
                  className="inline-flex h-9 items-center gap-2 rounded-xl border border-border bg-white/[0.04] px-4 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.08]"
                >
                  <UserCheck className="size-3.5 text-muted-foreground" />
                  <span>Switch Account</span>
                </button>
                <button
                  type="button"
                  onClick={onSignOut}
                  className="inline-flex h-9 items-center gap-2 rounded-xl border border-red-500/25 bg-red-500/10 px-4 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20"
                >
                  <LogOut className="size-3.5" />
                  <span>Sign Out</span>
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={onOpenAuthModal}
                className="inline-flex h-9 items-center gap-2 rounded-xl bg-primary px-4 text-xs font-semibold text-primary-foreground transition-opacity hover:opacity-90"
              >
                <Lock className="size-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>
        </div>

        {/* Card 2: Analysis Mode & Service Availability */}
        <div className="surface-panel flex flex-col justify-between space-y-5 rounded-2xl p-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.04] text-emerald-400">
                  <Activity className="size-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Analysis Data Mode &amp; Health</h3>
              </div>
              <span
                className={`flex items-center gap-1 rounded-md border px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                  isHealthy
                    ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
                    : isConnecting
                    ? 'border-border bg-white/[0.04] text-muted-foreground'
                    : 'border-red-500/25 bg-red-500/10 text-red-400'
                }`}
              >
                <CheckCircle2 className="size-3" />
                <span>{isHealthy ? 'ONLINE' : isConnecting ? 'CONNECTING' : 'OFFLINE'}</span>
              </span>
            </div>

            <div className="space-y-2">
              <span className="block text-xs font-medium text-muted-foreground">
                Intelligence Source Mode
              </span>
              <div className="grid grid-cols-2 gap-1.5 rounded-xl border border-border bg-background p-1">
                <button
                  type="button"
                  onClick={() => setIsLiveMode(true)}
                  className={`rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                    isLiveMode
                      ? 'border border-emerald-500/30 bg-emerald-500/15 text-emerald-300'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  Live Feeds
                </button>
                <button
                  type="button"
                  onClick={() => setIsLiveMode(false)}
                  className={`rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                    !isLiveMode
                      ? 'border border-amber-500/30 bg-amber-500/15 text-amber-300'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  Demo Fixtures
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                {isLiveMode
                  ? 'Queries live NVD, EPSS, and CISA KEV threat intelligence sources.'
                  : 'Uses deterministic offline reference fixtures without external network calls.'}
              </p>
            </div>
          </div>

          <div className="space-y-2 border-t border-border pt-4">
            <button
              type="button"
              onClick={handleTestConnection}
              disabled={isTesting}
              className="flex h-9 w-full items-center justify-center gap-2 rounded-xl border border-border bg-white/[0.04] px-3 text-xs font-medium text-zinc-200 transition-colors hover:bg-white/[0.08] hover:text-foreground disabled:opacity-50"
            >
              <Wifi className="size-3.5 text-muted-foreground" />
              <span>Test Service Connectivity</span>
            </button>
            {testResult && (
              <p className="rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-zinc-200">
                {testResult}
              </p>
            )}
          </div>
        </div>

        {/* Card 3: Threat Intelligence Feeds */}
        <div className="surface-panel space-y-4 rounded-2xl p-6">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2.5">
              <div className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.04] text-sky-400">
                <ShieldCheck className="size-4" />
              </div>
              <h3 className="text-sm font-semibold text-foreground">Threat Intelligence Feeds</h3>
            </div>
            <span
              className={`rounded-md px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                intelFeeds?.status === 'operational'
                  ? 'border border-emerald-500/25 bg-emerald-500/10 text-emerald-400'
                  : 'border border-amber-500/25 bg-amber-500/10 text-amber-400'
              }`}
            >
              {intelFeeds?.status ? intelFeeds.status.toUpperCase() : 'OPERATIONAL'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="surface-subpanel flex items-center justify-between rounded-xl p-3.5">
              <div>
                <div className="flex items-center gap-2">
                  <p className="text-[13px] font-semibold text-foreground">NIST NVD API 2.0</p>
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10.5px] ${
                      nvd.status === 'operational'
                        ? 'bg-emerald-500/10 text-emerald-400'
                        : 'bg-amber-500/10 text-amber-400'
                    }`}
                  >
                    {nvd.status || 'operational'}
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">CVSS Metrics &amp; CWEs</p>
                {nvd.last_error && (
                  <p className="mt-1 font-mono text-[11px] text-amber-300">Note: {nvd.last_error}</p>
                )}
              </div>
              <div className="text-right font-mono text-xs">
                <span className="block font-semibold text-foreground">{nvd.cached_items || 0} Cached</span>
                <span className="text-[11px] text-muted-foreground">TTL: {nvd.ttl_hours || 12}h</span>
              </div>
            </div>

            <div className="surface-subpanel flex items-center justify-between rounded-xl p-3.5">
              <div>
                <p className="text-[13px] font-semibold text-foreground">FIRST.org EPSS v3</p>
                <p className="mt-1 text-xs text-muted-foreground">30-Day Exploit Probability &amp; Percentile</p>
              </div>
              <div className="text-right font-mono text-xs">
                <span className="block font-semibold text-foreground">{epss.cached_items || 0} Cached</span>
                <span className="text-[11px] text-muted-foreground">TTL: {epss.ttl_hours || 24}h</span>
              </div>
            </div>

            <div className="surface-subpanel flex items-center justify-between rounded-xl p-3.5">
              <div>
                <p className="text-[13px] font-semibold text-foreground">CISA KEV Catalog</p>
                <p className="mt-1 text-xs text-muted-foreground">Known Exploited Vulnerabilities Feed</p>
              </div>
              <div className="text-right font-mono text-xs">
                <span className="block font-semibold text-red-400">
                  {kev.known_exploited_cves_count || 1790} Active CVEs
                </span>
                <span className="text-[11px] text-muted-foreground">TTL: {kev.ttl_hours || 6}h</span>
              </div>
            </div>
          </div>
        </div>

        {/* Card 4: Risk Scoring & Remediation Methodology */}
        <div className="surface-panel space-y-4 rounded-2xl p-6">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2.5">
              <div className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.04] text-amber-400">
                <Sliders className="size-4" />
              </div>
              <h3 className="text-sm font-semibold text-foreground">Risk Prioritization Model</h3>
            </div>
            <span className="rounded-md border border-border bg-white/[0.04] px-2.5 py-0.5 font-mono text-[11px] font-semibold text-zinc-300">
              0–100 SCALE
            </span>
          </div>

          <div className="space-y-2 text-[13px]">
            {scoringWeights.map((item) => (
              <div
                key={item.label}
                className="flex items-center justify-between border-b border-border py-2 last:border-b-0"
              >
                <span className="text-zinc-200">{item.label}</span>
                <span className="font-mono font-semibold text-foreground">{item.weight}</span>
              </div>
            ))}
          </div>

          <div className="surface-subpanel rounded-xl p-3.5 text-xs leading-relaxed text-zinc-300">
            Remediation guidance is generated with evidence citations and backed by deterministic fallback rules whenever AI inference is unreachable.
          </div>
        </div>
      </div>
    </div>
  );
};
