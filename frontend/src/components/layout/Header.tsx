import React, { useState, useRef, useEffect } from 'react';
import {
  Activity,
  RefreshCw,
  Menu,
  X,
  LogOut,
  ChevronDown,
  UserCheck,
  Lock,
} from 'lucide-react';
import { TabType } from './Sidebar';
import { UserProfile } from '../../types/auth';

interface HeaderProps {
  activeTab: TabType;
  isLiveMode: boolean;
  setIsLiveMode: (live: boolean) => void;
  systemHealth: string | null;
  intelFeeds: any;
  onRefresh: () => void;
  isRefreshing?: boolean;
  mobileMenuOpen?: boolean;
  setMobileMenuOpen?: (open: boolean) => void;
  user: UserProfile | null;
  onOpenAuthModal: () => void;
  onSignOut: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  isLiveMode,
  setIsLiveMode,
  systemHealth,
  intelFeeds,
  onRefresh,
  isRefreshing = false,
  mobileMenuOpen = false,
  setMobileMenuOpen,
  user,
  onOpenAuthModal,
  onSignOut,
}) => {
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [statusMenuOpen, setStatusMenuOpen] = useState(false);
  const accountMenuRef = useRef<HTMLDivElement>(null);
  const statusMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (accountMenuRef.current && !accountMenuRef.current.contains(e.target as Node)) {
        setAccountMenuOpen(false);
      }
      if (statusMenuRef.current && !statusMenuRef.current.contains(e.target as Node)) {
        setStatusMenuOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setAccountMenuOpen(false);
        setStatusMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const isHealthy = systemHealth === 'healthy';
  const isConnecting = systemHealth === null || systemHealth === undefined;
  const kevCount = intelFeeds?.feeds?.cisa_kev?.known_exploited_cves_count || 1790;
  const nvdFeed = intelFeeds?.feeds?.nist_nvd;
  const epssFeed = intelFeeds?.feeds?.first_epss;
  const kevFeed = intelFeeds?.feeds?.cisa_kev;

  const getFeedDotColor = (status?: string) => {
    if (!status || status === 'operational') return 'bg-emerald-400';
    if (status === 'rate_limited' || status === 'degraded' || status === 'uninitialized') return 'bg-amber-400';
    return 'bg-red-400';
  };

  const overallStatusDot = isConnecting
    ? 'bg-zinc-400 animate-pulse'
    : isHealthy
    ? 'bg-emerald-400'
    : 'bg-red-400 animate-pulse';

  const overallStatusText = isConnecting
    ? 'Connecting...'
    : isHealthy
    ? 'Feeds & API Online'
    : 'Offline';

  const pageTitles: Record<TabType, string> = {
    overview: 'Security Operations Overview',
    workspace: 'Personal Assessment Workspace',
    analyzer: 'CVE Intelligence & Prioritization',
    history: 'Assessment Audit Log',
    analytics: 'Vulnerability Risk Analytics',
    settings: 'Workspace & Feed Settings',
  };

  const currentTitle = pageTitles[activeTab] || pageTitles.overview;

  return (
    <header className="sticky top-0 z-30 h-[52px] shrink-0 border-b border-border bg-background/85 backdrop-blur-md">
      <div className="flex h-full items-center justify-between gap-3 px-4 sm:px-6">
        {/* Left: Mobile Trigger + Active Page Title */}
        <div className="flex min-w-0 items-center gap-3">
          {setMobileMenuOpen && (
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.03] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground lg:hidden"
              aria-label="Toggle Navigation"
            >
              {mobileMenuOpen ? <X className="size-4" /> : <Menu className="size-4" />}
            </button>
          )}

          <h1 className="truncate text-[13.5px] font-semibold tracking-tight text-foreground">
            {currentTitle}
          </h1>
        </div>

        {/* Right: Consolidated Status Popover, Refresh, Mode Switch, Account */}
        <div className="flex shrink-0 items-center gap-2">
          {/* Consolidated Feeds & API Status Indicator */}
          <div className="relative" ref={statusMenuRef}>
            <button
              type="button"
              onClick={() => {
                setStatusMenuOpen((prev) => !prev);
                setAccountMenuOpen(false);
              }}
              aria-expanded={statusMenuOpen}
              className={`flex h-8 items-center gap-2 rounded-lg border px-2.5 text-[11px] font-medium transition-colors ${
                isConnecting || isHealthy
                  ? 'border-border bg-white/[0.02] text-zinc-300 hover:bg-white/[0.05] hover:text-foreground'
                  : 'border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/15'
              }`}
              title="Inspect API & Threat Feed Status"
            >
              <span className={`size-1.5 rounded-full ${overallStatusDot}`} />
              <span className="hidden sm:inline">{overallStatusText}</span>
              <ChevronDown className="size-3 text-muted-foreground" />
            </button>

            {statusMenuOpen && (
              <div className="absolute right-0 z-50 mt-2 w-72 rounded-xl border border-border bg-popover p-3 text-xs shadow-2xl">
                <div className="mb-2.5 flex items-center justify-between border-b border-border pb-2">
                  <span className="font-semibold text-foreground">System & Feed Telemetry</span>
                  <span className={`font-mono text-[10.5px] ${isHealthy ? 'text-emerald-400' : isConnecting ? 'text-muted-foreground' : 'text-red-400'}`}>
                    {isConnecting ? 'Connecting' : isHealthy ? 'API Online' : 'Offline'}
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between rounded-lg bg-white/[0.02] px-2.5 py-1.5">
                    <div className="flex items-center gap-2">
                      <span className={`size-1.5 rounded-full ${getFeedDotColor(nvdFeed?.status)}`} />
                      <span className="text-zinc-200">NIST NVD 2.0</span>
                    </div>
                    <span className="font-mono text-[10.5px] text-muted-foreground">
                      {nvdFeed?.status || 'operational'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg bg-white/[0.02] px-2.5 py-1.5">
                    <div className="flex items-center gap-2">
                      <span className={`size-1.5 rounded-full ${getFeedDotColor(epssFeed?.status)}`} />
                      <span className="text-zinc-200">FIRST EPSS v3</span>
                    </div>
                    <span className="font-mono text-[10.5px] text-muted-foreground">
                      {epssFeed?.status || 'operational'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg bg-white/[0.02] px-2.5 py-1.5">
                    <div className="flex items-center gap-2">
                      <span className={`size-1.5 rounded-full ${getFeedDotColor(kevFeed?.status)}`} />
                      <span className="text-zinc-200">CISA KEV</span>
                    </div>
                    <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
                      {kevFeed?.status || 'operational'} ({kevCount})
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="flex size-8 items-center justify-center rounded-lg border border-border bg-white/[0.02] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground disabled:opacity-50"
            title="Refresh Intelligence and Assessments"
          >
            <RefreshCw className={`size-3.5 ${isRefreshing ? 'animate-spin text-foreground' : ''}`} />
          </button>

          {/* Mode Switcher */}
          <button
            type="button"
            onClick={() => setIsLiveMode(!isLiveMode)}
            className={`flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[11px] font-medium transition-colors ${
              isLiveMode
                ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/15'
                : 'border-amber-500/25 bg-amber-500/10 text-amber-400 hover:bg-amber-500/15'
            }`}
            title="Toggle between Live Upstream Feeds and Simulated Offline Fixtures"
          >
            <Activity className="size-3.5" />
            <span className="hidden sm:inline">{isLiveMode ? 'LIVE' : 'DEMO'}</span>
          </button>

          {/* Account Menu / Profile Button */}
          <div className="relative" ref={accountMenuRef}>
            {user ? (
              <div>
                <button
                  type="button"
                  onClick={() => {
                    setAccountMenuOpen((prev) => !prev);
                    setStatusMenuOpen(false);
                  }}
                  className="flex h-8 items-center gap-2 rounded-lg border border-border bg-white/[0.03] px-2.5 text-xs text-foreground transition-colors hover:bg-white/[0.06]"
                >
                  <div className="flex size-5 items-center justify-center rounded-full bg-white text-[10.5px] font-semibold text-zinc-950">
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <span className="hidden max-w-[110px] truncate font-medium sm:inline">
                    {user.name || user.username}
                  </span>
                  <ChevronDown className="size-3.5 text-muted-foreground" />
                </button>

                {accountMenuOpen && (
                  <div className="absolute right-0 z-50 mt-2 w-64 rounded-xl border border-border bg-popover py-1.5 text-xs shadow-2xl">
                    <div className="border-b border-border px-3.5 py-2.5">
                      <div className="truncate font-semibold text-foreground">{user.name || user.username}</div>
                      <div className="truncate text-[11px] text-muted-foreground">{user.email || 'Signed in'}</div>
                    </div>

                    <div className="p-1">
                      <button
                        type="button"
                        onClick={() => {
                          setAccountMenuOpen(false);
                          onOpenAuthModal();
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-zinc-300 transition-colors hover:bg-white/[0.05] hover:text-foreground"
                      >
                        <UserCheck className="size-3.5 text-muted-foreground" />
                        <span>Switch Account</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setAccountMenuOpen(false);
                          onSignOut();
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-red-400 transition-colors hover:bg-red-500/10"
                      >
                        <LogOut className="size-3.5" />
                        <span>Sign Out</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <button
                type="button"
                onClick={onOpenAuthModal}
                className="flex h-8 items-center gap-1.5 rounded-lg bg-primary px-3 text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
              >
                <Lock className="size-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
