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
  Settings,
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
  onOpenSettings?: () => void;
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
  onOpenSettings,
  onSignOut,
}) => {
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const accountMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (accountMenuRef.current && !accountMenuRef.current.contains(e.target as Node)) {
        setAccountMenuOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setAccountMenuOpen(false);
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
  const feedRows = [
    { name: 'NIST NVD 2.0', status: intelFeeds?.feeds?.nist_nvd?.status },
    { name: 'FIRST EPSS v3', status: intelFeeds?.feeds?.first_epss?.status },
    {
      name: 'CISA KEV',
      status: intelFeeds?.feeds?.cisa_kev?.status,
      suffix: ` (${kevCount})`,
    },
  ];

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
    : 'API Offline';

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

        {/* Right: Single Account / Sign-In Trigger (Feeds, Refresh & Mode live inside Account menu) */}
        <div className="relative flex shrink-0 items-center" ref={accountMenuRef}>
          {user ? (
            <div>
              <button
                type="button"
                onClick={() => setAccountMenuOpen((prev) => !prev)}
                aria-expanded={accountMenuOpen}
                className="flex h-8 items-center gap-2 rounded-lg border border-border bg-white/[0.03] px-2.5 text-xs text-foreground transition-colors hover:bg-white/[0.06]"
              >
                <div className="flex size-5 items-center justify-center rounded-full bg-white text-[10.5px] font-semibold text-zinc-950">
                  {(user.name || user.username).charAt(0).toUpperCase()}
                </div>
                <span className="hidden max-w-[200px] truncate font-medium sm:inline">
                  {user.email || user.name || user.username}
                </span>
                <ChevronDown className="size-3.5 text-muted-foreground" />
              </button>

              {accountMenuOpen && (
                <div className="absolute right-0 z-50 mt-2 w-72 rounded-xl border border-border bg-popover py-1.5 text-xs shadow-2xl">
                  {/* Identity */}
                  <div className="border-b border-border px-3.5 py-2.5">
                    <div className="truncate font-semibold text-foreground">{user.name || user.username}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{user.email || 'Signed in'}</div>
                  </div>

                  {/* Consolidated Feeds & API Status + Refresh + Data Mode */}
                  <div className="space-y-2 border-b border-border px-3.5 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`size-1.5 rounded-full ${overallStatusDot}`} />
                        <span className="font-medium text-foreground">{overallStatusText}</span>
                      </div>
                      <button
                        type="button"
                        onClick={onRefresh}
                        disabled={isRefreshing}
                        title="Refresh Feeds & Assessments"
                        aria-label="Refresh Feeds and Assessments"
                        className="flex size-6 items-center justify-center rounded-md border border-border bg-white/[0.03] text-muted-foreground transition-colors hover:bg-white/[0.08] hover:text-foreground disabled:opacity-50"
                      >
                        <RefreshCw className={`size-3 ${isRefreshing ? 'animate-spin text-foreground' : ''}`} />
                      </button>
                    </div>

                    <div className="space-y-1">
                      {feedRows.map((feed) => (
                        <div
                          key={feed.name}
                          className="flex items-center justify-between rounded-lg bg-white/[0.025] px-2.5 py-1 text-[11px]"
                        >
                          <span className="flex items-center gap-2 text-zinc-300">
                            <span className={`size-1.5 rounded-full ${getFeedDotColor(feed.status)}`} />
                            <span>{feed.name}</span>
                          </span>
                          <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
                            {feed.status || 'operational'}
                            {feed.suffix || ''}
                          </span>
                        </div>
                      ))}
                    </div>

                    <button
                      type="button"
                      onClick={() => setIsLiveMode(!isLiveMode)}
                      className="flex w-full items-center justify-between rounded-lg border border-border bg-white/[0.02] px-2.5 py-1.5 text-left transition-colors hover:bg-white/[0.05]"
                      title="Toggle between Live Upstream Feeds and Simulated Offline Fixtures"
                    >
                      <span className="flex items-center gap-2 text-zinc-300">
                        <Activity className="size-3.5 text-muted-foreground" />
                        <span>Feed Mode</span>
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                          isLiveMode
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-amber-500/15 text-amber-400'
                        }`}
                      >
                        {isLiveMode ? 'LIVE' : 'DEMO'}
                      </span>
                    </button>
                  </div>

                  {/* Account Actions */}
                  <div className="p-1">
                    {onOpenSettings && (
                      <button
                        type="button"
                        onClick={() => {
                          setAccountMenuOpen(false);
                          onOpenSettings();
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-zinc-300 transition-colors hover:bg-white/[0.05] hover:text-foreground"
                      >
                        <Settings className="size-3.5 text-muted-foreground" />
                        <span>Settings</span>
                      </button>
                    )}

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
    </header>
  );
};
