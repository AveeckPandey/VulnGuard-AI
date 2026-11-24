import React, { useState } from 'react';
import {
  Shield,
  Activity,
  Wifi,
  RefreshCw,
  Menu,
  X,
  Cpu,
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

  const isHealthy = systemHealth === 'healthy';
  const isConnecting = systemHealth === null || systemHealth === undefined;
  const kevCount = intelFeeds?.feeds?.cisa_kev?.known_exploited_cves_count || 1790;
  const nvdFeed = intelFeeds?.feeds?.nist_nvd;
  const epssFeed = intelFeeds?.feeds?.first_epss;
  const kevFeed = intelFeeds?.feeds?.cisa_kev;

  const getFeedColor = (status?: string) => {
    if (!status || status === 'operational') return 'bg-emerald-400';
    if (status === 'rate_limited' || status === 'degraded') return 'bg-amber-400';
    return 'bg-red-400';
  };

  const pageTitles: Record<TabType, { title: string; subtitle: string }> = {
    overview: {
      title: 'Security Operations Overview',
      subtitle: 'Global vulnerability posture & threat telemetry',
    },
    workspace: {
      title: 'Personal Assessment Workspace',
      subtitle: 'Tenant-isolated triage telemetry & personal analytics',
    },
    analyzer: {
      title: 'CVE Intelligence & Prioritization',
      subtitle: 'Deterministic 0–100 risk scoring with NVIDIA Nemotron AI',
    },
    history: {
      title: 'Assessment Audit Log',
      subtitle: 'Persisted DynamoDB investigations & triage history',
    },
    analytics: {
      title: 'Vulnerability Risk Analytics',
      subtitle: 'Multi-factor risk distributions & exposure heatmaps',
    },
    settings: {
      title: 'System & Cloud Settings',
      subtitle: 'Threat intelligence cache, AI models & AWS infrastructure',
    },
  };

  const current = pageTitles[activeTab] || pageTitles.overview;

  return (
    <header className="border-b border-slate-800/80 bg-[#080d19]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Left: Mobile Menu Toggle + Brand + Page Title */}
        <div className="flex items-center space-x-3 sm:space-x-4">
          {setMobileMenuOpen && (
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-2 rounded-xl bg-slate-800/80 text-slate-300 hover:text-white"
              aria-label="Toggle Navigation"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          )}

          <div className="flex items-center space-x-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-500 rounded-full border-2 border-[#080d19] animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent">
                  VulnGuard AI
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex items-center space-x-1">
                  <Cpu className="w-2.5 h-2.5" />
                  <span>Nemotron</span>
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden xl:block">
                AI CVE Intelligence & Deterministic Prioritization
              </p>
            </div>
          </div>

          {/* Current Page Title Separator (Hidden on small mobile) */}
          <div className="hidden md:flex items-center space-x-2 pl-4 border-l border-slate-800">
            <div>
              <h2 className="text-sm font-bold text-slate-200">{current.title}</h2>
              <p className="text-[11px] text-slate-500">{current.subtitle}</p>
            </div>
          </div>
        </div>

        {/* Right: Live Intel Feeds, Mode, Account & Status */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          {/* Feed Pills */}
          <div className="hidden lg:flex items-center space-x-1.5 text-xs">
            <div
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300 cursor-default"
              title={nvdFeed?.last_error ? `NVD: ${nvdFeed.last_error}` : `NVD 2.0: ${nvdFeed?.status || 'operational'}`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${getFeedColor(nvdFeed?.status)} ${nvdFeed?.status === 'operational' ? 'animate-pulse' : ''}`} />
              <span>NVD 2.0</span>
            </div>
            <div
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300 cursor-default"
              title={epssFeed?.last_error ? `EPSS: ${epssFeed.last_error}` : `EPSS v3: ${epssFeed?.status || 'operational'}`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${getFeedColor(epssFeed?.status)}`} />
              <span>EPSS v3</span>
            </div>
            <div
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300 cursor-default"
              title={kevFeed?.last_error ? `CISA KEV: ${kevFeed.last_error}` : `CISA KEV: ${kevFeed?.status || 'operational'} (${kevCount} catalogued)`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${getFeedColor(kevFeed?.status)}`} />
              <span>CISA KEV ({kevCount})</span>
            </div>
          </div>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-xl bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-all disabled:opacity-50"
            title="Refresh Intelligence and Assessments"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          {/* Mode Switcher */}
          <button
            onClick={() => setIsLiveMode(!isLiveMode)}
            className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
              isLiveMode
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
            title="Toggle between Live Upstream Feeds and Simulated Offline Fixtures"
          >
            <Activity className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{isLiveMode ? 'LIVE' : 'DEMO'}</span>
          </button>

          {/* Health Indicator */}
          <div
            className={`flex items-center space-x-1.5 text-xs px-2.5 py-1.5 rounded-xl border ${
              isConnecting
                ? 'bg-slate-900/80 border-slate-800 text-slate-400'
                : isHealthy
                ? 'bg-slate-900/80 border-slate-800 text-slate-300'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
            }`}
            title={
              isConnecting
                ? 'Connecting to API...'
                : isHealthy
                ? 'FastAPI & DynamoDB Online'
                : 'Backend Unreachable'
            }
          >
            <Wifi
              className={`w-3.5 h-3.5 ${
                isConnecting
                  ? 'text-cyan-400 animate-pulse'
                  : isHealthy
                  ? 'text-emerald-400'
                  : 'text-red-400 animate-pulse'
              }`}
            />
            <span className="hidden sm:inline">
              {isConnecting ? 'Connecting...' : isHealthy ? 'API Online' : 'Offline'}
            </span>
          </div>

          {/* Account Menu / Profile Button */}
          <div className="relative">
            {user ? (
              <div>
                <button
                  onClick={() => setAccountMenuOpen(!accountMenuOpen)}
                  className="flex items-center space-x-2 px-2.5 py-1.5 rounded-xl bg-slate-900/80 border border-slate-700/80 hover:border-cyan-500/50 text-slate-200 transition-all text-xs"
                >
                  <div className="w-6 h-6 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white font-bold text-[11px]">
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <span className="hidden sm:inline font-semibold max-w-[110px] truncate">
                    {user.name || user.username}
                  </span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                </button>

                {accountMenuOpen && (
                  <div className="absolute right-0 mt-2 w-64 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-2xl py-2 z-50 text-xs animate-in fade-in duration-150">
                    <div className="px-4 py-2 border-b border-slate-800">
                      <div className="font-bold text-white truncate">{user.name || user.username}</div>
                      <div className="text-[11px] text-slate-400 truncate">{user.email || 'No email registered'}</div>
                      <div className="text-[10px] font-mono text-cyan-400 mt-1 truncate">
                        ID: {user.sub}
                      </div>
                    </div>

                    <div className="py-1">
                      <button
                        onClick={() => {
                          setAccountMenuOpen(false);
                          onOpenAuthModal();
                        }}
                        className="w-full text-left px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-800/60 flex items-center space-x-2 transition-all"
                      >
                        <UserCheck className="w-4 h-4 text-cyan-400" />
                        <span>Switch Persona / Auth</span>
                      </button>

                      <button
                        onClick={() => {
                          setAccountMenuOpen(false);
                          onSignOut();
                        }}
                        className="w-full text-left px-4 py-2 text-red-400 hover:bg-red-500/10 flex items-center space-x-2 transition-all"
                      >
                        <LogOut className="w-4 h-4" />
                        <span>Sign Out</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <button
                onClick={onOpenAuthModal}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs shadow-md shadow-sky-500/20 transition-all"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
