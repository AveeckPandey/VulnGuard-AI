import React from 'react';
import { Shield, Activity, Wifi } from 'lucide-react';

interface HeaderProps {
  isLiveMode: boolean;
  setIsLiveMode: (live: boolean) => void;
  systemHealth: string | null;
  intelFeeds: any;
}

export const Header: React.FC<HeaderProps> = ({
  isLiveMode,
  setIsLiveMode,
  systemHealth,
  intelFeeds,
}) => {
  const isHealthy = systemHealth === 'healthy';
  const kevCount = intelFeeds?.feeds?.cisa_kev?.known_exploited_cves_count || 0;

  return (
    <header className="border-b border-border bg-[#0b1120]/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div className="flex items-center space-x-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-500 rounded-full border-2 border-background animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white via-slate-200 to-sky-400 bg-clip-text text-transparent">
                VulnGuard AI
              </span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                Nova AI
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              AI-Powered CVE Intelligence & Deterministic Prioritization
            </p>
          </div>
        </div>

        {/* Live Intel Feeds & Status */}
        <div className="flex items-center space-x-3 sm:space-x-5">
          {/* Feed Pills */}
          <div className="hidden md:flex items-center space-x-2 text-xs">
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700/50 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              <span>NVD 2.0</span>
            </div>
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700/50 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>EPSS v3</span>
            </div>
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700/50 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
              <span>KEV ({kevCount > 0 ? kevCount : '1.7k+'})</span>
            </div>
          </div>

          {/* Mode Switcher */}
          <button
            onClick={() => setIsLiveMode(!isLiveMode)}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
              isLiveMode
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
            title="Toggle between Live Upstream APIs and Offline Demo Fixtures"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>{isLiveMode ? 'LIVE MODE' : 'DEMO MODE'}</span>
          </button>

          {/* Health Indicator */}
          <div
            className={`flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-lg border ${
              isHealthy
                ? 'bg-slate-800/60 border-slate-700 text-slate-300'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
            }`}
          >
            <Wifi className={`w-3.5 h-3.5 ${isHealthy ? 'text-emerald-400' : 'text-red-400 animate-pulse'}`} />
            <span className="hidden sm:inline">{isHealthy ? 'API Online' : 'Connecting...'}</span>
          </div>
        </div>
      </div>
    </header>
  );
};
