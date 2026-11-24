import React from 'react';
import {
  LayoutDashboard,
  UserCheck,
  Crosshair,
  History,
  BarChart3,
  Settings,
  Flame,
  ShieldAlert,
  AlertTriangle,
  Database,
  Cpu,
  Lock,
} from 'lucide-react';
import { UserProfile } from '../../types/auth';

export type TabType = 'overview' | 'workspace' | 'analyzer' | 'history' | 'analytics' | 'settings';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  onSelectPresetCve: (cveId: string, criticality: any, exposure: any, context: string) => void;
  historyCount: number;
  user: UserProfile | null;
  onOpenAuthModal: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  onSelectPresetCve,
  historyCount,
  user,
  onOpenAuthModal,
}) => {
  const presets = [
    {
      cve: 'CVE-2021-44228',
      name: 'Log4Shell (RCE)',
      icon: Flame,
      color: 'text-red-400',
      criticality: 'CRITICAL',
      exposure: 'PUBLIC_FACING',
      context: 'Public Edge API Gateway with Log4j 2.14.0',
    },
    {
      cve: 'CVE-2023-34362',
      name: 'MOVEit SQL Injection',
      icon: ShieldAlert,
      color: 'text-orange-400',
      criticality: 'HIGH',
      exposure: 'PUBLIC_FACING',
      context: 'Public Managed File Transfer Web Application',
    },
    {
      cve: 'CVE-2024-3094',
      name: 'XZ Utils Backdoor',
      icon: AlertTriangle,
      color: 'text-amber-400',
      criticality: 'CRITICAL',
      exposure: 'PUBLIC_FACING',
      context: 'Linux Production SSH Build Servers',
    },
  ];

  const navItems = [
    { id: 'overview' as TabType, label: 'Overview', icon: LayoutDashboard },
    { id: 'workspace' as TabType, label: 'My Workspace', icon: UserCheck, badge: user ? 'Active' : undefined },
    { id: 'analyzer' as TabType, label: 'CVE Analyzer', icon: Crosshair },
    { id: 'history' as TabType, label: 'Assessment History', icon: History, count: historyCount },
    { id: 'analytics' as TabType, label: 'Analytics', icon: BarChart3 },
    { id: 'settings' as TabType, label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-full lg:w-64 bg-[#080d19] border-r border-slate-800/80 p-4 flex flex-col justify-between shrink-0 h-full">
      <div className="space-y-6">
        {/* Navigation Tabs */}
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 px-3">
            Navigation
          </span>
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.count !== undefined && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                      {item.count}
                    </span>
                  )}
                  {item.badge && (
                    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Quick Investigation Presets */}
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 px-3 flex items-center justify-between">
            <span>Quick CVE Presets</span>
            <span className="text-[10px] text-cyan-400 lowercase font-normal">click to test</span>
          </span>
          <div className="mt-2 space-y-1.5">
            {presets.map((preset) => {
              const Icon = preset.icon;
              return (
                <button
                  key={preset.cve}
                  onClick={() => {
                    setActiveTab('analyzer');
                    onSelectPresetCve(preset.cve, preset.criticality, preset.exposure, preset.context);
                  }}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-cyan-500/30 hover:bg-slate-800/50 transition-all group"
                >
                  <div className="flex items-center space-x-2">
                    <Icon className={`w-3.5 h-3.5 ${preset.color} shrink-0`} />
                    <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-cyan-300">
                      {preset.cve}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 truncate pl-5">
                    {preset.name}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Account & Architecture Footer */}
      <div className="pt-4 border-t border-slate-800/80 space-y-2">
        {/* Active Persona / User Status Pill */}
        <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
          {user ? (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase font-bold text-slate-400">Signed In</span>
                <span className="text-[10px] font-mono text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                  {user.isDemo ? 'Demo' : 'Cognito'}
                </span>
              </div>
              <div className="font-semibold text-slate-200 truncate">{user.name || user.username}</div>
              <div className="text-[11px] text-slate-400 truncate font-mono">{user.sub}</div>
            </div>
          ) : (
            <div className="space-y-2 text-center">
              <div className="flex items-center justify-center space-x-1.5 text-slate-400">
                <Lock className="w-3.5 h-3.5" />
                <span className="text-xs">Guest Mode</span>
              </div>
              <button
                onClick={onOpenAuthModal}
                className="w-full py-1.5 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 font-semibold text-xs border border-sky-500/40 transition-all"
              >
                Sign In / Switch
              </button>
            </div>
          )}
        </div>

        <div className="p-2.5 rounded-xl bg-slate-900/40 border border-slate-800/60 text-xs text-slate-400 space-y-1">
          <div className="flex items-center space-x-2 text-slate-300 text-[11px]">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>NVIDIA Nemotron Guardrailed</span>
          </div>
          <div className="flex items-center space-x-2 text-[11px] text-slate-400">
            <Database className="w-3 h-3 text-emerald-400 shrink-0" />
            <span>DynamoDB UserHistoryIndex</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
