import React from 'react';
import { Crosshair, History, Cpu, Flame, ShieldAlert, AlertTriangle } from 'lucide-react';

interface SidebarProps {
  activeTab: 'triage' | 'history' | 'sources';
  setActiveTab: (tab: 'triage' | 'history' | 'sources') => void;
  onSelectPresetCve: (cveId: string, criticality: any, exposure: any, context: string) => void;
  historyCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  onSelectPresetCve,
  historyCount,
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
      cve: 'CVE-2023-38606',
      name: 'Apple Kernel State',
      icon: ShieldAlert,
      color: 'text-orange-400',
      criticality: 'HIGH',
      exposure: 'INTERNAL',
      context: 'Internal Corporate Mac Fleet iOS/macOS',
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

  return (
    <aside className="w-full lg:w-64 bg-[#0b1120] border-r border-border p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-6">
        {/* Navigation Tabs */}
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-3">
            Operations
          </span>
          <nav className="mt-2 space-y-1">
            <button
              onClick={() => setActiveTab('triage')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'triage'
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Crosshair className="w-4 h-4" />
                <span>Triage & Prioritize</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'history'
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center space-x-3">
                <History className="w-4 h-4" />
                <span>Assessments Log</span>
              </div>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                {historyCount}
              </span>
            </button>
          </nav>
        </div>

        {/* Quick Investigation Presets */}
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-3 flex items-center justify-between">
            <span>Quick CVE Presets</span>
            <span className="text-[10px] text-sky-400 lowercase font-normal">click to test</span>
          </span>
          <div className="mt-2 space-y-1.5">
            {presets.map((preset) => {
              const Icon = preset.icon;
              return (
                <button
                  key={preset.cve}
                  onClick={() => {
                    setActiveTab('triage');
                    onSelectPresetCve(preset.cve, preset.criticality, preset.exposure, preset.context);
                  }}
                  className="w-full text-left p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-800/50 transition-all group"
                >
                  <div className="flex items-center space-x-2">
                    <Icon className={`w-3.5 h-3.5 ${preset.color} shrink-0`} />
                    <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-sky-300">
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

      {/* Architecture Footer */}
      <div className="pt-4 border-t border-slate-800/80">
        <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400 space-y-1.5">
          <div className="flex items-center space-x-2 text-slate-300 font-medium">
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            <span>LangGraph & AWS Bedrock</span>
          </div>
          <p className="text-[11px] leading-tight text-slate-400">
            Powered by Amazon Nova models, deterministic heuristic scoring, and DynamoDB.
          </p>
        </div>
      </div>
    </aside>
  );
};
