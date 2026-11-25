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
  Shield,
  Lock,
} from 'lucide-react';
import {
  Sidebar as PrimitiveSidebar,
  SidebarHeader,
  SidebarNav,
  SidebarSection,
  SidebarItem,
  SidebarNested,
  SidebarFooter,
  SidebarToggle,
  SidebarVariant,
  useSidebar,
} from '@/components/ui/sidebar';
import { UserProfile } from '../../types/auth';

export type TabType = 'overview' | 'workspace' | 'analyzer' | 'history' | 'analytics' | 'settings';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  onSelectPresetCve: (cveId: string, criticality: any, exposure: any, context: string) => void;
  historyCount: number;
  user: UserProfile | null;
  onOpenAuthModal: () => void;
  variant?: SidebarVariant;
}

function CountBadge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-md bg-[color-mix(in_srgb,var(--foreground)_7%,transparent)] px-1.5 py-0.5 text-[10.5px] font-medium leading-none text-[var(--muted-foreground)] tabular-nums">
      {children}
    </span>
  );
}

function StatusBadge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-md bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium leading-none text-emerald-400">
      {children}
    </span>
  );
}

function WorkspaceMark() {
  const { collapsed } = useSidebar();
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <div className="flex size-6 shrink-0 items-center justify-center rounded-[7px] bg-[color:var(--color-brand,var(--primary))] text-[color:var(--color-brand-foreground,var(--primary-foreground))]">
        <Shield className="size-3.5" strokeWidth={2.25} />
      </div>
      {!collapsed && (
        <span className="truncate text-[13.5px] font-semibold leading-none tracking-tight text-foreground">
          VulnGuard AI
        </span>
      )}
    </div>
  );
}

function UserFooter({
  user,
  onOpenAuthModal,
}: {
  user: UserProfile | null;
  onOpenAuthModal: () => void;
}) {
  const { collapsed } = useSidebar();

  if (user) {
    return (
      <button
        type="button"
        onClick={onOpenAuthModal}
        title={collapsed ? `${user.name || user.username} (${user.sub})` : 'Switch Persona / Auth'}
        className="flex w-full min-w-0 items-center gap-2.5 rounded-lg text-left transition-opacity hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div className="flex size-6 shrink-0 items-center justify-center rounded-full bg-white text-[11px] font-semibold text-zinc-950">
          {(user.name || user.username).charAt(0).toUpperCase()}
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <div className="flex items-center justify-between gap-1.5">
              <span className="truncate text-[12.5px] font-medium leading-tight text-foreground">
                {user.name || user.username}
              </span>
              <span className="shrink-0 rounded bg-white/[0.07] px-1.5 py-0.5 font-mono text-[9.5px] text-muted-foreground">
                {user.isDemo ? 'Demo' : 'Cognito'}
              </span>
            </div>
            <div className="truncate font-mono text-[10.5px] leading-tight text-muted-foreground">
              {user.sub}
            </div>
          </div>
        )}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={onOpenAuthModal}
      title={collapsed ? 'Guest Mode — Sign In / Switch' : undefined}
      className="flex w-full min-w-0 items-center gap-2.5 rounded-lg text-left transition-opacity hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex size-6 shrink-0 items-center justify-center rounded-full border border-white/[0.1] bg-white/[0.04] text-muted-foreground">
        <Lock className="size-3" />
      </div>
      {!collapsed && (
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-medium leading-tight text-foreground">
            Guest Mode
          </div>
          <div className="truncate text-[11px] leading-tight text-muted-foreground">
            Sign In / Switch
          </div>
        </div>
      )}
    </button>
  );
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  onSelectPresetCve,
  historyCount,
  user,
  onOpenAuthModal,
  variant = 'collapsible',
}) => {
  const presets = [
    {
      cve: 'CVE-2021-44228',
      name: 'Log4Shell',
      icon: Flame,
      color: 'text-red-400',
      criticality: 'CRITICAL',
      exposure: 'PUBLIC_FACING',
      context: 'Public Edge API Gateway with Log4j 2.14.0',
    },
    {
      cve: 'CVE-2023-34362',
      name: 'MOVEit',
      icon: ShieldAlert,
      color: 'text-orange-400',
      criticality: 'HIGH',
      exposure: 'PUBLIC_FACING',
      context: 'Public Managed File Transfer Web Application',
    },
    {
      cve: 'CVE-2024-3094',
      name: 'XZ Utils',
      icon: AlertTriangle,
      color: 'text-amber-400',
      criticality: 'CRITICAL',
      exposure: 'PUBLIC_FACING',
      context: 'Linux Production SSH Build Servers',
    },
  ];

  const navItems: Array<{
    id: TabType;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: React.ReactNode;
  }> = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    {
      id: 'workspace',
      label: 'My Workspace',
      icon: UserCheck,
      badge: user ? <StatusBadge>Active</StatusBadge> : undefined,
    },
    { id: 'analyzer', label: 'CVE Analyzer', icon: Crosshair },
    {
      id: 'history',
      label: 'Assessment History',
      icon: History,
      badge: <CountBadge>{historyCount}</CountBadge>,
    },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <PrimitiveSidebar
      variant={variant}
      width={268}
      collapsedWidth={60}
      aria-label="Main navigation"
      className="h-full !bg-[#0d0d10]"
    >
      <SidebarHeader className="border-b border-border">
        <WorkspaceMark />
        <SidebarToggle className="ml-auto" />
      </SidebarHeader>

      <SidebarNav className="sidebar-nav">
        <SidebarSection label="Navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <SidebarItem
                key={item.id}
                icon={<Icon className="size-[17px]" />}
                active={activeTab === item.id}
                badge={item.badge}
                onClick={() => setActiveTab(item.id)}
              >
                {item.label}
              </SidebarItem>
            );
          })}
        </SidebarSection>

        <SidebarSection className="mt-2 border-t border-border pt-2">
          <SidebarNested
            icon={<Flame className="size-[17px]" />}
            label="Quick CVE Presets"
            defaultOpen
          >
            {presets.map((preset) => {
              const Icon = preset.icon;
              return (
                <SidebarItem
                  key={preset.cve}
                  icon={<Icon className={`size-[15px] ${preset.color}`} />}
                  className="px-2.5 text-[12.5px]"
                  badge={
                    <span className="text-[10px] font-normal text-muted-foreground">
                      {preset.name}
                    </span>
                  }
                  onClick={() => {
                    setActiveTab('analyzer');
                    onSelectPresetCve(
                      preset.cve,
                      preset.criticality,
                      preset.exposure,
                      preset.context
                    );
                  }}
                >
                  {preset.cve}
                </SidebarItem>
              );
            })}
          </SidebarNested>
        </SidebarSection>
      </SidebarNav>

      <SidebarFooter>
        <UserFooter user={user} onOpenAuthModal={onOpenAuthModal} />
      </SidebarFooter>
    </PrimitiveSidebar>
  );
};
