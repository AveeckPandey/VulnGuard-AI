import React from 'react';
import { Shield, ExternalLink, Lock, UserCheck } from 'lucide-react';
import { TabType } from './Sidebar';
import { UserProfile } from '../../types/auth';

interface FooterProps {
  user: UserProfile | null;
  onNavigate: (tab: TabType) => void;
  onOpenAuthModal: () => void;
}

export const Footer: React.FC<FooterProps> = ({
  user,
  onNavigate,
  onOpenAuthModal,
}) => {
  const navLinks: Array<{ id: TabType; label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'workspace', label: 'My Workspace' },
    { id: 'analyzer', label: 'CVE Analyzer' },
    { id: 'history', label: 'Assessment History' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'settings', label: 'Settings' },
  ];

  const feedLinks = [
    { label: 'NIST NVD API 2.0', href: 'https://nvd.nist.gov/' },
    { label: 'FIRST.org EPSS v3', href: 'https://www.first.org/epss/' },
    {
      label: 'CISA KEV Catalog',
      href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    },
  ];

  return (
    <footer className="mt-auto border-t border-border bg-[#0c0c0e]">
      <div className="mx-auto w-full max-w-[1360px] px-4 py-8 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-12">
          {/* Column 1: Brand & Overview */}
          <div className="space-y-3 lg:col-span-4">
            <div className="flex items-center gap-2.5">
              <div className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <Shield className="size-4" strokeWidth={2.25} />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold tracking-tight text-foreground">
                  VulnGuard AI
                </span>
                <span className="rounded border border-border bg-white/[0.04] px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                  v1.0.0
                </span>
              </div>
            </div>
            <p className="max-w-sm text-[13px] leading-relaxed text-muted-foreground">
              AI-powered CVE intelligence and deterministic vulnerability prioritization platform combining live threat feeds with evidence-grounded remediation.
            </p>
          </div>

          {/* Column 2: Platform Navigation */}
          <div className="space-y-3 lg:col-span-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Platform
            </h4>
            <ul className="space-y-2 text-[13px]">
              {navLinks.map((link) => (
                <li key={link.id}>
                  <a
                    href={`#${link.id}`}
                    onClick={(e) => {
                      e.preventDefault();
                      onNavigate(link.id);
                    }}
                    className="text-zinc-300 transition-colors hover:text-foreground"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Column 3: Threat Intelligence Sources */}
          <div className="space-y-3 lg:col-span-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Threat Intel Sources
            </h4>
            <ul className="space-y-2 text-[13px]">
              {feedLinks.map((feed) => (
                <li key={feed.label}>
                  <a
                    href={feed.href}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-zinc-300 transition-colors hover:text-foreground"
                  >
                    <span>{feed.label}</span>
                    <ExternalLink className="size-3 text-muted-foreground" />
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Column 4: Capabilities & Session */}
          <div className="space-y-3 lg:col-span-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Capabilities &amp; Workspace
            </h4>
            <ul className="space-y-1.5 font-mono text-xs text-muted-foreground">
              <li>3-Stage Triage Pipeline</li>
              <li>0–100 Deterministic Risk Scoring</li>
              <li>AI &amp; Rule-Based Remediation</li>
            </ul>
            <div className="pt-1">
              {user ? (
                <div className="inline-flex items-center gap-2 rounded-lg border border-border bg-white/[0.03] px-3 py-1.5 text-xs text-zinc-200">
                  <UserCheck className="size-3.5 text-emerald-400" />
                  <span className="truncate">Signed in as {user.name || user.username}</span>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={onOpenAuthModal}
                  className="inline-flex items-center gap-2 rounded-lg border border-white/[0.14] bg-white/[0.05] px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.1]"
                >
                  <Lock className="size-3.5 text-sky-400" />
                  <span>Sign In to Workspace</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Bottom Compliance & Attribution Bar */}
        <div className="mt-8 flex flex-col justify-between gap-3 border-t border-border pt-5 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <span>
            Custom risk heuristic for portfolio triage—not a replacement for regulatory compliance mandates.
          </span>
          <span className="shrink-0 font-mono text-zinc-300">
            VulnGuard AI · MIT License
          </span>
        </div>
      </div>
    </footer>
  );
};
