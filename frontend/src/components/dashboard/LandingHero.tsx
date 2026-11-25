import React from 'react';
import {
  Shield,
  ArrowRight,
  Database,
  TrendingUp,
  AlertTriangle,
  Sparkles,
  Lock,
  Calculator,
  Cpu,
  CheckCircle2,
  FileText,
  BarChart3,
  Radar,
  Crosshair,
} from 'lucide-react';

interface LandingHeroProps {
  onNavigateToAnalyzer: () => void;
  onExploreFeedsClick?: () => void;
  onSelectPreset?: (cveId: string, criticality: any, exposure: any, context: string) => void;
  onOpenAuthModal?: () => void;
  isAuthenticated?: boolean;
}

export const LandingHero: React.FC<LandingHeroProps> = ({
  onNavigateToAnalyzer,
  onExploreFeedsClick,
  onSelectPreset,
  onOpenAuthModal,
  isAuthenticated = false,
}) => {
  const sampleComponents = [
    {
      label: 'CVSS Severity (30%)',
      detail: 'Base 10.0',
      points: '+30.0 pts',
      width: '100%',
      color: 'bg-sky-400',
    },
    {
      label: 'EPSS Probability (30%)',
      detail: '97.54% (99.9th pct)',
      points: '+29.26 pts',
      width: '97.5%',
      color: 'bg-indigo-400',
    },
    {
      label: 'CISA KEV Status (20%)',
      detail: 'Active in KEV',
      points: '+20.0 pts',
      width: '100%',
      color: 'bg-red-400',
    },
    {
      label: 'Asset Criticality (10%)',
      detail: 'CRITICAL',
      points: '+10.0 pts',
      width: '100%',
      color: 'bg-amber-400',
    },
    {
      label: 'Perimeter Exposure (10%)',
      detail: 'PUBLIC_FACING',
      points: '+10.0 pts',
      width: '100%',
      color: 'bg-emerald-400',
    },
  ];

  const outputModules = [
    {
      title: 'Risk Score & Provisional Audit',
      desc: '0–100 gauge, SLA tier, and explicit notice if any upstream feed was missing or provisional.',
      icon: Radar,
    },
    {
      title: 'Three Live Threat Cards',
      desc: 'NVD CVSS vector & CWEs (CWE-502, CWE-400), EPSS probability bar + percentile, and CISA KEV mandate/due date.',
      icon: Shield,
    },
    {
      title: 'Factor Contribution Chart',
      desc: 'Visual horizontal breakdown showing exact points contributed by each of the 5 weighted signals.',
      icon: BarChart3,
    },
    {
      title: 'AI Remediation Roadmap & Citations',
      desc: 'Executive summary, technical impact, patching steps, compensating workarounds, and clickable official source URLs.',
      icon: FileText,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Hero / Guest Mode Header Banner */}
      <div className="surface-panel relative overflow-hidden rounded-2xl p-6 sm:p-8">
        <div className="relative z-10 max-w-4xl space-y-5">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.12] bg-white/[0.04] px-3.5 py-1.5 font-mono text-xs font-medium text-zinc-200">
            <Sparkles className="size-3.5 text-sky-400" />
            <span>
              {isAuthenticated
                ? 'Autonomous Cybersecurity Intelligence Platform'
                : 'Guest Preview Mode · Public Exploration'}
            </span>
          </div>

          <h2 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl lg:text-4xl">
            {isAuthenticated
              ? 'Prioritize Vulnerabilities with Ground-Truth Evidence'
              : 'Understand and Prioritize CVE Risk with Ground-Truth Evidence'}
          </h2>

          <p className="max-w-3xl text-sm leading-7 text-zinc-300 sm:text-[15px]">
            {isAuthenticated
              ? 'VulnGuard combines official CVSS metrics, real-time EPSS weaponization probabilities, and CISA KEV exploitation catalogs into an evidence-grounded risk score with verified generative AI remediation roadmaps.'
              : 'VulnGuard AI automates vulnerability triage by combining live threat feeds (NIST NVD, FIRST EPSS, CISA KEV), your asset exposure context, and a deterministic 0–100 scoring model—backed by guardrailed AI remediation roadmaps.'}
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              type="button"
              onClick={onNavigateToAnalyzer}
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-primary px-5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
            >
              <span>Analyze a CVE</span>
              <ArrowRight className="size-4" />
            </button>

            {onExploreFeedsClick && (
              <button
                type="button"
                onClick={onExploreFeedsClick}
                className="inline-flex h-10 items-center gap-2 rounded-xl border border-border bg-white/[0.04] px-4 text-sm font-medium text-foreground transition-colors hover:bg-white/[0.08]"
              >
                <Database className="size-4 text-muted-foreground" />
                <span>Threat Intel Status</span>
              </button>
            )}

            {!isAuthenticated && onOpenAuthModal && (
              <button
                type="button"
                onClick={onOpenAuthModal}
                className="inline-flex h-10 items-center gap-2 rounded-xl border border-border bg-white/[0.04] px-4 text-sm font-medium text-foreground transition-colors hover:bg-white/[0.08]"
              >
                <Lock className="size-4 text-muted-foreground" />
                <span>Sign In / Demo Personas</span>
              </button>
            )}
          </div>

          {/* Guest Mode Notice */}
          {!isAuthenticated && (
            <div className="surface-subpanel inline-flex items-center gap-2.5 rounded-xl px-3.5 py-2 text-[13px] text-zinc-200">
              <Lock className="size-3.5 shrink-0 text-sky-400" />
              <span>
                You are in <strong className="font-semibold text-foreground">Guest Mode</strong>.
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Guest Understanding Statements & Sample Results Preview */}
      {!isAuthenticated && (
        <>
          {/* Section: How VulnGuard AI Works */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 px-1">
              <div>
                <h3 className="text-base font-semibold tracking-tight text-foreground">
                  How VulnGuard AI Works
                </h3>
                <p className="mt-0.5 text-[13px] text-muted-foreground">
                  3-Stage Automated Vulnerability Triage Pipeline
                </p>
              </div>
              <span className="rounded-lg border border-border bg-[#131316] px-3 py-1 font-mono text-xs text-zinc-300">
                CRITICAL (85–100) · HIGH (70–84) · MEDIUM (40–69) · LOW (0–39)
              </span>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {/* Stage 1 */}
              <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6">
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-sky-400">
                      <Database className="size-4" />
                    </div>
                    <span className="rounded-md bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-zinc-300">
                      Stage 1 · Async Fetch
                    </span>
                  </div>
                  <div>
                    <h4 className="text-[15px] font-semibold text-foreground">
                      Multi-Source Threat Intelligence
                    </h4>
                    <ul className="mt-2.5 space-y-2 text-[13.5px] leading-relaxed text-zinc-300">
                      <li>• Queries <strong className="font-semibold text-foreground">NIST NVD API 2.0</strong> for official CVSS scores, vectors, and CWEs.</li>
                      <li>• Queries <strong className="font-semibold text-foreground">FIRST.org EPSS v3</strong> for 30-day exploit probability and percentile.</li>
                      <li>• Checks <strong className="font-semibold text-foreground">CISA KEV Catalog</strong> (1,790+ CVEs), separating confirmed negatives from feed outages.</li>
                    </ul>
                  </div>
                </div>
                <div className="border-t border-border pt-3 font-mono text-xs text-zinc-400">
                  Real-time feeds with TTL caching
                </div>
              </div>

              {/* Stage 2 */}
              <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6">
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-amber-400">
                      <Calculator className="size-4" />
                    </div>
                    <span className="rounded-md bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-zinc-300">
                      Stage 2 · 0–100 Model
                    </span>
                  </div>
                  <div>
                    <h4 className="text-[15px] font-semibold text-foreground">
                      Deterministic Risk Prioritization
                    </h4>
                    <ul className="mt-2.5 space-y-2 text-[13.5px] leading-relaxed text-zinc-300">
                      <li>• <strong className="font-semibold text-foreground">CVSS Severity (30%):</strong> Score × 10</li>
                      <li>• <strong className="font-semibold text-foreground">EPSS Probability (30%):</strong> Probability × 100</li>
                      <li>• <strong className="font-semibold text-foreground">CISA KEV (20%):</strong> Active 100 · Negative 0 · Unknown 30</li>
                      <li>• <strong className="font-semibold text-foreground">Asset &amp; Exposure (10% each):</strong> Criticality &amp; Perimeter</li>
                    </ul>
                  </div>
                </div>
                <div className="border-t border-border pt-3 font-mono text-xs text-zinc-400">
                  Flags provisional scores when feeds are missing
                </div>
              </div>

              {/* Stage 3 */}
              <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6">
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-emerald-400">
                      <Cpu className="size-4" />
                    </div>
                    <span className="rounded-md bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-zinc-300">
                      Stage 3 · AI + Fail-Safe
                    </span>
                  </div>
                  <div>
                    <h4 className="text-[15px] font-semibold text-foreground">
                      Evidence-Grounded Remediation
                    </h4>
                    <p className="mt-2.5 text-[13.5px] leading-relaxed text-zinc-300">
                      Generates an executive summary, technical impact, in-the-wild exploitation assessment, patching checklist, and compensating controls using AI-assisted synthesis with automatic deterministic rule fallback when AI is unavailable.
                    </p>
                  </div>
                </div>
                <div className="border-t border-border pt-3 font-mono text-xs text-zinc-400">
                  Every roadmap cites verifiable NVD / EPSS / KEV URLs
                </div>
              </div>
            </div>
          </div>

          {/* Section: Sample Assessment Results Preview */}
          <div className="surface-panel space-y-6 rounded-2xl p-6">
            <div className="flex flex-col justify-between gap-4 border-b border-border pb-5 md:flex-row md:items-center">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="rounded-md border border-sky-500/30 bg-sky-500/10 px-2.5 py-0.5 font-mono text-xs font-medium text-sky-300">
                    Sample Output Preview (Reference Fixture)
                  </span>
                  <span className="text-[13px] text-muted-foreground">
                    Critical Asset · Public Facing · Production API Gateway
                  </span>
                </div>
                <h3 className="font-mono text-lg font-semibold text-foreground">
                  CVE-2021-44228 · Apache Log4j2 Remote Code Execution (Log4Shell)
                </h3>
              </div>

              <div className="shrink-0">
                <div className="inline-flex items-center gap-2.5 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2">
                  <span className="font-mono text-xl font-semibold text-foreground tabular-nums">
                    99.26
                  </span>
                  <span className="font-mono text-xs text-zinc-300">/ 100</span>
                  <span className="ml-1 rounded-md border border-red-500/30 bg-red-500/20 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-red-300">
                    CRITICAL PRIORITY
                  </span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
              {/* Left 5 cols: Weighted Breakdown */}
              <div className="space-y-3 lg:col-span-5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold uppercase tracking-wider text-foreground">
                    5-Factor Score Breakdown
                  </span>
                  <span className="font-mono text-xs text-muted-foreground">Sum = 99.26 pts</span>
                </div>
                <div className="space-y-2.5">
                  {sampleComponents.map((comp) => (
                    <div key={comp.label} className="surface-subpanel space-y-2 rounded-xl p-3.5">
                      <div className="flex items-center justify-between text-[13px]">
                        <span className="font-medium text-foreground">{comp.label}</span>
                        <span className="font-mono font-semibold text-foreground">{comp.points}</span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-white/[0.08]">
                        <div className={`h-full rounded-full ${comp.color}`} style={{ width: comp.width }} />
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">{comp.detail}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right 7 cols: What Full Assessment Results Include */}
              <div className="space-y-4 lg:col-span-7">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold uppercase tracking-wider text-foreground">
                    What Full Assessment Results Include
                  </span>
                  <span className="text-xs text-muted-foreground">4 Output Modules</span>
                </div>

                <div className="surface-subpanel divide-y divide-white/[0.07] rounded-xl">
                  {outputModules.map((mod) => {
                    const Icon = mod.icon;
                    return (
                      <div key={mod.title} className="flex items-start gap-3 p-4">
                        <Icon className="mt-0.5 size-4 shrink-0 text-sky-400" />
                        <div>
                          <h4 className="text-sm font-semibold text-foreground">{mod.title}</h4>
                          <p className="mt-0.5 text-[13px] leading-relaxed text-zinc-300">{mod.desc}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Reference Citation & Remediation Preview */}
                <div className="surface-subpanel space-y-2.5 rounded-xl p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-400">
                      <CheckCircle2 className="size-4" />
                      <span>Sample Remediation &amp; Official Citations</span>
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">
                      AI-Generated Guidance
                    </span>
                  </div>
                  <p className="text-[13.5px] leading-relaxed text-zinc-200">
                    Immediate upgrade of Apache Log4j2 to 2.17.1+ (or 2.12.4 / 2.3.2 for legacy Java), removal of <code className="font-mono text-xs text-foreground">JndiLookup</code> class where patching is staged, and perimeter egress filtering against untrusted LDAP/RMI callbacks.
                  </p>
                  <div className="flex flex-wrap gap-2 pt-1 font-mono text-xs text-zinc-300">
                    <span className="rounded-md border border-border bg-background px-2.5 py-1">nvd.nist.gov</span>
                    <span className="rounded-md border border-border bg-background px-2.5 py-1">api.first.org</span>
                    <span className="rounded-md border border-border bg-background px-2.5 py-1">cisa.gov</span>
                  </div>
                </div>
              </div>
            </div>

            {onSelectPreset && (
              <div className="flex flex-col justify-between gap-3 border-t border-border pt-4 sm:flex-row sm:items-center">
                <p className="text-[13px] text-muted-foreground">
                  Load this vulnerability with pre-configured edge context in the live CVE Analyzer.
                </p>
                <button
                  type="button"
                  onClick={() =>
                    onSelectPreset(
                      'CVE-2021-44228',
                      'CRITICAL',
                      'PUBLIC_FACING',
                      'Public Edge API Gateway with Log4j 2.14.0'
                    )
                  }
                  className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl border border-white/[0.16] bg-white/[0.06] px-4 text-[13px] font-medium text-foreground transition-colors hover:border-white/[0.28] hover:bg-white/[0.12]"
                >
                  <Crosshair className="size-3.5 text-sky-400" />
                  <span>Run Live Log4Shell Assessment</span>
                  <ArrowRight className="size-3.5 text-muted-foreground" />
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {/* 3 Real Data Sources Breakdown (Shown for Authenticated Users) */}
      {isAuthenticated && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6 transition-colors hover:border-white/[0.16]">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-sky-400">
                  <Shield className="size-4" />
                </div>
                <span className="rounded-md bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-zinc-300">
                  Baseline Metrics
                </span>
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-foreground">NIST NVD API 2.0</h3>
                <p className="mt-1.5 text-[13.5px] leading-relaxed text-zinc-300">
                  Ingests authoritative CVSS v4.0 &amp; v3.1 base scores, attack vector telemetry (AV/AC/PR/UI), and CWE weakness categorizations directly from NIST.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between border-t border-border pt-3 font-mono text-xs text-muted-foreground">
              <span>Score Standard:</span>
              <span className="text-foreground">CVSS 0.0 – 10.0</span>
            </div>
          </div>

          <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6 transition-colors hover:border-white/[0.16]">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-sky-400">
                  <TrendingUp className="size-4" />
                </div>
                <span className="rounded-md bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-zinc-300">
                  Probability
                </span>
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-foreground">FIRST.org EPSS v3</h3>
                <p className="mt-1.5 text-[13.5px] leading-relaxed text-zinc-300">
                  Calculates daily empirical exploitation probabilities and honeypot percentiles, forecasting the likelihood of weaponization over the next 30 days.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between border-t border-border pt-3 font-mono text-xs text-muted-foreground">
              <span>Exploit Prediction:</span>
              <span className="text-foreground">0.0% – 100.0%</span>
            </div>
          </div>

          <div className="surface-panel flex flex-col justify-between space-y-4 rounded-2xl p-6 transition-colors hover:border-white/[0.16]">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-xl border border-border bg-white/[0.04] text-red-400">
                  <AlertTriangle className="size-4" />
                </div>
                <span className="rounded-md bg-red-500/15 px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wider text-red-300">
                  In-the-Wild
                </span>
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-foreground">CISA KEV Catalog</h3>
                <p className="mt-1.5 text-[13.5px] leading-relaxed text-zinc-300">
                  Validates whether the vulnerability is actively weaponized by threat actors and cross-references federal mandatory remediation deadlines.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between border-t border-border pt-3 font-mono text-xs text-muted-foreground">
              <span>Known Exploited:</span>
              <span className="text-red-400">1,790+ Active CVEs</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
