import { useState, useEffect, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import ElectricLogo from '@/components/ui/ElectricLogo';
import { Header } from './components/layout/Header';
import { Footer } from './components/layout/Footer';
import { Sidebar, TabType } from './components/layout/Sidebar';
import { OverviewView } from './components/dashboard/OverviewView';
import { MyWorkspaceView } from './components/dashboard/MyWorkspaceView';
import { AnalyticsDashboard } from './components/dashboard/AnalyticsDashboard';
import { SettingsPanel } from './components/settings/SettingsPanel';
import { CveSearchBar } from './components/dashboard/CveSearchBar';
import { RiskScoreCard } from './components/dashboard/RiskScoreCard';
import { ThreatIntelCards } from './components/dashboard/ThreatIntelCards';
import { FactorBreakdownChart } from './components/dashboard/FactorBreakdownChart';
import { AiRemediationPanel } from './components/dashboard/AiRemediationPanel';
import { EvidenceCitations } from './components/dashboard/EvidenceCitations';
import { LandingHero } from './components/dashboard/LandingHero';
import { AssessmentHistoryTable } from './components/history/AssessmentHistoryTable';
import { AssessmentDetailModal } from './components/details/AssessmentDetailModal';
import { AuthModal } from './components/auth/AuthModal';
import { apiClient, ApiError, getResolvedApiEndpointDisplay } from './api/client';
import { authService, authManager, completeCognitoLogin } from './api/auth';
import {
  AssessmentResponse,
  AssessmentSummary,
  AssetCriticality,
  InternetExposure,
  AssessmentRequest,
  UserWorkspaceSummary,
} from './types/assessment';
import { AuthState, UserProfile } from './types/auth';
import { AlertCircle, Shield, WifiOff } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  // Authentication & Workspace States
  const [authState, setAuthState] = useState<AuthState>(() => authService.getInitialState());
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);
  const [userWorkspace, setUserWorkspace] = useState<UserWorkspaceSummary | null>(null);

  // Form parameters
  const [selectedCve, setSelectedCve] = useState<string>('CVE-2021-44228');
  const [criticality, setCriticality] = useState<AssetCriticality>('CRITICAL');
  const [exposure, setExposure] = useState<InternetExposure>('PUBLIC_FACING');
  const [systemContext, setSystemContext] = useState<string>('Public Edge Payment Ingress API Gateway');

  // Application Data States
  const [currentAssessment, setCurrentAssessment] = useState<AssessmentResponse | null>(null);
  const [detailedAssessment, setDetailedAssessment] = useState<AssessmentResponse | null>(null);
  const [history, setHistory] = useState<AssessmentSummary[]>([]);
  const [intelFeeds, setIntelFeeds] = useState<any>(null);
  const [systemHealth, setSystemHealth] = useState<any>(null);

  // UI States
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Complete the Cognito authorization-code exchange after the hosted login redirects back.
  useEffect(() => {
    if (window.location.pathname !== '/callback') return;
    completeCognitoLogin()
      .then((session) => {
        if (session) setAuthState(authManager.getInitialState());
      })
      .catch((err) => setErrorMessage(err instanceof Error ? err.message : 'Sign-in failed.'));
  }, []);

  const fetchSystemStatus = useCallback(async () => {
    try {
      const health = await apiClient.getHealth();
      setSystemHealth(health);
      const feeds = await apiClient.getThreatIntelStatus();
      setIntelFeeds(feeds);
    } catch {
      setSystemHealth({ status: 'unreachable' });
    }
  }, []);

  const loadHistory = useCallback(async () => {
    setIsRefreshing(true);
    const requestToken = authManager.getAccessToken();
    try {
      const data = await apiClient.listAssessments(50);
      if (requestToken === authManager.getAccessToken()) setHistory(data);
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 401) {
        console.info('Authentication required to load assessment history.');
      } else {
        console.warn('Could not load history:', err);
      }
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  const loadWorkspace = useCallback(async () => {
    if (!authState.isAuthenticated) {
      setUserWorkspace(null);
      return;
    }
    const requestToken = authManager.getAccessToken();
    try {
      const summary = await apiClient.getUserWorkspace();
      if (requestToken === authManager.getAccessToken()) setUserWorkspace(summary);
    } catch (err) {
      console.warn('Could not load user workspace summary:', err);
    }
  }, [authState.isAuthenticated, authState.session?.accessToken]);

  // Initial Data Fetch & Reload on Auth State Change
  useEffect(() => {
    setHistory([]);
    setUserWorkspace(null);
    setCurrentAssessment(null);
    setDetailedAssessment(null);
  }, [authState.user?.sub, authState.session?.accessToken]);

  useEffect(() => {
    fetchSystemStatus();
    loadHistory();
    loadWorkspace();
  }, [fetchSystemStatus, loadHistory, loadWorkspace]);

  const handleAnalyze = async (request: AssessmentRequest) => {
    const requestToken = authManager.getAccessToken();
    setIsLoading(true);
    setErrorMessage(null);
    setCurrentAssessment(null);
    try {
      const result = await apiClient.analyzeVulnerability(request);
      if (requestToken !== authManager.getAccessToken()) return;
      setCurrentAssessment(result);
      loadHistory();
      loadWorkspace();
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 401) {
          setErrorMessage(
            'Authentication Required (HTTP 401): Please sign in to run and save private assessments.'
          );
          setAuthModalOpen(true);
        } else {
          setErrorMessage(error.message);
        }
      } else {
        setErrorMessage('Failed to complete vulnerability assessment.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectPresetCve = (
    cveId: string,
    crit: AssetCriticality,
    expo: InternetExposure,
    ctx: string
  ) => {
    setSelectedCve(cveId);
    setCriticality(crit);
    setExposure(expo);
    setSystemContext(ctx);
    setActiveTab('analyzer');
    handleAnalyze({
      cve_id: cveId,
      asset_criticality: crit,
      internet_exposure: expo,
      system_context: ctx,
      simulate_offline: !isLiveMode,
    });
  };

  const handleSelectAssessment = async (id: string) => {
    const requestToken = authManager.getAccessToken();
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const result = await apiClient.getAssessment(id);
      if (requestToken === authManager.getAccessToken()) setDetailedAssessment(result);
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 404) {
        setErrorMessage(`Assessment ${id} not found in your private workspace partition.`);
      } else {
        setErrorMessage(`Failed to retrieve assessment ${id} from database.`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadIntoAnalyzer = (assessment: AssessmentResponse | AssessmentSummary) => {
    if ('intelligence' in assessment) {
      setCurrentAssessment(assessment as AssessmentResponse);
    }
    setSelectedCve(assessment.cve_id);
    setCriticality(assessment.asset_criticality);
    setExposure(assessment.internet_exposure);
    setDetailedAssessment(null);
    setActiveTab('analyzer');
  };

  const handleRefreshAll = async () => {
    await Promise.all([fetchSystemStatus(), loadHistory(), loadWorkspace()]);
  };

  const handleSignOut = () => {
    authService.signOut();
    setAuthState({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      session: null,
      error: null,
    });
    setHistory([]);
    setUserWorkspace(null);
    setCurrentAssessment(null);
    setDetailedAssessment(null);
  };

  return (
    <div className="relative flex min-h-screen bg-background text-foreground lg:h-screen lg:overflow-hidden">
      {/* Ambient App Background */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 z-0 opacity-20"
      >
        <ElectricLogo
          src="/logo.svg"
          color="#bae6fd"
          glowColor="#0284c7"
          scale={0.65}
          strands={4}
          bend={0.5}
          crackle={1.2}
          arcs={1}
          speed={1.8}
          interactive={false}
          intensity={1.0}
          glow={1.2}
          flicker={0.35}
          theme="dark"
        />
      </div>

      {/* Desktop Collapsible Sidebar */}
      <div className="relative z-10 hidden h-full shrink-0 lg:flex">
        <Sidebar
          variant="collapsible"
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          onSelectPresetCve={handleSelectPresetCve}
          historyCount={history.length}
          user={authState.user}
          onOpenAuthModal={() => setAuthModalOpen(true)}
        />
      </div>

      {/* Mobile Slide-Over Sidebar Drawer */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
              onClick={() => setMobileMenuOpen(false)}
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
              className="fixed inset-y-0 left-0 z-50 flex h-full lg:hidden"
            >
              <Sidebar
                variant="default"
                activeTab={activeTab}
                setActiveTab={(tab) => {
                  setActiveTab(tab);
                  setMobileMenuOpen(false);
                }}
                onSelectPresetCve={(cve, crit, expo, ctx) => {
                  handleSelectPresetCve(cve, crit, expo, ctx);
                  setMobileMenuOpen(false);
                }}
                historyCount={history.length}
                user={authState.user}
                onOpenAuthModal={() => {
                  setMobileMenuOpen(false);
                  setAuthModalOpen(true);
                }}
              />
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Main Content Shell */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col lg:h-full lg:overflow-hidden">
        <Header
          activeTab={activeTab}
          isLiveMode={isLiveMode}
          setIsLiveMode={setIsLiveMode}
          systemHealth={systemHealth?.status}
          intelFeeds={intelFeeds}
          onRefresh={handleRefreshAll}
          isRefreshing={isRefreshing}
          mobileMenuOpen={mobileMenuOpen}
          setMobileMenuOpen={setMobileMenuOpen}
          user={authState.user}
          onOpenAuthModal={() => setAuthModalOpen(true)}
          onSignOut={handleSignOut}
        />

        {/* Backend Connectivity Warning Banner if Unreachable */}
        {systemHealth?.status === 'unreachable' && (
          <div className="flex items-center justify-between gap-3 border-b border-red-500/25 bg-red-500/10 px-4 py-2 text-xs text-red-400 sm:px-6">
            <div className="flex items-center gap-2">
              <WifiOff className="size-4 shrink-0 text-red-400" />
              <span>
                <strong>Backend Disconnected:</strong> Cannot reach API backend ({getResolvedApiEndpointDisplay()}). Ensure the backend server is running.
              </span>
            </div>
            <button
              type="button"
              onClick={fetchSystemStatus}
              className="shrink-0 rounded-md bg-red-500/20 px-2.5 py-1 text-[11px] font-medium text-white transition-colors hover:bg-red-500/30"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Scrollable Workspace Pane */}
        <main className="flex flex-1 flex-col overflow-y-auto">
          <div className="mx-auto w-full max-w-[1360px] flex-1 space-y-6 px-4 py-6 sm:px-6 lg:px-8">
            {/* Error Banner */}
            {errorMessage && (
              <div className="flex flex-col items-start justify-between gap-3 rounded-xl border border-red-500/25 bg-red-500/10 px-4 py-3 text-xs text-red-300 sm:flex-row sm:items-center">
                <div className="flex items-center gap-2.5">
                  <AlertCircle className="size-4 shrink-0 text-red-400" />
                  <span>{errorMessage}</span>
                </div>
                <div className="ml-auto flex shrink-0 items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setAuthModalOpen(true)}
                    className="rounded-lg bg-red-500/20 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-red-500/30"
                  >
                    Manage Auth
                  </button>
                  <button
                    type="button"
                    onClick={() => setErrorMessage(null)}
                    className="text-xs text-red-400 underline hover:text-white"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            )}

            {/* TAB 1: OVERVIEW DASHBOARD */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <LandingHero
                  onNavigateToAnalyzer={() => setActiveTab('analyzer')}
                  onSelectPreset={handleSelectPresetCve}
                  onOpenAuthModal={() => setAuthModalOpen(true)}
                  isAuthenticated={authState.isAuthenticated}
                />

                <OverviewView
                  history={history}
                  onSelectAssessment={handleSelectAssessment}
                  onNavigateToAnalyzer={() => setActiveTab('analyzer')}
                />
              </div>
            )}

            {/* TAB 2: MY WORKSPACE */}
            {activeTab === 'workspace' && (
              <MyWorkspaceView
                user={authState.user}
                workspace={userWorkspace}
                intelFeeds={intelFeeds}
                onNavigateToAnalyzer={() => setActiveTab('analyzer')}
                onSelectAssessment={handleSelectAssessment}
                onSelectPreset={handleSelectPresetCve}
                onOpenAuthModal={() => setAuthModalOpen(true)}
              />
            )}

            {/* TAB 3: CVE ANALYZER */}
            {activeTab === 'analyzer' && (
              <div className="space-y-6">
                <CveSearchBar
                  onAnalyze={handleAnalyze}
                  isLoading={isLoading}
                  isLiveMode={isLiveMode}
                  selectedCve={selectedCve}
                  setSelectedCve={setSelectedCve}
                  criticality={criticality}
                  setCriticality={setCriticality}
                  exposure={exposure}
                  setExposure={setExposure}
                  systemContext={systemContext}
                  setSystemContext={setSystemContext}
                />

                {currentAssessment ? (
                  <div className="space-y-6">
                    <RiskScoreCard assessment={currentAssessment} />
                    <ThreatIntelCards intel={currentAssessment.intelligence} />
                    <FactorBreakdownChart
                      components={currentAssessment.risk_score.components}
                      totalScore={currentAssessment.risk_score.total_score}
                    />
                    <AiRemediationPanel
                      remediation={currentAssessment.remediation}
                      cveId={currentAssessment.cve_id}
                    />
                    <EvidenceCitations
                      citations={currentAssessment.remediation.evidence_citations}
                    />
                  </div>
                ) : (
                  <div className="rounded-2xl border border-dashed border-border bg-card/50 py-20 text-center">
                    <Shield className="mx-auto mb-3 size-10 text-zinc-700" />
                    <p className="text-sm font-semibold text-foreground">No Assessment Loaded</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Enter a CVE identifier above and click "Analyze Vulnerability" to generate a prioritized risk report and remediation plan.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: ASSESSMENT HISTORY */}
            {activeTab === 'history' && (
              <AssessmentHistoryTable
                history={history}
                onSelectAssessment={handleSelectAssessment}
                onRefresh={loadHistory}
                isLoading={isRefreshing}
                onLoadIntoAnalyzer={handleLoadIntoAnalyzer}
              />
            )}

            {/* TAB 5: DEEP ANALYTICS */}
            {activeTab === 'analytics' && <AnalyticsDashboard history={history} />}

            {/* TAB 6: WORKSPACE & FEED SETTINGS */}
            {activeTab === 'settings' && (
              <SettingsPanel
                systemHealth={systemHealth}
                intelFeeds={intelFeeds}
                onRefresh={handleRefreshAll}
                isRefreshing={isRefreshing}
                user={authState.user}
                isLiveMode={isLiveMode}
                setIsLiveMode={setIsLiveMode}
                onOpenAuthModal={() => setAuthModalOpen(true)}
                onSignOut={handleSignOut}
              />
            )}
          </div>

          {/* Global Full-Bleed Workspace Footer */}
          <Footer
            user={authState.user}
            onNavigate={setActiveTab}
            onOpenAuthModal={() => setAuthModalOpen(true)}
          />
        </main>
      </div>

      {/* Detailed Modal View */}
      {detailedAssessment && (
        <AssessmentDetailModal
          assessment={detailedAssessment}
          onClose={() => setDetailedAssessment(null)}
          onLoadIntoAnalyzer={handleLoadIntoAnalyzer}
        />
      )}

      {/* Authentication Modal */}
      {authModalOpen && (
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          onAuthSuccess={(user: UserProfile) => {
            const session = authManager.getSession();
            setAuthState({
              isAuthenticated: true,
              isLoading: false,
              user,
              session,
              error: null,
            });
            setAuthModalOpen(false);
          }}
        />
      )}
    </div>
  );
}

export default App;
