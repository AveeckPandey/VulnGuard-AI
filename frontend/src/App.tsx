import { useState, useEffect, useCallback } from 'react';
import { Header } from './components/layout/Header';
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
      .then(session => { if (session) setAuthState(authManager.getInitialState()); })
      .catch(err => setErrorMessage(err instanceof Error ? err.message : 'Sign-in failed.'));
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
      // Refresh history & workspace summary from DynamoDB
      loadHistory();
      loadWorkspace();
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 401) {
          setErrorMessage(
            'Authentication Required (HTTP 401): Please sign in with Cognito or select a demo persona to run user-isolated assessments.'
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
    <div className="min-h-screen bg-[#080d19] text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* Top Header */}
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
        <div className="bg-red-500/10 border-b border-red-500/30 px-4 py-2 text-xs text-red-400 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <WifiOff className="w-4 h-4 text-red-400 shrink-0" />
            <span>
              <strong>Backend Disconnected:</strong> Cannot reach API backend ({getResolvedApiEndpointDisplay()}). Ensure the backend server is running.
            </span>
          </div>
          <button
            onClick={fetchSystemStatus}
            className="text-white bg-red-500/20 px-2 py-0.5 rounded hover:bg-red-500/30 text-[11px]"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Main Layout Body */}
      <div className="flex-1 flex flex-col lg:flex-row relative">
        {/* Mobile Slide-Out Backdrop */}
        {mobileMenuOpen && (
          <div
            className="fixed inset-0 bg-black/60 z-40 lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          />
        )}

        {/* Left Sidebar (Desktop fixed + Mobile slide-over) */}
        <div
          className={`fixed lg:static top-16 bottom-0 left-0 z-40 w-64 transform transition-transform duration-200 ease-in-out lg:transform-none ${
            mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
          }`}
        >
          <Sidebar
            activeTab={activeTab}
            setActiveTab={(tab) => {
              setActiveTab(tab);
              setMobileMenuOpen(false);
            }}
            onSelectPresetCve={handleSelectPresetCve}
            historyCount={history.length}
            user={authState.user}
            onOpenAuthModal={() => setAuthModalOpen(true)}
          />
        </div>

        {/* Center / Main Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
          {/* Error Banner */}
          {errorMessage && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
              <div className="flex items-center space-x-3 shrink-0 ml-auto">
                <button
                  onClick={() => setAuthModalOpen(true)}
                  className="px-2.5 py-1 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-white font-medium text-xs transition-all"
                >
                  Manage Auth
                </button>
                <button
                  onClick={() => setErrorMessage(null)}
                  className="text-red-400 hover:text-white text-xs underline"
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

          {/* TAB 2: MY WORKSPACE (PERSONAL TRIAGE TELEMETRY) */}
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

          {/* TAB 3: CVE ANALYZER (PRIMARY FEATURE) */}
          {activeTab === 'analyzer' && (
            <div className="space-y-6">
              {/* CVE Search & Environmental Context Form */}
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

              {/* Assessment Results Section */}
              {currentAssessment ? (
                <div className="space-y-6 animate-in fade-in duration-300">
                  {/* Risk Score Summary Banner */}
                  <RiskScoreCard assessment={currentAssessment} />

                  {/* 3 Real Threat Intel Cards (NVD, EPSS, CISA KEV) */}
                  <ThreatIntelCards intel={currentAssessment.intelligence} />

                  {/* Factor Breakdown Chart */}
                  <FactorBreakdownChart
                    components={currentAssessment.risk_score.components}
                    totalScore={currentAssessment.risk_score.total_score}
                  />

                  {/* NVIDIA Nemotron AI Remediation Panel */}
                  <AiRemediationPanel
                    remediation={currentAssessment.remediation}
                    cveId={currentAssessment.cve_id}
                  />

                  {/* Verifiable Source Citations */}
                  <EvidenceCitations
                    citations={currentAssessment.remediation.evidence_citations}
                  />
                </div>
              ) : (
                <div className="py-20 text-center text-slate-500">
                  <Shield className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                  <p className="text-sm font-semibold text-slate-300">No Assessment Loaded</p>
                  <p className="text-xs text-slate-500 mt-1">
                    Enter a CVE identifier above and click "Analyze Vulnerability" to execute the LangGraph pipeline.
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
          {activeTab === 'analytics' && (
            <AnalyticsDashboard history={history} />
          )}

          {/* TAB 6: SYSTEM & CLOUD SETTINGS */}
          {activeTab === 'settings' && (
            <SettingsPanel
              systemHealth={systemHealth}
              intelFeeds={intelFeeds}
              onRefresh={handleRefreshAll}
              isRefreshing={isRefreshing}
            />
          )}
        </main>
      </div>

      {/* Detailed Modal View when inspecting any assessment from History or Overview */}
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
