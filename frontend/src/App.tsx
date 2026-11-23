import { useState, useEffect } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar, TabType } from './components/layout/Sidebar';
import { OverviewView } from './components/dashboard/OverviewView';
import { AnalyticsDashboard } from './components/dashboard/AnalyticsDashboard';
import { SettingsPanel } from './components/settings/SettingsPanel';
import { CveSearchBar } from './components/dashboard/CveSearchBar';
import { RiskScoreCard } from './components/dashboard/RiskScoreCard';
import { ThreatIntelCards } from './components/dashboard/ThreatIntelCards';
import { FactorBreakdownChart } from './components/dashboard/FactorBreakdownChart';
import { AiRemediationPanel } from './components/dashboard/AiRemediationPanel';
import { EvidenceCitations } from './components/dashboard/EvidenceCitations';
import { AssessmentHistoryTable } from './components/history/AssessmentHistoryTable';
import { AssessmentDetailModal } from './components/details/AssessmentDetailModal';
import { apiClient, ApiError } from './api/client';
import {
  AssessmentResponse,
  AssessmentSummary,
  AssetCriticality,
  InternetExposure,
  AssessmentRequest,
} from './types/assessment';
import { AlertCircle, Shield, WifiOff } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

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

  // Initial Data Fetch
  useEffect(() => {
    fetchSystemStatus();
    loadHistory();
    performInitialAnalysis();
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const health = await apiClient.getHealth();
      setSystemHealth(health);
      const feeds = await apiClient.getThreatIntelStatus();
      setIntelFeeds(feeds);
    } catch {
      setSystemHealth({ status: 'unreachable' });
    }
  };

  const loadHistory = async () => {
    setIsRefreshing(true);
    try {
      const data = await apiClient.listAssessments(50);
      setHistory(data);
    } catch (err) {
      console.warn('Could not load history:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const performInitialAnalysis = async () => {
    try {
      const result = await apiClient.analyzeVulnerability({
        cve_id: 'CVE-2021-44228',
        asset_criticality: 'CRITICAL',
        internet_exposure: 'PUBLIC_FACING',
        system_context: 'Public Edge Payment Ingress API Gateway',
        simulate_offline: false,
      });
      setCurrentAssessment(result);
    } catch (e) {
      console.warn('Initial preset analysis notice:', e);
    }
  };

  const handleAnalyze = async (request: AssessmentRequest) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const result = await apiClient.analyzeVulnerability(request);
      setCurrentAssessment(result);
      // Refresh history list from DynamoDB
      loadHistory();
    } catch (error) {
      if (error instanceof ApiError) {
        setErrorMessage(error.message);
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
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const result = await apiClient.getAssessment(id);
      setDetailedAssessment(result);
    } catch {
      setErrorMessage(`Failed to retrieve assessment ${id} from database.`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadIntoAnalyzer = (assessment: AssessmentResponse) => {
    setCurrentAssessment(assessment);
    setSelectedCve(assessment.cve_id);
    setCriticality(assessment.asset_criticality);
    setExposure(assessment.internet_exposure);
    setSystemContext(assessment.system_context || '');
    setDetailedAssessment(null);
    setActiveTab('analyzer');
  };

  const handleRefreshAll = async () => {
    await Promise.all([fetchSystemStatus(), loadHistory()]);
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
      />

      {/* Backend Connectivity Warning Banner if Unreachable */}
      {systemHealth?.status === 'unreachable' && (
        <div className="bg-red-500/10 border-b border-red-500/30 px-4 py-2 text-xs text-red-400 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <WifiOff className="w-4 h-4 text-red-400 shrink-0" />
            <span>
              <strong>Backend Disconnected:</strong> Cannot reach FastAPI at http://127.0.0.1:8000. Ensure the backend server is running.
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
          />
        </div>

        {/* Center / Main Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
          {/* Error Banner */}
          {errorMessage && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
              <button
                onClick={() => setErrorMessage(null)}
                className="text-red-400 hover:text-white text-xs underline ml-4"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* TAB 1: OVERVIEW DASHBOARD */}
          {activeTab === 'overview' && (
            <OverviewView
              history={history}
              onSelectAssessment={handleSelectAssessment}
              onNavigateToAnalyzer={() => setActiveTab('analyzer')}
            />
          )}

          {/* TAB 2: CVE ANALYZER (PRIMARY FEATURE) */}
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

          {/* TAB 3: ASSESSMENT HISTORY */}
          {activeTab === 'history' && (
            <AssessmentHistoryTable
              history={history}
              onSelectAssessment={handleSelectAssessment}
              onRefresh={loadHistory}
              isLoading={isRefreshing}
            />
          )}

          {/* TAB 4: DEEP ANALYTICS */}
          {activeTab === 'analytics' && (
            <AnalyticsDashboard history={history} />
          )}

          {/* TAB 5: SYSTEM & CLOUD SETTINGS */}
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
    </div>
  );
}

export default App;
