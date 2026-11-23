import { useState, useEffect } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import { OverviewStats } from './components/dashboard/OverviewStats';
import { CveSearchBar } from './components/dashboard/CveSearchBar';
import { RiskScoreCard } from './components/dashboard/RiskScoreCard';
import { ThreatIntelCards } from './components/dashboard/ThreatIntelCards';
import { FactorBreakdownChart } from './components/dashboard/FactorBreakdownChart';
import { AiRemediationPanel } from './components/dashboard/AiRemediationPanel';
import { EvidenceCitations } from './components/dashboard/EvidenceCitations';
import { AssessmentHistoryTable } from './components/history/AssessmentHistoryTable';
import { apiClient, ApiError } from './api/client';
import {
  AssessmentResponse,
  AssessmentSummary,
  AssetCriticality,
  InternetExposure,
  AssessmentRequest,
} from './types/assessment';
import { AlertCircle, Shield } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<'triage' | 'history' | 'sources'>('triage');
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);

  // Form parameters
  const [selectedCve, setSelectedCve] = useState<string>('CVE-2021-44228');
  const [criticality, setCriticality] = useState<AssetCriticality>('CRITICAL');
  const [exposure, setExposure] = useState<InternetExposure>('PUBLIC_FACING');
  const [systemContext, setSystemContext] = useState<string>('Public Edge Payment Ingress API Gateway');

  // Application Data States
  const [currentAssessment, setCurrentAssessment] = useState<AssessmentResponse | null>(null);
  const [history, setHistory] = useState<AssessmentSummary[]>([]);
  const [intelFeeds, setIntelFeeds] = useState<any>(null);
  const [systemHealth, setSystemHealth] = useState<string | null>(null);

  // UI States
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Initial Data Fetch
  useEffect(() => {
    fetchSystemStatus();
    loadHistory();
    // Auto-analyze initial preset on startup
    performInitialAnalysis();
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const health = await apiClient.getHealth();
      setSystemHealth(health.status);
      const feeds = await apiClient.getThreatIntelStatus();
      setIntelFeeds(feeds);
    } catch {
      setSystemHealth('unreachable');
    }
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const data = await apiClient.listAssessments(25);
      setHistory(data);
    } catch (err) {
      console.warn('Could not load history:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  const performInitialAnalysis = async () => {
    await handleAnalyze({
      cve_id: 'CVE-2021-44228',
      asset_criticality: 'CRITICAL',
      internet_exposure: 'PUBLIC_FACING',
      system_context: 'Public Edge Payment Ingress API Gateway',
      simulate_offline: false, // Use live upstream
    });
  };

  const handleAnalyze = async (request: AssessmentRequest) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const result = await apiClient.analyzeVulnerability(request);
      setCurrentAssessment(result);
      // Refresh history list
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
      setCurrentAssessment(result);
      setSelectedCve(result.cve_id);
      setCriticality(result.asset_criticality);
      setExposure(result.internet_exposure);
      setSystemContext(result.system_context || '');
      setActiveTab('triage');
    } catch (error) {
      setErrorMessage(`Failed to retrieve assessment ${id}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col selection:bg-sky-500 selection:text-white">
      {/* Top Header */}
      <Header
        isLiveMode={isLiveMode}
        setIsLiveMode={setIsLiveMode}
        systemHealth={systemHealth}
        intelFeeds={intelFeeds}
      />

      {/* Main Layout Body */}
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Left Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          onSelectPresetCve={handleSelectPresetCve}
          historyCount={history.length}
        />

        {/* Center / Main Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
          {/* Top Overview Statistics Cards */}
          <OverviewStats history={history} />

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

          {activeTab === 'triage' ? (
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

                  {/* AI Remediation Panel (Bedrock Nova / Deterministic) */}
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
                <div className="py-16 text-center text-slate-400">
                  <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-sm font-semibold text-slate-300">No Assessment Loaded</p>
                  <p className="text-xs text-slate-400 mt-1">Enter a CVE identifier above and click Analyze & Prioritize.</p>
                </div>
              )}
            </div>
          ) : (
            /* History Tab */
            <AssessmentHistoryTable
              history={history}
              onSelectAssessment={handleSelectAssessment}
              onRefresh={loadHistory}
              isLoading={historyLoading}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
