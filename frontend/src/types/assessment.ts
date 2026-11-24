export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type InternetExposure = 'INTERNAL' | 'PUBLIC_FACING';
export type PriorityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IntelSourceStatus = 'AVAILABLE' | 'CONFIRMED_NEGATIVE' | 'UNKNOWN_OR_MISSING' | 'SIMULATED';

export interface ScoreComponent {
  name: string;
  raw_value: string | number | boolean;
  normalized_score: number;
  weight: number;
  weighted_contribution: number;
  description: string;
}

export interface RiskScoreBreakdown {
  total_score: number;
  priority_level: PriorityLevel;
  is_provisional: boolean;
  provisional_reasons: string[];
  components: ScoreComponent[];
  summary: string;
  formula_disclaimer: string;
}

export interface NvdIntel {
  cve_id: string;
  status: IntelSourceStatus;
  description: string | null;
  cvss_version: string | null;
  cvss_base_score: number | null;
  cvss_severity: string | null;
  cvss_vector_string: string | null;
  published_date: string | null;
  last_modified_date: string | null;
  references: string[];
  weaknesses: string[];
  fetched_at: string;
  source_url: string;
  is_simulated: boolean;
}

export interface EpssIntel {
  cve_id: string;
  status: IntelSourceStatus;
  epss_probability: number | null;
  epss_percentile: number | null;
  model_date: string | null;
  fetched_at: string;
  source_url: string;
  is_simulated: boolean;
}

export interface CisaKevIntel {
  cve_id: string;
  status: IntelSourceStatus;
  is_known_exploited: boolean | null;
  vulnerability_name: string | null;
  date_added: string | null;
  required_action: string | null;
  due_date: string | null;
  known_ransomware_use: string | null;
  notes: string | null;
  fetched_at: string;
  source_url: string;
  is_simulated: boolean;
}

export interface AggregatedIntel {
  cve_id: string;
  nvd: NvdIntel;
  epss: EpssIntel;
  cisa_kev: CisaKevIntel;
  is_simulated: boolean;
}

export interface AiRemediation {
  executive_summary: string;
  technical_impact: string;
  exploitation_assessment: string;
  remediation_steps: string[];
  mitigation_workarounds: string[];
  evidence_citations: string[];
  model_used: string;
  is_fallback_deterministic: boolean;
}

export interface AssessmentResponse {
  id: string;
  cve_id: string;
  owner_user_id?: string | null;
  asset_criticality: AssetCriticality;
  internet_exposure: InternetExposure;
  system_context: string | null;
  intelligence: AggregatedIntel;
  risk_score: RiskScoreBreakdown;
  remediation: AiRemediation;
  created_at: string;
  execution_time_ms: number;
  disclaimer: string;
}

export interface AssessmentSummary {
  id: string;
  cve_id: string;
  owner_user_id?: string | null;
  priority_level: PriorityLevel;
  total_score: number;
  cvss_base_score: number | null;
  epss_probability: number | null;
  is_known_exploited: boolean | null;
  asset_criticality: AssetCriticality;
  internet_exposure: InternetExposure;
  created_at: string;
}

export interface PaginatedAssessmentsResponse {
  items: AssessmentSummary[];
  count: number;
  next_cursor: string | null;
  has_more: boolean;
}

export interface UserWorkspaceSummary {
  user_id: string;
  email?: string | null;
  client_type?: string;
  total_assessments: number;
  recent_assessments: AssessmentSummary[];
  priority_distribution: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}

export interface AssessmentRequest {
  cve_id: string;
  asset_criticality: AssetCriticality;
  internet_exposure: InternetExposure;
  system_context?: string;
  simulate_offline?: boolean;
}
