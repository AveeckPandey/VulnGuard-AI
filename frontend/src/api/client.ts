import { AssessmentRequest, AssessmentResponse, AssessmentSummary } from '../types/assessment';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export class ApiError extends Error {
  status: number;
  details?: any;

  constructor(message: string, status: number, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      let errorMessage = `HTTP Error ${response.status}: ${response.statusText}`;
      let errorDetails: any = null;
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorData.message || errorMessage;
        errorDetails = errorData.details || errorData;
      } catch {
        // Response was not JSON
      }
      throw new ApiError(errorMessage, response.status, errorDetails);
    }
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(
      error instanceof Error ? error.message : 'Network connection failed. Ensure backend service is running.',
      0
    );
  }
}

export const apiClient = {
  async analyzeVulnerability(req: AssessmentRequest): Promise<AssessmentResponse> {
    return request<AssessmentResponse>('/api/analyze', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  async getAssessment(id: string): Promise<AssessmentResponse> {
    return request<AssessmentResponse>(`/api/assessments/${id}`);
  },

  async listAssessments(limit: number = 20): Promise<AssessmentSummary[]> {
    return request<AssessmentSummary[]>(`/api/assessments?limit=${limit}`);
  },

  async getThreatIntelStatus(): Promise<any> {
    return request<any>('/api/threat-intel/status');
  },

  async getHealth(): Promise<any> {
    return request<any>('/health');
  },
};
