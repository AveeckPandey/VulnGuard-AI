import {
  AssessmentRequest,
  AssessmentResponse,
  AssessmentSummary,
  PaginatedAssessmentsResponse,
  UserWorkspaceSummary,
} from '../types/assessment';
import { authManager } from './auth';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

// Token management backed by authManager session
export function setUserAuthToken(token: string | null): void {
  if (token) {
    authManager.loginWithTokens(token);
  } else {
    authManager.clearSession();
  }
}

export function getUserAuthToken(): string | null {
  return authManager.getAccessToken();
}

export function getResolvedApiEndpointDisplay(): string {
  if (API_BASE_URL) {
    return API_BASE_URL;
  }
  if (typeof window !== 'undefined' && window.location?.origin) {
    return `${window.location.origin}/api (Same-Origin Gateway)`;
  }
  return '/api (Same-Origin Gateway)';
}

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
  const token = authManager.getAccessToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...((options.headers as Record<string, string>) || {}),
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
  setUserAuthToken(token: string | null): void {
    setUserAuthToken(token);
  },

  getUserAuthToken(): string | null {
    return getUserAuthToken();
  },

  async analyzeVulnerability(req: AssessmentRequest): Promise<AssessmentResponse> {
    return request<AssessmentResponse>('/api/analyze', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  async getAssessment(id: string): Promise<AssessmentResponse> {
    return request<AssessmentResponse>(`/api/assessments/${id}`);
  },

  async listAssessments(limit: number = 20, cursor?: string): Promise<AssessmentSummary[]> {
    const query = cursor ? `limit=${limit}&cursor=${encodeURIComponent(cursor)}` : `limit=${limit}`;
    return request<AssessmentSummary[]>(`/api/assessments?${query}`);
  },

  async listAssessmentsPaged(limit: number = 20, cursor?: string | null): Promise<PaginatedAssessmentsResponse> {
    const query = cursor ? `limit=${limit}&cursor=${encodeURIComponent(cursor)}` : `limit=${limit}`;
    return request<PaginatedAssessmentsResponse>(`/api/assessments/paged?${query}`);
  },

  async getUserWorkspace(): Promise<UserWorkspaceSummary> {
    return request<UserWorkspaceSummary>('/api/user/workspace');
  },

  async getThreatIntelStatus(): Promise<any> {
    return request<any>('/api/threat-intel/status');
  },

  async getHealth(): Promise<any> {
    return request<any>('/health');
  },
};
