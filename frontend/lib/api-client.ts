/**
 * SmellPin API Client
 * Centralized API client with authentication, error handling, and caching
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { CONFIG } from './config';

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

export interface ApiError {
  code: string;
  message: string;
  details?: any;
  statusCode?: number;
}

// Request Configuration
interface ApiRequestConfig extends AxiosRequestConfig {
  skipAuth?: boolean;
  retry?: boolean;
  retryAttempts?: number;
  retryDelay?: number;
}

class SmellPinApiClient {
  private client: AxiosInstance;
  private retryAttempts = CONFIG.API.REQUEST.RETRY_ATTEMPTS;
  private retryDelay = CONFIG.API.REQUEST.RETRY_DELAY;

  constructor() {
    this.client = axios.create({
      baseURL: CONFIG.API.API_BASE_URL,
      timeout: CONFIG.API.REQUEST.TIMEOUT,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor - Add authentication
    this.client.interceptors.request.use(
      (config) => {
        if (typeof window !== 'undefined' && !config.skipAuth) {
          const token = this.getAuthToken();
          if (token) {
            config.headers.Authorization = `Bearer ${token}`;
          }
        }

        // Add request ID for tracking
        config.headers['X-Request-ID'] = this.generateRequestId();
        
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor - Handle errors and retries
    this.client.interceptors.response.use(
      (response: AxiosResponse<ApiResponse>) => {
        return response;
      },
      async (error) => {
        const originalRequest = error.config;

        // Handle authentication errors
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          this.clearAuthToken();
          
          // Redirect to login page if in browser
          if (typeof window !== 'undefined') {
            window.location.href = '/login';
          }
          
          return Promise.reject(new ApiError({
            code: 'AUTHENTICATION_REQUIRED',
            message: '认证已过期，请重新登录',
            statusCode: 401,
          }));
        }

        // Handle rate limiting
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'] || this.retryDelay / 1000;
          
          return Promise.reject(new ApiError({
            code: 'RATE_LIMIT_EXCEEDED',
            message: `请求过于频繁，请在 ${retryAfter} 秒后重试`,
            statusCode: 429,
            details: { retryAfter: parseInt(retryAfter) },
          }));
        }

        // Handle network errors with retry
        if (originalRequest.retry !== false && this.shouldRetry(error) && !originalRequest._retryCount) {
          originalRequest._retryCount = 0;
        }

        if (originalRequest._retryCount < this.retryAttempts) {
          originalRequest._retryCount++;
          
          const delay = this.calculateRetryDelay(originalRequest._retryCount);
          await this.sleep(delay);
          
          return this.client(originalRequest);
        }

        return Promise.reject(this.createApiError(error));
      }
    );
  }

  private getAuthToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem('token') || sessionStorage.getItem('token');
  }

  private clearAuthToken(): void {
    if (typeof window === 'undefined') return;
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private shouldRetry(error: any): boolean {
    // Retry on network errors, timeout, or 5xx server errors
    return (
      !error.response || // Network error
      error.code === 'ECONNABORTED' || // Timeout
      (error.response.status >= 500 && error.response.status < 600) // Server error
    );
  }

  private calculateRetryDelay(attempt: number): number {
    // Exponential backoff with jitter
    const baseDelay = this.retryDelay;
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 1000;
    return Math.min(exponentialDelay + jitter, 30000); // Max 30 seconds
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private createApiError(error: any): ApiError {
    if (error.response?.data?.error) {
      return new ApiError({
        code: error.response.data.code || 'API_ERROR',
        message: error.response.data.error,
        statusCode: error.response.status,
        details: error.response.data.details,
      });
    }

    if (error.code === 'ECONNABORTED') {
      return new ApiError({
        code: 'TIMEOUT_ERROR',
        message: '请求超时，请检查网络连接',
        details: { timeout: this.client.defaults.timeout },
      });
    }

    if (!error.response) {
      return new ApiError({
        code: 'NETWORK_ERROR',
        message: '网络连接失败，请检查网络设置',
      });
    }

    return new ApiError({
      code: 'UNKNOWN_ERROR',
      message: error.message || '发生未知错误',
      statusCode: error.response?.status,
    });
  }

  // HTTP Methods
  async get<T = any>(url: string, config?: ApiRequestConfig): Promise<T> {
    const response = await this.client.get<ApiResponse<T>>(url, config);
    return this.handleResponse(response);
  }

  async post<T = any>(url: string, data?: any, config?: ApiRequestConfig): Promise<T> {
    const response = await this.client.post<ApiResponse<T>>(url, data, config);
    return this.handleResponse(response);
  }

  async put<T = any>(url: string, data?: any, config?: ApiRequestConfig): Promise<T> {
    const response = await this.client.put<ApiResponse<T>>(url, data, config);
    return this.handleResponse(response);
  }

  async patch<T = any>(url: string, data?: any, config?: ApiRequestConfig): Promise<T> {
    const response = await this.client.patch<ApiResponse<T>>(url, data, config);
    return this.handleResponse(response);
  }

  async delete<T = any>(url: string, config?: ApiRequestConfig): Promise<T> {
    const response = await this.client.delete<ApiResponse<T>>(url, config);
    return this.handleResponse(response);
  }

  private handleResponse<T>(response: AxiosResponse<ApiResponse<T>>): T {
    const { data } = response;
    
    if (!data.success) {
      throw new ApiError({
        code: 'API_ERROR',
        message: data.error || data.message || 'API请求失败',
      });
    }

    return data.data as T;
  }

  // Utility methods
  setAuthToken(token: string, remember: boolean = false): void {
    if (typeof window === 'undefined') return;
    
    if (remember) {
      localStorage.setItem('token', token);
    } else {
      sessionStorage.setItem('token', token);
    }
  }

  getBaseURL(): string {
    return this.client.defaults.baseURL || '';
  }

  // File upload helper
  async uploadFile(url: string, file: File, onProgress?: (progress: number) => void): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);

    return this.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(progress);
        }
      },
    });
  }
}

class ApiError extends Error {
  public code: string;
  public statusCode?: number;
  public details?: any;

  constructor({ code, message, statusCode, details }: {
    code: string;
    message: string;
    statusCode?: number;
    details?: any;
  }) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

// Create singleton instance
const apiClient = new SmellPinApiClient();

export { SmellPinApiClient, ApiError };
export default apiClient;