/**
 * API Client Implementation
 * Production-ready HTTP client with comprehensive error handling, retry logic, and caching
 */

import type {
  ApiClient,
  ApiClientConfig,
  ApiResponse,
  RequestConfig,
  InternalRequestConfig,
  HttpMethod,
  BatchRequest,
  BatchResponse,
  CacheEntry,
  RequestInterceptor,
  ResponseInterceptor,
  ErrorContext,
} from './types';

import {
  ApiError,
  NetworkError,
  ValidationError,
  ErrorFactory,
} from './errors';

// Default configuration
const DEFAULT_CONFIG: ApiClientConfig = {
  baseUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api',
  timeout: 30000, // 30 seconds
  retries: 3,
  retryDelay: 1000, // 1 second
  retryCondition: (error: unknown) => ErrorFactory.isRetryable(error),
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
};

class ApiClientImpl implements ApiClient {
  public readonly config: ApiClientConfig;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly requestInterceptors: RequestInterceptor[] = [];
  private readonly responseInterceptors: ResponseInterceptor[] = [];
  private readonly activeRequests = new Map<string, AbortController>();

  constructor(config: Partial<ApiClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ==================== HTTP METHODS ====================

  async get<T>(url: string, config?: RequestConfig): Promise<ApiResponse<T>> {
    return this.request<T>({ url, method: 'GET', ...config });
  }

  async post<T>(url: string, data?: unknown, config?: RequestConfig): Promise<ApiResponse<T>> {
    return this.request<T>({ url, method: 'POST', data, ...config });
  }

  async put<T>(url: string, data?: unknown, config?: RequestConfig): Promise<ApiResponse<T>> {
    return this.request<T>({ url, method: 'PUT', data, ...config });
  }

  async delete<T>(url: string, config?: RequestConfig): Promise<ApiResponse<T>> {
    return this.request<T>({ url, method: 'DELETE', ...config });
  }

  async patch<T>(url: string, data?: unknown, config?: RequestConfig): Promise<ApiResponse<T>> {
    return this.request<T>({ url, method: 'PATCH', data, ...config });
  }

  async head(url: string, config?: RequestConfig): Promise<ApiResponse<void>> {
    return this.request<void>({ url, method: 'HEAD', ...config });
  }

  async options(url: string, config?: RequestConfig): Promise<ApiResponse<void>> {
    return this.request<void>({ url, method: 'OPTIONS', ...config });
  }

  // ==================== FILE UPLOAD ====================

  async upload<T>(url: string, file: File | FormData, config?: RequestConfig): Promise<ApiResponse<T>> {
    let formData: FormData;

    if (file instanceof FormData) {
      formData = file;
    } else {
      formData = new FormData();
      formData.append('file', file);
    }

    return this.request<T>({
      url,
      method: 'POST',
      data: formData,
      headers: {
        // Remove Content-Type to let browser set boundary
        ...config?.headers,
        'Content-Type': undefined as any,
      },
      ...config,
    });
  }

  async uploadMultiple<T>(url: string, files: File[], config?: RequestConfig): Promise<ApiResponse<T>> {
    const formData = new FormData();
    files.forEach((file, index) => {
      formData.append(`files[${index}]`, file);
    });

    return this.upload<T>(url, formData, config);
  }

  // ==================== BATCH REQUESTS ====================

  async batch<T>(requests: BatchRequest[]): Promise<BatchResponse<T>[]> {
    const promises = requests.map(async (request) => {
      try {
        const response = await this.request<T>({
          url: request.url,
          method: request.method,
          data: request.data,
          ...request.config,
        });
        
        return {
          id: request.id,
          response,
        };
      } catch (error) {
        return {
          id: request.id,
          error,
        };
      }
    });

    return Promise.all(promises);
  }

  // ==================== CORE REQUEST METHOD ====================

  private async request<T>(config: InternalRequestConfig): Promise<ApiResponse<T>> {
    const requestId = generateRequestId();
    const startTime = performance.now();

    try {
      // Build full URL
      const fullUrl = this.buildUrl(config.url, config.params);
      
      // Create error context for debugging
      const errorContext: ErrorContext = {
        url: fullUrl,
        method: config.method,
        requestId,
        timestamp: new Date().toISOString(),
        config,
        attempt: 1,
        maxRetries: config.retries ?? this.config.retries,
      };

      // Check cache first
      if (config.method === 'GET' && config.cache !== false) {
        const cacheKey = this.getCacheKey(fullUrl, config);
        const cached = this.getFromCache<T>(cacheKey);
        if (cached) {
          return cached.data;
        }
      }

      // Apply request interceptors
      let finalConfig = await this.applyRequestInterceptors(config);

      // Perform request with retry logic
      const response = await this.executeWithRetry<T>(finalConfig, errorContext);

      // Apply response interceptors
      const finalResponse = await this.applyResponseInterceptors(response);

      // Cache GET requests
      if (config.method === 'GET' && config.cache !== false && finalResponse.success) {
        const cacheKey = this.getCacheKey(fullUrl, config);
        const ttl = typeof config.cache === 'number' ? config.cache : 5 * 60 * 1000; // 5 minutes default
        this.setCache(cacheKey, finalResponse, ttl);
      }

      // Track performance
      this.trackPerformance({
        url: fullUrl,
        method: config.method,
        duration: performance.now() - startTime,
        status: finalResponse.success ? 200 : 500,
        cached: false,
      });

      return finalResponse;

    } catch (error) {
      // Track error
      this.trackPerformance({
        url: this.buildUrl(config.url, config.params),
        method: config.method,
        duration: performance.now() - startTime,
        error: ErrorFactory.getErrorMessage(error),
        cached: false,
      });

      throw error;
    } finally {
      // Cleanup active request
      this.activeRequests.delete(requestId);
    }
  }

  // ==================== REQUEST EXECUTION WITH RETRY ====================

  private async executeWithRetry<T>(
    config: InternalRequestConfig,
    context: ErrorContext
  ): Promise<ApiResponse<T>> {
    const maxRetries = config.retries ?? this.config.retries;
    const retryCondition = config.retryCondition ?? this.config.retryCondition!;
    
    let lastError: unknown;

    for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
      try {
        context.attempt = attempt;
        
        // Create abort controller
        const abortController = new AbortController();
        this.activeRequests.set(context.requestId, abortController);

        // Combine signals
        const signals = [abortController.signal];
        if (config.signal) {
          signals.push(config.signal);
        }

        const signal = this.combineSignals(signals);

        // Set timeout
        const timeout = config.timeout ?? this.config.timeout;
        const timeoutId = setTimeout(() => abortController.abort(), timeout);

        try {
          const response = await this.executeRequest<T>(config, signal);
          clearTimeout(timeoutId);
          return response;
        } finally {
          clearTimeout(timeoutId);
        }

      } catch (error) {
        lastError = error;

        // Don't retry on last attempt
        if (attempt > maxRetries) {
          break;
        }

        // Check if error is retryable
        if (!retryCondition(error)) {
          break;
        }

        // Calculate retry delay
        const baseDelay = config.retryDelay ?? this.config.retryDelay;
        const delay = this.calculateRetryDelay(baseDelay, attempt);

        // Wait before retry
        await this.sleep(delay);
      }
    }

    // Throw the last error
    throw lastError;
  }

  // ==================== ACTUAL HTTP REQUEST ====================

  private async executeRequest<T>(
    config: InternalRequestConfig,
    signal: AbortSignal
  ): Promise<ApiResponse<T>> {
    const url = this.buildUrl(config.url, config.params);
    const headers = this.buildHeaders(config);

    try {
      const fetchConfig: RequestInit = {
        method: config.method,
        headers,
        signal,
        credentials: 'include',
      };

      // Add body for non-GET requests
      if (config.data && config.method !== 'GET' && config.method !== 'HEAD') {
        if (config.data instanceof FormData) {
          fetchConfig.body = config.data;
        } else {
          fetchConfig.body = JSON.stringify(config.data);
        }
      }

      const response = await fetch(url, fetchConfig);

      // Parse response
      return await this.parseResponse<T>(response, config);

    } catch (error) {
      if (error instanceof Error) {
        throw NetworkError.fromFetchError(error);
      }
      throw new NetworkError('Request failed', { type: 'network' });
    }
  }

  // ==================== RESPONSE PARSING ====================

  private async parseResponse<T>(
    response: Response,
    config: InternalRequestConfig
  ): Promise<ApiResponse<T>> {
    const responseType = config.responseType || 'json';

    try {
      let data: any;

      switch (responseType) {
        case 'json':
          data = await response.json();
          break;
        case 'text':
          data = await response.text();
          break;
        case 'blob':
          data = await response.blob();
          break;
        case 'arrayBuffer':
          data = await response.arrayBuffer();
          break;
        default:
          data = await response.json();
      }

      // Check if response indicates success
      const validateStatus = config.validateStatus || ((status: number) => status >= 200 && status < 300);
      
      if (!validateStatus(response.status)) {
        throw ErrorFactory.fromStatus(
          response.status,
          data?.message || response.statusText,
          { data },
        );
      }

      // Return success response
      return {
        success: true,
        data: data as T,
        metadata: {
          requestId: generateRequestId(),
          timestamp: new Date().toISOString(),
          version: '1.0',
        },
      };

    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      // Handle parse errors
      throw new ApiError(
        'Failed to parse response',
        'PARSE_ERROR',
        response.status
      );
    }
  }

  // ==================== INTERCEPTORS ====================

  private async applyRequestInterceptors(
    config: InternalRequestConfig
  ): Promise<InternalRequestConfig> {
    let finalConfig = { ...config };

    for (const interceptor of this.requestInterceptors) {
      try {
        finalConfig = await interceptor.handler(finalConfig);
      } catch (error) {
        if (interceptor.errorHandler) {
          interceptor.errorHandler(error);
        } else {
          throw error;
        }
      }
    }

    return finalConfig;
  }

  private async applyResponseInterceptors<T>(
    response: ApiResponse<T>
  ): Promise<ApiResponse<T>> {
    let finalResponse = { ...response };

    for (const interceptor of this.responseInterceptors) {
      try {
        finalResponse = await interceptor.handler(finalResponse);
      } catch (error) {
        if (interceptor.errorHandler) {
          interceptor.errorHandler(error);
        } else {
          throw error;
        }
      }
    }

    return finalResponse;
  }

  // ==================== CONFIGURATION METHODS ====================

  setBaseUrl(baseUrl: string): void {
    (this.config as any).baseUrl = baseUrl;
  }

  setHeader(key: string, value: string): void {
    (this.config as any).headers = {
      ...this.config.headers,
      [key]: value,
    };
  }

  removeHeader(key: string): void {
    const headers = { ...this.config.headers };
    delete headers[key];
    (this.config as any).headers = headers;
  }

  setAuth(config: any): void {
    (this.config as any).auth = config;
  }

  // ==================== INTERCEPTOR MANAGEMENT ====================

  addRequestInterceptor(interceptor: RequestInterceptor): void {
    this.requestInterceptors.push(interceptor);
  }

  addResponseInterceptor(interceptor: ResponseInterceptor): void {
    this.responseInterceptors.push(interceptor);
  }

  removeInterceptor(name: string): void {
    const requestIndex = this.requestInterceptors.findIndex(i => i.name === name);
    if (requestIndex !== -1) {
      this.requestInterceptors.splice(requestIndex, 1);
    }

    const responseIndex = this.responseInterceptors.findIndex(i => i.name === name);
    if (responseIndex !== -1) {
      this.responseInterceptors.splice(responseIndex, 1);
    }
  }

  // ==================== CACHE MANAGEMENT ====================

  clearCache(): void {
    this.cache.clear();
  }

  getCacheKey(url: string, config?: RequestConfig): string {
    const key = `${url}${config ? JSON.stringify(config) : ''}`;
    return btoa(key).replace(/[+/=]/g, '');
  }

  private getFromCache<T>(key: string): CacheEntry<T> | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    
    if (!entry) return null;
    
    // Check if expired
    if (Date.now() > entry.timestamp + entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry;
  }

  private setCache<T>(key: string, data: ApiResponse<T>, ttl: number): void {
    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
      ttl,
      key,
    };

    this.cache.set(key, entry);

    // Simple LRU: remove oldest entries if cache is too large
    if (this.cache.size > 100) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }
  }

  // ==================== UTILITY METHODS ====================

  isOnline(): boolean {
    return navigator.onLine;
  }

  getRetryCount(url: string): number {
    // Implementation would track retry counts per URL
    return 0;
  }

  abort(requestId?: string): void {
    if (requestId) {
      const controller = this.activeRequests.get(requestId);
      controller?.abort();
    }
  }

  abortAll(): void {
    this.activeRequests.forEach(controller => controller.abort());
    this.activeRequests.clear();
  }

  // ==================== HELPER METHODS ====================

  private buildUrl(url: string, params?: Record<string, any>): string {
    const baseUrl = this.config.baseUrl || '';
    const fullUrl = url.startsWith('http') ? url : `${baseUrl}${url}`;

    if (!params) return fullUrl;

    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value != null) {
        searchParams.append(key, String(value));
      }
    });

    const queryString = searchParams.toString();
    return queryString ? `${fullUrl}?${queryString}` : fullUrl;
  }

  private buildHeaders(config: InternalRequestConfig): Record<string, string> {
    const headers: Record<string, string> = {
      ...this.config.headers,
      ...config.headers,
    };

    // Add authentication header
    const auth = this.config.auth;
    if (auth?.tokenProvider) {
      const token = auth.tokenProvider();
      if (token) {
        switch (auth.type) {
          case 'bearer':
            headers.Authorization = `Bearer ${token}`;
            break;
          case 'api-key':
            headers['X-API-Key'] = token;
            break;
        }
      }
    }

    // Remove undefined values
    Object.keys(headers).forEach(key => {
      if (headers[key] === undefined) {
        delete headers[key];
      }
    });

    return headers;
  }

  private calculateRetryDelay(baseDelay: number, attempt: number): number {
    // Exponential backoff with jitter
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 0.1 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, 30000); // Max 30 seconds
  }

  private combineSignals(signals: AbortSignal[]): AbortSignal {
    const controller = new AbortController();
    
    signals.forEach(signal => {
      if (signal.aborted) {
        controller.abort();
      } else {
        signal.addEventListener('abort', () => controller.abort());
      }
    });

    return controller.signal;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private trackPerformance(metrics: {
    url: string;
    method: HttpMethod;
    duration: number;
    status?: number;
    error?: string;
    cached: boolean;
  }): void {
    // Implementation would send metrics to analytics service
    if (process.env.NODE_ENV === 'development') {
      console.log('API Metrics:', metrics);
    }
  }
}

// ==================== UTILITY FUNCTIONS ====================

function generateRequestId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// ==================== DEFAULT INTERCEPTORS ====================

const authInterceptor: RequestInterceptor = {
  name: 'auth',
  handler: async (config) => {
    // This will be implemented with actual auth store integration
    return config;
  },
};

const loggingInterceptor: ResponseInterceptor = {
  name: 'logging',
  handler: async (response) => {
    if (process.env.NODE_ENV === 'development') {
      console.log('API Response:', response);
    }
    return response;
  },
};

// ==================== EXPORT ====================

export const apiClient = new ApiClientImpl();

// Add default interceptors
apiClient.addRequestInterceptor(authInterceptor);
apiClient.addResponseInterceptor(loggingInterceptor);