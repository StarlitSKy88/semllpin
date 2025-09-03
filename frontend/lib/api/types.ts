/**
 * API Client Type Definitions
 * Comprehensive types for HTTP client functionality
 */

// ==================== BASE TYPES ====================

export interface ApiResponse<T = unknown> {
  readonly success: boolean;
  readonly data?: T;
  readonly error?: ApiErrorResponse;
  readonly metadata?: ResponseMetadata;
}

export interface ApiErrorResponse {
  readonly code: string;
  readonly message: string;
  readonly details?: Record<string, unknown>;
  readonly timestamp: string;
  readonly requestId?: string;
  readonly validation?: ValidationErrorField[];
}

export interface ValidationErrorField {
  readonly field: string;
  readonly message: string;
  readonly code: string;
  readonly value?: unknown;
}

export interface ResponseMetadata {
  readonly pagination?: PaginationInfo;
  readonly requestId: string;
  readonly timestamp: string;
  readonly version: string;
  readonly rateLimit?: RateLimitInfo;
}

export interface PaginationInfo {
  readonly page: number;
  readonly limit: number;
  readonly total: number;
  readonly totalPages: number;
  readonly hasNext: boolean;
  readonly hasPrevious: boolean;
}

export interface RateLimitInfo {
  readonly limit: number;
  readonly remaining: number;
  readonly reset: number;
  readonly retryAfter?: number;
}

// ==================== CLIENT CONFIGURATION ====================

export interface ApiClientConfig {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly retries: number;
  readonly retryDelay: number;
  readonly retryCondition?: (error: unknown) => boolean;
  readonly headers?: Record<string, string>;
  readonly interceptors?: {
    readonly request?: RequestInterceptor[];
    readonly response?: ResponseInterceptor[];
  };
  readonly auth?: AuthConfig;
  readonly cache?: CacheConfig;
}

export interface AuthConfig {
  readonly type: 'bearer' | 'api-key' | 'basic';
  readonly tokenProvider?: () => string | null;
  readonly refreshTokenProvider?: () => Promise<string>;
  readonly onAuthError?: (error: unknown) => void;
}

export interface CacheConfig {
  readonly enabled: boolean;
  readonly ttl: number; // Time to live in milliseconds
  readonly maxSize: number;
  readonly keyGenerator?: (url: string, config?: RequestConfig) => string;
}

// ==================== REQUEST CONFIGURATION ====================

export interface RequestConfig {
  readonly headers?: Record<string, string>;
  readonly timeout?: number;
  readonly retries?: number;
  readonly retryDelay?: number;
  readonly cache?: boolean | number; // true for default TTL, number for specific TTL
  readonly signal?: AbortSignal;
  readonly onUploadProgress?: (progress: ProgressEvent) => void;
  readonly onDownloadProgress?: (progress: ProgressEvent) => void;
  readonly validateStatus?: (status: number) => boolean;
  readonly responseType?: 'json' | 'text' | 'blob' | 'arrayBuffer';
}

// ==================== INTERCEPTORS ====================

export interface RequestInterceptor {
  readonly name: string;
  readonly handler: (config: InternalRequestConfig) => InternalRequestConfig | Promise<InternalRequestConfig>;
  readonly errorHandler?: (error: unknown) => unknown;
}

export interface ResponseInterceptor {
  readonly name: string;
  readonly handler: <T>(response: ApiResponse<T>) => ApiResponse<T> | Promise<ApiResponse<T>>;
  readonly errorHandler?: (error: unknown) => unknown;
}

export interface InternalRequestConfig extends RequestConfig {
  readonly url: string;
  readonly method: HttpMethod;
  readonly data?: unknown;
  readonly params?: Record<string, string | number | boolean>;
  readonly baseUrl?: string;
}

// ==================== HTTP METHODS ====================

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

// ==================== CLIENT INTERFACE ====================

export interface ApiClient {
  readonly config: ApiClientConfig;
  
  // HTTP methods
  readonly get: <T>(url: string, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly post: <T>(url: string, data?: unknown, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly put: <T>(url: string, data?: unknown, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly delete: <T>(url: string, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly patch: <T>(url: string, data?: unknown, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly head: (url: string, config?: RequestConfig) => Promise<ApiResponse<void>>;
  readonly options: (url: string, config?: RequestConfig) => Promise<ApiResponse<void>>;
  
  // File upload
  readonly upload: <T>(url: string, file: File | FormData, config?: RequestConfig) => Promise<ApiResponse<T>>;
  readonly uploadMultiple: <T>(url: string, files: File[], config?: RequestConfig) => Promise<ApiResponse<T>>;
  
  // Batch requests
  readonly batch: <T>(requests: BatchRequest[]) => Promise<BatchResponse<T>[]>;
  
  // Configuration
  readonly setBaseUrl: (baseUrl: string) => void;
  readonly setHeader: (key: string, value: string) => void;
  readonly removeHeader: (key: string) => void;
  readonly setAuth: (config: AuthConfig) => void;
  
  // Interceptors
  readonly addRequestInterceptor: (interceptor: RequestInterceptor) => void;
  readonly addResponseInterceptor: (interceptor: ResponseInterceptor) => void;
  readonly removeInterceptor: (name: string) => void;
  
  // Cache
  readonly clearCache: () => void;
  readonly getCacheKey: (url: string, config?: RequestConfig) => string;
  
  // Utilities
  readonly isOnline: () => boolean;
  readonly getRetryCount: (url: string) => number;
  readonly abort: (requestId?: string) => void;
  readonly abortAll: () => void;
}

// ==================== BATCH REQUESTS ====================

export interface BatchRequest {
  readonly id: string;
  readonly url: string;
  readonly method: HttpMethod;
  readonly data?: unknown;
  readonly config?: RequestConfig;
}

export interface BatchResponse<T> {
  readonly id: string;
  readonly response?: ApiResponse<T>;
  readonly error?: unknown;
}

// ==================== CACHE TYPES ====================

export interface CacheEntry<T = unknown> {
  readonly data: ApiResponse<T>;
  readonly timestamp: number;
  readonly ttl: number;
  readonly key: string;
}

export interface CacheStorage {
  readonly get: <T>(key: string) => CacheEntry<T> | null;
  readonly set: <T>(key: string, entry: CacheEntry<T>) => void;
  readonly delete: (key: string) => void;
  readonly clear: () => void;
  readonly size: () => number;
  readonly keys: () => string[];
}

// ==================== ERROR TYPES ====================

export interface ErrorContext {
  readonly url: string;
  readonly method: HttpMethod;
  readonly requestId: string;
  readonly timestamp: string;
  readonly config: InternalRequestConfig;
  readonly attempt: number;
  readonly maxRetries: number;
}

export interface NetworkErrorInfo {
  readonly type: 'network' | 'timeout' | 'abort' | 'offline';
  readonly status?: number;
  readonly statusText?: string;
  readonly headers?: Record<string, string>;
}

export interface ValidationErrorInfo {
  readonly fields: ValidationErrorField[];
  readonly code: string;
  readonly message: string;
}

// ==================== MIDDLEWARE TYPES ====================

export interface Middleware {
  readonly name: string;
  readonly priority: number;
  readonly execute: (context: MiddlewareContext) => Promise<MiddlewareContext>;
}

export interface MiddlewareContext {
  readonly request: InternalRequestConfig;
  readonly response?: ApiResponse;
  readonly error?: unknown;
  readonly metadata: Record<string, unknown>;
}

// ==================== RETRY CONFIGURATION ====================

export interface RetryConfig {
  readonly maxRetries: number;
  readonly retryDelay: number;
  readonly retryDelayType: 'fixed' | 'exponential' | 'linear';
  readonly maxRetryDelay: number;
  readonly retryCondition: (error: unknown, attempt: number) => boolean;
  readonly onRetry?: (error: unknown, attempt: number) => void;
}

// ==================== RATE LIMITING ====================

export interface RateLimiter {
  readonly canMakeRequest: () => boolean;
  readonly getRemainingRequests: () => number;
  readonly getResetTime: () => number;
  readonly waitForReset: () => Promise<void>;
}

// ==================== MONITORING & ANALYTICS ====================

export interface RequestMetrics {
  readonly startTime: number;
  readonly endTime?: number;
  readonly duration?: number;
  readonly size?: {
    readonly request: number;
    readonly response: number;
  };
  readonly cached: boolean;
  readonly retryCount: number;
}

export interface AnalyticsEvent {
  readonly type: 'request' | 'response' | 'error' | 'cache-hit' | 'cache-miss';
  readonly url: string;
  readonly method: HttpMethod;
  readonly status?: number;
  readonly duration?: number;
  readonly error?: string;
  readonly metadata?: Record<string, unknown>;
  readonly timestamp: number;
}

export interface AnalyticsProvider {
  readonly track: (event: AnalyticsEvent) => void;
  readonly flush: () => Promise<void>;
}

// ==================== WEB VITALS INTEGRATION ====================

export interface PerformanceMetrics {
  readonly fcp?: number; // First Contentful Paint
  readonly lcp?: number; // Largest Contentful Paint
  readonly fid?: number; // First Input Delay
  readonly cls?: number; // Cumulative Layout Shift
  readonly ttfb?: number; // Time to First Byte
}

export interface WebVitalsConfig {
  readonly enabled: boolean;
  readonly reportUrl?: string;
  readonly sampleRate: number;
  readonly onReport?: (metrics: PerformanceMetrics) => void;
}