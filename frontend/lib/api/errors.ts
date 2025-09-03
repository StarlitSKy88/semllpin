/**
 * API Error Classes
 * Custom error types for comprehensive error handling
 */

import type { ApiErrorResponse, ErrorContext, NetworkErrorInfo, ValidationErrorInfo } from './types';

// ==================== BASE API ERROR ====================

export class ApiError extends Error {
  public readonly name = 'ApiError';
  public readonly code: string;
  public readonly status?: number;
  public readonly context?: ErrorContext;
  public readonly timestamp: string;
  public readonly requestId?: string;
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    code: string = 'API_ERROR',
    status?: number,
    context?: ErrorContext,
    details?: Record<string, unknown>
  ) {
    super(message);
    
    this.code = code;
    this.status = status;
    this.context = context;
    this.timestamp = new Date().toISOString();
    this.requestId = context?.requestId;
    this.details = details;

    // Maintains proper stack trace for where error was thrown (only in V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiError);
    }
  }

  /**
   * Create ApiError from API response
   */
  static fromResponse(
    response: { status: number; data?: ApiErrorResponse },
    context?: ErrorContext
  ): ApiError {
    const errorData = response.data;
    const message = errorData?.message || `HTTP ${response.status} Error`;
    const code = errorData?.code || `HTTP_${response.status}`;
    
    return new ApiError(
      message,
      code,
      response.status,
      context,
      errorData?.details
    );
  }

  /**
   * Convert to plain object for serialization
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      status: this.status,
      timestamp: this.timestamp,
      requestId: this.requestId,
      details: this.details,
      stack: this.stack,
    };
  }

  /**
   * Check if error is retryable
   */
  isRetryable(): boolean {
    // Default retry conditions
    if (!this.status) return false;
    
    return (
      this.status >= 500 || // Server errors
      this.status === 408 || // Request timeout
      this.status === 429    // Too many requests
    );
  }
}

// ==================== NETWORK ERROR ====================

export class NetworkError extends ApiError {
  public readonly name = 'NetworkError';
  public readonly networkInfo: NetworkErrorInfo;

  constructor(
    message: string,
    networkInfo: NetworkErrorInfo,
    context?: ErrorContext
  ) {
    super(message, 'NETWORK_ERROR', networkInfo.status, context);
    this.networkInfo = networkInfo;
  }

  /**
   * Create from fetch error
   */
  static fromFetchError(
    error: Error,
    context?: ErrorContext
  ): NetworkError {
    let networkInfo: NetworkErrorInfo;
    
    if (error.name === 'AbortError') {
      networkInfo = { type: 'abort' };
    } else if (error.name === 'TimeoutError' || error.message.includes('timeout')) {
      networkInfo = { type: 'timeout' };
    } else if (!navigator.onLine) {
      networkInfo = { type: 'offline' };
    } else {
      networkInfo = { type: 'network' };
    }

    return new NetworkError(
      error.message || 'Network request failed',
      networkInfo,
      context
    );
  }

  /**
   * Network errors are generally retryable
   */
  isRetryable(): boolean {
    return this.networkInfo.type !== 'abort';
  }
}

// ==================== VALIDATION ERROR ====================

export class ValidationError extends ApiError {
  public readonly name = 'ValidationError';
  public readonly validationInfo: ValidationErrorInfo;

  constructor(
    message: string,
    validationInfo: ValidationErrorInfo,
    context?: ErrorContext
  ) {
    super(message, 'VALIDATION_ERROR', 400, context);
    this.validationInfo = validationInfo;
  }

  /**
   * Create from API validation response
   */
  static fromResponse(
    response: { status: number; data?: ApiErrorResponse },
    context?: ErrorContext
  ): ValidationError {
    const errorData = response.data;
    const fields = errorData?.validation || [];
    
    const validationInfo: ValidationErrorInfo = {
      fields,
      code: errorData?.code || 'VALIDATION_FAILED',
      message: errorData?.message || 'Validation failed',
    };

    return new ValidationError(
      validationInfo.message,
      validationInfo,
      context
    );
  }

  /**
   * Get field-specific error
   */
  getFieldError(fieldName: string): string | null {
    const field = this.validationInfo.fields.find(f => f.field === fieldName);
    return field?.message || null;
  }

  /**
   * Get all field errors as object
   */
  getFieldErrors(): Record<string, string> {
    return this.validationInfo.fields.reduce((acc, field) => {
      acc[field.field] = field.message;
      return acc;
    }, {} as Record<string, string>);
  }

  /**
   * Validation errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== AUTHENTICATION ERROR ====================

export class AuthenticationError extends ApiError {
  public readonly name = 'AuthenticationError';

  constructor(
    message: string = 'Authentication failed',
    code: string = 'AUTH_ERROR',
    context?: ErrorContext
  ) {
    super(message, code, 401, context);
  }

  /**
   * Authentication errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== AUTHORIZATION ERROR ====================

export class AuthorizationError extends ApiError {
  public readonly name = 'AuthorizationError';

  constructor(
    message: string = 'Access forbidden',
    code: string = 'FORBIDDEN',
    context?: ErrorContext
  ) {
    super(message, code, 403, context);
  }

  /**
   * Authorization errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== NOT FOUND ERROR ====================

export class NotFoundError extends ApiError {
  public readonly name = 'NotFoundError';

  constructor(
    message: string = 'Resource not found',
    code: string = 'NOT_FOUND',
    context?: ErrorContext
  ) {
    super(message, code, 404, context);
  }

  /**
   * Not found errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== CONFLICT ERROR ====================

export class ConflictError extends ApiError {
  public readonly name = 'ConflictError';

  constructor(
    message: string = 'Resource conflict',
    code: string = 'CONFLICT',
    context?: ErrorContext
  ) {
    super(message, code, 409, context);
  }

  /**
   * Conflict errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== RATE LIMIT ERROR ====================

export class RateLimitError extends ApiError {
  public readonly name = 'RateLimitError';
  public readonly retryAfter?: number;

  constructor(
    message: string = 'Rate limit exceeded',
    retryAfter?: number,
    context?: ErrorContext
  ) {
    super(message, 'RATE_LIMIT_EXCEEDED', 429, context);
    this.retryAfter = retryAfter;
  }

  /**
   * Rate limit errors are retryable after a delay
   */
  isRetryable(): boolean {
    return true;
  }

  /**
   * Get retry delay in milliseconds
   */
  getRetryDelay(): number {
    return (this.retryAfter || 60) * 1000; // Default to 60 seconds
  }
}

// ==================== SERVER ERROR ====================

export class ServerError extends ApiError {
  public readonly name = 'ServerError';

  constructor(
    message: string = 'Internal server error',
    status: number = 500,
    code: string = 'SERVER_ERROR',
    context?: ErrorContext
  ) {
    super(message, code, status, context);
  }

  /**
   * Server errors are generally retryable
   */
  isRetryable(): boolean {
    return true;
  }
}

// ==================== TIMEOUT ERROR ====================

export class TimeoutError extends NetworkError {
  public readonly name = 'TimeoutError';

  constructor(
    message: string = 'Request timeout',
    timeout: number,
    context?: ErrorContext
  ) {
    super(message, { type: 'timeout' }, context);
  }

  /**
   * Timeout errors are retryable
   */
  isRetryable(): boolean {
    return true;
  }
}

// ==================== ABORT ERROR ====================

export class AbortError extends NetworkError {
  public readonly name = 'AbortError';

  constructor(
    message: string = 'Request aborted',
    context?: ErrorContext
  ) {
    super(message, { type: 'abort' }, context);
  }

  /**
   * Abort errors are not retryable
   */
  isRetryable(): boolean {
    return false;
  }
}

// ==================== ERROR FACTORY ====================

export class ErrorFactory {
  /**
   * Create appropriate error from HTTP status
   */
  static fromStatus(
    status: number,
    message: string,
    response?: { data?: ApiErrorResponse },
    context?: ErrorContext
  ): ApiError {
    const errorData = response?.data;
    const code = errorData?.code || `HTTP_${status}`;

    switch (status) {
      case 400:
        if (errorData?.validation?.length) {
          return ValidationError.fromResponse({ status, data: errorData }, context);
        }
        return new ApiError(message, code, status, context);
      
      case 401:
        return new AuthenticationError(message, code, context);
      
      case 403:
        return new AuthorizationError(message, code, context);
      
      case 404:
        return new NotFoundError(message, code, context);
      
      case 409:
        return new ConflictError(message, code, context);
      
      case 429:
        const retryAfter = errorData?.details?.retryAfter as number | undefined;
        return new RateLimitError(message, retryAfter, context);
      
      case 408:
        return new TimeoutError(message, 0, context);
      
      default:
        if (status >= 500) {
          return new ServerError(message, status, code, context);
        }
        
        return new ApiError(message, code, status, context);
    }
  }

  /**
   * Create error from network failure
   */
  static fromNetworkError(
    error: Error,
    context?: ErrorContext
  ): NetworkError {
    return NetworkError.fromFetchError(error, context);
  }

  /**
   * Check if error is of specific type
   */
  static isErrorType<T extends ApiError>(
    error: unknown,
    ErrorClass: new (...args: any[]) => T
  ): error is T {
    return error instanceof ErrorClass;
  }

  /**
   * Extract error message from unknown error
   */
  static getErrorMessage(error: unknown): string {
    if (error instanceof ApiError) {
      return error.message;
    }
    
    if (error instanceof Error) {
      return error.message;
    }
    
    if (typeof error === 'string') {
      return error;
    }
    
    return 'An unknown error occurred';
  }

  /**
   * Check if error is retryable
   */
  static isRetryable(error: unknown): boolean {
    if (error instanceof ApiError) {
      return error.isRetryable();
    }
    
    return false;
  }
}