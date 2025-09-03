import { Env } from '../index';

export interface ErrorResponse {
  error: string;
  message: string;
  status: number;
  timestamp: string;
}

export class APIError extends Error {
  public status: number;
  public code?: string;

  constructor(message: string, status: number = 500, code?: string) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.code = code;
  }
}

export function createErrorResponse(
  error: string,
  message: string,
  status: number = 500
): Response {
  const errorResponse: ErrorResponse = {
    error,
    message,
    status,
    timestamp: new Date().toISOString()
  };

  return new Response(JSON.stringify(errorResponse), {
    status,
    headers: {
      'Content-Type': 'application/json'
    }
  });
}

export function errorHandler(
  error: Error,
  request: Request,
  env: Env
): Response {
  console.error('API Error:', {
    message: error.message,
    stack: error.stack,
    url: request.url,
    method: request.method,
    timestamp: new Date().toISOString()
  });

  // Handle specific error types
  if (error instanceof APIError) {
    return createErrorResponse(
      error.code || 'API_ERROR',
      error.message,
      error.status
    );
  }

  // Handle validation errors (Zod)
  if (error.name === 'ZodError') {
    return createErrorResponse(
      'VALIDATION_ERROR',
      'Invalid request data',
      400
    );
  }

  // Handle JWT authentication errors
  if (error.message.includes('JWT')) {
    return createErrorResponse(
      'AUTH_ERROR',
      'Invalid or expired token',
      401
    );
  }

  // Handle rate limit errors
  if (error.message.includes('rate limit')) {
    return createErrorResponse(
      'RATE_LIMIT_ERROR',
      'Too many requests',
      429
    );
  }

  // Default server error
  return createErrorResponse(
    'INTERNAL_ERROR',
    'An unexpected error occurred',
    500
  );
}

// Utility function to wrap async handlers with error handling
export function withErrorHandler(
  handler: (request: Request, env: Env, ctx: ExecutionContext, params?: Record<string, string>) => Promise<Response>
) {
  return async (request: Request, env: Env, ctx: ExecutionContext, params?: Record<string, string>): Promise<Response> => {
    try {
      return await handler(request, env, ctx, params);
    } catch (error) {
      return errorHandler(error as Error, request, env);
    }
  };
}