import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { config } from '../config/config';

// Custom error class
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public code?: string;

  constructor(
    message: string,
    statusCode: number = 500,
    code?: string,
    isOperational: boolean = true,
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    if (code) {
      this.code = code;
    }

    Error.captureStackTrace(this, this.constructor);
  }
}

// Error response interface
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    stack?: string;
  };
  timestamp: string;
}

// Send error response
const sendErrorResponse = (
  res: Response,
  error: AppError,
  req: Request,
): void => {
  const errorResponse: ErrorResponse = {
    success: false,
    error: {
      code: error.code || 'INTERNAL_SERVER_ERROR',
      message: error.message,
    },
    timestamp: new Date().toISOString(),
  };

  // Include stack trace in development// 在开发环境中添加错误堆栈
  if (config.nodeEnv === 'development' && error.stack) {
    errorResponse.error.stack = error.stack;
  }

  // Log error
  const logData: any = {
    requestId: req.id,
    method: req.method,
    url: req.url,
    statusCode: error.statusCode,
    message: error.message,
    stack: error.stack,
  };

  if (req.user?.id) {
    logData.userId = req.user.id;
  }

  logger.error('API Error:', logData);

  res.status(error.statusCode).json(errorResponse);
};

// Handle different types of errors
const handleDatabaseError = (error: any): AppError => {
  if (error.code === '23505') {
    // Unique constraint violation
    return new AppError('数据已存在', 409, 'DUPLICATE_ENTRY');
  }

  if (error.code === '23503') {
    // Foreign key constraint violation
    return new AppError('关联数据不存在', 400, 'FOREIGN_KEY_VIOLATION');
  }

  if (error.code === '23502') {
    // Not null constraint violation
    return new AppError('必填字段不能为空', 400, 'REQUIRED_FIELD_MISSING');
  }

  if (error.code === '42P01') {
    // Table does not exist
    return new AppError('数据表不存在', 500, 'TABLE_NOT_FOUND');
  }

  return new AppError('数据库操作失败', 500, 'DATABASE_ERROR');
};

const handleValidationError = (error: any): AppError => {
  const messages = error.details?.map((detail: any) => detail.message).join(', ');
  return new AppError(
    `数据验证失败: ${messages}`,
    400,
    'VALIDATION_ERROR',
  );
};

const handleJWTError = (error: any): AppError => {
  if (error.name === 'JsonWebTokenError') {
    return new AppError('无效的访问令牌', 401, 'INVALID_TOKEN');
  }

  if (error.name === 'TokenExpiredError') {
    return new AppError('访问令牌已过期', 401, 'TOKEN_EXPIRED');
  }

  return new AppError('令牌验证失败', 401, 'TOKEN_ERROR');
};

const handleMulterError = (error: any): AppError => {
  if (error.code === 'LIMIT_FILE_SIZE') {
    return new AppError('文件大小超出限制', 400, 'FILE_TOO_LARGE');
  }

  if (error.code === 'LIMIT_FILE_COUNT') {
    return new AppError('文件数量超出限制', 400, 'TOO_MANY_FILES');
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return new AppError('不支持的文件类型', 400, 'UNSUPPORTED_FILE_TYPE');
  }

  return new AppError('文件上传失败', 400, 'FILE_UPLOAD_ERROR');
};

const handleCastError = (_error: any): AppError => {
  return new AppError('无效的数据格式', 400, 'INVALID_DATA_FORMAT');
};

// Main error handler middleware
export const errorHandler = (
  error: any,
  req: Request,
  res: Response,
  _next: NextFunction,
): void => {
  let appError: AppError;

  // If it's already an AppError, use it directly
  if (error instanceof AppError) {
    appError = error;
  } else {
    // Handle different types of errors
    if (error.name === 'ValidationError') {
      appError = handleValidationError(error);
    } else if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      appError = handleJWTError(error);
    } else if (error.code && typeof error.code === 'string') {
      if (error.code.startsWith('23') || error.code.startsWith('42')) {
        appError = handleDatabaseError(error);
      } else if (error.code.startsWith('LIMIT_')) {
        appError = handleMulterError(error);
      } else {
        appError = new AppError('服务器内部错误', 500, 'INTERNAL_SERVER_ERROR');
      }
    } else if (error.name === 'CastError') {
      appError = handleCastError(error);
    } else {
      // Generic error
      appError = new AppError(
        config.nodeEnv === 'development' ? error.message : '服务器内部错误',
        500,
        'INTERNAL_SERVER_ERROR',
      );
    }
  }

  sendErrorResponse(res, appError, req);
};

// Async error wrapper
export const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>,
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Not found handler
export const notFoundHandler = (
  req: Request,
  _res: Response,
  next: NextFunction,
): void => {
  const error = new AppError(
    `路由 ${req.originalUrl} 不存在`,
    404,
    'ROUTE_NOT_FOUND',
  );
  next(error);
};

// Validation error helper
export const createValidationError = (
  field: string,
  message: string,
): AppError => {
  return new AppError(
    `${field}: ${message}`,
    400,
    'VALIDATION_ERROR',
  );
};

// Authorization error helper
export const createAuthError = (message: string = '未授权访问'): AppError => {
  return new AppError(message, 401, 'UNAUTHORIZED');
};

// Forbidden error helper
export const createForbiddenError = (message: string = '权限不足'): AppError => {
  return new AppError(message, 403, 'FORBIDDEN');
};

// Not found error helper
export const createNotFoundError = (resource: string = '资源'): AppError => {
  return new AppError(`${resource}不存在`, 404, 'NOT_FOUND');
};

// Conflict error helper
export const createConflictError = (message: string): AppError => {
  return new AppError(message, 409, 'CONFLICT');
};

// Rate limit error helper
export const createRateLimitError = (): AppError => {
  return new AppError(
    '请求过于频繁，请稍后再试',
    429,
    'RATE_LIMIT_EXCEEDED',
  );
};

export default errorHandler;
