import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { config } from '../config/config';
import { AppError } from './errorHandler';

// 错误严重程度枚举
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// 错误类别枚举
export enum ErrorCategory {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  VALIDATION = 'validation',
  DATABASE = 'database',
  NETWORK = 'network',
  FILE_SYSTEM = 'file_system',
  THIRD_PARTY = 'third_party',
  RATE_LIMIT = 'rate_limit',
  BUSINESS_LOGIC = 'business_logic',
  SYSTEM = 'system'
}

// 增强的错误类
export class EnhancedError extends AppError {
  public severity: ErrorSeverity;
  public category: ErrorCategory;
  public retryable: boolean;
  public context?: Record<string, any>;
  public userId?: string;
  public requestId?: string;
  public timestamp: Date;
  public correlationId?: string;

  constructor(
    message: string,
    statusCode: number = 500,
    code?: string,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    category: ErrorCategory = ErrorCategory.SYSTEM,
    retryable: boolean = false,
    context?: Record<string, any>
  ) {
    super(message, statusCode, code);
    this.severity = severity;
    this.category = category;
    this.retryable = retryable;
    this.context = context;
    this.timestamp = new Date();
  }
}

// 错误统计接口
interface ErrorStats {
  total: number;
  byCategory: Record<ErrorCategory, number>;
  bySeverity: Record<ErrorSeverity, number>;
  byStatusCode: Record<number, number>;
  recentErrors: Array<{
    timestamp: Date;
    message: string;
    category: ErrorCategory;
    severity: ErrorSeverity;
  }>;
}

// 错误监控类
class ErrorMonitor {
  private stats: ErrorStats = {
    total: 0,
    byCategory: {} as Record<ErrorCategory, number>,
    bySeverity: {} as Record<ErrorSeverity, number>,
    byStatusCode: {},
    recentErrors: []
  };

  private readonly MAX_RECENT_ERRORS = 100;

  constructor() {
    // 初始化统计
    Object.values(ErrorCategory).forEach(category => {
      this.stats.byCategory[category] = 0;
    });
    Object.values(ErrorSeverity).forEach(severity => {
      this.stats.bySeverity[severity] = 0;
    });
  }

  recordError(error: EnhancedError): void {
    this.stats.total++;
    this.stats.byCategory[error.category]++;
    this.stats.bySeverity[error.severity]++;
    this.stats.byStatusCode[error.statusCode] = (this.stats.byStatusCode[error.statusCode] || 0) + 1;

    // 记录最近的错误
    this.stats.recentErrors.unshift({
      timestamp: error.timestamp,
      message: error.message,
      category: error.category,
      severity: error.severity
    });

    // 保持最近错误列表的大小
    if (this.stats.recentErrors.length > this.MAX_RECENT_ERRORS) {
      this.stats.recentErrors = this.stats.recentErrors.slice(0, this.MAX_RECENT_ERRORS);
    }

    // 检查是否需要告警
    this.checkAlertConditions(error);
  }

  private checkAlertConditions(error: EnhancedError): void {
    // 关键错误立即告警
    if (error.severity === ErrorSeverity.CRITICAL) {
      this.sendAlert('Critical Error Detected', {
        message: error.message,
        code: error.code,
        category: error.category,
        requestId: error.requestId,
        userId: error.userId,
        context: error.context
      });
    }

    // 检查错误率是否过高
    const recentCriticalErrors = this.stats.recentErrors
      .filter(e => e.severity === ErrorSeverity.CRITICAL && 
                   Date.now() - e.timestamp.getTime() < 5 * 60 * 1000) // 5分钟内
      .length;

    if (recentCriticalErrors >= 5) {
      this.sendAlert('High Critical Error Rate', {
        count: recentCriticalErrors,
        timeframe: '5 minutes'
      });
    }
  }

  private sendAlert(title: string, details: Record<string, any>): void {
    // 这里可以集成实际的告警系统，比如邮件、Slack、钉钉等
    logger.error('🚨 ALERT: ' + title, details);
    
    // 可以在这里集成第三方告警服务
    // await notificationService.sendAlert(title, details);
  }

  getStats(): ErrorStats {
    return { ...this.stats };
  }

  resetStats(): void {
    this.stats = {
      total: 0,
      byCategory: {} as Record<ErrorCategory, number>,
      bySeverity: {} as Record<ErrorSeverity, number>,
      byStatusCode: {},
      recentErrors: []
    };

    Object.values(ErrorCategory).forEach(category => {
      this.stats.byCategory[category] = 0;
    });
    Object.values(ErrorSeverity).forEach(severity => {
      this.stats.bySeverity[severity] = 0;
    });
  }
}

// 全局错误监控实例
export const errorMonitor = new ErrorMonitor();

// 重试机制类
class RetryManager {
  private static readonly DEFAULT_MAX_RETRIES = 3;
  private static readonly DEFAULT_DELAY = 1000; // 1秒

  static async executeWithRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = this.DEFAULT_MAX_RETRIES,
    baseDelay: number = this.DEFAULT_DELAY,
    exponentialBackoff: boolean = true
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;

        // 检查错误是否可重试
        if (!this.isRetryableError(error) || attempt === maxRetries) {
          throw error;
        }

        // 计算延迟时间
        const delay = exponentialBackoff 
          ? baseDelay * Math.pow(2, attempt)
          : baseDelay;

        logger.warn(`Operation failed, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`, {
          error: (error as Error).message,
          attempt: attempt + 1,
          maxRetries
        });

        await this.delay(delay);
      }
    }

    throw lastError!;
  }

  private static isRetryableError(error: any): boolean {
    if (error instanceof EnhancedError) {
      return error.retryable;
    }

    // 基于错误类型判断是否可重试
    const retryableCodes = [
      'ECONNRESET',
      'ETIMEDOUT',
      'ENOTFOUND',
      'EAI_AGAIN',
      'ECONNREFUSED'
    ];

    const retryableStatusCodes = [408, 429, 502, 503, 504];

    return retryableCodes.includes(error.code) || 
           retryableStatusCodes.includes(error.statusCode);
  }

  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// 错误工厂类
export class ErrorFactory {
  static createDatabaseError(message: string, originalError?: any): EnhancedError {
    return new EnhancedError(
      message,
      500,
      'DATABASE_ERROR',
      ErrorSeverity.HIGH,
      ErrorCategory.DATABASE,
      true, // 数据库错误通常可重试
      { originalError: originalError?.message }
    );
  }

  static createValidationError(field: string, message: string): EnhancedError {
    return new EnhancedError(
      `${field}: ${message}`,
      400,
      'VALIDATION_ERROR',
      ErrorSeverity.LOW,
      ErrorCategory.VALIDATION,
      false
    );
  }

  static createAuthenticationError(message: string = '身份验证失败'): EnhancedError {
    return new EnhancedError(
      message,
      401,
      'AUTHENTICATION_ERROR',
      ErrorSeverity.MEDIUM,
      ErrorCategory.AUTHENTICATION,
      false
    );
  }

  static createAuthorizationError(message: string = '权限不足'): EnhancedError {
    return new EnhancedError(
      message,
      403,
      'AUTHORIZATION_ERROR',
      ErrorSeverity.MEDIUM,
      ErrorCategory.AUTHORIZATION,
      false
    );
  }

  static createRateLimitError(): EnhancedError {
    return new EnhancedError(
      '请求过于频繁，请稍后重试',
      429,
      'RATE_LIMIT_EXCEEDED',
      ErrorSeverity.LOW,
      ErrorCategory.RATE_LIMIT,
      true
    );
  }

  static createNetworkError(message: string, retryable: boolean = true): EnhancedError {
    return new EnhancedError(
      message,
      503,
      'NETWORK_ERROR',
      ErrorSeverity.HIGH,
      ErrorCategory.NETWORK,
      retryable
    );
  }

  static createBusinessLogicError(message: string, code?: string): EnhancedError {
    return new EnhancedError(
      message,
      400,
      code || 'BUSINESS_LOGIC_ERROR',
      ErrorSeverity.MEDIUM,
      ErrorCategory.BUSINESS_LOGIC,
      false
    );
  }

  static createSystemError(message: string, critical: boolean = false): EnhancedError {
    return new EnhancedError(
      message,
      500,
      'SYSTEM_ERROR',
      critical ? ErrorSeverity.CRITICAL : ErrorSeverity.HIGH,
      ErrorCategory.SYSTEM,
      false
    );
  }
}

// 增强的错误处理中间件
export const enhancedErrorHandler = (
  error: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let enhancedError: EnhancedError;

  // 转换为增强错误
  if (error instanceof EnhancedError) {
    enhancedError = error;
  } else if (error instanceof AppError) {
    enhancedError = new EnhancedError(
      error.message,
      error.statusCode,
      error.code,
      ErrorSeverity.MEDIUM,
      ErrorCategory.SYSTEM,
      false
    );
  } else {
    // 处理原生错误
    enhancedError = convertToEnhancedError(error);
  }

  // 添加请求上下文
  enhancedError.requestId = req.id;
  enhancedError.userId = (req as any).user?.id;
  enhancedError.correlationId = req.headers['x-correlation-id'] as string;
  
  if (!enhancedError.context) {
    enhancedError.context = {};
  }
  enhancedError.context['url'] = req.url;
  enhancedError.context['method'] = req.method;
  enhancedError.context['userAgent'] = req.headers['user-agent'];
  enhancedError.context['ip'] = req.ip;

  // 记录错误统计
  errorMonitor.recordError(enhancedError);

  // 构造响应
  const errorResponse = {
    success: false,
    error: {
      code: enhancedError.code || 'INTERNAL_SERVER_ERROR',
      message: enhancedError.message,
      category: enhancedError.category,
      retryable: enhancedError.retryable,
      requestId: enhancedError.requestId,
      timestamp: enhancedError.timestamp.toISOString()
    },
    timestamp: new Date().toISOString()
  };

  // 在开发环境中包含更多信息
  if (config.nodeEnv === 'development') {
    (errorResponse.error as any).stack = enhancedError.stack;
    (errorResponse.error as any).context = enhancedError.context;
    (errorResponse.error as any).severity = enhancedError.severity;
  }

  // 记录日志
  const logLevel = getLogLevel(enhancedError.severity);
  logger[logLevel]('Enhanced Error Handler', {
    requestId: enhancedError.requestId,
    userId: enhancedError.userId,
    correlationId: enhancedError.correlationId,
    error: {
      message: enhancedError.message,
      code: enhancedError.code,
      category: enhancedError.category,
      severity: enhancedError.severity,
      retryable: enhancedError.retryable,
      statusCode: enhancedError.statusCode
    },
    context: enhancedError.context,
    stack: config.nodeEnv === 'development' ? enhancedError.stack : undefined
  });

  res.status(enhancedError.statusCode).json(errorResponse);
};

// 转换原生错误为增强错误
function convertToEnhancedError(error: any): EnhancedError {
  // 数据库错误
  if (error.code && typeof error.code === 'string') {
    if (error.code.startsWith('23')) {
      return ErrorFactory.createDatabaseError('数据库约束违反', error);
    }
    if (error.code.startsWith('42')) {
      return ErrorFactory.createDatabaseError('数据库查询错误', error);
    }
    if (['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT'].includes(error.code)) {
      return ErrorFactory.createNetworkError(`网络连接失败: ${error.message}`);
    }
  }

  // JWT错误
  if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
    return ErrorFactory.createAuthenticationError('令牌验证失败');
  }

  // 验证错误
  if (error.name === 'ValidationError') {
    return ErrorFactory.createValidationError('validation', '数据验证失败');
  }

  // 默认系统错误
  return ErrorFactory.createSystemError(
    config.nodeEnv === 'development' ? error.message : '系统内部错误'
  );
}

// 根据错误严重程度获取日志级别
function getLogLevel(severity: ErrorSeverity): 'debug' | 'info' | 'warn' | 'error' {
  switch (severity) {
    case ErrorSeverity.LOW:
      return 'info';
    case ErrorSeverity.MEDIUM:
      return 'warn';
    case ErrorSeverity.HIGH:
    case ErrorSeverity.CRITICAL:
      return 'error';
    default:
      return 'error';
  }
}

// 异步错误包装器（支持重试）
export const asyncHandlerWithRetry = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>,
  maxRetries: number = 1
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await RetryManager.executeWithRetry(
        () => fn(req, res, next),
        maxRetries
      );
    } catch (error) {
      next(error);
    }
  };
};

// 导出重试管理器
export { RetryManager };

export default enhancedErrorHandler;