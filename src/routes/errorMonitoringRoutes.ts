import express from 'express';
import { Request, Response } from 'express';
import { errorMonitor, ErrorFactory, ErrorSeverity, ErrorCategory } from '../middleware/enhancedErrorHandler';
import { logger } from '../utils/logger';
import { asyncHandler } from '../middleware/errorHandler';

const router = express.Router();

// 获取错误统计信息
router.get('/stats', asyncHandler(async (req: Request, res: Response) => {
  const stats = errorMonitor.getStats();
  
  // 计算错误率趋势
  const now = Date.now();
  const oneHourAgo = now - 60 * 60 * 1000;
  const recentErrorsCount = stats.recentErrors.filter(
    error => error.timestamp.getTime() > oneHourAgo
  ).length;

  const response = {
    ...stats,
    trends: {
      errorsInLastHour: recentErrorsCount,
      averageErrorsPerHour: stats.total / Math.max(1, Math.floor((now - stats.recentErrors[stats.recentErrors.length - 1]?.timestamp?.getTime() || now) / (60 * 60 * 1000))),
    },
    healthStatus: getHealthStatus(stats)
  };

  res.json({
    success: true,
    data: response,
    timestamp: new Date().toISOString()
  });
}));

// 获取最近的错误列表
router.get('/recent', asyncHandler(async (req: Request, res: Response) => {
  const { limit = 50, severity, category } = req.query;
  const stats = errorMonitor.getStats();
  
  let recentErrors = stats.recentErrors;
  
  // 按严重程度过滤
  if (severity && Object.values(ErrorSeverity).includes(severity as ErrorSeverity)) {
    recentErrors = recentErrors.filter(error => error.severity === severity);
  }
  
  // 按类别过滤
  if (category && Object.values(ErrorCategory).includes(category as ErrorCategory)) {
    recentErrors = recentErrors.filter(error => error.category === category);
  }
  
  // 限制数量
  recentErrors = recentErrors.slice(0, parseInt(limit as string));

  res.json({
    success: true,
    data: {
      errors: recentErrors,
      total: recentErrors.length,
      filters: { severity, category, limit }
    },
    timestamp: new Date().toISOString()
  });
}));

// 重置错误统计
router.post('/reset-stats', asyncHandler(async (req: Request, res: Response) => {
  errorMonitor.resetStats();
  
  logger.info('Error statistics reset', {
    user: req.ip,
    requestId: req.id
  });

  res.json({
    success: true,
    message: 'Error statistics have been reset',
    timestamp: new Date().toISOString()
  });
}));

// 手动触发测试错误（仅开发环境）
router.post('/test-error', asyncHandler(async (req: Request, res: Response) => {
  if (process.env['NODE_ENV'] === 'production') {
    throw ErrorFactory.createAuthorizationError('Test errors are not allowed in production');
  }

  const { type = 'system', severity = ErrorSeverity.MEDIUM } = req.body;

  let testError;
  switch (type) {
    case 'database':
      testError = ErrorFactory.createDatabaseError('Test database error');
      break;
    case 'validation':
      testError = ErrorFactory.createValidationError('testField', 'This is a test validation error');
      break;
    case 'authentication':
      testError = ErrorFactory.createAuthenticationError('Test authentication error');
      break;
    case 'authorization':
      testError = ErrorFactory.createAuthorizationError('Test authorization error');
      break;
    case 'network':
      testError = ErrorFactory.createNetworkError('Test network error');
      break;
    case 'business':
      testError = ErrorFactory.createBusinessLogicError('Test business logic error');
      break;
    case 'critical':
      testError = ErrorFactory.createSystemError('Test critical system error', true);
      break;
    default:
      testError = ErrorFactory.createSystemError('Test system error');
  }

  logger.info('Test error triggered', {
    type,
    severity,
    user: req.ip,
    requestId: req.id
  });

  throw testError;
}));

// 获取错误分析报告
router.get('/analysis', asyncHandler(async (req: Request, res: Response) => {
  const stats = errorMonitor.getStats();
  
  // 分析错误模式
  const analysis = {
    topErrorCategories: getTopItems(stats.byCategory, 5),
    topErrorSeverities: getTopItems(stats.bySeverity, 5),
    topStatusCodes: getTopItems(stats.byStatusCode, 5),
    errorTrends: analyzeErrorTrends(stats.recentErrors),
    recommendations: generateRecommendations(stats)
  };

  res.json({
    success: true,
    data: analysis,
    timestamp: new Date().toISOString()
  });
}));

// 获取系统健康状态
router.get('/health', asyncHandler(async (req: Request, res: Response) => {
  const stats = errorMonitor.getStats();
  const healthStatus = getHealthStatus(stats);
  
  res.json({
    success: true,
    data: {
      status: healthStatus.overall,
      details: healthStatus,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      errorStats: {
        total: stats.total,
        critical: stats.bySeverity[ErrorSeverity.CRITICAL] || 0,
        high: stats.bySeverity[ErrorSeverity.HIGH] || 0
      }
    },
    timestamp: new Date().toISOString()
  });
}));

// 辅助函数：获取Top N项目
function getTopItems(data: Record<string, number>, limit: number = 5) {
  return Object.entries(data)
    .sort(([,a], [,b]) => b - a)
    .slice(0, limit)
    .map(([key, value]) => ({ name: key, count: value }));
}

// 辅助函数：分析错误趋势
function analyzeErrorTrends(recentErrors: Array<{timestamp: Date; severity: ErrorSeverity; category: ErrorCategory}>) {
  const now = Date.now();
  const intervals = {
    last15min: now - 15 * 60 * 1000,
    last1hour: now - 60 * 60 * 1000,
    last6hours: now - 6 * 60 * 60 * 1000,
    last24hours: now - 24 * 60 * 60 * 1000
  };

  const trends: Record<string, number> = {};
  
  Object.entries(intervals).forEach(([period, startTime]) => {
    trends[period] = recentErrors.filter(error => 
      error.timestamp.getTime() > startTime
    ).length;
  });

  return trends;
}

// 辅助函数：生成改进建议
function generateRecommendations(stats: any): string[] {
  const recommendations: string[] = [];

  // 基于错误统计生成建议
  if (stats.bySeverity[ErrorSeverity.CRITICAL] > 0) {
    recommendations.push('检测到关键错误，需要立即处理');
  }

  if (stats.byCategory[ErrorCategory.DATABASE] > stats.total * 0.3) {
    recommendations.push('数据库错误占比较高，建议检查数据库连接和查询优化');
  }

  if (stats.byCategory[ErrorCategory.AUTHENTICATION] > stats.total * 0.2) {
    recommendations.push('认证错误较多，建议检查令牌管理和用户认证流程');
  }

  if (stats.byCategory[ErrorCategory.RATE_LIMIT] > stats.total * 0.1) {
    recommendations.push('限流错误频发，建议调整限流策略或优化客户端重试机制');
  }

  const recentCriticalCount = stats.recentErrors.filter((error: any) => 
    error.severity === ErrorSeverity.CRITICAL && 
    Date.now() - error.timestamp.getTime() < 60 * 60 * 1000
  ).length;

  if (recentCriticalCount > 5) {
    recommendations.push('过去一小时内关键错误过多，建议进行系统检查');
  }

  if (recommendations.length === 0) {
    recommendations.push('系统错误状态良好，继续保持监控');
  }

  return recommendations;
}

// 辅助函数：获取健康状态
function getHealthStatus(stats: any) {
  const criticalCount = stats.bySeverity[ErrorSeverity.CRITICAL] || 0;
  const highCount = stats.bySeverity[ErrorSeverity.HIGH] || 0;
  const totalErrors = stats.total;

  // 计算最近一小时的错误数量
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const recentErrors = stats.recentErrors.filter((error: any) => 
    error.timestamp.getTime() > oneHourAgo
  ).length;

  let overall = 'healthy';
  let score = 100;

  // 扣分规则
  if (criticalCount > 0) {
    score -= criticalCount * 20;
    overall = 'critical';
  }
  
  if (highCount > 5) {
    score -= (highCount - 5) * 5;
    if (overall !== 'critical') overall = 'warning';
  }

  if (recentErrors > 10) {
    score -= (recentErrors - 10) * 2;
    if (overall === 'healthy') overall = 'warning';
  }

  score = Math.max(0, score);

  if (score < 70 && overall !== 'critical') {
    overall = 'warning';
  } else if (score >= 90 && overall !== 'critical') {
    overall = 'healthy';
  }

  return {
    overall,
    score,
    details: {
      criticalErrors: criticalCount,
      highSeverityErrors: highCount,
      totalErrors,
      recentErrorsLastHour: recentErrors
    }
  };
}

export default router;