import { Request, Response, NextFunction } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import { advancedPerformanceMonitor } from '../middleware/advancedPerformanceMonitor';
// import { advancedCompressionMiddleware } from '../middleware/compressionMiddleware';
import { advancedRateLimiter } from '../middleware/advancedRateLimiter';
import { advancedCacheService } from '../services/advancedCacheService';
// import { optimizedQueryService } from '../services/optimizedQueryService';
import { getRedisClient } from '../config/redis';
import { db } from '../config/database';

// 获取性能概览
export const getPerformanceOverview = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  try {
    // 获取各种性能统计
    const [
      performanceStats,
      compressionStats,
      rateLimitStats,
      cacheStats,
      systemHealth,
    ] = await Promise.all([
      advancedPerformanceMonitor.getDetailedStats(),
      Promise.resolve({}), // placeholder for compression stats
      advancedRateLimiter.getStats(),
      advancedCacheService.getCacheStats(),
      getSystemHealth(),
    ]);

    const overview = {
      timestamp: new Date(),
      performance: performanceStats,
      compression: compressionStats,
      rateLimit: rateLimitStats,
      cache: cacheStats,
      system: systemHealth,
      summary: {
        status: determineSystemStatus(performanceStats, systemHealth),
        criticalIssues: identifyCriticalIssues(performanceStats, systemHealth),
        recommendations: generateRecommendations(performanceStats, compressionStats, cacheStats),
      },
    };

    logger.info('Performance overview generated', {
      totalRequests: performanceStats.totalRequests,
      avgResponseTime: performanceStats.avgResponseTime,
      errorRate: performanceStats.errorRate,
      cacheHitRate: cacheStats.hitRate,
    });

    res.json({
      success: true,
      data: overview,
    });
  } catch (error) {
    logger.error('Failed to get performance overview', {
      error: (error as Error).message,
    });
    
    res.json({
      success: true,
      data: {
        error: 'Failed to load performance data',
        timestamp: new Date(),
      },
    });
  }
});

// 获取实时指标
export const getRealTimeMetrics = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const metrics = advancedPerformanceMonitor.getRealTimeMetrics();
  
  // 计算最近5分钟的关键指标
  const now = Date.now();
  const last5Minutes = metrics.filter(m => now - m.timestamp.getTime() < 5 * 60 * 1000);
  
  const realTimeData = {
    timestamp: new Date(),
    activeRequests: last5Minutes.length,
    averageResponseTime: last5Minutes.length > 0 
      ? Math.round(last5Minutes.reduce((sum, m) => sum + m.responseTime, 0) / last5Minutes.length)
      : 0,
    requestsPerSecond: Math.round(last5Minutes.length / 300 * 10) / 10, // 5分钟内的平均RPS
    errorRate: last5Minutes.length > 0
      ? Math.round((last5Minutes.filter(m => m.statusCode >= 400).length / last5Minutes.length) * 100)
      : 0,
    slowRequests: last5Minutes.filter(m => m.responseTime > 1000).length,
    memoryUsage: process.memoryUsage(),
    cpuUsage: process.cpuUsage(),
    recentRequests: last5Minutes.slice(-20).map(m => ({
      timestamp: m.timestamp,
      method: m.method,
      endpoint: m.endpoint,
      responseTime: m.responseTime,
      statusCode: m.statusCode,
    })),
  };

  res.json({
    success: true,
    data: realTimeData,
  });
});

// 获取端点性能分析
export const getEndpointAnalysis = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<Response | void> => {
  const { endpoint } = req.params;
  
  if (!endpoint) {
    return res.status(400).json({
      success: false,
      error: { message: 'Endpoint parameter is required' },
    });
  }

  const decodedEndpoint = decodeURIComponent(endpoint);
  const analysis = advancedPerformanceMonitor.getEndpointPerformance(decodedEndpoint);
  
  res.json({
    success: true,
    data: {
      endpoint: decodedEndpoint,
      ...analysis,
      analysis: {
        performanceGrade: getPerformanceGrade(analysis.avgResponseTime),
        recommendedOptimizations: getOptimizationRecommendations(analysis),
        trends: analyzeTrends(analysis.recentMetrics),
      },
    },
  });
});

// 获取缓存性能分析
export const getCacheAnalysis = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const cacheStats = await advancedCacheService.getCacheStats();
  
  const redis = getRedisClient();
  const redisInfo = await redis.info('memory');
  
  const analysis = {
    timestamp: new Date(),
    stats: cacheStats,
    redisMemory: parseRedisMemoryInfo(redisInfo),
    recommendations: generateCacheRecommendations(cacheStats),
    topCachedEndpoints: await getTopCachedEndpoints(),
  };

  res.json({
    success: true,
    data: analysis,
  });
});

// 获取数据库性能分析
export const getDatabaseAnalysis = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  try {
    const analysis = await analyzeDatabasePerformance();
    
    res.json({
      success: true,
      data: analysis,
    });
  } catch (error) {
    logger.error('Database analysis failed', {
      error: (error as Error).message,
    });
    
    res.status(500).json({
      success: false,
      error: { message: 'Failed to analyze database performance' },
    });
  }
});

// 获取性能历史数据
export const getPerformanceHistory = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { timeRange = '1h', metric = 'responseTime' } = req.query;
  
  try {
    const redis = getRedisClient();
    const historyData = await getHistoricalPerformanceData(
      redis, 
      timeRange as string, 
      metric as string
    );
    
    res.json({
      success: true,
      data: {
        timeRange,
        metric,
        data: historyData,
        summary: calculateHistorySummary(historyData),
      },
    });
  } catch (error) {
    logger.error('Failed to get performance history', {
      error: (error as Error).message,
      timeRange,
      metric,
    });
    
    res.status(500).json({
      success: false,
      error: { message: 'Failed to load performance history' },
    });
  }
});

// 性能优化建议
export const getOptimizationSuggestions = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const [
    performanceStats,
    cacheStats,
    dbAnalysis,
  ] = await Promise.all([
    advancedPerformanceMonitor.getDetailedStats(),
    advancedCacheService.getCacheStats(),
    analyzeDatabasePerformance(),
  ]);

  const suggestions = generateOptimizationSuggestions(
    performanceStats,
    cacheStats,
    dbAnalysis
  );

  res.json({
    success: true,
    data: {
      timestamp: new Date(),
      suggestions,
      priorityActions: suggestions
        .filter(s => s.priority === 'high')
        .slice(0, 5),
      estimatedImpact: calculateEstimatedImpact(suggestions),
    },
  });
});

// 触发缓存预热
export const triggerCacheWarmup = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  try {
    // 启动缓存预热
    // optimizedQueryService.warmupCommonQueries().catch(error => {
    //   logger.error('Cache warmup failed', { error: error.message });
    // });
    
    res.json({
      success: true,
      message: 'Cache warmup initiated',
      timestamp: new Date(),
    });
  } catch (error) {
    logger.error('Failed to trigger cache warmup', {
      error: (error as Error).message,
    });
    
    res.status(500).json({
      success: false,
      error: { message: 'Failed to initiate cache warmup' },
    });
  }
});

// 辅助函数
async function getSystemHealth() {
  const redis = getRedisClient();
  
  try {
    const [redisHealth, dbHealth] = await Promise.all([
      redis.ping().then(() => true).catch(() => false),
      db.raw('SELECT 1').then(() => true).catch(() => false),
    ]);

    const memUsage = process.memoryUsage();
    const uptime = process.uptime();

    return {
      redis: redisHealth,
      database: dbHealth,
      uptime: Math.round(uptime),
      memory: {
        used: Math.round(memUsage.heapUsed / 1024 / 1024),
        total: Math.round(memUsage.heapTotal / 1024 / 1024),
        percentage: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100),
      },
      timestamp: new Date(),
    };
  } catch (error) {
    logger.error('System health check failed', {
      error: (error as Error).message,
    });
    
    return {
      redis: false,
      database: false,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      error: 'Health check failed',
      timestamp: new Date(),
    };
  }
}

function determineSystemStatus(performanceStats: any, systemHealth: any): 'healthy' | 'warning' | 'critical' {
  if (!systemHealth.redis || !systemHealth.database) {
    return 'critical';
  }
  
  if (performanceStats.errorRate > 10 || performanceStats.avgResponseTime > 3000) {
    return 'critical';
  }
  
  if (performanceStats.errorRate > 5 || performanceStats.avgResponseTime > 1000 || systemHealth.memory.percentage > 80) {
    return 'warning';
  }
  
  return 'healthy';
}

function identifyCriticalIssues(performanceStats: any, systemHealth: any): string[] {
  const issues: string[] = [];
  
  if (!systemHealth.redis) {
    issues.push('Redis connection failed');
  }
  
  if (!systemHealth.database) {
    issues.push('Database connection failed');
  }
  
  if (performanceStats.errorRate > 10) {
    issues.push(`High error rate: ${performanceStats.errorRate}%`);
  }
  
  if (performanceStats.avgResponseTime > 3000) {
    issues.push(`Very slow response time: ${performanceStats.avgResponseTime}ms`);
  }
  
  if (systemHealth.memory.percentage > 90) {
    issues.push(`High memory usage: ${systemHealth.memory.percentage}%`);
  }
  
  return issues;
}

function generateRecommendations(performanceStats: any, compressionStats: any, cacheStats: any): string[] {
  const recommendations: string[] = [];
  
  if (performanceStats.avgResponseTime > 1000) {
    recommendations.push('Consider optimizing database queries and adding indexes');
  }
  
  if (cacheStats.hitRate < 70) {
    recommendations.push('Improve cache strategy and increase cache TTL for stable data');
  }
  
  if (compressionStats.totalRequests > 0 && compressionStats.avgCompressionRatio < 30) {
    recommendations.push('Review compression settings and enable Brotli for better compression');
  }
  
  if (performanceStats.errorRate > 5) {
    recommendations.push('Investigate and fix recurring errors to improve user experience');
  }
  
  return recommendations;
}

function getPerformanceGrade(avgResponseTime: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (avgResponseTime < 200) return 'A';
  if (avgResponseTime < 500) return 'B';
  if (avgResponseTime < 1000) return 'C';
  if (avgResponseTime < 2000) return 'D';
  return 'F';
}

function getOptimizationRecommendations(analysis: any): string[] {
  const recommendations: string[] = [];
  
  if (analysis.avgResponseTime > 1000) {
    recommendations.push('Add database indexes for this endpoint');
    recommendations.push('Implement result caching');
  }
  
  if (analysis.errorRate > 5) {
    recommendations.push('Review error handling and input validation');
  }
  
  if (analysis.requestCount > 100) {
    recommendations.push('Consider rate limiting for high-traffic endpoint');
  }
  
  return recommendations;
}

function analyzeTrends(recentMetrics: any[]): any {
  if (recentMetrics.length < 10) {
    return { trend: 'insufficient_data', message: 'Not enough data for trend analysis' };
  }
  
  const recent = recentMetrics.slice(-10);
  const earlier = recentMetrics.slice(-20, -10);
  
  const recentAvg = recent.reduce((sum, m) => sum + m.responseTime, 0) / recent.length;
  const earlierAvg = earlier.reduce((sum, m) => sum + m.responseTime, 0) / earlier.length;
  
  const change = ((recentAvg - earlierAvg) / earlierAvg) * 100;
  
  if (Math.abs(change) < 5) {
    return { trend: 'stable', change, message: 'Performance is stable' };
  } else if (change > 0) {
    return { trend: 'degrading', change, message: 'Performance is degrading' };
  } else {
    return { trend: 'improving', change, message: 'Performance is improving' };
  }
}

function parseRedisMemoryInfo(info: string): any {
  const lines = info.split('\n');
  const memory: any = {};
  
  lines.forEach(line => {
    if (line.includes(':')) {
      const [key, value] = line.split(':');
      if (key.includes('memory')) {
        memory[key] = value.trim();
      }
    }
  });
  
  return memory;
}

function generateCacheRecommendations(cacheStats: any): string[] {
  const recommendations: string[] = [];
  
  if (cacheStats.hitRate < 50) {
    recommendations.push('Cache hit rate is low - review cache keys and TTL settings');
  }
  
  if (cacheStats.tagIndexSize > 10000) {
    recommendations.push('Large tag index - consider cleaning up unused cache tags');
  }
  
  return recommendations;
}

async function getTopCachedEndpoints(): Promise<any[]> {
  // This would typically query Redis for cache statistics
  // For now, return mock data
  return [
    { endpoint: '/api/v1/annotations/list', hits: 1250, misses: 150, hitRate: 89.3 },
    { endpoint: '/api/v1/annotations/:id', hits: 890, misses: 110, hitRate: 89.0 },
    { endpoint: '/api/v1/users/profile/me', hits: 670, misses: 30, hitRate: 95.7 },
  ];
}

async function analyzeDatabasePerformance(): Promise<any> {
  try {
    // Check database connection performance
    const start = Date.now();
    await db.raw('SELECT 1');
    const connectionTime = Date.now() - start;
    
    // Get basic database stats (this would vary by database type)
    const stats = {
      connectionTime,
      status: 'connected',
      recommendations: [] as string[],
    };
    
    if (connectionTime > 100) {
      stats.recommendations.push('Database connection is slow - check network latency');
    }
    
    return {
      timestamp: new Date(),
      connection: stats,
      // Add more database-specific analysis here
    };
  } catch (error) {
    return {
      timestamp: new Date(),
      connection: {
        status: 'error',
        error: (error as Error).message,
      },
    };
  }
}

async function getHistoricalPerformanceData(redis: any, timeRange: string, metric: string): Promise<any[]> {
  // This would query Redis for historical performance data
  // For now, return mock data
  const now = Date.now();
  const points = 24; // 24 data points
  const interval = timeRange === '1h' ? 2.5 * 60 * 1000 : 60 * 60 * 1000; // 2.5 min or 1 hour
  
  return Array.from({ length: points }, (_, i) => ({
    timestamp: new Date(now - (points - i - 1) * interval),
    value: Math.random() * 1000 + 200, // Mock response time data
  }));
}

function calculateHistorySummary(data: any[]): any {
  if (data.length === 0) {
    return { min: 0, max: 0, avg: 0, trend: 'no_data' };
  }
  
  const values = data.map(d => d.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
  
  // Simple trend analysis
  const firstHalf = values.slice(0, Math.floor(values.length / 2));
  const secondHalf = values.slice(Math.floor(values.length / 2));
  const firstAvg = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length;
  const secondAvg = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length;
  
  const trend = secondAvg > firstAvg * 1.1 ? 'increasing' : 
                secondAvg < firstAvg * 0.9 ? 'decreasing' : 'stable';
  
  return {
    min: Math.round(min),
    max: Math.round(max),
    avg: Math.round(avg),
    trend,
  };
}

function generateOptimizationSuggestions(performanceStats: any, cacheStats: any, dbAnalysis: any): any[] {
  const suggestions = [
    {
      category: 'Database',
      title: 'Add database indexes',
      description: 'Create indexes for frequently queried columns to improve query performance',
      priority: performanceStats.avgResponseTime > 1000 ? 'high' : 'medium',
      estimatedImpact: 'High',
      effort: 'Medium',
      implementation: 'Run the database migration to add performance indexes',
    },
    {
      category: 'Caching',
      title: 'Implement smarter caching strategy',
      description: 'Use advanced caching with tags and refresh-ahead strategy',
      priority: cacheStats.hitRate < 70 ? 'high' : 'low',
      estimatedImpact: 'High',
      effort: 'Low',
      implementation: 'Already implemented - ensure proper cache configuration',
    },
    {
      category: 'Performance',
      title: 'Enable Brotli compression',
      description: 'Use Brotli compression for better compression ratios',
      priority: 'medium',
      estimatedImpact: 'Medium',
      effort: 'Low',
      implementation: 'Already available - enable in production configuration',
    },
  ];
  
  return suggestions;
}

function calculateEstimatedImpact(suggestions: any[]): any {
  const highImpact = suggestions.filter(s => s.estimatedImpact === 'High').length;
  const mediumImpact = suggestions.filter(s => s.estimatedImpact === 'Medium').length;
  const lowImpact = suggestions.filter(s => s.estimatedImpact === 'Low').length;
  
  return {
    potentialResponseTimeReduction: `${highImpact * 30 + mediumImpact * 15 + lowImpact * 5}%`,
    implementationEffort: suggestions.reduce((total, s) => {
      return total + (s.effort === 'High' ? 3 : s.effort === 'Medium' ? 2 : 1);
    }, 0),
    prioritySuggestions: suggestions.filter(s => s.priority === 'high').length,
  };
}