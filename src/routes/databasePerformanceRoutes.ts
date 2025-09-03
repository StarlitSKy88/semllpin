import express from 'express';
import { Request, Response } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import { databaseQueryOptimizer, databaseIndexManager } from '../services/databaseQueryOptimizer';
import { queryPerformanceMonitor } from '../services/queryPerformanceMonitor';
import { checkDatabaseHealth, db } from '../config/database';
import { logger } from '../utils/logger';
import { config } from '../config/config';

const router = express.Router();

// 获取数据库性能概览
router.get('/overview', asyncHandler(async (req: Request, res: Response) => {
  const performanceStats = databaseQueryOptimizer.getPerformanceStats();
  const monitoringMetrics = queryPerformanceMonitor.getMetrics();
  const dbHealth = await checkDatabaseHealth();
  
  const overview = {
    status: dbHealth.healthy ? 'healthy' : 'degraded',
    score: Math.round(
      (performanceStats.totalQueries > 0 ? 
        ((performanceStats.totalQueries - performanceStats.slowQueries) / performanceStats.totalQueries) * 100 
        : 100)
    ),
    metrics: {
      totalQueries: performanceStats.totalQueries,
      slowQueries: performanceStats.slowQueries,
      averageExecutionTime: Math.round(performanceStats.averageExecutionTime),
      errorRate: monitoringMetrics.totalQueries > 0 ? 
        Math.round((monitoringMetrics.failedQueries / monitoringMetrics.totalQueries) * 100 * 100) / 100 : 0,
      cacheHitRate: monitoringMetrics.cacheHitRate,
      queriesPerSecond: monitoringMetrics.queriesPerSecond,
    },
    database: {
      responseTime: dbHealth.details.responseTime,
      connectionPool: dbHealth.details.poolStatus,
      healthy: dbHealth.healthy,
    },
    system: {
      memory: monitoringMetrics.memoryUsage,
      uptime: process.uptime(),
    }
  };

  res.json({
    success: true,
    data: overview,
    timestamp: new Date().toISOString(),
  });
}));

// 获取详细的性能报告
router.get('/report', asyncHandler(async (req: Request, res: Response) => {
  const optimizerReport = databaseQueryOptimizer.getPerformanceReport();
  const monitoringReport = queryPerformanceMonitor.generateReport();
  
  const combinedReport = {
    summary: {
      ...optimizerReport.stats,
      ...monitoringReport.summary,
    },
    slowQueries: {
      optimizer: optimizerReport.stats.topSlowQueries.slice(0, 5),
      monitor: monitoringReport.slowQueries.slice(0, 5),
    },
    queryPatterns: monitoringReport.queryPatterns,
    errors: {
      recent: optimizerReport.stats.recentErrors,
      patterns: monitoringReport.failedQueries,
    },
    optimization: {
      suggestions: optimizerReport.suggestions,
      databaseHealth: optimizerReport.databaseHealth,
    },
    recommendations: [
      ...optimizerReport.suggestions.slice(0, 3).map(s => s.suggestion),
      ...monitoringReport.recommendations.slice(0, 3),
    ],
  };

  res.json({
    success: true,
    data: combinedReport,
    timestamp: new Date().toISOString(),
  });
}));

// 获取慢查询分析
router.get('/slow-queries', asyncHandler(async (req: Request, res: Response) => {
  const { limit = 10 } = req.query;
  
  const optimizerSlowQueries = databaseQueryOptimizer.getPerformanceStats().topSlowQueries;
  const monitorSlowQueries = queryPerformanceMonitor.getSlowQueries(Number(limit));
  
  const analysis = {
    fromOptimizer: optimizerSlowQueries.slice(0, Number(limit)),
    fromMonitor: monitorSlowQueries,
    summary: {
      totalSlowQueries: optimizerSlowQueries.length,
      averageSlowQueryTime: optimizerSlowQueries.length > 0 ? 
        Math.round(optimizerSlowQueries.reduce((sum, q) => sum + q.executionTime, 0) / optimizerSlowQueries.length) : 0,
      mostProblematicQueries: monitorSlowQueries.slice(0, 3).map(q => ({
        name: q.queryName,
        averageDuration: q.averageDuration,
        count: q.count,
      })),
    }
  };

  res.json({
    success: true,
    data: analysis,
    timestamp: new Date().toISOString(),
  });
}));

// 获取数据库索引分析
router.get('/indexes', asyncHandler(async (req: Request, res: Response) => {
  const existingIndexes = await databaseIndexManager.checkExistingIndexes();
  const suggestedIndexes = databaseIndexManager.suggestMissingIndexes();
  const tableStats = await databaseIndexManager.analyzeTableStats();
  
  const analysis = {
    existing: existingIndexes,
    suggestions: suggestedIndexes,
    tableStatistics: tableStats,
    summary: {
      totalIndexes: existingIndexes.length,
      suggestedImprovements: suggestedIndexes.length,
      tablesAnalyzed: tableStats.length,
      recommendations: suggestedIndexes.slice(0, 5).map(s => ({
        table: s.table,
        columns: s.columns,
        reason: s.reason,
      })),
    }
  };

  res.json({
    success: true,
    data: analysis,
    timestamp: new Date().toISOString(),
  });
}));

// 获取查询模式分析
router.get('/query-patterns', asyncHandler(async (req: Request, res: Response) => {
  const patterns = queryPerformanceMonitor.getQueryPatterns();
  const suggestions = databaseQueryOptimizer.generateOptimizationSuggestions();
  
  const analysis = {
    patterns,
    frequentPatterns: patterns.slice(0, 5),
    optimizationSuggestions: suggestions.filter(s => s.priority === 'high').slice(0, 3),
    summary: {
      uniquePatterns: patterns.length,
      mostFrequentPattern: patterns[0] || null,
      averageExecutionTime: patterns.length > 0 ? 
        Math.round(patterns.reduce((sum, p) => sum + p.averageDuration, 0) / patterns.length) : 0,
    }
  };

  res.json({
    success: true,
    data: analysis,
    timestamp: new Date().toISOString(),
  });
}));

// 获取缓存性能分析
router.get('/cache-performance', asyncHandler(async (req: Request, res: Response) => {
  const metrics = queryPerformanceMonitor.getMetrics();
  
  const analysis = {
    hitRate: metrics.cacheHitRate,
    totalQueries: metrics.totalQueries,
    cachedQueries: Math.round(metrics.totalQueries * (metrics.cacheHitRate / 100)),
    performance: {
      improvementFromCache: metrics.cacheHitRate > 0 ? 
        `Cache is improving performance by approximately ${Math.round(metrics.cacheHitRate)}%` : 
        'No cache performance data available',
      recommendation: metrics.cacheHitRate < 30 ? 
        'Consider implementing more caching strategies' : 
        metrics.cacheHitRate > 80 ? 
        'Excellent cache performance' : 
        'Good cache performance, consider optimizing cache keys',
    }
  };

  res.json({
    success: true,
    data: analysis,
    timestamp: new Date().toISOString(),
  });
}));

// 执行数据库优化建议（谨慎使用）
router.post('/optimize', asyncHandler(async (req: Request, res: Response) => {
  const { action, target } = req.body;
  
  if (config.NODE_ENV === 'production') {
    return res.status(403).json({
      success: false,
      error: 'Database optimization actions are not allowed in production',
    });
  }
  
  let result: any = {};
  
  try {
    switch (action) {
      case 'analyze_tables':
        if (config.database.host && config.database.host.includes('postgres')) {
          // PostgreSQL ANALYZE
          result = await Promise.all([
            'annotations',
            'users', 
            'annotation_likes',
            'media_files'
          ].map(async (table) => {
            try {
              await db.raw(`ANALYZE ${table}`);
              return { table, status: 'analyzed' };
            } catch (error) {
              return { table, status: 'error', error: (error as Error).message };
            }
          }));
        } else {
          result = { message: 'Table analysis is only available for PostgreSQL' };
        }
        break;
        
      case 'clear_query_cache':
        queryPerformanceMonitor.reset();
        databaseQueryOptimizer.resetMetrics();
        result = { message: 'Query performance metrics cleared' };
        break;
        
      case 'warmup_cache':
        // 这里可以添加缓存预热逻辑
        result = { message: 'Cache warmup initiated' };
        break;
        
      default:
        return res.status(400).json({
          success: false,
          error: 'Unknown optimization action',
        });
    }
    
    logger.info('Database optimization action executed', {
      action,
      target,
      result,
      user: req.user?.id,
    });
    
    return res.json({
      success: true,
      data: result,
      message: `Optimization action '${action}' completed`,
      timestamp: new Date().toISOString(),
    });
    
  } catch (error) {
    logger.error('Database optimization action failed', {
      action,
      target,
      error: (error as Error).message,
      user: req.user?.id,
    });
    
    return res.status(500).json({
      success: false,
      error: 'Optimization action failed',
      details: (error as Error).message,
    });
  }
}));

// 获取实时性能监控数据
router.get('/realtime', asyncHandler(async (req: Request, res: Response) => {
  const currentMetrics = queryPerformanceMonitor.getMetrics();
  const dbHealth = await checkDatabaseHealth();
  
  const realtimeData: {
    timestamp: string;
    status: string;
    currentLoad: any;
    resources: any;
    alerts: Array<{ level: string; message: string; }>;
  } = {
    timestamp: new Date().toISOString(),
    status: dbHealth.healthy ? 'healthy' : 'degraded',
    currentLoad: {
      activeConnections: dbHealth.details.poolStatus?.borrowed || 0,
      queriesPerSecond: currentMetrics.queriesPerSecond,
      averageResponseTime: currentMetrics.averageDuration,
      errorRate: currentMetrics.totalQueries > 0 ? 
        (currentMetrics.failedQueries / currentMetrics.totalQueries) * 100 : 0,
    },
    resources: {
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      connectionPool: dbHealth.details.poolStatus,
    },
    alerts: []
  };
  
  // 生成告警
  if (currentMetrics.averageDuration > 1000) {
    realtimeData.alerts.push({
      level: 'warning',
      message: `Average query time is ${currentMetrics.averageDuration}ms`,
    });
  }
  
  if (!dbHealth.healthy) {
    realtimeData.alerts.push({
      level: 'critical',
      message: 'Database health check failed',
    });
  }
  
  if (currentMetrics.failedQueries > 0) {
    realtimeData.alerts.push({
      level: 'warning', 
      message: `${currentMetrics.failedQueries} failed queries detected`,
    });
  }

  res.json({
    success: true,
    data: realtimeData,
  });
}));

// 重置性能监控数据
router.post('/reset', asyncHandler(async (req: Request, res: Response) => {
  queryPerformanceMonitor.reset();
  databaseQueryOptimizer.resetMetrics();
  
  logger.info('Database performance monitoring data reset', {
    user: req.user?.id,
    timestamp: new Date().toISOString(),
  });
  
  res.json({
    success: true,
    message: 'Performance monitoring data has been reset',
    timestamp: new Date().toISOString(),
  });
}));

export default router;