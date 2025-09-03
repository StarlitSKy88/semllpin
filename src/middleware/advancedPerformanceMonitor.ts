import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { getRedisClient } from '../config/redis';
import { promisify } from 'util';
import Redis from 'ioredis';

// 性能指标接口
export interface PerformanceMetrics {
  requestId: string;
  method: string;
  url: string;
  endpoint: string;
  statusCode: number;
  responseTime: number;
  cpuUsage: NodeJS.CpuUsage;
  memoryUsage: NodeJS.MemoryUsage;
  timestamp: Date;
  userAgent?: string;
  ip?: string;
  userId?: string;
  queryParams?: Record<string, any>;
  bodySize?: number;
  responseSize?: number;
  dbQueryTime?: number;
  cacheHits?: number;
  cacheMisses?: number;
  errors?: string[];
  warnings?: string[];
}

// 性能警告阈值
export interface PerformanceThresholds {
  responseTimeWarning: number; // 响应时间警告阈值（ms）
  responseTimeError: number; // 响应时间错误阈值（ms）
  memoryUsageWarning: number; // 内存使用警告阈值（MB）
  memoryUsageError: number; // 内存使用错误阈值（MB）
  cpuUsageWarning: number; // CPU使用警告阈值（%）
  cpuUsageError: number; // CPU使用错误阈值（%）
  dbQueryTimeWarning: number; // 数据库查询时间警告阈值（ms）
  dbQueryTimeError: number; // 数据库查询时间错误阈值（ms）
}

// 性能统计
export interface PerformanceStats {
  totalRequests: number;
  avgResponseTime: number;
  medianResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  slowestEndpoints: Array<{
    endpoint: string;
    avgResponseTime: number;
    requestCount: number;
  }>;
  errorRate: number;
  throughput: number; // requests per second
  memoryTrend: Array<{
    timestamp: number;
    usage: number;
  }>;
  cpuTrend: Array<{
    timestamp: number;
    usage: number;
  }>;
  topErrors: Array<{
    error: string;
    count: number;
    lastSeen: Date;
  }>;
}

// 默认阈值
const DEFAULT_THRESHOLDS: PerformanceThresholds = {
  responseTimeWarning: 1000, // 1秒
  responseTimeError: 3000, // 3秒
  memoryUsageWarning: 500, // 500MB
  memoryUsageError: 1000, // 1GB
  cpuUsageWarning: 70, // 70%
  cpuUsageError: 90, // 90%
  dbQueryTimeWarning: 500, // 500ms
  dbQueryTimeError: 2000, // 2秒
};

// 高级性能监控器
export class AdvancedPerformanceMonitor {
  private redis: Redis;
  private metrics: PerformanceMetrics[] = [];
  private maxMetricsHistory: number = 10000;
  private thresholds: PerformanceThresholds;
  private requestCounts: Map<string, number> = new Map();
  private responseTimes: Map<string, number[]> = new Map();
  private errorCounts: Map<string, number> = new Map();
  private alertCooldowns: Map<string, number> = new Map();
  private isTestEnv: boolean = process.env.NODE_ENV === 'test' || !!process.env.JEST_WORKER_ID;

  constructor(thresholds: Partial<PerformanceThresholds> = {}) {
    this.redis = getRedisClient();
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
    if (!this.isTestEnv && process.env.PERF_MONITOR_ENABLED !== 'false') {
      this.startBackgroundTasks();
    }
  }

  // 启动后台任务
  private startBackgroundTasks(): void {
    // 定期清理内存中的指标
    setInterval(() => {
      this.cleanupMetrics();
    }, 5 * 60 * 1000); // 5分钟

    // 定期生成统计报告
    setInterval(() => {
      this.generateStatsReport();
    }, 60 * 1000); // 1分钟

    // 定期检查系统健康状况
    setInterval(() => {
      this.checkSystemHealth();
    }, 30 * 1000); // 30秒
  }

  // 生成请求ID
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // 清理过期指标
  private cleanupMetrics(): void {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30分钟

    this.metrics = this.metrics.filter(metric => 
      now - metric.timestamp.getTime() < maxAge
    );

    // 清理请求计数
    for (const [key, timestamp] of this.alertCooldowns.entries()) {
      if (now - timestamp > 5 * 60 * 1000) { // 5分钟冷却
        this.alertCooldowns.delete(key);
      }
    }

    logger.debug('Performance metrics cleaned up', {
      remainingMetrics: this.metrics.length,
    });
  }

  // 检查性能阈值
  private checkThresholds(metrics: PerformanceMetrics): void {
    const alerts: string[] = [];

    // 检查响应时间
    if (metrics.responseTime >= this.thresholds.responseTimeError) {
      alerts.push(`CRITICAL: Response time ${metrics.responseTime}ms exceeds error threshold`);
    } else if (metrics.responseTime >= this.thresholds.responseTimeWarning) {
      alerts.push(`WARNING: Response time ${metrics.responseTime}ms exceeds warning threshold`);
    }

    // 检查内存使用
    const memoryUsageMB = metrics.memoryUsage.heapUsed / 1024 / 1024;
    if (memoryUsageMB >= this.thresholds.memoryUsageError) {
      alerts.push(`CRITICAL: Memory usage ${memoryUsageMB.toFixed(2)}MB exceeds error threshold`);
    } else if (memoryUsageMB >= this.thresholds.memoryUsageWarning) {
      alerts.push(`WARNING: Memory usage ${memoryUsageMB.toFixed(2)}MB exceeds warning threshold`);
    }

    // 检查数据库查询时间
    if (metrics.dbQueryTime) {
      if (metrics.dbQueryTime >= this.thresholds.dbQueryTimeError) {
        alerts.push(`CRITICAL: DB query time ${metrics.dbQueryTime}ms exceeds error threshold`);
      } else if (metrics.dbQueryTime >= this.thresholds.dbQueryTimeWarning) {
        alerts.push(`WARNING: DB query time ${metrics.dbQueryTime}ms exceeds warning threshold`);
      }
    }

    // 发送警报（避免重复发送）
    alerts.forEach(alert => {
      const alertKey = `${metrics.endpoint}:${alert.split(':')[0]}`;
      const lastAlert = this.alertCooldowns.get(alertKey) || 0;
      const now = Date.now();

      if (now - lastAlert > 5 * 60 * 1000) { // 5分钟冷却
        logger.warn('Performance threshold exceeded', {
          requestId: metrics.requestId,
          endpoint: metrics.endpoint,
          alert,
          metrics: {
            responseTime: metrics.responseTime,
            memoryUsage: memoryUsageMB,
            dbQueryTime: metrics.dbQueryTime,
          },
        });
        
        this.alertCooldowns.set(alertKey, now);

        if (!this.isTestEnv) {
          // 发送到Redis以供外部监控系统处理（测试环境禁用）
          this.redis.lpush('performance_alerts', JSON.stringify({
            timestamp: new Date(),
            level: alert.startsWith('CRITICAL') ? 'error' : 'warning',
            message: alert,
            metrics,
          })).catch(error => {
            logger.error('Failed to send alert to Redis', { error: error.message });
          });
        }
      }
    });
  }

  // 记录指标到Redis
  private async saveMetricsToRedis(metrics: PerformanceMetrics): Promise<void> {
    if (this.isTestEnv) return; // 测试环境跳过外部写入
    try {
      const key = `performance_metrics:${metrics.endpoint}`;
      const pipeline = this.redis.pipeline();
      
      // 保存详细指标
      pipeline.lpush(key, JSON.stringify(metrics));
      pipeline.ltrim(key, 0, 999); // 保持最近1000条记录
      pipeline.expire(key, 24 * 60 * 60); // 24小时过期

      // 更新聚合统计
      const statsKey = `performance_stats:${metrics.endpoint}`;
      pipeline.hincrby(statsKey, 'total_requests', 1);
      pipeline.hincrby(statsKey, 'total_response_time', metrics.responseTime);
      
      if (metrics.statusCode >= 400) {
        pipeline.hincrby(statsKey, 'error_count', 1);
      }

      pipeline.expire(statsKey, 24 * 60 * 60);
      await pipeline.exec();
    } catch (error) {
      logger.error('Failed to save metrics to Redis', {
        error: (error as Error).message,
        requestId: metrics.requestId,
      });
    }
  }

  // 生成统计报告
  private async generateStatsReport(): Promise<void> {
    if (this.isTestEnv) return; // 测试环境跳过
    try {
      const stats = await this.getDetailedStats();
      
      // 检查是否有异常情况需要报告
      if (stats.errorRate > 5) { // 错误率超过5%
        logger.warn('High error rate detected', {
          errorRate: stats.errorRate,
          totalRequests: stats.totalRequests,
        });
      }

      if (stats.avgResponseTime > this.thresholds.responseTimeWarning) {
        logger.warn('High average response time detected', {
          avgResponseTime: stats.avgResponseTime,
          p95ResponseTime: stats.p95ResponseTime,
        });
      }

      // 保存统计报告到Redis
      await this.redis.setex(
        'performance_report:latest',
        60 * 60, // 1小时
        JSON.stringify({
          timestamp: new Date(),
          ...stats,
        })
      );
    } catch (error) {
      logger.error('Failed to generate stats report', {
        error: (error as Error).message,
      });
    }
  }

  // 检查系统健康状况
  private async checkSystemHealth(): Promise<void> {
    if (this.isTestEnv) return; // 测试环境跳过
    try {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      
      // 计算CPU使用率（需要两次采样）
      setTimeout(() => {
        const cpuUsageEnd = process.cpuUsage(cpuUsage);
        const cpuPercent = (cpuUsageEnd.user + cpuUsageEnd.system) / 1000000 / 1 * 100; // 1秒内的CPU使用率

        const healthMetrics = {
          timestamp: new Date(),
          memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024),
            total: Math.round(memUsage.heapTotal / 1024 / 1024),
            external: Math.round(memUsage.external / 1024 / 1024),
            rss: Math.round(memUsage.rss / 1024 / 1024),
          },
          cpu: {
            usage: Math.round(cpuPercent * 100) / 100,
          },
          uptime: Math.round(process.uptime()),
        };

        // 保存健康指标到Redis
        this.redis.setex(
          'system_health:latest',
          60, // 1分钟
          JSON.stringify(healthMetrics)
        ).catch(error => {
          logger.error('Failed to save health metrics', { error: error.message });
        });

        // 检查健康阈值
        if (healthMetrics.memory.used >= this.thresholds.memoryUsageError) {
          logger.error('System memory usage critical', healthMetrics.memory);
        } else if (healthMetrics.memory.used >= this.thresholds.memoryUsageWarning) {
          logger.warn('System memory usage high', healthMetrics.memory);
        }

        if (healthMetrics.cpu.usage >= this.thresholds.cpuUsageError) {
          logger.error('System CPU usage critical', { usage: healthMetrics.cpu.usage });
        } else if (healthMetrics.cpu.usage >= this.thresholds.cpuUsageWarning) {
          logger.warn('System CPU usage high', { usage: healthMetrics.cpu.usage });
        }
      }, 1000); // 1秒后再次采样
    } catch (error) {
      logger.error('Failed to check system health', {
        error: (error as Error).message,
      });
    }
  }

  // 中间件
  public middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const requestId = this.generateRequestId();
      const startTime = process.hrtime.bigint();
      const startCpuUsage = process.cpuUsage();
      
      // 添加请求ID到请求对象
      (req as any).requestId = requestId;
      
      // 监听数据库查询时间（如果有相关事件）
      let dbQueryTime = 0;
      const originalQuery = (req as any).db?.query;
      if (originalQuery) {
        (req as any).db.query = (...args: any[]) => {
          const queryStart = Date.now();
          const result = originalQuery.apply((req as any).db, args);
          
          if (result && typeof result.then === 'function') {
            return result.then((data: any) => {
              dbQueryTime += Date.now() - queryStart;
              return data;
            });
          } else {
            dbQueryTime += Date.now() - queryStart;
            return result;
          }
        };
      }

      // 记录请求体大小
      let bodySize = 0;
      if (req.headers['content-length']) {
        bodySize = parseInt(req.headers['content-length'], 10) || 0;
      }

      // 监听响应结束
      res.on('finish', () => {
        const endTime = process.hrtime.bigint();
        const responseTime = Number(endTime - startTime) / 1000000; // 转换为毫秒
        const endCpuUsage = process.cpuUsage(startCpuUsage);
        const memoryUsage = process.memoryUsage();

        // 计算响应大小
        const responseSize = parseInt(res.getHeader('content-length') as string || '0', 10);

        const metrics: PerformanceMetrics = {
          requestId,
          method: req.method,
          url: req.originalUrl || req.url,
          endpoint: req.route?.path || req.path,
          statusCode: res.statusCode,
          responseTime: Math.round(responseTime * 100) / 100,
          cpuUsage: endCpuUsage,
          memoryUsage,
          timestamp: new Date(),
          userAgent: req.get('User-Agent'),
          ip: req.ip || req.connection.remoteAddress,
          userId: (req as any).user?.id,
          queryParams: Object.keys(req.query).length > 0 ? req.query : undefined,
          bodySize: bodySize > 0 ? bodySize : undefined,
          responseSize: responseSize > 0 ? responseSize : undefined,
          dbQueryTime: dbQueryTime > 0 ? dbQueryTime : undefined,
        };

        // 记录指标
        this.recordMetrics(metrics);
      });

      next();
    };
  }

  // 记录指标
  private recordMetrics(metrics: PerformanceMetrics): void {
    // 添加到内存
    this.metrics.push(metrics);
    if (this.metrics.length > this.maxMetricsHistory) {
      this.metrics.shift();
    }

    // 更新计数器
    const endpoint = metrics.endpoint;
    this.requestCounts.set(endpoint, (this.requestCounts.get(endpoint) || 0) + 1);

    // 更新响应时间记录
    if (!this.responseTimes.has(endpoint)) {
      this.responseTimes.set(endpoint, []);
    }
    const endpointTimes = this.responseTimes.get(endpoint)!;
    endpointTimes.push(metrics.responseTime);
    if (endpointTimes.length > 1000) { // 保持最近1000条记录
      endpointTimes.shift();
    }

    // 记录错误
    if (metrics.statusCode >= 400) {
      const errorKey = `${endpoint}:${metrics.statusCode}`;
      this.errorCounts.set(errorKey, (this.errorCounts.get(errorKey) || 0) + 1);
    }

    // 检查阈值
    this.checkThresholds(metrics);

    // 保存到Redis
    this.saveMetricsToRedis(metrics);

    // 记录详细日志
    const logLevel = metrics.responseTime > this.thresholds.responseTimeWarning ? 'warn' : 'info';
    logger[logLevel]('Request completed', {
      requestId: metrics.requestId,
      method: metrics.method,
      endpoint: metrics.endpoint,
      statusCode: metrics.statusCode,
      responseTime: metrics.responseTime,
      memoryUsed: Math.round(metrics.memoryUsage.heapUsed / 1024 / 1024),
      dbQueryTime: metrics.dbQueryTime,
    });
  }

  // 获取详细统计信息
  public async getDetailedStats(): Promise<PerformanceStats> {
    const now = Date.now();
    const last5Minutes = this.metrics.filter(m => now - m.timestamp.getTime() < 5 * 60 * 1000);
    const last1Hour = this.metrics.filter(m => now - m.timestamp.getTime() < 60 * 60 * 1000);

    if (last5Minutes.length === 0) {
      return {
        totalRequests: 0,
        avgResponseTime: 0,
        medianResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
        slowestEndpoints: [],
        errorRate: 0,
        throughput: 0,
        memoryTrend: [],
        cpuTrend: [],
        topErrors: [],
      };
    }

    // 计算响应时间统计
    const responseTimes = last5Minutes.map(m => m.responseTime).sort((a, b) => a - b);
    const totalRequests = last5Minutes.length;
    const errorCount = last5Minutes.filter(m => m.statusCode >= 400).length;

    const stats: PerformanceStats = {
      totalRequests,
      avgResponseTime: Math.round(responseTimes.reduce((sum, time) => sum + time, 0) / totalRequests),
      medianResponseTime: responseTimes[Math.floor(responseTimes.length / 2)] || 0,
      p95ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.95)] || 0,
      p99ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.99)] || 0,
      errorRate: Math.round((errorCount / totalRequests) * 100 * 100) / 100,
      throughput: Math.round(totalRequests / 5 * 100) / 100, // requests per second in last 5 minutes
      slowestEndpoints: this.getSlowstEndpoints(),
      memoryTrend: this.getMemoryTrend(last1Hour),
      cpuTrend: this.getCpuTrend(last1Hour),
      topErrors: this.getTopErrors(),
    };

    return stats;
  }

  // 获取最慢的端点
  private getSlowstEndpoints(): Array<{ endpoint: string; avgResponseTime: number; requestCount: number }> {
    const endpointStats = new Map<string, { totalTime: number; count: number }>();

    this.metrics.forEach(metric => {
      const stats = endpointStats.get(metric.endpoint) || { totalTime: 0, count: 0 };
      stats.totalTime += metric.responseTime;
      stats.count += 1;
      endpointStats.set(metric.endpoint, stats);
    });

    return Array.from(endpointStats.entries())
      .map(([endpoint, stats]) => ({
        endpoint,
        avgResponseTime: Math.round(stats.totalTime / stats.count),
        requestCount: stats.count,
      }))
      .sort((a, b) => b.avgResponseTime - a.avgResponseTime)
      .slice(0, 10);
  }

  // 获取内存趋势
  private getMemoryTrend(metrics: PerformanceMetrics[]): Array<{ timestamp: number; usage: number }> {
    const trend = metrics
      .filter((_, index) => index % 10 === 0) // 每10个取样1个
      .map(metric => ({
        timestamp: metric.timestamp.getTime(),
        usage: Math.round(metric.memoryUsage.heapUsed / 1024 / 1024),
      }));
    
    return trend.slice(-50); // 最近50个点
  }

  // 获取CPU趋势
  private getCpuTrend(metrics: PerformanceMetrics[]): Array<{ timestamp: number; usage: number }> {
    const trend = metrics
      .filter((_, index) => index % 10 === 0) // 每10个取样1个
      .map(metric => {
        const cpuUsage = (metric.cpuUsage.user + metric.cpuUsage.system) / 1000000; // 转换为秒
        return {
          timestamp: metric.timestamp.getTime(),
          usage: Math.round(cpuUsage * 100) / 100,
        };
      });
    
    return trend.slice(-50); // 最近50个点
  }

  // 获取顶级错误
  private getTopErrors(): Array<{ error: string; count: number; lastSeen: Date }> {
    const errorStats = new Map<string, { count: number; lastSeen: Date }>();

    this.metrics.forEach(metric => {
      if (metric.statusCode >= 400) {
        const errorKey = `${metric.statusCode} ${metric.endpoint}`;
        const stats = errorStats.get(errorKey) || { count: 0, lastSeen: new Date(0) };
        stats.count += 1;
        if (metric.timestamp > stats.lastSeen) {
          stats.lastSeen = metric.timestamp;
        }
        errorStats.set(errorKey, stats);
      }
    });

    return Array.from(errorStats.entries())
      .map(([error, stats]) => ({
        error,
        count: stats.count,
        lastSeen: stats.lastSeen,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  // 获取实时指标
  public getRealTimeMetrics(): PerformanceMetrics[] {
    const now = Date.now();
    return this.metrics.filter(m => now - m.timestamp.getTime() < 5 * 60 * 1000); // 最近5分钟
  }

  // 获取端点性能数据
  public getEndpointPerformance(endpoint: string): {
    requestCount: number;
    avgResponseTime: number;
    errorRate: number;
    recentMetrics: PerformanceMetrics[];
  } {
    const endpointMetrics = this.metrics.filter(m => m.endpoint === endpoint);
    const recentMetrics = endpointMetrics.filter(m => 
      Date.now() - m.timestamp.getTime() < 5 * 60 * 1000
    );

    if (recentMetrics.length === 0) {
      return {
        requestCount: 0,
        avgResponseTime: 0,
        errorRate: 0,
        recentMetrics: [],
      };
    }

    const errorCount = recentMetrics.filter(m => m.statusCode >= 400).length;
    const avgResponseTime = recentMetrics.reduce((sum, m) => sum + m.responseTime, 0) / recentMetrics.length;

    return {
      requestCount: recentMetrics.length,
      avgResponseTime: Math.round(avgResponseTime),
      errorRate: Math.round((errorCount / recentMetrics.length) * 100),
      recentMetrics: recentMetrics.slice(-100), // 最近100个请求
    };
  }
}

// 创建默认实例
export const advancedPerformanceMonitor = new AdvancedPerformanceMonitor();