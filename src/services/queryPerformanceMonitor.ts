import { Knex } from 'knex';
import { db } from '../config/database';
import { logger } from '../utils/logger';
import { config } from '../config/config';

// 查询性能监控配置
interface MonitorConfig {
  slowQueryThreshold: number;
  longRunningThreshold: number;
  enableLogging: boolean;
  enableMetrics: boolean;
  sampleRate: number; // 采样率，0-1之间
}

// 查询执行信息
interface QueryExecution {
  id: string;
  queryName: string;
  sql: string;
  params: any[];
  startTime: number;
  endTime?: number;
  duration?: number;
  success: boolean;
  error?: string;
  affectedRows?: number;
  resultSize?: number;
  cacheHit?: boolean;
  userId?: string;
  requestId?: string;
  stackTrace?: string;
}

// 性能指标
interface PerformanceMetrics {
  totalQueries: number;
  successfulQueries: number;
  failedQueries: number;
  totalDuration: number;
  averageDuration: number;
  slowQueries: number;
  cacheHitRate: number;
  queriesPerSecond: number;
  peakConcurrency: number;
  memoryUsage: NodeJS.MemoryUsage;
  connectionPoolStats: any;
}

// 查询性能监控类
export class QueryPerformanceMonitor {
  private config: MonitorConfig;
  private executions: Map<string, QueryExecution> = new Map();
  private completedExecutions: QueryExecution[] = [];
  private readonly MAX_COMPLETED_EXECUTIONS = 1000;
  private metricsStartTime: number = Date.now();
  private intervalId: NodeJS.Timeout | null = null;

  constructor(config: Partial<MonitorConfig> = {}) {
    this.config = {
      slowQueryThreshold: 1000, // 1秒
      longRunningThreshold: 30000, // 30秒
      enableLogging: config.enableLogging !== false,
      enableMetrics: config.enableMetrics !== false,
      sampleRate: config.sampleRate || ((process.env as any)['NODE_ENV'] === 'production' ? 0.1 : 1.0),
      ...config,
    };

    // 启动性能监控
    this.startMonitoring();
  }

  // 开始监控查询
  startQuery(
    queryName: string,
    sql: string,
    params: any[] = [],
    context: { userId?: string; requestId?: string } = {}
  ): string {
    // 根据采样率决定是否监控此查询
    if (Math.random() > this.config.sampleRate) {
      return ''; // 不监控
    }

    const executionId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const execution: QueryExecution = {
      id: executionId,
      queryName,
      sql: this.sanitizeSQL(sql),
      params: this.sanitizeParams(params),
      startTime: Date.now(),
      success: false,
      ...context,
    };

    // 记录堆栈跟踪（开发环境）
    if (process.env['NODE_ENV'] === 'development') {
      execution.stackTrace = new Error().stack;
    }

    this.executions.set(executionId, execution);

    // 设置长时间运行查询的检测
    if (this.config.longRunningThreshold > 0) {
      setTimeout(() => {
        const exec = this.executions.get(executionId);
        if (exec && !exec.endTime) {
          logger.warn('Long-running query detected', {
            executionId,
            queryName,
            duration: Date.now() - exec.startTime,
            sql: exec.sql.substring(0, 200),
          });
        }
      }, this.config.longRunningThreshold);
    }

    return executionId;
  }

  // 结束查询监控
  endQuery(
    executionId: string,
    success: boolean,
    error?: Error,
    resultInfo?: { affectedRows?: number; resultSize?: number; cacheHit?: boolean }
  ): void {
    if (!executionId || !this.executions.has(executionId)) {
      return;
    }

    const execution = this.executions.get(executionId)!;
    execution.endTime = Date.now();
    execution.duration = execution.endTime - execution.startTime;
    execution.success = success;
    execution.error = error?.message;
    execution.affectedRows = resultInfo?.affectedRows;
    execution.resultSize = resultInfo?.resultSize;
    execution.cacheHit = resultInfo?.cacheHit;

    // 移动到已完成列表
    this.executions.delete(executionId);
    this.completedExecutions.push(execution);

    // 保持最大记录数
    if (this.completedExecutions.length > this.MAX_COMPLETED_EXECUTIONS) {
      this.completedExecutions = this.completedExecutions.slice(-this.MAX_COMPLETED_EXECUTIONS);
    }

    // 记录慢查询
    if (this.config.enableLogging && execution.duration! > this.config.slowQueryThreshold) {
      logger.warn('Slow query detected', {
        executionId,
        queryName: execution.queryName,
        duration: execution.duration,
        sql: execution.sql.substring(0, 500),
        params: execution.params,
        success,
        error: error?.message,
        userId: execution.userId,
        requestId: execution.requestId,
      });
    }

    // 记录失败的查询
    if (!success && this.config.enableLogging) {
      logger.error('Query failed', {
        executionId,
        queryName: execution.queryName,
        duration: execution.duration,
        sql: execution.sql.substring(0, 500),
        params: execution.params,
        error: error?.message,
        userId: execution.userId,
        requestId: execution.requestId,
      });
    }
  }

  // 获取当前性能指标
  getMetrics(): PerformanceMetrics {
    const now = Date.now();
    const totalQueries = this.completedExecutions.length;
    const successfulQueries = this.completedExecutions.filter(e => e.success).length;
    const failedQueries = totalQueries - successfulQueries;
    
    const totalDuration = this.completedExecutions.reduce((sum, e) => sum + (e.duration || 0), 0);
    const averageDuration = totalQueries > 0 ? totalDuration / totalQueries : 0;
    
    const slowQueries = this.completedExecutions.filter(
      e => (e.duration || 0) > this.config.slowQueryThreshold
    ).length;

    const queriesWithCache = this.completedExecutions.filter(e => e.cacheHit !== undefined);
    const cacheHits = this.completedExecutions.filter(e => e.cacheHit === true).length;
    const cacheHitRate = queriesWithCache.length > 0 ? (cacheHits / queriesWithCache.length) * 100 : 0;

    const timeSpanMs = now - this.metricsStartTime;
    const queriesPerSecond = totalQueries / (timeSpanMs / 1000);

    const currentConcurrency = this.executions.size;
    const peakConcurrency = Math.max(currentConcurrency, this.getPeakConcurrency());

    return {
      totalQueries,
      successfulQueries,
      failedQueries,
      totalDuration,
      averageDuration: Math.round(averageDuration),
      slowQueries,
      cacheHitRate: Math.round(cacheHitRate * 100) / 100,
      queriesPerSecond: Math.round(queriesPerSecond * 100) / 100,
      peakConcurrency,
      memoryUsage: process.memoryUsage(),
      connectionPoolStats: this.getConnectionPoolStats(),
    };
  }

  // 获取慢查询统计
  getSlowQueries(limit: number = 10): Array<{
    queryName: string;
    averageDuration: number;
    maxDuration: number;
    count: number;
    examples: QueryExecution[];
  }> {
    const slowQueries = this.completedExecutions.filter(
      e => (e.duration || 0) > this.config.slowQueryThreshold
    );

    // 按查询名称分组
    const grouped = new Map<string, QueryExecution[]>();
    slowQueries.forEach((query: QueryExecution) => {
      if (!grouped.has(query.queryName)) {
        grouped.set(query.queryName, []);
      }
      grouped.get(query.queryName)!.push(query);
    });

    // 计算统计信息并排序
    const results = Array.from(grouped.entries()).map(([queryName, executions]) => {
      const durations = executions.map(e => e.duration || 0);
      const totalDuration = durations.reduce((sum, d) => sum + d, 0);
      const averageDuration = totalDuration / executions.length;
      const maxDuration = Math.max(...durations);
      
      return {
        queryName,
        averageDuration: Math.round(averageDuration),
        maxDuration,
        count: executions.length,
        examples: executions.slice(0, 3), // 最多3个示例
      };
    });

    return results
      .sort((a, b) => b.averageDuration - a.averageDuration)
      .slice(0, limit);
  }

  // 获取错误查询统计
  getFailedQueries(limit: number = 10): Array<{
    queryName: string;
    errorCount: number;
    latestError: string;
    examples: QueryExecution[];
  }> {
    const failedQueries = this.completedExecutions.filter(e => !e.success);

    // 按查询名称分组
    const grouped = new Map<string, QueryExecution[]>();
    failedQueries.forEach(query => {
      if (!grouped.has(query.queryName)) {
        grouped.set(query.queryName, []);
      }
      grouped.get(query.queryName)!.push(query);
    });

    const results = Array.from(grouped.entries()).map(([queryName, executions]) => {
      const latestExecution = executions.sort((a, b) => b.startTime - a.startTime)[0];
      
      return {
        queryName,
        errorCount: executions.length,
        latestError: latestExecution.error || 'Unknown error',
        examples: executions.slice(0, 3),
      };
    });

    return results
      .sort((a, b) => b.errorCount - a.errorCount)
      .slice(0, limit);
  }

  // 获取查询模式分析
  getQueryPatterns(): Array<{
    pattern: string;
    count: number;
    averageDuration: number;
    examples: string[];
  }> {
    // 简单的SQL模式匹配
    const patterns = new Map<string, { executions: QueryExecution[]; examples: Set<string> }>();
    
    this.completedExecutions.forEach(execution => {
      const pattern = this.extractQueryPattern(execution.sql);
      if (!patterns.has(pattern)) {
        patterns.set(pattern, { executions: [], examples: new Set() });
      }
      const patternData = patterns.get(pattern)!;
      patternData.executions.push(execution);
      patternData.examples.add(execution.sql.substring(0, 100));
    });

    return Array.from(patterns.entries()).map(([pattern, data]) => {
      const totalDuration = data.executions.reduce((sum, e) => sum + (e.duration || 0), 0);
      const averageDuration = data.executions.length > 0 ? totalDuration / data.executions.length : 0;
      
      return {
        pattern,
        count: data.executions.length,
        averageDuration: Math.round(averageDuration),
        examples: Array.from(data.examples).slice(0, 3),
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  }

  // 生成性能报告
  generateReport(): {
    summary: PerformanceMetrics;
    slowQueries: Array<{
      queryName: string;
      averageDuration: number;
      count: number;
      maxDuration: number;
      examples: QueryExecution[];
    }>;
    failedQueries: Array<{
      queryName: string;
      errorCount: number;
      latestError: string;
      examples: QueryExecution[];
    }>;
    queryPatterns: Array<{
      pattern: string;
      count: number;
      averageDuration: number;
      examples: string[];
    }>;
    recommendations: string[];
  } {
    const summary = this.getMetrics();
    const slowQueries = this.getSlowQueries();
    const failedQueries = this.getFailedQueries();
    const queryPatterns = this.getQueryPatterns();
    
    const recommendations: string[] = [];
    
    // 生成建议
    if (summary.cacheHitRate < 50) {
      recommendations.push('缓存命中率较低，考虑增加缓存策略或优化缓存键');
    }
    
    if (summary.averageDuration > 500) {
      recommendations.push('平均查询时间较高，建议优化数据库索引');
    }
    
    if ((summary.failedQueries / summary.totalQueries) > 0.05) {
      recommendations.push('查询失败率超过5%，需要检查数据库连接和查询逻辑');
    }
    
    if (summary.peakConcurrency > 20) {
      recommendations.push('并发查询数量较高，考虑增加连接池大小或优化查询效率');
    }

    if (slowQueries.length > 0) {
      recommendations.push(`发现${slowQueries.length}个慢查询模式，优先优化最频繁的慢查询`);
    }

    return {
      summary,
      slowQueries,
      failedQueries,
      queryPatterns,
      recommendations,
    };
  }

  // 重置监控数据
  reset(): void {
    this.completedExecutions = [];
    this.executions.clear();
    this.metricsStartTime = Date.now();
    logger.info('Query performance monitor reset');
  }

  // 启动监控
  private startMonitoring(): void {
    if (this.config.enableMetrics) {
      this.intervalId = setInterval(() => {
        this.cleanupOldExecutions();
      }, 60000); // 每分钟清理一次旧数据
    }
  }

  // 停止监控
  stopMonitoring(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  // 清理旧的执行记录
  private cleanupOldExecutions(): void {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    this.completedExecutions = this.completedExecutions.filter(
      e => e.startTime > oneHourAgo
    );
  }

  // 获取连接池状态
  private getConnectionPoolStats(): any {
    try {
      const pool = (db as any).client?.pool;
      if (pool) {
        return {
          size: pool.size || 0,
          available: pool.available || 0,
          borrowed: pool.borrowed || 0,
          pending: pool.pending || 0,
          max: pool.max || 0,
          min: pool.min || 0,
        };
      }
    } catch (error) {
      logger.warn('Failed to get connection pool stats', { error });
    }
    return null;
  }

  // 获取峰值并发数（简单实现）
  private getPeakConcurrency(): number {
    // 这里可以实现更复杂的峰值追踪逻辑
    return this.executions.size;
  }

  // 清理SQL语句（移除敏感信息）
  private sanitizeSQL(sql: string): string {
    // 简单的SQL清理，移除换行符和多余空格
    return sql.replace(/\s+/g, ' ').trim().substring(0, 1000);
  }

  // 清理参数（移除敏感信息）
  private sanitizeParams(params: any[]): any[] {
    if (!params || params.length === 0) return [];
    
    // 限制参数数量和长度
    return params.slice(0, 10).map(param => {
      if (typeof param === 'string' && param.length > 100) {
        return param.substring(0, 100) + '...';
      }
      return param;
    });
  }

  // 提取查询模式
  private extractQueryPattern(sql: string): string {
    // 简单的模式提取：替换数值和字符串字面量
    return sql
      .replace(/\d+/g, '?')
      .replace(/'[^']*'/g, '?')
      .replace(/"[^"]*"/g, '?')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, 100);
  }
}

// 创建全局监控实例
export const queryPerformanceMonitor = new QueryPerformanceMonitor({
  enableLogging: process.env['NODE_ENV'] !== 'production',
  enableMetrics: true,
  slowQueryThreshold: process.env['NODE_ENV'] === 'production' ? 2000 : 1000,
  sampleRate: process.env['NODE_ENV'] === 'production' ? 0.1 : 1.0,
});

// 监控装饰器
export function monitorQuery(queryName: string) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const executionId = queryPerformanceMonitor.startQuery(
        queryName,
        `${target.constructor.name}.${propertyName}`,
        args
      );
      
      try {
        const result = await method.apply(this, args);
        queryPerformanceMonitor.endQuery(executionId, true, undefined, {
          resultSize: Array.isArray(result) ? result.length : 1,
        });
        return result;
      } catch (error) {
        queryPerformanceMonitor.endQuery(executionId, false, error as Error);
        throw error;
      }
    };
    
    return descriptor;
  };
}

export default queryPerformanceMonitor;