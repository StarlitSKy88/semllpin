/**
 * Enhanced Database Performance Monitoring Service for SmellPin
 * Monitors query performance, connection health, and LBS-specific metrics
 * Target: Maintain <100ms query response times for critical operations
 * 
 * Features:
 * - Real-time performance metrics collection
 * - Connection pool health monitoring
 * - Index usage analytics
 * - Automated performance alerts
 * - PostgreSQL-specific optimizations
 * - Geographic query performance tracking
 */

import { db, monitorQuery } from '../config/database-optimized';
import { logger } from '../utils/logger';
import { EventEmitter } from 'events';

export interface PerformanceMetrics {
  timestamp: Date;
  queryType: string;
  duration: number;
  rowsAffected?: number;
  memoryUsed?: number;
  success: boolean;
  errorMessage?: string;
}

export interface LBSPerformanceStats {
  averageLocationQueryTime: number;
  geofenceDetectionTime: number;
  rewardCalculationTime: number;
  totalLBSQueries: number;
  activeUsers: number;
  peakConcurrency: number;
}

export interface DatabaseHealth {
  status: 'healthy' | 'warning' | 'critical';
  connectionPool: {
    active: number;
    idle: number;
    waiting: number;
    maxConnections: number;
  };
  queryPerformance: {
    averageResponseTime: number;
    slowQueryCount: number;
    errorRate: number;
  };
  lbsMetrics: LBSPerformanceStats;
  recommendations: string[];
}

class DatabaseMonitorService extends EventEmitter {
  private metrics: PerformanceMetrics[] = [];
  private readonly maxMetricsHistory = 10000;
  private readonly slowQueryThreshold = 100; // milliseconds - more aggressive for better performance
  private readonly criticalQueryThreshold = 200; // milliseconds
  private monitoringInterval?: NodeJS.Timeout;
  private alertThresholds: Map<string, number> = new Map();
  private consecutiveSlowQueries = 0;
  private lastHealthCheck?: Date;

  constructor() {
    super();
    this.setupAlertThresholds();
    this.startMonitoring();
  }

  /**
   * Setup default alert thresholds
   */
  private setupAlertThresholds(): void {
    this.alertThresholds.set('connectionUtilization', 80); // 80% connection pool usage
    this.alertThresholds.set('avgResponseTime', 150); // 150ms average response time
    this.alertThresholds.set('errorRate', 0.02); // 2% error rate
    this.alertThresholds.set('slowQueryRate', 0.1); // 10% slow query rate
    this.alertThresholds.set('consecutiveSlowQueries', 5); // 5 consecutive slow queries
  }

  /**
   * Start continuous database monitoring
   */
  startMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    // Monitor every 30 seconds
    this.monitoringInterval = setInterval(async () => {
      try {
        await this.collectSystemMetrics();
        await this.analyzeLBSPerformance();
        this.cleanupOldMetrics();
      } catch (error) {
        logger.error('Database monitoring error:', error);
      }
    }, 30000);

    logger.info('🔍 Database monitoring started');
  }

  /**
   * Stop monitoring
   */
  stopMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
      logger.info('🔍 Database monitoring stopped');
    }
  }

  /**
   * Record query performance metrics
   */
  recordMetric(metric: PerformanceMetrics): void {
    this.metrics.push(metric);
    
    // Log slow queries immediately
    if (metric.duration > this.slowQueryThreshold) {
      logger.warn(`🐌 Slow ${metric.queryType} query: ${metric.duration}ms`, {
        success: metric.success,
        rowsAffected: metric.rowsAffected,
        error: metric.errorMessage
      });
    }
  }

  /**
   * Execute and monitor a query
   */
  async executeWithMonitoring<T>(
    queryType: string,
    queryFn: () => Promise<T>,
    expectedRowEstimate?: number
  ): Promise<T> {
    return monitorQuery(queryType, queryFn, {
      slowQueryThreshold: this.slowQueryThreshold,
      timeout: 30000 // 30 second timeout
    });
  }

  /**
   * Monitor specific LBS query patterns
   */
  async monitorLocationQuery<T>(
    queryFn: () => Promise<T>,
    location: { lat: number; lng: number },
    radius: number
  ): Promise<T> {
    const startTime = performance.now();
    
    try {
      const result = await queryFn();
      const duration = performance.now() - startTime;
      
      this.recordMetric({
        timestamp: new Date(),
        queryType: 'location_query',
        duration,
        success: true,
        memoryUsed: process.memoryUsage().heapUsed
      });
      
      return result;
    } catch (error) {
      const duration = performance.now() - startTime;
      
      this.recordMetric({
        timestamp: new Date(),
        queryType: 'location_query',
        duration,
        success: false,
        errorMessage: (error as Error).message
      });
      
      throw error;
    }
  }

  /**
   * Get current database health status
   */
  async getDatabaseHealth(): Promise<DatabaseHealth> {
    const [connectionStats, queryStats, lbsStats] = await Promise.all([
      this.getConnectionPoolStats(),
      this.getQueryPerformanceStats(),
      this.getLBSPerformanceStats()
    ]);

    const recommendations = this.generateRecommendations(queryStats, lbsStats);
    const status = this.calculateHealthStatus(queryStats, lbsStats);

    return {
      status,
      connectionPool: connectionStats,
      queryPerformance: queryStats,
      lbsMetrics: lbsStats,
      recommendations
    };
  }

  /**
   * Get connection pool statistics
   */
  private async getConnectionPoolStats(): Promise<DatabaseHealth['connectionPool']> {
    try {
      const pool = (db as any).client?.pool;
      
      return {
        active: pool?.borrowed || 0,
        idle: pool?.available || 0,
        waiting: pool?.pending || 0,
        maxConnections: pool?.max || 0
      };
    } catch (error) {
      logger.error('Error getting connection pool stats:', error);
      return {
        active: 0,
        idle: 0,
        waiting: 0,
        maxConnections: 0
      };
    }
  }

  /**
   * Analyze query performance over recent time period
   */
  private getQueryPerformanceStats(): DatabaseHealth['queryPerformance'] {
    const recentMetrics = this.getRecentMetrics(300000); // Last 5 minutes
    
    if (recentMetrics.length === 0) {
      return {
        averageResponseTime: 0,
        slowQueryCount: 0,
        errorRate: 0
      };
    }

    const totalDuration = recentMetrics.reduce((sum, m) => sum + m.duration, 0);
    const slowQueries = recentMetrics.filter(m => m.duration > this.slowQueryThreshold);
    const errorCount = recentMetrics.filter(m => !m.success).length;

    return {
      averageResponseTime: totalDuration / recentMetrics.length,
      slowQueryCount: slowQueries.length,
      errorRate: errorCount / recentMetrics.length
    };
  }

  /**
   * Get LBS-specific performance metrics
   */
  private async getLBSPerformanceStats(): Promise<LBSPerformanceStats> {
    const recentMetrics = this.getRecentMetrics(300000); // Last 5 minutes
    const locationQueries = recentMetrics.filter(m => m.queryType === 'location_query');
    
    try {
      // Get additional stats from database
      const [activeUsersResult, concurrencyResult] = await Promise.all([
        db.raw(`
          SELECT COUNT(DISTINCT user_id) as count 
          FROM location_reports 
          WHERE server_timestamp > NOW() - INTERVAL '5 minutes'
        `),
        db.raw(`
          SELECT COUNT(*) as count 
          FROM lbs_check_ins 
          WHERE status = 'active' AND check_out_time IS NULL
        `)
      ]);

      const activeUsers = activeUsersResult.rows?.[0]?.count || 0;
      const peakConcurrency = concurrencyResult.rows?.[0]?.count || 0;

      return {
        averageLocationQueryTime: locationQueries.length > 0 
          ? locationQueries.reduce((sum, m) => sum + m.duration, 0) / locationQueries.length 
          : 0,
        geofenceDetectionTime: this.calculateAverageQueryTime('geofence_detection'),
        rewardCalculationTime: this.calculateAverageQueryTime('reward_calculation'),
        totalLBSQueries: locationQueries.length,
        activeUsers: parseInt(activeUsers),
        peakConcurrency: parseInt(peakConcurrency)
      };
    } catch (error) {
      logger.error('Error getting LBS performance stats:', error);
      return {
        averageLocationQueryTime: 0,
        geofenceDetectionTime: 0,
        rewardCalculationTime: 0,
        totalLBSQueries: 0,
        activeUsers: 0,
        peakConcurrency: 0
      };
    }
  }

  /**
   * Calculate average query time for specific query type
   */
  private calculateAverageQueryTime(queryType: string): number {
    const queries = this.getRecentMetrics(300000).filter(m => m.queryType === queryType);
    if (queries.length === 0) return 0;
    
    return queries.reduce((sum, m) => sum + m.duration, 0) / queries.length;
  }

  /**
   * Collect system-level database metrics
   */
  private async collectSystemMetrics(): Promise<void> {
    try {
      // Get PostgreSQL statistics if available
      const [pgStats, slowQueries] = await Promise.allSettled([
        this.collectPostgreSQLStats(),
        this.getSlowQueries()
      ]);

      if (pgStats.status === 'fulfilled') {
        logger.debug('PostgreSQL stats collected', pgStats.value);
      }

      if (slowQueries.status === 'fulfilled') {
        const slow = slowQueries.value;
        if (slow.length > 0) {
          logger.warn(`Found ${slow.length} slow queries in past 5 minutes`);
        }
      }
    } catch (error) {
      logger.error('Error collecting system metrics:', error);
    }
  }

  /**
   * Collect PostgreSQL-specific statistics
   */
  private async collectPostgreSQLStats(): Promise<any> {
    try {
      const result = await db.raw(`
        SELECT 
          schemaname,
          tablename,
          n_tup_ins as inserts,
          n_tup_upd as updates,
          n_tup_del as deletes,
          n_tup_hot_upd as hot_updates,
          n_live_tup as live_tuples,
          n_dead_tup as dead_tuples,
          last_vacuum,
          last_autovacuum,
          last_analyze,
          last_autoanalyze
        FROM pg_stat_user_tables 
        WHERE schemaname = 'public'
        ORDER BY n_tup_ins + n_tup_upd + n_tup_del DESC
        LIMIT 10
      `);

      return result.rows || [];
    } catch (error) {
      // Not PostgreSQL or missing permissions
      return [];
    }
  }

  /**
   * Get slow queries from pg_stat_statements if available
   */
  private async getSlowQueries(): Promise<any[]> {
    try {
      const result = await db.raw(`
        SELECT 
          query,
          calls,
          total_time,
          mean_time,
          max_time,
          stddev_time
        FROM pg_stat_statements 
        WHERE mean_time > 200 
        ORDER BY mean_time DESC 
        LIMIT 5
      `);

      return result.rows || [];
    } catch (error) {
      // pg_stat_statements not available
      return [];
    }
  }

  /**
   * Analyze LBS-specific performance patterns
   */
  private async analyzeLBSPerformance(): Promise<void> {
    try {
      // Check for performance degradation patterns
      const recentLocationQueries = this.metrics
        .filter(m => m.queryType === 'location_query' && 
                Date.now() - m.timestamp.getTime() < 300000)
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

      if (recentLocationQueries.length > 10) {
        const recent = recentLocationQueries.slice(0, 5);
        const older = recentLocationQueries.slice(-5);
        
        const recentAvg = recent.reduce((sum, m) => sum + m.duration, 0) / recent.length;
        const olderAvg = older.reduce((sum, m) => sum + m.duration, 0) / older.length;
        
        // Alert if performance degraded by more than 50%
        if (recentAvg > olderAvg * 1.5) {
          logger.warn('🚨 LBS query performance degradation detected', {
            recentAverage: `${recentAvg.toFixed(2)}ms`,
            previousAverage: `${olderAvg.toFixed(2)}ms`,
            degradation: `${((recentAvg / olderAvg - 1) * 100).toFixed(1)}%`
          });
        }
      }
    } catch (error) {
      logger.error('Error analyzing LBS performance:', error);
    }
  }

  /**
   * Generate performance recommendations
   */
  private generateRecommendations(
    queryStats: DatabaseHealth['queryPerformance'],
    lbsStats: LBSPerformanceStats
  ): string[] {
    const recommendations: string[] = [];

    // Query performance recommendations
    if (queryStats.averageResponseTime > 200) {
      recommendations.push('Average query response time is above 200ms target');
    }

    if (queryStats.slowQueryCount > 5) {
      recommendations.push('High number of slow queries detected - consider query optimization');
    }

    if (queryStats.errorRate > 0.01) {
      recommendations.push('Query error rate is above 1% - investigate failing queries');
    }

    // LBS-specific recommendations
    if (lbsStats.averageLocationQueryTime > 100) {
      recommendations.push('Location queries are slow - check spatial indexes');
    }

    if (lbsStats.geofenceDetectionTime > 150) {
      recommendations.push('Geofence detection is slow - optimize geofence queries');
    }

    if (lbsStats.activeUsers > 1000 && lbsStats.averageLocationQueryTime > 50) {
      recommendations.push('Consider read replicas for high user load');
    }

    return recommendations;
  }

  /**
   * Calculate overall health status
   */
  private calculateHealthStatus(
    queryStats: DatabaseHealth['queryPerformance'],
    lbsStats: LBSPerformanceStats
  ): DatabaseHealth['status'] {
    let score = 100;

    // Penalize slow queries
    if (queryStats.averageResponseTime > 500) score -= 30;
    else if (queryStats.averageResponseTime > 200) score -= 15;

    // Penalize high error rate
    if (queryStats.errorRate > 0.05) score -= 25;
    else if (queryStats.errorRate > 0.01) score -= 10;

    // Penalize slow LBS queries
    if (lbsStats.averageLocationQueryTime > 200) score -= 20;
    else if (lbsStats.averageLocationQueryTime > 100) score -= 10;

    if (score >= 80) return 'healthy';
    if (score >= 60) return 'warning';
    return 'critical';
  }

  /**
   * Get metrics from recent time period
   */
  private getRecentMetrics(timeWindowMs: number): PerformanceMetrics[] {
    const cutoff = Date.now() - timeWindowMs;
    return this.metrics.filter(m => m.timestamp.getTime() > cutoff);
  }

  /**
   * Clean up old metrics to prevent memory leaks
   */
  private cleanupOldMetrics(): void {
    if (this.metrics.length > this.maxMetricsHistory) {
      this.metrics = this.metrics.slice(-this.maxMetricsHistory);
    }
  }

  /**
   * Export metrics for external monitoring
   */
  exportMetrics(): {
    recentMetrics: PerformanceMetrics[];
    summary: {
      totalQueries: number;
      averageResponseTime: number;
      slowQueries: number;
      errors: number;
    };
  } {
    const recent = this.getRecentMetrics(3600000); // Last hour
    
    return {
      recentMetrics: recent,
      summary: {
        totalQueries: recent.length,
        averageResponseTime: recent.length > 0 
          ? recent.reduce((sum, m) => sum + m.duration, 0) / recent.length 
          : 0,
        slowQueries: recent.filter(m => m.duration > this.slowQueryThreshold).length,
        errors: recent.filter(m => !m.success).length
      }
    };
  }

  /**
   * Get detailed performance report
   */
  async getPerformanceReport(): Promise<{
    health: DatabaseHealth;
    metrics: ReturnType<DatabaseMonitorService['exportMetrics']>;
    slowQueries: Array<{
      queryType: string;
      averageDuration: number;
      count: number;
      maxDuration: number;
    }>;
  }> {
    const [health, metrics] = await Promise.all([
      this.getDatabaseHealth(),
      Promise.resolve(this.exportMetrics())
    ]);

    // Analyze slow queries by type
    const slowQueries = this.analyzeSlowQueriesByType();

    return {
      health,
      metrics,
      slowQueries
    };
  }

  /**
   * Analyze slow queries grouped by type
   */
  private analyzeSlowQueriesByType(): Array<{
    queryType: string;
    averageDuration: number;
    count: number;
    maxDuration: number;
  }> {
    const recentSlowQueries = this.getRecentMetrics(3600000)
      .filter(m => m.duration > this.slowQueryThreshold);

    const byType = new Map<string, number[]>();
    
    recentSlowQueries.forEach(m => {
      if (!byType.has(m.queryType)) {
        byType.set(m.queryType, []);
      }
      byType.get(m.queryType)!.push(m.duration);
    });

    return Array.from(byType.entries()).map(([queryType, durations]) => ({
      queryType,
      count: durations.length,
      averageDuration: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      maxDuration: Math.max(...durations)
    })).sort((a, b) => b.averageDuration - a.averageDuration);
  }
}

// Export singleton instance
export const databaseMonitor = new DatabaseMonitorService();

// Graceful shutdown
process.on('SIGINT', () => {
  databaseMonitor.stopMonitoring();
});

process.on('SIGTERM', () => {
  databaseMonitor.stopMonitoring();
});

export default databaseMonitor;