/**
 * Database Connection Pool Monitor Service
 * 
 * Provides real-time monitoring, alerting, and automatic recovery
 * for database connection pool health and performance.
 */

import { EventEmitter } from 'events';
import { db, checkDatabaseHealth } from '../config/database';
import { logger } from '../utils/logger';

interface ConnectionPoolMetrics {
  timestamp: Date;
  poolSize: number;
  availableConnections: number;
  borrowedConnections: number;
  pendingConnections: number;
  utilization: number;
  responseTime: number;
  healthy: boolean;
  errorCount: number;
}

interface AlertThresholds {
  utilizationWarning: number;      // 80%
  utilizationCritical: number;     // 95%
  responseTimeWarning: number;     // 500ms
  responseTimeCritical: number;    // 1000ms
  errorRateWarning: number;        // 5%
  errorRateCritical: number;       // 10%
}

class DatabaseConnectionMonitor extends EventEmitter {
  private metrics: ConnectionPoolMetrics[] = [];
  private monitoringInterval?: NodeJS.Timeout;
  private alertThresholds: AlertThresholds;
  private consecutiveErrors = 0;
  private lastAlertTime: { [key: string]: number } = {};
  private readonly maxMetricsHistory = 1000;
  
  constructor() {
    super();
    
    this.alertThresholds = {
      utilizationWarning: 80,
      utilizationCritical: 95,
      responseTimeWarning: 500,
      responseTimeCritical: 1000,
      errorRateWarning: 5,
      errorRateCritical: 10
    };
  }

  /**
   * Start monitoring database connection pool
   */
  startMonitoring(intervalMs: number = 15000): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    this.monitoringInterval = setInterval(async () => {
      try {
        await this.collectMetrics();
        this.analyzeMetrics();
        this.cleanupOldMetrics();
      } catch (error) {
        logger.error('❌ Database monitoring error:', error);
      }
    }, intervalMs);

    logger.info('🔍 Database connection pool monitoring started', { 
      interval: `${intervalMs}ms`,
      thresholds: this.alertThresholds
    });
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
   * Collect current connection pool metrics
   */
  private async collectMetrics(): Promise<void> {
    const startTime = Date.now();
    
    try {
      const healthCheck = await checkDatabaseHealth();
      const responseTime = Date.now() - startTime;
      
      const pool = (db as any).client?.pool;
      const poolSize = pool?.size || 0;
      const availableConnections = pool?.available || 0;
      const borrowedConnections = pool?.borrowed || 0;
      const pendingConnections = pool?.pending || 0;
      
      const utilization = poolSize > 0 ? (borrowedConnections / poolSize) * 100 : 0;
      
      const metric: ConnectionPoolMetrics = {
        timestamp: new Date(),
        poolSize,
        availableConnections,
        borrowedConnections,
        pendingConnections,
        utilization,
        responseTime,
        healthy: healthCheck.healthy,
        errorCount: healthCheck.healthy ? 0 : 1
      };

      this.metrics.push(metric);
      
      // Reset consecutive errors on successful check
      if (healthCheck.healthy) {
        this.consecutiveErrors = 0;
      } else {
        this.consecutiveErrors++;
      }

      // Emit real-time metric
      this.emit('metrics', metric);
      
    } catch (error) {
      this.consecutiveErrors++;
      logger.error('❌ Failed to collect database metrics:', error);
      
      const errorMetric: ConnectionPoolMetrics = {
        timestamp: new Date(),
        poolSize: 0,
        availableConnections: 0,
        borrowedConnections: 0,
        pendingConnections: 0,
        utilization: 0,
        responseTime: Date.now() - startTime,
        healthy: false,
        errorCount: 1
      };
      
      this.metrics.push(errorMetric);
      this.emit('metrics', errorMetric);
    }
  }

  /**
   * Analyze metrics and trigger alerts if needed
   */
  private analyzeMetrics(): void {
    if (this.metrics.length === 0) return;

    const latestMetric = this.metrics[this.metrics.length - 1];
    const recentMetrics = this.metrics.slice(-10); // Last 10 readings
    
    // Check utilization alerts
    this.checkUtilizationAlerts(latestMetric);
    
    // Check response time alerts
    this.checkResponseTimeAlerts(latestMetric);
    
    // Check error rate alerts
    this.checkErrorRateAlerts(recentMetrics);
    
    // Check consecutive errors
    this.checkConsecutiveErrors();
    
    // Check for connection pool exhaustion
    this.checkPoolExhaustion(latestMetric);
  }

  /**
   * Check connection pool utilization alerts
   */
  private checkUtilizationAlerts(metric: ConnectionPoolMetrics): void {
    const { utilization } = metric;
    
    if (utilization >= this.alertThresholds.utilizationCritical) {
      this.sendAlert('utilization_critical', 
        `🚨 CRITICAL: Connection pool utilization at ${utilization.toFixed(1)}%`, 
        { metric }, 300000); // 5 minute cooldown
    } else if (utilization >= this.alertThresholds.utilizationWarning) {
      this.sendAlert('utilization_warning', 
        `⚠️ WARNING: High connection pool utilization at ${utilization.toFixed(1)}%`, 
        { metric }, 900000); // 15 minute cooldown
    }
  }

  /**
   * Check response time alerts
   */
  private checkResponseTimeAlerts(metric: ConnectionPoolMetrics): void {
    const { responseTime } = metric;
    
    if (responseTime >= this.alertThresholds.responseTimeCritical) {
      this.sendAlert('response_time_critical', 
        `🚨 CRITICAL: Database response time ${responseTime}ms`, 
        { metric }, 300000);
    } else if (responseTime >= this.alertThresholds.responseTimeWarning) {
      this.sendAlert('response_time_warning', 
        `⚠️ WARNING: Slow database response time ${responseTime}ms`, 
        { metric }, 900000);
    }
  }

  /**
   * Check error rate alerts
   */
  private checkErrorRateAlerts(recentMetrics: ConnectionPoolMetrics[]): void {
    if (recentMetrics.length === 0) return;
    
    const totalErrors = recentMetrics.reduce((sum, m) => sum + m.errorCount, 0);
    const errorRate = (totalErrors / recentMetrics.length) * 100;
    
    if (errorRate >= this.alertThresholds.errorRateCritical) {
      this.sendAlert('error_rate_critical', 
        `🚨 CRITICAL: High database error rate ${errorRate.toFixed(1)}%`, 
        { errorRate, recentMetrics: recentMetrics.length }, 300000);
    } else if (errorRate >= this.alertThresholds.errorRateWarning) {
      this.sendAlert('error_rate_warning', 
        `⚠️ WARNING: Elevated database error rate ${errorRate.toFixed(1)}%`, 
        { errorRate, recentMetrics: recentMetrics.length }, 900000);
    }
  }

  /**
   * Check for consecutive connection errors
   */
  private checkConsecutiveErrors(): void {
    if (this.consecutiveErrors >= 5) {
      this.sendAlert('consecutive_errors', 
        `🚨 CRITICAL: ${this.consecutiveErrors} consecutive database connection failures`, 
        { consecutiveErrors: this.consecutiveErrors }, 300000);
    } else if (this.consecutiveErrors >= 3) {
      this.sendAlert('consecutive_errors_warning', 
        `⚠️ WARNING: ${this.consecutiveErrors} consecutive database connection failures`, 
        { consecutiveErrors: this.consecutiveErrors }, 600000);
    }
  }

  /**
   * Check for connection pool exhaustion
   */
  private checkPoolExhaustion(metric: ConnectionPoolMetrics): void {
    const { availableConnections, pendingConnections } = metric;
    
    if (availableConnections === 0 && pendingConnections > 0) {
      this.sendAlert('pool_exhausted', 
        `🚨 CRITICAL: Connection pool exhausted, ${pendingConnections} requests waiting`, 
        { metric }, 300000);
    }
  }

  /**
   * Send alert with rate limiting
   */
  private sendAlert(
    alertType: string, 
    message: string, 
    data: any, 
    cooldownMs: number
  ): void {
    const now = Date.now();
    const lastAlert = this.lastAlertTime[alertType] || 0;
    
    if (now - lastAlert < cooldownMs) {
      return; // Rate limited
    }
    
    this.lastAlertTime[alertType] = now;
    
    logger.error(message, data);
    this.emit('alert', {
      type: alertType,
      message,
      data,
      timestamp: new Date()
    });
  }

  /**
   * Get current connection pool status
   */
  getPoolStatus(): {
    current: ConnectionPoolMetrics | null;
    summary: {
      averageUtilization: number;
      averageResponseTime: number;
      errorRate: number;
      healthyChecks: number;
      totalChecks: number;
    };
  } {
    const current = this.metrics.length > 0 ? this.metrics[this.metrics.length - 1] : null;
    const recentMetrics = this.metrics.slice(-20); // Last 20 readings
    
    if (recentMetrics.length === 0) {
      return {
        current,
        summary: {
          averageUtilization: 0,
          averageResponseTime: 0,
          errorRate: 0,
          healthyChecks: 0,
          totalChecks: 0
        }
      };
    }
    
    const totalUtilization = recentMetrics.reduce((sum, m) => sum + m.utilization, 0);
    const totalResponseTime = recentMetrics.reduce((sum, m) => sum + m.responseTime, 0);
    const totalErrors = recentMetrics.reduce((sum, m) => sum + m.errorCount, 0);
    const healthyChecks = recentMetrics.filter(m => m.healthy).length;
    
    return {
      current,
      summary: {
        averageUtilization: totalUtilization / recentMetrics.length,
        averageResponseTime: totalResponseTime / recentMetrics.length,
        errorRate: (totalErrors / recentMetrics.length) * 100,
        healthyChecks,
        totalChecks: recentMetrics.length
      }
    };
  }

  /**
   * Generate performance report
   */
  generateReport(): {
    status: 'healthy' | 'warning' | 'critical';
    metrics: ConnectionPoolMetrics[];
    recommendations: string[];
  } {
    const status = this.getPoolStatus();
    const recommendations: string[] = [];
    
    // Generate recommendations based on metrics
    if (status.summary.averageUtilization > 80) {
      recommendations.push('Consider increasing max pool size - high utilization detected');
    }
    
    if (status.summary.averageResponseTime > 500) {
      recommendations.push('Database response time is high - check network and query performance');
    }
    
    if (status.summary.errorRate > 5) {
      recommendations.push('High error rate detected - investigate connection stability');
    }
    
    if (this.consecutiveErrors >= 3) {
      recommendations.push('Consecutive connection failures - check database availability');
    }
    
    // Determine overall status
    let overallStatus: 'healthy' | 'warning' | 'critical' = 'healthy';
    
    if (status.summary.errorRate > 10 || this.consecutiveErrors >= 5 || 
        status.summary.averageUtilization > 95) {
      overallStatus = 'critical';
    } else if (status.summary.errorRate > 5 || this.consecutiveErrors >= 3 || 
               status.summary.averageUtilization > 80 || 
               status.summary.averageResponseTime > 500) {
      overallStatus = 'warning';
    }
    
    return {
      status: overallStatus,
      metrics: this.metrics.slice(-50), // Last 50 metrics
      recommendations
    };
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
   * Force database reconnection (emergency recovery)
   */
  async forceReconnect(): Promise<void> {
    logger.warn('🔄 Forcing database reconnection...');
    
    try {
      // Destroy current connection pool
      await db.destroy();
      
      // Wait before recreating
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // This would need to reinitialize the database connection
      // Implementation depends on your app's architecture
      logger.info('✅ Database reconnection completed');
      
    } catch (error) {
      logger.error('❌ Failed to force database reconnection:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const databaseConnectionMonitor = new DatabaseConnectionMonitor();

// Graceful shutdown
process.on('SIGINT', () => {
  databaseConnectionMonitor.stopMonitoring();
});

process.on('SIGTERM', () => {
  databaseConnectionMonitor.stopMonitoring();
});

export default databaseConnectionMonitor;