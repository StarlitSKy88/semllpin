/**
 * 健康检查服务
 * 提供系统健康状态检查功能
 */

import { logger } from '../utils/logger';

const isTestEnv = (process.env['NODE_ENV'] === 'test') || (typeof process.env['JEST_WORKER_ID'] !== 'undefined');

// 健康状态枚举
export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
}

// 服务健康信息接口
export interface ServiceHealthInfo {
  status: HealthStatus;
  responseTime?: number;
  error?: string;
  details?: any;
  lastCheck?: string;
}

// 系统健康信息接口
export interface SystemHealthInfo {
  status: HealthStatus;
  timestamp: string;
  version: string;
  environment: string;
  uptime: number;
  services: {
    [serviceName: string]: ServiceHealthInfo;
  };
  metrics?: {
    [metricName: string]: number;
  };
}

class HealthService {
  private healthChecks: Map<string, () => Promise<ServiceHealthInfo>> = new Map();
  private lastHealthCheck: SystemHealthInfo | null = null;
  private healthCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.startPeriodicHealthCheck();
  }

  /**
   * 注册健康检查函数
   */
  registerHealthCheck(serviceName: string, checkFunction: () => Promise<ServiceHealthInfo>): void {
    this.healthChecks.set(serviceName, checkFunction);
    logger.info(`Health check registered for service: ${serviceName}`);
  }

  /**
   * 移除健康检查函数
   */
  unregisterHealthCheck(serviceName: string): void {
    this.healthChecks.delete(serviceName);
    logger.info(`Health check unregistered for service: ${serviceName}`);
  }

  /**
   * 执行所有健康检查
   */
  async performHealthCheck(): Promise<SystemHealthInfo> {
    const startTime = Date.now();
    const services: { [serviceName: string]: ServiceHealthInfo } = {};

    // 并行执行所有健康检查
    const healthCheckPromises = Array.from(this.healthChecks.entries()).map(
      async ([serviceName, checkFunction]) => {
        try {
          const result = await Promise.race([
            checkFunction(),
            this.createTimeoutPromise(5000), // 5秒超时
          ]);
          services[serviceName] = {
            ...result,
            lastCheck: new Date().toISOString(),
          };
        } catch (error) {
          services[serviceName] = {
            status: HealthStatus.UNHEALTHY,
            error: error instanceof Error ? error.message : 'Unknown error',
            lastCheck: new Date().toISOString(),
          };
        }
      },
    );

    await Promise.all(healthCheckPromises);

    // 计算整体健康状态
    const overallStatus = this.calculateOverallStatus(services);

    const healthInfo: SystemHealthInfo = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: process.env['npm_package_version'] || '1.0.0',
      environment: process.env['NODE_ENV'] || 'development',
      uptime: Math.floor((Date.now() - (process.uptime() * 1000)) / 1000),
      services,
      metrics: {
        healthCheckDuration: Date.now() - startTime,
      },
    };

    this.lastHealthCheck = healthInfo;
    return healthInfo;
  }

  /**
   * 获取最后一次健康检查结果
   */
  getLastHealthCheck(): SystemHealthInfo | null {
    return this.lastHealthCheck;
  }

  /**
   * 计算整体健康状态
   */
  private calculateOverallStatus(services: { [serviceName: string]: ServiceHealthInfo }): HealthStatus {
    const statuses = Object.values(services).map(service => service.status);

    if (statuses.includes(HealthStatus.UNHEALTHY)) {
      return HealthStatus.UNHEALTHY;
    }

    if (statuses.includes(HealthStatus.DEGRADED)) {
      return HealthStatus.DEGRADED;
    }

    return HealthStatus.HEALTHY;
  }

  /**
   * 创建超时Promise
   */
  private createTimeoutPromise(timeout: number): Promise<ServiceHealthInfo> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Health check timeout after ${timeout}ms`));
      }, timeout);
    });
  }

  /**
   * 开始定期健康检查
   */
  private startPeriodicHealthCheck(): void {
    // 每30秒执行一次健康检查
    if (isTestEnv) {
      // 测试环境下不启动定时任务，避免Jest悬挂
      return;
    }
    const interval = setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        logger.error('Periodic health check failed', { error });
      }
    }, 30000);
    // 不中断事件循环且避免无用表达式告警
    const maybeUnref = (interval as any).unref;
    if (typeof maybeUnref === 'function') {
      maybeUnref.call(interval);
    }
    this.healthCheckInterval = interval;
  }

  /**
   * 停止定期健康检查
   */
  stopPeriodicHealthCheck(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  /**
   * 检查特定服务的健康状态
   */
  async checkServiceHealth(serviceName: string): Promise<ServiceHealthInfo | null> {
    const checkFunction = this.healthChecks.get(serviceName);
    if (!checkFunction) {
      return null;
    }

    try {
      const result = await checkFunction();
      return {
        ...result,
        lastCheck: new Date().toISOString(),
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Unknown error',
        lastCheck: new Date().toISOString(),
      };
    }
  }

  /**
   * 获取系统健康状态（别名方法）
   */
  async getSystemHealth(): Promise<SystemHealthInfo> {
    return this.performHealthCheck();
  }

  /**
    * 获取简单健康状态
    */
  async getSimpleHealth(): Promise<{ status: string; timestamp: string }> {
    const health = await this.performHealthCheck();
    return {
      status: health.status,
      timestamp: health.timestamp,
    };
  }

  /**
    * 获取就绪状态
    */
  async getReadinessStatus(): Promise<SystemHealthInfo> {
    return this.performHealthCheck();
  }

  /**
   * 获取存活状态
   */
  async getLivenessStatus(): Promise<{ status: string; timestamp: string; uptime: number }> {
    return {
      status: HealthStatus.HEALTHY,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }

  /**
   * 获取系统信息
   */
  getSystemInfo(): any {
    return {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      pid: process.pid,
      ppid: process.ppid,
      cwd: process.cwd(),
      execPath: process.execPath,
      version: process.env['npm_package_version'] || '1.0.0',
    };
  }

  /**
   * 初始化健康检查服务
   */
  async initialize(): Promise<void> {
    logger.info('Initializing health service...');
    // 执行初始健康检查
    await this.performHealthCheck();
    logger.info('Health service initialized successfully');
  }

  /**
   * 清理健康检查服务
   */
  async cleanup(): Promise<void> {
    logger.info('Cleaning up health service...');
    this.stopPeriodicHealthCheck();
    this.healthChecks.clear();
    this.lastHealthCheck = null;
    logger.info('Health service cleaned up successfully');
  }
}

// 导出单例实例
export const healthService = new HealthService();
export default healthService;
