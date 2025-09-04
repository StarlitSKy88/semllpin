import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { getRedisClient } from '../config/redis';
import cluster from 'cluster';
import os from 'os';

interface ConcurrencyConfig {
  maxConcurrentRequests: number;
  queueTimeout: number;
  priorityRoutes: string[];
  adaptiveScaling: boolean;
  circuitBreaker: {
    enabled: boolean;
    errorThreshold: number;
    timeout: number;
  };
}

interface RequestStats {
  activeRequests: number;
  queuedRequests: number;
  completedRequests: number;
  errorRate: number;
  avgResponseTime: number;
  peakConcurrency: number;
}

export class ConcurrencyOptimizer {
  private config: ConcurrencyConfig;
  private activeRequests = new Set<string>();
  private requestQueue: Array<{
    req: Request;
    res: Response;
    next: NextFunction;
    priority: number;
    timestamp: number;
  }> = [];
  private stats: RequestStats = {
    activeRequests: 0,
    queuedRequests: 0,
    completedRequests: 0,
    errorRate: 0,
    avgResponseTime: 0,
    peakConcurrency: 0,
  };
  private circuitBreakerState: 'closed' | 'open' | 'half-open' = 'closed';
  private circuitBreakerErrors = 0;
  private circuitBreakerLastError = 0;
  private redis = getRedisClient();

  constructor(config: Partial<ConcurrencyConfig> = {}) {
    this.config = {
      maxConcurrentRequests: config.maxConcurrentRequests || os.cpus().length * 4,
      queueTimeout: config.queueTimeout || 30000, // 30秒
      priorityRoutes: config.priorityRoutes || ['/api/v1/health', '/api/v1/auth'],
      adaptiveScaling: config.adaptiveScaling !== false,
      circuitBreaker: {
        enabled: config.circuitBreaker?.enabled !== false,
        errorThreshold: config.circuitBreaker?.errorThreshold || 0.5,
        timeout: config.circuitBreaker?.timeout || 60000,
      },
    };

    // 启动后台处理队列
    this.processQueue();
    
    // 定期统计报告
    if (cluster.isMaster || !cluster.worker) {
      setInterval(() => this.logStats(), 60000); // 每分钟记录统计
    }
  }

  // 获取请求优先级
  private getRequestPriority(req: Request): number {
    const path = req.path;
    const method = req.method;
    
    // 健康检查最高优先级
    if (path === '/api/v1/health') return 10;
    
    // 认证相关高优先级
    if (this.config.priorityRoutes.some(route => path.startsWith(route))) return 8;
    
    // GET请求中等优先级
    if (method === 'GET') return 5;
    
    // POST/PUT/DELETE低优先级
    if (['POST', 'PUT', 'DELETE'].includes(method)) return 3;
    
    // 默认优先级
    return 1;
  }

  // 检查熔断器状态
  private checkCircuitBreaker(): boolean {
    if (!this.config.circuitBreaker.enabled) return true;
    
    const now = Date.now();
    
    switch (this.circuitBreakerState) {
      case 'closed':
        return true;
        
      case 'open':
        // 检查是否应该转换到半开状态
        if (now - this.circuitBreakerLastError > this.config.circuitBreaker.timeout) {
          this.circuitBreakerState = 'half-open';
          logger.info('Circuit breaker moved to half-open state');
          return true;
        }
        return false;
        
      case 'half-open':
        return true;
        
      default:
        return true;
    }
  }

  // 记录请求结果
  private recordRequestResult(success: boolean, responseTime: number): void {
    this.stats.completedRequests++;
    
    // 更新平均响应时间
    this.stats.avgResponseTime = 
      (this.stats.avgResponseTime * (this.stats.completedRequests - 1) + responseTime) / 
      this.stats.completedRequests;
    
    if (!success) {
      this.circuitBreakerErrors++;
      this.circuitBreakerLastError = Date.now();
      
      // 计算错误率
      const recentRequests = Math.min(this.stats.completedRequests, 100); // 最近100个请求
      this.stats.errorRate = this.circuitBreakerErrors / recentRequests;
      
      // 检查是否应该打开熔断器
      if (this.config.circuitBreaker.enabled && 
          this.stats.errorRate > this.config.circuitBreaker.errorThreshold &&
          this.circuitBreakerState === 'closed') {
        this.circuitBreakerState = 'open';
        logger.error('Circuit breaker opened due to high error rate', {
          errorRate: this.stats.errorRate,
          threshold: this.config.circuitBreaker.errorThreshold,
        });
      }
    } else if (this.circuitBreakerState === 'half-open') {
      // 半开状态下成功请求，转换为关闭状态
      this.circuitBreakerState = 'closed';
      this.circuitBreakerErrors = Math.max(0, this.circuitBreakerErrors - 1);
      logger.info('Circuit breaker closed after successful request');
    }
  }

  // 自适应调整并发限制
  private adaptiveConcurrencyAdjustment(): void {
    if (!this.config.adaptiveScaling) return;
    
    const { avgResponseTime, errorRate, activeRequests } = this.stats;
    const utilizationRatio = activeRequests / this.config.maxConcurrentRequests;
    
    // 如果响应时间过长或错误率过高，降低并发限制
    if (avgResponseTime > 5000 || errorRate > 0.1) {
      this.config.maxConcurrentRequests = Math.max(1, 
        Math.floor(this.config.maxConcurrentRequests * 0.8));
      logger.warn('Reducing concurrent requests due to performance issues', {
        newLimit: this.config.maxConcurrentRequests,
        avgResponseTime,
        errorRate,
      });
    }
    // 如果性能良好且利用率高，增加并发限制
    else if (avgResponseTime < 1000 && errorRate < 0.01 && utilizationRatio > 0.8) {
      this.config.maxConcurrentRequests = Math.min(
        os.cpus().length * 8, // 最大不超过CPU数量的8倍
        Math.floor(this.config.maxConcurrentRequests * 1.2)
      );
      logger.info('Increasing concurrent requests due to good performance', {
        newLimit: this.config.maxConcurrentRequests,
        avgResponseTime,
        errorRate,
      });
    }
  }

  // 处理请求队列
  private async processQueue(): Promise<void> {
    setInterval(async () => {
      const now = Date.now();
      
      // 清理超时的队列请求
      const originalLength = this.requestQueue.length;
      this.requestQueue = this.requestQueue.filter(item => {
        if (now - item.timestamp > this.config.queueTimeout) {
          item.res.status(503).json({
            success: false,
            error: {
              code: 'QUEUE_TIMEOUT',
              message: 'Request timed out in queue',
            },
          });
          return false;
        }
        return true;
      });
      
      const timeoutCount = originalLength - this.requestQueue.length;
      if (timeoutCount > 0) {
        logger.warn(`Cleaned up ${timeoutCount} timed out requests from queue`);
      }
      
      // 处理队列中的请求
      while (this.requestQueue.length > 0 && 
             this.activeRequests.size < this.config.maxConcurrentRequests &&
             this.checkCircuitBreaker()) {
        
        // 按优先级排序
        this.requestQueue.sort((a, b) => b.priority - a.priority);
        
        const item = this.requestQueue.shift();
        if (!item) break;
        
        await this.executeRequest(item.req, item.res, item.next);
      }
      
      // 自适应调整
      this.adaptiveConcurrencyAdjustment();
      
    }, 100); // 每100ms处理一次队列
  }

  // 执行请求
  private async executeRequest(req: Request, res: Response, next: NextFunction): Promise<void> {
    const requestId = `${Date.now()}-${Math.random()}`;
    const startTime = Date.now();
    
    this.activeRequests.add(requestId);
    this.stats.activeRequests = this.activeRequests.size;
    this.stats.peakConcurrency = Math.max(this.stats.peakConcurrency, this.stats.activeRequests);
    
    // 监听响应结束
    res.on('finish', () => {
      const responseTime = Date.now() - startTime;
      const success = res.statusCode < 400;
      
      this.activeRequests.delete(requestId);
      this.stats.activeRequests = this.activeRequests.size;
      
      this.recordRequestResult(success, responseTime);
    });

    // 监听连接关闭
    req.on('close', () => {
      if (this.activeRequests.has(requestId)) {
        this.activeRequests.delete(requestId);
        this.stats.activeRequests = this.activeRequests.size;
        logger.debug('Request connection closed', { requestId });
      }
    });
    
    next();
  }

  // 记录统计信息
  private async logStats(): Promise<void> {
    const stats = {
      ...this.stats,
      queuedRequests: this.requestQueue.length,
      circuitBreakerState: this.circuitBreakerState,
      maxConcurrentRequests: this.config.maxConcurrentRequests,
    };
    
    logger.info('Concurrency stats', stats);
    
    // 将统计信息存储到Redis中供监控使用
    try {
      await this.redis.setex('concurrency:stats', 300, JSON.stringify(stats));
    } catch (error) {
      logger.error('Failed to store concurrency stats', { error: (error as Error).message });
    }
  }

  // 主中间件
  public middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      // 熔断器检查
      if (!this.checkCircuitBreaker()) {
        logger.warn('Request rejected by circuit breaker', { path: req.path });
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Service temporarily unavailable',
          },
        });
      }
      
      // 检查当前并发数
      if (this.activeRequests.size >= this.config.maxConcurrentRequests) {
        const priority = this.getRequestPriority(req);
        
        // 高优先级请求可以排队
        if (priority >= 8) {
          this.requestQueue.push({
            req,
            res,
            next,
            priority,
            timestamp: Date.now(),
          });
          
          this.stats.queuedRequests = this.requestQueue.length;
          
          logger.debug('High priority request queued', {
            path: req.path,
            priority,
            queueLength: this.requestQueue.length,
          });
          
          return Promise.resolve(); // 不调用next()，等待队列处理
        }
        
        // 低优先级请求直接拒绝
        logger.warn('Request rejected due to high concurrency', {
          path: req.path,
          activeRequests: this.activeRequests.size,
          maxConcurrent: this.config.maxConcurrentRequests,
        });
        
        return res.status(503).json({
          success: false,
          error: {
            code: 'HIGH_CONCURRENCY',
            message: 'Server is busy, please try again later',
          },
        });
      }
      
      // 直接执行请求
      await this.executeRequest(req, res, next);
    };
  }

  // 获取统计信息
  public getStats(): RequestStats & {
    queuedRequests: number;
    circuitBreakerState: string;
    maxConcurrentRequests: number;
  } {
    return {
      ...this.stats,
      queuedRequests: this.requestQueue.length,
      circuitBreakerState: this.circuitBreakerState,
      maxConcurrentRequests: this.config.maxConcurrentRequests,
    };
  }

  // 手动调整并发限制
  public adjustConcurrencyLimit(newLimit: number): void {
    this.config.maxConcurrentRequests = Math.max(1, newLimit);
    logger.info('Manually adjusted concurrency limit', {
      newLimit: this.config.maxConcurrentRequests,
    });
  }

  // 重置熔断器
  public resetCircuitBreaker(): void {
    this.circuitBreakerState = 'closed';
    this.circuitBreakerErrors = 0;
    this.circuitBreakerLastError = 0;
    logger.info('Circuit breaker manually reset');
  }

  // 清空请求队列
  public clearQueue(): void {
    const clearedCount = this.requestQueue.length;
    this.requestQueue.forEach(item => {
      item.res.status(503).json({
        success: false,
        error: {
          code: 'QUEUE_CLEARED',
          message: 'Request queue was cleared',
        },
      });
    });
    this.requestQueue = [];
    logger.info(`Cleared ${clearedCount} requests from queue`);
  }
}

// 预设配置
export const ConcurrencyPresets = {
  // 开发环境
  development: {
    maxConcurrentRequests: 10,
    queueTimeout: 10000,
    adaptiveScaling: true,
    circuitBreaker: {
      enabled: false,
      errorThreshold: 0.5,
      timeout: 60000,
    },
  },
  
  // 测试环境
  testing: {
    maxConcurrentRequests: 50,
    queueTimeout: 30000,
    adaptiveScaling: true,
    circuitBreaker: {
      enabled: true,
      errorThreshold: 0.3,
      timeout: 30000,
    },
  },
  
  // 生产环境
  production: {
    maxConcurrentRequests: os.cpus().length * 4,
    queueTimeout: 60000,
    adaptiveScaling: true,
    circuitBreaker: {
      enabled: true,
      errorThreshold: 0.1,
      timeout: 60000,
    },
  },
  
  // 高负载环境
  highLoad: {
    maxConcurrentRequests: os.cpus().length * 8,
    queueTimeout: 30000,
    adaptiveScaling: true,
    priorityRoutes: ['/api/v1/health', '/api/v1/auth', '/api/v1/annotations/nearby'],
    circuitBreaker: {
      enabled: true,
      errorThreshold: 0.2,
      timeout: 30000,
    },
  },
};

// 创建实例
export const concurrencyOptimizer = new ConcurrencyOptimizer(ConcurrencyPresets.production);
export const developmentConcurrencyOptimizer = new ConcurrencyOptimizer(ConcurrencyPresets.development);
export const testingConcurrencyOptimizer = new ConcurrencyOptimizer(ConcurrencyPresets.testing);
export const highLoadConcurrencyOptimizer = new ConcurrencyOptimizer(ConcurrencyPresets.highLoad);