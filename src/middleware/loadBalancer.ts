import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { getRedisClient } from '../config/redis';
import cluster from 'cluster';
import os from 'os';

interface WorkerStats {
  id: number;
  pid: number;
  activeRequests: number;
  totalRequests: number;
  errors: number;
  averageResponseTime: number;
  memoryUsage: number;
  cpuUsage: number;
  lastSeen: number;
}

interface LoadBalanceConfig {
  strategy: 'round-robin' | 'least-connections' | 'weighted-round-robin' | 'ip-hash' | 'random';
  healthCheckInterval: number;
  weights: Record<number, number>; // worker ID -> weight
  stickySession: boolean;
  sessionTimeout: number;
}

export class LoadBalancer {
  private config: LoadBalanceConfig;
  private workerStats: Map<number, WorkerStats> = new Map();
  private currentWorkerIndex = 0;
  private redis = getRedisClient();
  private sessionMap: Map<string, number> = new Map(); // IP -> worker ID

  constructor(config: Partial<LoadBalanceConfig> = {}) {
    this.config = {
      strategy: config.strategy || 'least-connections',
      healthCheckInterval: config.healthCheckInterval || 30000,
      weights: config.weights || {},
      stickySession: config.stickySession || false,
      sessionTimeout: config.sessionTimeout || 1800000, // 30分钟
    };

    // 只在主进程中初始化
    if (cluster.isMaster || !cluster.worker) {
      this.initializeCluster();
      this.startHealthCheck();
      this.startStatsCollection();
    }
  }

  // 初始化集群
  private initializeCluster(): void {
    if (!cluster.isMaster) return;

    const numWorkers = process.env['NODE_ENV'] === 'production' 
      ? os.cpus().length 
      : Math.min(2, os.cpus().length);

    logger.info(`Starting ${numWorkers} worker processes`);

    // 创建工作进程
    for (let i = 0; i < numWorkers; i++) {
      this.forkWorker();
    }

    // 监听工作进程退出
    cluster.on('exit', (worker, code, signal) => {
      logger.error(`Worker ${worker.process.pid} died`, { code, signal });
      
      // 从统计中移除死亡的worker
      this.workerStats.delete(worker.id);
      
      // 重启worker
      setTimeout(() => {
        logger.info('Restarting worker');
        this.forkWorker();
      }, 1000);
    });

    // 监听worker消息
    cluster.on('message', (worker, message) => {
      if (message.type === 'stats') {
        this.updateWorkerStats(worker.id, message.stats);
      }
    });
  }

  // 创建新的工作进程
  private forkWorker(): void {
    const worker = cluster.fork();
    
    // 初始化worker统计信息
    this.workerStats.set(worker.id, {
      id: worker.id,
      pid: worker.process.pid!,
      activeRequests: 0,
      totalRequests: 0,
      errors: 0,
      averageResponseTime: 0,
      memoryUsage: 0,
      cpuUsage: 0,
      lastSeen: Date.now(),
    });

    // 设置权重
    if (!this.config.weights[worker.id]) {
      this.config.weights[worker.id] = 1;
    }

    logger.info(`Worker ${worker.process.pid} started with ID ${worker.id}`);
  }

  // 更新worker统计信息
  private updateWorkerStats(workerId: number, stats: Partial<WorkerStats>): void {
    const workerStats = this.workerStats.get(workerId);
    if (workerStats) {
      Object.assign(workerStats, stats, { lastSeen: Date.now() });
    }
  }

  // 健康检查
  private startHealthCheck(): void {
    setInterval(() => {
      const now = Date.now();
      
      for (const [workerId, stats] of this.workerStats) {
        // 检查worker是否响应
        if (now - stats.lastSeen > this.config.healthCheckInterval * 2) {
          logger.warn(`Worker ${workerId} appears to be unresponsive`, {
            lastSeen: stats.lastSeen,
            pid: stats.pid,
          });
          
          // 降低权重或移除
          if (this.config.weights[workerId] > 0) {
            this.config.weights[workerId] = Math.max(0, this.config.weights[workerId] - 0.1);
          }
        } else {
          // 恢复权重
          if (this.config.weights[workerId] < 1) {
            this.config.weights[workerId] = Math.min(1, this.config.weights[workerId] + 0.1);
          }
        }
      }
      
      // 清理过期的会话映射
      this.cleanupExpiredSessions();
      
    }, this.config.healthCheckInterval);
  }

  // 统计信息收集
  private startStatsCollection(): void {
    setInterval(async () => {
      const aggregatedStats = this.getAggregatedStats();
      
      // 记录到日志
      logger.info('Load balancer stats', aggregatedStats);
      
      // 存储到Redis
      try {
        await this.redis.setex(
          'loadbalancer:stats',
          300,
          JSON.stringify(aggregatedStats)
        );
      } catch (error) {
        logger.error('Failed to store load balancer stats', {
          error: (error as Error).message,
        });
      }
    }, 60000); // 每分钟收集一次统计
  }

  // 清理过期会话
  private cleanupExpiredSessions(): void {
    const now = Date.now();
    const expiredSessions: string[] = [];
    
    for (const [sessionId, workerId] of this.sessionMap) {
      // 这里简单地基于时间清理，实际项目中可能需要更复杂的逻辑
      if (!this.workerStats.has(workerId)) {
        expiredSessions.push(sessionId);
      }
    }
    
    expiredSessions.forEach(sessionId => {
      this.sessionMap.delete(sessionId);
    });
  }

  // Round Robin策略
  private roundRobinSelect(): number | null {
    const availableWorkers = Array.from(this.workerStats.keys());
    if (availableWorkers.length === 0) return null;

    this.currentWorkerIndex = (this.currentWorkerIndex + 1) % availableWorkers.length;
    return availableWorkers[this.currentWorkerIndex];
  }

  // 最少连接策略
  private leastConnectionsSelect(): number | null {
    let selectedWorker: number | null = null;
    let minConnections = Infinity;

    for (const [workerId, stats] of this.workerStats) {
      if (this.config.weights[workerId] > 0 && stats.activeRequests < minConnections) {
        minConnections = stats.activeRequests;
        selectedWorker = workerId;
      }
    }

    return selectedWorker;
  }

  // 加权轮询策略
  private weightedRoundRobinSelect(): number | null {
    const workers = Array.from(this.workerStats.entries());
    if (workers.length === 0) return null;

    // 简单的加权轮询实现
    const totalWeight = workers.reduce((sum, [id]) => sum + (this.config.weights[id] || 0), 0);
    if (totalWeight === 0) return null;

    let randomWeight = Math.random() * totalWeight;
    
    for (const [workerId, stats] of workers) {
      randomWeight -= this.config.weights[workerId] || 0;
      if (randomWeight <= 0) {
        return workerId;
      }
    }

    return workers[0][0]; // fallback
  }

  // IP哈希策略
  private ipHashSelect(ip: string): number | null {
    const availableWorkers = Array.from(this.workerStats.keys());
    if (availableWorkers.length === 0) return null;

    // 简单哈希函数
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      const char = ip.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // 转换为32位整数
    }

    const index = Math.abs(hash) % availableWorkers.length;
    return availableWorkers[index];
  }

  // 随机策略
  private randomSelect(): number | null {
    const availableWorkers = Array.from(this.workerStats.keys()).filter(
      id => this.config.weights[id] > 0
    );
    
    if (availableWorkers.length === 0) return null;
    
    const randomIndex = Math.floor(Math.random() * availableWorkers.length);
    return availableWorkers[randomIndex];
  }

  // 选择worker
  private selectWorker(req: Request): number | null {
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    
    // 检查粘性会话
    if (this.config.stickySession && this.sessionMap.has(clientIp)) {
      const workerId = this.sessionMap.get(clientIp)!;
      if (this.workerStats.has(workerId) && this.config.weights[workerId] > 0) {
        return workerId;
      } else {
        // 清理无效会话
        this.sessionMap.delete(clientIp);
      }
    }

    // 根据策略选择worker
    let selectedWorker: number | null = null;
    
    switch (this.config.strategy) {
      case 'round-robin':
        selectedWorker = this.roundRobinSelect();
        break;
      case 'least-connections':
        selectedWorker = this.leastConnectionsSelect();
        break;
      case 'weighted-round-robin':
        selectedWorker = this.weightedRoundRobinSelect();
        break;
      case 'ip-hash':
        selectedWorker = this.ipHashSelect(clientIp);
        break;
      case 'random':
        selectedWorker = this.randomSelect();
        break;
      default:
        selectedWorker = this.leastConnectionsSelect();
    }

    // 设置粘性会话
    if (selectedWorker && this.config.stickySession) {
      this.sessionMap.set(clientIp, selectedWorker);
    }

    return selectedWorker;
  }

  // 获取聚合统计信息
  private getAggregatedStats() {
    const stats = Array.from(this.workerStats.values());
    
    return {
      totalWorkers: stats.length,
      totalActiveRequests: stats.reduce((sum, s) => sum + s.activeRequests, 0),
      totalRequests: stats.reduce((sum, s) => sum + s.totalRequests, 0),
      totalErrors: stats.reduce((sum, s) => sum + s.errors, 0),
      averageResponseTime: stats.length > 0 
        ? stats.reduce((sum, s) => sum + s.averageResponseTime, 0) / stats.length 
        : 0,
      averageMemoryUsage: stats.length > 0
        ? stats.reduce((sum, s) => sum + s.memoryUsage, 0) / stats.length 
        : 0,
      averageCpuUsage: stats.length > 0
        ? stats.reduce((sum, s) => sum + s.cpuUsage, 0) / stats.length 
        : 0,
      activeSessions: this.sessionMap.size,
      strategy: this.config.strategy,
      workers: Object.fromEntries(
        stats.map(s => [
          s.id,
          {
            ...s,
            weight: this.config.weights[s.id] || 0,
          }
        ])
      ),
    };
  }

  // 在worker进程中报告统计信息
  public reportStats(stats: Partial<WorkerStats>): void {
    if (cluster.isWorker && process.send) {
      process.send({
        type: 'stats',
        stats: {
          ...stats,
          id: cluster.worker!.id,
          pid: process.pid,
        },
      });
    }
  }

  // 中间件（仅在主进程中使用）
  public middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // 如果不是主进程，直接通过
      if (!cluster.isMaster) {
        return next();
      }

      const startTime = Date.now();
      const selectedWorker = this.selectWorker(req);

      if (!selectedWorker) {
        logger.error('No available workers for request', {
          path: req.path,
          ip: req.ip,
        });
        
        return res.status(503).json({
          success: false,
          error: {
            code: 'NO_WORKERS_AVAILABLE',
            message: 'Service temporarily unavailable',
          },
        });
      }

      // 添加worker信息到请求头（用于调试）
      res.setHeader('X-Worker-ID', selectedWorker.toString());
      
      // 记录请求开始
      const workerStats = this.workerStats.get(selectedWorker);
      if (workerStats) {
        workerStats.activeRequests++;
        workerStats.totalRequests++;
      }

      // 监听响应结束
      res.on('finish', () => {
        const responseTime = Date.now() - startTime;
        
        if (workerStats) {
          workerStats.activeRequests--;
          
          // 更新平均响应时间
          workerStats.averageResponseTime = 
            (workerStats.averageResponseTime + responseTime) / 2;
          
          // 记录错误
          if (res.statusCode >= 400) {
            workerStats.errors++;
          }
        }
      });

      next();
    };
  }

  // 获取统计信息
  public getStats() {
    return this.getAggregatedStats();
  }

  // 手动调整worker权重
  public setWorkerWeight(workerId: number, weight: number): void {
    this.config.weights[workerId] = Math.max(0, Math.min(1, weight));
    logger.info(`Set worker ${workerId} weight to ${weight}`);
  }

  // 获取健康的workers
  public getHealthyWorkers(): number[] {
    return Array.from(this.workerStats.keys()).filter(
      id => this.config.weights[id] > 0
    );
  }

  // 手动重启worker
  public restartWorker(workerId: number): void {
    if (cluster.isMaster) {
      const worker = cluster.workers?.[workerId];
      if (worker) {
        logger.info(`Manually restarting worker ${workerId}`);
        worker.kill();
      }
    }
  }
}

// 预设配置
export const LoadBalancePresets = {
  development: {
    strategy: 'round-robin' as const,
    healthCheckInterval: 10000,
    stickySession: false,
  },
  
  production: {
    strategy: 'least-connections' as const,
    healthCheckInterval: 30000,
    stickySession: true,
    sessionTimeout: 1800000,
  },
  
  highLoad: {
    strategy: 'weighted-round-robin' as const,
    healthCheckInterval: 15000,
    stickySession: true,
    sessionTimeout: 900000,
  },
};

// 创建实例
export const loadBalancer = new LoadBalancer(
  process.env['NODE_ENV'] === 'production' 
    ? LoadBalancePresets.production 
    : LoadBalancePresets.development
);