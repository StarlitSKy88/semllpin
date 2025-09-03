import { Request, Response, NextFunction } from 'express';
import client from 'prom-client';
import { logger } from '../utils/logger';
import os from 'os';

// 在测试环境中禁用后台定时任务，避免Jest悬挂
const isTestEnv = (process.env['NODE_ENV'] === 'test') || (typeof process.env['JEST_WORKER_ID'] !== 'undefined');

// 创建默认指标收集器
const register = new client.Registry();

// 收集默认指标（内存、CPU等）
client.collectDefaultMetrics({
  register,
  prefix: 'smellpin_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});

// HTTP请求总数计数器
const httpRequestsTotal = new client.Counter({
  name: 'smellpin_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code', 'user_agent'],
  registers: [register],
});

// HTTP请求持续时间直方图
const httpRequestDuration = new client.Histogram({
  name: 'smellpin_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
  registers: [register],
});

// 活跃用户数量
const activeUsers = new client.Gauge({
  name: 'smellpin_active_users',
  help: 'Number of active users',
  registers: [register],
});

// 数据库连接数
const databaseConnections = new client.Gauge({
  name: 'smellpin_database_connections_total',
  help: 'Total number of database connections',
  labelNames: ['state'],
  registers: [register],
});

// Redis连接状态
const redisConnections = new client.Gauge({
  name: 'smellpin_redis_connections_total',
  help: 'Total number of Redis connections',
  labelNames: ['state'],
  registers: [register],
});

// 业务指标 - 标注创建数
const annotationsCreated = new client.Counter({
  name: 'smellpin_annotations_created_total',
  help: 'Total number of annotations created',
  labelNames: ['country', 'intensity_level'],
  registers: [register],
});

// 业务指标 - LBS奖励发放数
const lbsRewards = new client.Counter({
  name: 'smellpin_lbs_rewards_total',
  help: 'Total number of LBS rewards distributed',
  labelNames: ['reward_type', 'location_type'],
  registers: [register],
});

// 支付成功率
const paymentSuccess = new client.Counter({
  name: 'smellpin_payments_total',
  help: 'Total number of payment attempts',
  labelNames: ['status', 'payment_method'],
  registers: [register],
});

// WebSocket连接数
const websocketConnections = new client.Gauge({
  name: 'smellpin_websocket_connections',
  help: 'Number of active WebSocket connections',
  registers: [register],
});

// 错误率计数器
const errorRate = new client.Counter({
  name: 'smellpin_errors_total',
  help: 'Total number of errors',
  labelNames: ['error_type', 'endpoint'],
  registers: [register],
});

// 系统资源使用率
const systemResources = new client.Gauge({
  name: 'smellpin_system_resources',
  help: 'System resource usage',
  labelNames: ['resource_type'],
  registers: [register],
});

// 定期更新系统资源指标
// 仅在非测试环境中启用，避免测试用例存在未关闭的句柄
if (!isTestEnv) {
  const interval = setInterval(() => {
    try {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      const loadAvg = os.loadavg();

      // 内存使用率
      systemResources.set(
        { resource_type: 'memory_heap_used' },
        memUsage['heapUsed'] / 1024 / 1024, // MB
      );

      systemResources.set(
        { resource_type: 'memory_heap_total' },
        memUsage['heapTotal'] / 1024 / 1024, // MB
      );

      systemResources.set(
        { resource_type: 'memory_rss' },
        memUsage['rss'] / 1024 / 1024, // MB
      );

      // CPU使用率（微秒转换为百分比）
      systemResources.set(
        { resource_type: 'cpu_user' },
        cpuUsage['user'] / 1000000, // 秒
      );

      systemResources.set(
        { resource_type: 'cpu_system' },
        cpuUsage['system'] / 1000000, // 秒
      );

      // 系统负载
      systemResources.set(
        { resource_type: 'load_avg_1m' },
        loadAvg[0] || 0,
      );

      systemResources.set(
        { resource_type: 'load_avg_5m' },
        loadAvg[1] || 0,
      );

      systemResources.set(
        { resource_type: 'load_avg_15m' },
        loadAvg[2] || 0,
      );

    } catch (error) {
      logger.error('更新系统资源指标失败:', error);
    }
  }, 30000); // 每30秒更新一次
  // 不阻塞事件循环
  // @ts-ignore
  interval.unref && interval.unref();
}

// Prometheus监控中间件
export const prometheusMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();

  // 记录请求开始时间
  res.locals['startTime'] = startTime;

  // 监听响应结束事件
  res.on('finish', () => {
    try {
      const duration = (Date.now() - startTime) / 1000;
      const route = req.route?.path || req.path || 'unknown';
      const method = req.method;
      const statusCode = res.statusCode.toString();
      const userAgent = req.get('User-Agent') || 'unknown';

      // 记录HTTP请求指标
      httpRequestsTotal.inc({
        method,
        route,
        status_code: statusCode,
        user_agent: userAgent.substring(0, 50), // 限制长度
      });

      httpRequestDuration.observe(
        { method, route, status_code: statusCode },
        duration,
      );

      // 记录错误
      if (res.statusCode >= 400) {
        const errorType = res.statusCode >= 500 ? 'server_error' : 'client_error';
        errorRate.inc({
          error_type: errorType,
          endpoint: route,
        });
      }

    } catch (error) {
      logger.error('Prometheus指标记录失败:', error);
    }
  });

  next();
};

// 获取指标数据的端点处理器
export const metricsHandler = async (_req: Request, res: Response) => {
  try {
    res.set('Content-Type', register.contentType);
    const metrics = await register.metrics();
    res.end(metrics);
  } catch (error) {
    logger.error('获取Prometheus指标失败:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'METRICS_ERROR',
        message: '获取监控指标失败',
      },
    });
  }
};

// 导出指标对象供其他模块使用
export const metrics = {
  httpRequestsTotal,
  httpRequestDuration,
  activeUsers,
  databaseConnections,
  redisConnections,
  annotationsCreated,
  lbsRewards,
  paymentSuccess,
  websocketConnections,
  errorRate,
  systemResources,
  register,
};

// 业务指标记录函数
export const recordBusinessMetrics = {
  // 记录标注创建
  annotationCreated: (country: string, intensityLevel: string) => {
    annotationsCreated.inc({ country, intensity_level: intensityLevel });
  },

  // 记录LBS奖励
  lbsReward: (rewardType: string, locationType: string) => {
    lbsRewards.inc({ reward_type: rewardType, location_type: locationType });
  },

  // 记录支付结果
  payment: (status: 'success' | 'failed', paymentMethod: string) => {
    paymentSuccess.inc({ status, payment_method: paymentMethod });
  },

  // 更新活跃用户数
  updateActiveUsers: (count: number) => {
    activeUsers.set(count);
  },

  // 更新WebSocket连接数
  updateWebSocketConnections: (count: number) => {
    websocketConnections.set(count);
  },

  // 更新数据库连接数
  updateDatabaseConnections: (active: number, idle: number, waiting: number) => {
    databaseConnections.set({ state: 'active' }, active);
    databaseConnections.set({ state: 'idle' }, idle);
    databaseConnections.set({ state: 'waiting' }, waiting);
  },

  // 更新Redis连接状态
  updateRedisConnections: (connected: number, disconnected: number) => {
    redisConnections.set({ state: 'connected' }, connected);
    redisConnections.set({ state: 'disconnected' }, disconnected);
  },
};

export default {
  prometheusMiddleware,
  metricsHandler,
  metrics,
  recordBusinessMetrics,
};
