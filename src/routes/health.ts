import { Router, Request, Response } from 'express';
// import { config } from '../config/config';
import { logger } from '../utils/logger';
import { healthService } from '../services/healthService';
import { HealthStatus as HealthStatusEnum } from '../services/healthService';
import pool from '../config/database';
import { getRedisClient } from '../config/redis';
// import redisMock from '../utils/redis-mock';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

const router = Router();

interface HealthCheckResult {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  version: string;
  environment: string;
  uptime: number;
  services: {
    database: ServiceHealth;
    redis: ServiceHealth;
    filesystem: ServiceHealth;
    memory: ServiceHealth;
    cpu: ServiceHealth;
  };
  metrics: {
    totalRequests: number;
    activeConnections: number;
    responseTime: number;
    errorRate: number;
  };
}

interface ServiceHealth {
  status: 'healthy' | 'unhealthy' | 'degraded';
  responseTime?: number;
  error?: string;
  details?: any;
}

// 全局指标存储
const globalMetrics = {
  totalRequests: 0,
  activeConnections: 0,
  totalErrors: 0,
  startTime: Date.now(),
};

// 更新请求计数
const updateMetrics = {
  incrementRequests: () => globalMetrics.totalRequests++,
  incrementErrors: () => globalMetrics.totalErrors++,
  setActiveConnections: (count: number) => globalMetrics.activeConnections = count,
};

// 检查数据库健康状态
async function checkDatabaseHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();

  try {
    // 测试数据库连接
    const result = await pool.raw('SELECT 1 as health_check, NOW() as current_time');
    const responseTime = Date.now() - startTime;

    if (result.rows && result.rows.length > 0) {
      return {
        status: responseTime < 1000 ? 'healthy' : 'degraded',
        responseTime,
        details: {
          connected: true,
          serverTime: result.rows[0].current_time,
        },
      };
    } else {
      return {
        status: 'unhealthy',
        responseTime,
        error: 'Database query returned no results',
      };
    }
  } catch (error) {
    return {
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown database error',
    };
  }
}

// 检查 Redis 健康状态
async function checkRedisHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();

  try {
    const redisClient = getRedisClient();
    // 测试 Redis 连接
    const testKey = `health_check_${Date.now()}`;
    const testValue = 'ok';

    await redisClient.set(testKey, testValue, 'EX', 10); // 10秒过期
    const result = await redisClient.get(testKey);
    await redisClient.del(testKey);

    const responseTime = Date.now() - startTime;

    if (result === testValue) {
      return {
        status: responseTime < 500 ? 'healthy' : 'degraded',
        responseTime,
        details: {
          connected: true,
          keyspace: await redisClient.info('keyspace'),
        },
      };
    } else {
      return {
        status: 'unhealthy',
        responseTime,
        error: 'Redis test key-value operation failed',
      };
    }
  } catch (error) {
    return {
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown Redis error',
    };
  }
}

// 检查文件系统健康状态
async function checkFilesystemHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();

  try {
    const tempDir = os.tmpdir();
    const testFile = path.join(tempDir, `health_check_${Date.now()}.tmp`);
    const testContent = 'health check test';

    // 写入测试文件
    await fs.writeFile(testFile, testContent);

    // 读取测试文件
    const readContent = await fs.readFile(testFile, 'utf8');

    // 删除测试文件
    await fs.unlink(testFile);

    const responseTime = Date.now() - startTime;

    if (readContent === testContent) {
      // 获取磁盘使用情况
      await fs.stat(tempDir);

      return {
        status: responseTime < 100 ? 'healthy' : 'degraded',
        responseTime,
        details: {
          tempDir,
          writable: true,
          readable: true,
        },
      };
    } else {
      return {
        status: 'unhealthy',
        responseTime,
        error: 'Filesystem read/write test failed',
      };
    }
  } catch (error) {
    return {
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown filesystem error',
    };
  }
}

// 检查内存使用情况
function checkMemoryHealth(): ServiceHealth {
  const memUsage = process.memoryUsage();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = (usedMem / totalMem) * 100;

  let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';

  if (memUsagePercent > 90) {
    status = 'unhealthy';
  } else if (memUsagePercent > 80) {
    status = 'degraded';
  }

  return {
    status,
    details: {
      rss: Math.round(memUsage.rss / 1024 / 1024), // MB
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
      external: Math.round(memUsage.external / 1024 / 1024), // MB
      systemTotal: Math.round(totalMem / 1024 / 1024), // MB
      systemFree: Math.round(freeMem / 1024 / 1024), // MB
      systemUsagePercent: Math.round(memUsagePercent * 100) / 100,
    },
  };
}

// 检查 CPU 使用情况
function checkCpuHealth(): ServiceHealth {
  const cpus = os.cpus();
  const loadAvg = os.loadavg();

  // 计算 CPU 使用率（简化版本）
  const load1min = loadAvg[0];
  const cpuCount = cpus.length;
  const cpuUsagePercent = load1min ? (load1min / cpuCount) * 100 : 0;

  let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';

  if (cpuUsagePercent > 90) {
    status = 'unhealthy';
  } else if (cpuUsagePercent > 80) {
    status = 'degraded';
  }

  return {
    status,
    details: {
      cores: cpuCount,
      model: cpus[0]?.model || 'Unknown',
      loadAverage: {
        '1min': Math.round((loadAvg[0] || 0) * 100) / 100,
        '5min': Math.round((loadAvg[1] || 0) * 100) / 100,
        '15min': Math.round((loadAvg[2] || 0) * 100) / 100,
      },
      usagePercent: Math.round(cpuUsagePercent * 100) / 100,
    },
  };
}

// 计算整体健康状态
function calculateOverallStatus(services: HealthCheckResult['services']): 'healthy' | 'unhealthy' | 'degraded' {
  const statuses = Object.values(services).map(service => service.status);

  if (statuses.includes('unhealthy')) {
    return 'unhealthy';
  }

  if (statuses.includes('degraded')) {
    return 'degraded';
  }

  return 'healthy';
}

// 详细健康检查
router.get('/', async (_req: Request, res: Response) => {
  try {
    const healthData = await healthService.getSystemHealth();

    const statusCode = healthData.status === HealthStatusEnum.HEALTHY ? 200 :
      healthData.status === HealthStatusEnum.DEGRADED ? 200 : 503;

    res.status(statusCode).json({
      success: healthData.status !== HealthStatusEnum.UNHEALTHY,
      data: healthData,
      message: healthData.status === HealthStatusEnum.HEALTHY ? '服务运行正常' :
        healthData.status === HealthStatusEnum.DEGRADED ? '服务运行降级' : '服务异常',
    });
  } catch (error) {
    logger.error('Health check failed', { error });
    res.status(500).json({
      success: false,
      error: 'Health check failed',
      message: '健康检查失败',
    });
  }
});

// 基础健康检查端点（保留原有逻辑）
router.get('/detailed', async (_req: Request, res: Response) => {
  try {
    const startTime = Date.now();

    // 并行检查所有服务
    const [database, redis, filesystem] = await Promise.all([
      checkDatabaseHealth(),
      checkRedisHealth(),
      checkFilesystemHealth(),
    ]);

    const memory = checkMemoryHealth();
    const cpu = checkCpuHealth();

    const services = { database, redis, filesystem, memory, cpu };
    const overallStatus = calculateOverallStatus(services);

    // 计算指标
    const uptime = Math.floor((Date.now() - globalMetrics.startTime) / 1000);
    const errorRate = globalMetrics.totalRequests > 0
      ? (globalMetrics.totalErrors / globalMetrics.totalRequests) * 100
      : 0;

    const healthStatus: HealthCheckResult = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: process.env['APP_VERSION'] || '1.0.0',
      environment: process.env['NODE_ENV'] || 'development',
      uptime,
      services,
      metrics: {
        totalRequests: globalMetrics.totalRequests,
        activeConnections: globalMetrics.activeConnections,
        responseTime: Date.now() - startTime,
        errorRate: Math.round(errorRate * 100) / 100,
      },
    };

    // 根据健康状态设置 HTTP 状态码
    const httpStatus = overallStatus === 'healthy' ? 200 :
      overallStatus === 'degraded' ? 200 : 503;

    res.status(httpStatus).json({
      code: httpStatus,
      message: `System is ${overallStatus}`,
      data: healthStatus,
    });

  } catch (error) {
    res.status(503).json({
      code: 503,
      message: 'Health check failed',
      data: {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      },
    });
  }
});

// 简化健康检查
router.get('/simple', async (_req: Request, res: Response) => {
  try {
    const healthData = await healthService.getSimpleHealth();

    const statusCode = healthData.status === HealthStatusEnum.HEALTHY ? 200 : 503;

    res.status(statusCode).json({
      status: healthData.status,
      timestamp: healthData.timestamp,
    });
  } catch (error) {
    logger.error('Simple health check failed', { error });
    res.status(500).json({
      status: HealthStatusEnum.UNHEALTHY,
      timestamp: new Date().toISOString(),
    });
  }
});

// 简化的健康检查端点（用于负载均衡器）
router.get('/simple-legacy', async (_req: Request, res: Response) => {
  try {
    const healthData = await healthService.getSystemHealth();
    const dbComponent = healthData.services['database'];
    const redisComponent = healthData.services['redis'];

    const isHealthy =
      dbComponent?.status === 'healthy' &&
      redisComponent?.status === 'healthy';

    if (isHealthy) {
      res.status(200).json({ status: 'ok' });
    } else {
      res.status(503).json({ status: 'error' });
    }
  } catch (error) {
    res.status(503).json({ status: 'error' });
  }
});

// 就绪检查（Kubernetes readiness probe）
router.get('/ready', async (_req: Request, res: Response) => {
  try {
    const readinessData = await healthService.getReadinessStatus();

    const statusCode = readinessData.status === 'healthy' ? 200 : 503;

    res.status(statusCode).json(readinessData);
  } catch (error) {
    logger.error('Readiness check failed', { error });
    res.status(503).json({
      ready: false,
      components: ['system'],
    });
  }
});

// 就绪检查端点（用于 Kubernetes）
router.get('/ready-legacy', async (_req: Request, res: Response) => {
  try {
    const readinessData = await healthService.getLastHealthCheck();
    const statusCode = readinessData?.status === 'healthy' ? 200 : 503;

    res.status(statusCode).json({
      status: readinessData?.status === 'healthy' ? 'ready' : 'not ready',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'not ready',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });
  }
});

// 存活检查（Kubernetes liveness probe）
router.get('/live', async (_req: Request, res: Response) => {
  try {
    const livenessData = await healthService.getLivenessStatus();

    const statusCode = livenessData.status === 'healthy' ? 200 : 503;

    res.status(statusCode).json(livenessData);
  } catch (error) {
    logger.error('Liveness check failed', { error });
    res.status(503).json({
      alive: false,
    });
  }
});

// 存活检查端点（用于 Kubernetes）
router.get('/live-legacy', (_req: Request, res: Response) => {
  // 简单的存活检查，只要进程在运行就返回成功
  res.status(200).json({ status: 'alive' });
});

// 系统信息
router.get('/info', (_req: Request, res: Response) => {
  try {
    const systemInfo = healthService.getSystemInfo();

    res.status(200).json({
      success: true,
      data: systemInfo,
      message: '系统信息获取成功',
    });
  } catch (error) {
    logger.error('System info check failed', { error });
    res.status(500).json({
      success: false,
      error: 'System info check failed',
      message: '系统信息获取失败',
    });
  }
});

// 详细的系统信息端点
router.get('/info-legacy', (_req: Request, res: Response) => {
  const systemInfo = {
    node: {
      version: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
      uptime: process.uptime(),
    },
    os: {
      type: os.type(),
      release: os.release(),
      hostname: os.hostname(),
      totalmem: os.totalmem(),
      freemem: os.freemem(),
      cpus: os.cpus().length,
    },
    app: {
      name: process.env['APP_NAME'] || 'SmellPin',
      version: process.env['APP_VERSION'] || '1.0.0',
      environment: process.env['NODE_ENV'] || 'development',
      port: process.env['PORT'] || 3000,
    },
  };

  res.json({
    code: 200,
    message: 'System information',
    data: systemInfo,
  });
});

// 数据库连接检查
router.get('/db', async (_req: Request, res: Response) => {
  try {
    const healthData = await healthService.getSystemHealth();
    const dbComponent = healthData.services['database'];

    const statusCode = dbComponent?.status === HealthStatusEnum.HEALTHY ? 200 :
      dbComponent?.status === HealthStatusEnum.DEGRADED ? 200 : 503;

    res.status(statusCode).json({
      success: dbComponent?.status !== HealthStatusEnum.UNHEALTHY,
      data: healthData,
      message: dbComponent?.status === HealthStatusEnum.HEALTHY ? '数据库连接正常' :
        dbComponent?.status === HealthStatusEnum.DEGRADED ? '数据库连接降级' : '数据库连接异常',
    });
  } catch (error) {
    logger.error('Database health check failed', { error });
    res.status(500).json({
      success: false,
      error: 'Database health check failed',
      message: '数据库健康检查失败',
    });
  }
});

// Redis连接检查
router.get('/redis', async (_req: Request, res: Response) => {
  try {
    const healthData = await healthService.getSystemHealth();
    const redisComponent = healthData.services['redis'];

    const statusCode = redisComponent?.status === HealthStatusEnum.HEALTHY ? 200 :
      redisComponent?.status === HealthStatusEnum.DEGRADED ? 200 : 503;

    res.status(statusCode).json({
      success: redisComponent?.status !== HealthStatusEnum.UNHEALTHY,
      data: healthData,
      message: redisComponent?.status === HealthStatusEnum.HEALTHY ? 'Redis连接正常' :
        redisComponent?.status === HealthStatusEnum.DEGRADED ? 'Redis连接降级' : 'Redis连接异常',
    });
  } catch (error) {
    logger.error('Redis health check failed', { error });
    res.status(500).json({
      success: false,
      error: 'Redis health check failed',
      message: 'Redis健康检查失败',
    });
  }
});

export { router as healthRouter, updateMetrics };
