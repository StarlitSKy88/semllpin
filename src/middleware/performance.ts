import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
// import { db } from '@/config/database';
// import Redis from 'ioredis';

// 性能监控中间件
export interface PerformanceMetrics {
  requestId: string;
  method: string;
  url: string;
  statusCode: number;
  responseTime: number;
  memoryUsage: NodeJS.MemoryUsage;
  timestamp: Date;
  userAgent?: string;
  ip?: string;
}

// 内存中存储最近的性能指标
const recentMetrics: PerformanceMetrics[] = [];
const MAX_METRICS_HISTORY = 1000;

// 性能监控中间件
export const performanceMonitor = (req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  // 添加请求ID到请求对象
  (req as any).requestId = requestId;

  // 监听响应结束事件
  res.on('finish', () => {
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    const memoryUsage = process.memoryUsage();

    const userAgent = req.get('User-Agent');
    const clientIp = req.ip || req.connection.remoteAddress;

    const metrics: PerformanceMetrics = {
      requestId,
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      responseTime,
      memoryUsage,
      timestamp: new Date(),
      ...(userAgent && { userAgent }),
      ...(clientIp && { ip: clientIp }),
    };

    // 记录到内存
    recentMetrics.push(metrics);
    if (recentMetrics.length > MAX_METRICS_HISTORY) {
      recentMetrics.shift();
    }

    // 记录慢查询
    if (responseTime > 1000) {
      logger.warn('Slow API request detected', {
        requestId,
        method: req.method,
        url: req.originalUrl,
        responseTime,
        statusCode: res.statusCode,
      });
    }

    // 记录错误响应
    if (res.statusCode >= 400) {
      logger.error('API error response', {
        requestId,
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        responseTime,
      });
    }

    // 记录性能指标到日志
    logger.info('API request completed', {
      requestId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      responseTime,
      memoryUsage: {
        rss: Math.round(memoryUsage.rss / 1024 / 1024), // MB
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
      },
    });
  });

  next();
};

// 获取性能统计
export const getPerformanceStats = () => {
  const now = Date.now();
  const last5Minutes = recentMetrics.filter(m => now - m.timestamp.getTime() < 5 * 60 * 1000);
  const last1Hour = recentMetrics.filter(m => now - m.timestamp.getTime() < 60 * 60 * 1000);

  const calculateStats = (metrics: PerformanceMetrics[]) => {
    if (metrics.length === 0) {
      return {
        count: 0,
        avgResponseTime: 0,
        minResponseTime: 0,
        maxResponseTime: 0,
        errorRate: 0,
        avgMemoryUsage: 0,
      };
    }

    const responseTimes = metrics.map(m => m.responseTime);
    const errors = metrics.filter(m => m.statusCode >= 400);
    const memoryUsages = metrics.map(m => m.memoryUsage.heapUsed);

    return {
      count: metrics.length,
      avgResponseTime: Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length),
      minResponseTime: Math.min(...responseTimes),
      maxResponseTime: Math.max(...responseTimes),
      errorRate: Math.round((errors.length / metrics.length) * 100 * 100) / 100,
      avgMemoryUsage: Math.round(memoryUsages.reduce((a, b) => a + b, 0) / memoryUsages.length / 1024 / 1024),
    };
  };

  return {
    last5Minutes: calculateStats(last5Minutes),
    last1Hour: calculateStats(last1Hour),
    total: calculateStats(recentMetrics),
    slowestEndpoints: recentMetrics
      .sort((a, b) => b.responseTime - a.responseTime)
      .slice(0, 10)
      .map(m => ({
        url: m.url,
        method: m.method,
        responseTime: m.responseTime,
        timestamp: m.timestamp,
      })),
  };
};

// 缓存中间件
export const cacheMiddleware = (ttlSeconds: number = 300) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // 只缓存GET请求
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = `cache:${req.originalUrl || req.url}:${JSON.stringify(req.query)}`;

    try {
      // 这里应该使用Redis，但为了兼容性，我们使用内存缓存
      const cached = (global as any).cache?.[cacheKey];

      if (cached && Date.now() - cached.timestamp < ttlSeconds * 1000) {
        logger.info('Cache hit', { url: req.originalUrl, cacheKey });
        return res.json(cached.data);
      }

      // 重写res.json以缓存响应
      const originalJson = res.json;
      res.json = function (data: any) {
        // 只缓存成功响应
        if (res.statusCode === 200) {
          if (!(global as any).cache) {
            (global as any).cache = {};
          }
          (global as any).cache[cacheKey] = {
            data,
            timestamp: Date.now(),
          };
          logger.info('Response cached', { url: req.originalUrl, cacheKey });
        }
        return originalJson.call(this, data);
      };

      next();
    } catch (error) {
      logger.error('Cache middleware error', { error: (error as Error).message, url: req.originalUrl });
      next();
    }
  };
};

// 清理缓存
export const clearCache = (pattern?: string) => {
  if (!(global as any).cache) {
    return;
  }

  if (pattern) {
    const keys = Object.keys((global as any).cache);
    keys.forEach(key => {
      if (key.includes(pattern)) {
        delete (global as any).cache[key];
      }
    });
    logger.info('Cache cleared with pattern', { pattern });
  } else {
    (global as any).cache = {};
    logger.info('All cache cleared');
  }
};

// 数据库查询优化中间件
export const optimizeQuery = (req: Request, _res: Response, next: NextFunction) => {
  // 添加查询优化提示
  (req as any).queryHints = {
    useIndex: (tableName: string, indexName: string) => {
      return `/*+ USE_INDEX(${tableName}, ${indexName}) */`;
    },
    forceIndex: (tableName: string, indexName: string) => {
      return `/*+ FORCE_INDEX(${tableName}, ${indexName}) */`;
    },
    limit: (count: number) => {
      return Math.min(count, 100); // 限制最大查询数量
    },
  };

  next();
};

// 请求限流中间件
const requestCounts = new Map<string, { count: number; resetTime: number }>();

export const rateLimiter = (maxRequests: number = 100, windowMs: number = 60000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientId = req.ip || 'unknown';
    const now = Date.now();

    const clientData = requestCounts.get(clientId);

    if (!clientData || now > clientData.resetTime) {
      requestCounts.set(clientId, {
        count: 1,
        resetTime: now + windowMs,
      });
      return next();
    }

    if (clientData.count >= maxRequests) {
      logger.warn('Rate limit exceeded', {
        clientId,
        count: clientData.count,
        maxRequests,
      });

      return res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later',
        },
        retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
      });
    }

    clientData.count++;
    requestCounts.set(clientId, clientData);

    // 设置响应头
    res.set({
      'X-RateLimit-Limit': maxRequests.toString(),
      'X-RateLimit-Remaining': (maxRequests - clientData.count).toString(),
      'X-RateLimit-Reset': new Date(clientData.resetTime).toISOString(),
    });

    next();
  };
};

// 清理过期的限流记录
setInterval(() => {
  const now = Date.now();
  for (const [clientId, data] of requestCounts.entries()) {
    if (now > data.resetTime) {
      requestCounts.delete(clientId);
    }
  }
}, 60000); // 每分钟清理一次

// 压缩中间件配置
export const compressionConfig = {
  filter: (req: Request, _res: Response) => {
    // 不压缩图片和视频
    if (req.headers['content-type']?.startsWith('image/') ||
        req.headers['content-type']?.startsWith('video/')) {
      return false;
    }
    return true;
  },
  threshold: 1024, // 只压缩大于1KB的响应
  level: 6, // 压缩级别 (1-9)
};
