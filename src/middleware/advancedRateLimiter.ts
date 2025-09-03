import { Request, Response, NextFunction } from 'express';
import { getRedisClient } from '../config/redis';
import { logger } from '../utils/logger';
import Redis from 'ioredis';

// 限流策略枚举
export enum RateLimitStrategy {
  FIXED_WINDOW = 'fixed_window',
  SLIDING_WINDOW_LOG = 'sliding_window_log',
  SLIDING_WINDOW_COUNTER = 'sliding_window_counter',
  TOKEN_BUCKET = 'token_bucket',
  LEAKY_BUCKET = 'leaky_bucket',
}

// 限流配置接口
export interface RateLimitConfig {
  windowMs: number; // 时间窗口（毫秒）
  maxRequests: number; // 最大请求数
  strategy: RateLimitStrategy; // 限流策略
  keyGenerator?: (req: Request) => string; // 自定义键生成器
  skipSuccessfulRequests?: boolean; // 跳过成功请求
  skipFailedRequests?: boolean; // 跳过失败请求
  skipIf?: (req: Request) => boolean; // 自定义跳过条件
  onLimitReached?: (req: Request, res: Response) => void; // 达到限制时的回调
  responseHeaders?: boolean; // 是否添加响应头
  progressiveDelay?: boolean; // 渐进式延迟
  whitelist?: string[]; // IP白名单
  blacklist?: string[]; // IP黑名单
  userLimits?: Record<string, number>; // 用户特定限制
  endpointLimits?: Record<string, Partial<RateLimitConfig>>; // 端点特定限制
}

// 限流统计接口
export interface RateLimitStats {
  totalRequests: number;
  blockedRequests: number;
  blockRate: number;
  avgResponseTime: number;
  peakRequestsPerMinute: number;
  uniqueClients: number;
}

// 默认配置
const DEFAULT_CONFIG: RateLimitConfig = {
  windowMs: 60 * 1000, // 1分钟
  maxRequests: 100,
  strategy: RateLimitStrategy.SLIDING_WINDOW_COUNTER,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  responseHeaders: true,
  progressiveDelay: false,
  whitelist: [],
  blacklist: [],
  userLimits: {},
  endpointLimits: {},
};

// 高级限流器类
export class AdvancedRateLimiter {
  private config: RateLimitConfig;
  private redis: Redis;
  private stats: Map<string, RateLimitStats> = new Map();

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.redis = getRedisClient();
  }

  // 默认键生成器
  private defaultKeyGenerator(req: Request): string {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const userId = (req as any).user?.id || 'anonymous';
    const endpoint = req.route?.path || req.path;
    
    return `rate_limit:${ip}:${userId}:${endpoint}`;
  }

  // 获取限流键
  private getKey(req: Request): string {
    if (this.config.keyGenerator) {
      return this.config.keyGenerator(req);
    }
    return this.defaultKeyGenerator(req);
  }

  // 检查IP白名单/黑名单
  private checkIpAccess(req: Request): 'allow' | 'deny' | 'check' {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    
    if (this.config.blacklist?.includes(ip)) {
      return 'deny';
    }
    
    if (this.config.whitelist?.includes(ip)) {
      return 'allow';
    }
    
    return 'check';
  }

  // 获取用户特定限制
  private getUserLimit(req: Request): number {
    const userId = (req as any).user?.id;
    if (userId && this.config.userLimits?.[userId]) {
      return this.config.userLimits[userId];
    }
    return this.config.maxRequests;
  }

  // 获取端点特定配置
  private getEndpointConfig(req: Request): RateLimitConfig {
    const endpoint = req.route?.path || req.path;
    const endpointConfig = this.config.endpointLimits?.[endpoint];
    
    if (endpointConfig) {
      return { ...this.config, ...endpointConfig };
    }
    
    return this.config;
  }

  // 固定窗口限流
  private async fixedWindowLimit(
    key: string,
    maxRequests: number,
    windowMs: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const now = Date.now();
    const window = Math.floor(now / windowMs);
    const windowKey = `${key}:${window}`;

    const pipeline = this.redis.pipeline();
    pipeline.incr(windowKey);
    pipeline.expire(windowKey, Math.ceil(windowMs / 1000));
    
    const results = await pipeline.exec();
    const totalRequests = results?.[0]?.[1] as number || 0;

    const remaining = Math.max(0, maxRequests - totalRequests);
    const resetTime = (window + 1) * windowMs;

    return {
      allowed: totalRequests <= maxRequests,
      remaining,
      resetTime,
      totalRequests,
    };
  }

  // 滑动窗口计数器限流
  private async slidingWindowCounterLimit(
    key: string,
    maxRequests: number,
    windowMs: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const now = Date.now();
    const currentWindow = Math.floor(now / windowMs);
    const previousWindow = currentWindow - 1;
    const percentageInCurrent = (now % windowMs) / windowMs;

    const pipeline = this.redis.pipeline();
    pipeline.get(`${key}:${currentWindow}`);
    pipeline.get(`${key}:${previousWindow}`);
    
    const results = await pipeline.exec();
    const currentCount = parseInt(results?.[0]?.[1] as string || '0');
    const previousCount = parseInt(results?.[1]?.[1] as string || '0');

    const approximateCount = Math.floor(
      previousCount * (1 - percentageInCurrent) + currentCount
    );

    // 如果允许请求，增加计数器
    if (approximateCount < maxRequests) {
      const incrPipeline = this.redis.pipeline();
      incrPipeline.incr(`${key}:${currentWindow}`);
      incrPipeline.expire(`${key}:${currentWindow}`, Math.ceil(windowMs / 1000 * 2)); // 保存2个窗口的数据
      await incrPipeline.exec();
    }

    const remaining = Math.max(0, maxRequests - approximateCount - 1);
    const resetTime = (currentWindow + 1) * windowMs;

    return {
      allowed: approximateCount < maxRequests,
      remaining,
      resetTime,
      totalRequests: approximateCount + (approximateCount < maxRequests ? 1 : 0),
    };
  }

  // 滑动窗口日志限流
  private async slidingWindowLogLimit(
    key: string,
    maxRequests: number,
    windowMs: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const now = Date.now();
    const cutoff = now - windowMs;
    const windowKey = `${key}:log`;

    const pipeline = this.redis.pipeline();
    // 移除过期的请求记录
    pipeline.zremrangebyscore(windowKey, 0, cutoff);
    // 获取当前窗口内的请求数
    pipeline.zcard(windowKey);
    
    const results = await pipeline.exec();
    const currentCount = results?.[1]?.[1] as number || 0;

    if (currentCount < maxRequests) {
      // 添加新的请求记录
      const addPipeline = this.redis.pipeline();
      addPipeline.zadd(windowKey, now, `${now}-${Math.random()}`);
      addPipeline.expire(windowKey, Math.ceil(windowMs / 1000));
      await addPipeline.exec();
    }

    const remaining = Math.max(0, maxRequests - currentCount - (currentCount < maxRequests ? 1 : 0));
    const resetTime = now + windowMs;

    return {
      allowed: currentCount < maxRequests,
      remaining,
      resetTime,
      totalRequests: currentCount + (currentCount < maxRequests ? 1 : 0),
    };
  }

  // 令牌桶限流
  private async tokenBucketLimit(
    key: string,
    maxRequests: number,
    windowMs: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const bucketKey = `${key}:bucket`;
    const now = Date.now();
    const refillRate = maxRequests / windowMs; // 令牌/毫秒

    // 获取当前令牌数和最后更新时间
    const pipeline = this.redis.pipeline();
    pipeline.hmget(bucketKey, 'tokens', 'lastRefill');
    
    const results = await pipeline.exec();
    const data = results?.[0]?.[1] as string[] || ['0', '0'];
    
    let tokens = Math.min(parseFloat(data[0] || '0'), maxRequests);
    const lastRefill = parseInt(data[1] || '0') || now;

    // 计算应该添加的令牌数
    const timePassed = now - lastRefill;
    const tokensToAdd = timePassed * refillRate;
    tokens = Math.min(tokens + tokensToAdd, maxRequests);

    let allowed = false;
    if (tokens >= 1) {
      tokens -= 1;
      allowed = true;
    }

    // 更新令牌桶状态
    const updatePipeline = this.redis.pipeline();
    updatePipeline.hmset(bucketKey, 'tokens', tokens.toString(), 'lastRefill', now.toString());
    updatePipeline.expire(bucketKey, Math.ceil(windowMs / 1000 * 2));
    await updatePipeline.exec();

    return {
      allowed,
      remaining: Math.floor(tokens),
      resetTime: now + ((maxRequests - tokens) / refillRate),
      totalRequests: allowed ? 1 : 0,
    };
  }

  // 漏桶限流
  private async leakyBucketLimit(
    key: string,
    maxRequests: number,
    windowMs: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const bucketKey = `${key}:leaky`;
    const now = Date.now();
    const leakRate = maxRequests / windowMs; // 请求/毫秒

    // 获取当前队列长度和最后处理时间
    const pipeline = this.redis.pipeline();
    pipeline.hmget(bucketKey, 'queue', 'lastLeak');
    
    const results = await pipeline.exec();
    const data = results?.[0]?.[1] as string[] || ['0', '0'];
    
    let queueSize = parseInt(data[0] || '0');
    const lastLeak = parseInt(data[1] || '0') || now;

    // 计算漏出的请求数
    const timePassed = now - lastLeak;
    const leaked = Math.floor(timePassed * leakRate);
    queueSize = Math.max(0, queueSize - leaked);

    let allowed = false;
    if (queueSize < maxRequests) {
      queueSize += 1;
      allowed = true;
    }

    // 更新漏桶状态
    const updatePipeline = this.redis.pipeline();
    updatePipeline.hmset(bucketKey, 'queue', queueSize.toString(), 'lastLeak', now.toString());
    updatePipeline.expire(bucketKey, Math.ceil(windowMs / 1000 * 2));
    await updatePipeline.exec();

    return {
      allowed,
      remaining: Math.max(0, maxRequests - queueSize),
      resetTime: now + ((queueSize / leakRate)),
      totalRequests: queueSize,
    };
  }

  // 执行限流检查
  private async checkRateLimit(
    req: Request,
    config: RateLimitConfig
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number; totalRequests: number }> {
    const key = this.getKey(req);
    const maxRequests = this.getUserLimit(req);

    switch (config.strategy) {
      case RateLimitStrategy.FIXED_WINDOW:
        return this.fixedWindowLimit(key, maxRequests, config.windowMs);
        
      case RateLimitStrategy.SLIDING_WINDOW_LOG:
        return this.slidingWindowLogLimit(key, maxRequests, config.windowMs);
        
      case RateLimitStrategy.SLIDING_WINDOW_COUNTER:
        return this.slidingWindowCounterLimit(key, maxRequests, config.windowMs);
        
      case RateLimitStrategy.TOKEN_BUCKET:
        return this.tokenBucketLimit(key, maxRequests, config.windowMs);
        
      case RateLimitStrategy.LEAKY_BUCKET:
        return this.leakyBucketLimit(key, maxRequests, config.windowMs);
        
      default:
        return this.slidingWindowCounterLimit(key, maxRequests, config.windowMs);
    }
  }

  // 渐进式延迟
  private async applyProgressiveDelay(req: Request, totalRequests: number, maxRequests: number): Promise<void> {
    if (!this.config.progressiveDelay) return;

    const overageRatio = (totalRequests - maxRequests) / maxRequests;
    if (overageRatio > 0) {
      const delay = Math.min(overageRatio * 1000, 5000); // 最大延迟5秒
      
      logger.warn('Applying progressive delay', {
        ip: req.ip,
        delay,
        totalRequests,
        maxRequests,
      });
      
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // 更新统计信息
  private updateStats(key: string, blocked: boolean, responseTime?: number): void {
    const stats = this.stats.get(key) || {
      totalRequests: 0,
      blockedRequests: 0,
      blockRate: 0,
      avgResponseTime: 0,
      peakRequestsPerMinute: 0,
      uniqueClients: 0,
    };

    stats.totalRequests++;
    if (blocked) {
      stats.blockedRequests++;
    }
    stats.blockRate = (stats.blockedRequests / stats.totalRequests) * 100;
    
    if (responseTime) {
      stats.avgResponseTime = (stats.avgResponseTime + responseTime) / 2;
    }

    this.stats.set(key, stats);
  }

  // 主中间件
  public middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      const startTime = Date.now();
      
      try {
        // 检查跳过条件
        if (this.config.skipIf && this.config.skipIf(req)) {
          return next();
        }

        // 检查IP访问权限
        const ipAccess = this.checkIpAccess(req);
        if (ipAccess === 'deny') {
          logger.warn('IP blacklisted', { ip: req.ip, path: req.path });
          return res.status(403).json({
            success: false,
            error: {
              code: 'IP_BLACKLISTED',
              message: 'Access denied',
            },
          });
        }

        if (ipAccess === 'allow') {
          return next();
        }

        // 获取端点特定配置
        const config = this.getEndpointConfig(req);
        
        // 执行限流检查
        const result = await this.checkRateLimit(req, config);

        // 应用渐进式延迟
        if (result.totalRequests > config.maxRequests) {
          await this.applyProgressiveDelay(req, result.totalRequests, config.maxRequests);
        }

        // 设置响应头
        if (config.responseHeaders) {
          res.setHeader('X-RateLimit-Limit', config.maxRequests.toString());
          res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
          res.setHeader('X-RateLimit-Reset', new Date(result.resetTime).toISOString());
          res.setHeader('X-RateLimit-Strategy', config.strategy);
        }

        // 检查是否超过限制
        if (!result.allowed) {
          // 记录限流事件
          logger.warn('Rate limit exceeded', {
            ip: req.ip,
            path: req.path,
            totalRequests: result.totalRequests,
            limit: config.maxRequests,
            strategy: config.strategy,
          });

          // 更新统计
          this.updateStats(this.getKey(req), true);

          // 调用回调
          if (config.onLimitReached) {
            config.onLimitReached(req, res);
          }

          const retryAfter = Math.ceil((result.resetTime - Date.now()) / 1000);
          res.setHeader('Retry-After', retryAfter.toString());

          return res.status(429).json({
            success: false,
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Too many requests, please try again later',
              retryAfter,
            },
            timestamp: new Date().toISOString(),
          });
        }

        // 监听响应结束以更新统计
        res.on('finish', () => {
          const responseTime = Date.now() - startTime;
          const shouldSkip = (config.skipSuccessfulRequests && res.statusCode < 400) ||
                           (config.skipFailedRequests && res.statusCode >= 400);
          
          if (!shouldSkip) {
            this.updateStats(this.getKey(req), false, responseTime);
          }
        });

        next();
      } catch (error) {
        logger.error('Rate limiting error', {
          error: (error as Error).message,
          ip: req.ip,
          path: req.path,
        });
        
        // 发生错误时允许请求通过
        next();
      }
    };
  }

  // 获取统计信息
  public getStats(): Record<string, RateLimitStats> {
    return Object.fromEntries(this.stats);
  }

  // 清理统计信息
  public clearStats(): void {
    this.stats.clear();
  }

  // 重置特定键的限流
  public async resetLimit(key: string): Promise<void> {
    const patterns = [
      `${key}*`,
      `${key}:*`,
    ];

    for (const pattern of patterns) {
      const keys = await this.redis.keys(pattern);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    }

    logger.info('Rate limit reset', { key });
  }
}

// 预设配置
export const RateLimitPresets = {
  // 严格限制
  strict: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 10,
    strategy: RateLimitStrategy.SLIDING_WINDOW_COUNTER,
    progressiveDelay: true,
  },

  // 标准限制
  standard: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 60,
    strategy: RateLimitStrategy.SLIDING_WINDOW_COUNTER,
  },

  // 宽松限制
  lenient: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 200,
    strategy: RateLimitStrategy.FIXED_WINDOW,
  },

  // API限制 - 优化负载测试性能
  api: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 5000, // 提高到5000请求/分钟
    strategy: RateLimitStrategy.TOKEN_BUCKET,
    skipSuccessfulRequests: false,
    skipFailedRequests: true,
  },

  // 认证端点
  auth: {
    windowMs: 15 * 60 * 1000, // 15分钟
    maxRequests: 5,
    strategy: RateLimitStrategy.SLIDING_WINDOW_LOG,
    progressiveDelay: true,
  },

  // 负载测试模式 - 高并发支持
  loadTest: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 50000, // 50000请求/分钟，支持高并发测试
    strategy: RateLimitStrategy.TOKEN_BUCKET,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
    progressiveDelay: false,
    responseHeaders: true,
  },

  // 生产环境高性能
  production: {
    windowMs: 60 * 1000, // 1分钟
    maxRequests: 10000, // 10000请求/分钟
    strategy: RateLimitStrategy.TOKEN_BUCKET,
    skipSuccessfulRequests: false,
    skipFailedRequests: true,
    progressiveDelay: false,
    endpointLimits: {
      '/api/v1/health': {
        maxRequests: 50000, // 健康检查不限流
      },
      '/api/v1/annotations/list': {
        maxRequests: 5000, // 列表查询稍微限制
        strategy: RateLimitStrategy.SLIDING_WINDOW_COUNTER,
      },
      '/api/v1/annotations/nearby': {
        maxRequests: 5000, // 地理查询限制
        strategy: RateLimitStrategy.SLIDING_WINDOW_COUNTER,
      },
      '/uploads/*': {
        maxRequests: 20000, // 静态资源高限制
        strategy: RateLimitStrategy.FIXED_WINDOW,
      },
    },
  },
};

// 创建默认实例
export const advancedRateLimiter = new AdvancedRateLimiter();
export const strictRateLimiter = new AdvancedRateLimiter(RateLimitPresets.strict);
export const standardRateLimiter = new AdvancedRateLimiter(RateLimitPresets.standard);
export const lenientRateLimiter = new AdvancedRateLimiter(RateLimitPresets.lenient);
export const apiRateLimiter = new AdvancedRateLimiter(RateLimitPresets.api);
export const authRateLimiter = new AdvancedRateLimiter(RateLimitPresets.auth);
export const loadTestRateLimiter = new AdvancedRateLimiter(RateLimitPresets.loadTest);
export const productionRateLimiter = new AdvancedRateLimiter(RateLimitPresets.production);