import Redis from 'ioredis';
import { config } from './config';
import { logger } from '@/utils/logger';

// Redis 配置
const redisConfig: any = {
  host: config.redis?.host || 'localhost',
  port: config.redis?.port || 6379,
  db: config.redis?.db || 0,
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  keepAlive: 30000,
  connectTimeout: 10000,
  commandTimeout: 5000,
};

// 只有当password存在时才添加到配置中
if (config.redis?.password) {
  redisConfig.password = config.redis.password;
}

// 创建 Redis 实例 - 测试环境使用模拟客户端
let redis: any;
if (process.env['NODE_ENV'] === 'test' || process.env['DISABLE_REDIS'] === 'true') {
  // 模拟Redis客户端
  redis = {
    status: 'ready',
    get: async () => null,
    set: async () => 'OK',
    setex: async () => 'OK',
    del: async () => 1,
    keys: async () => [],
    exists: async () => 0,
    expire: async () => 1,
    ttl: async () => -1,
    incr: async () => 1,
    decr: async () => 0,
    lpush: async () => 1,
    lrange: async () => [],
    sadd: async () => 1,
    smembers: async () => [],
    zadd: async () => 1,
    zrevrange: async () => [],
    hset: async () => 1,
    hget: async () => null,
    hgetall: async () => ({}),
    info: async () => '',
    on: () => {},
    disconnect: async () => {},
  };
} else {
  redis = new Redis(redisConfig);
}

export { redis };

// Redis 连接事件处理 - 只在非测试环境启用
if (process.env['NODE_ENV'] !== 'test' && process.env['DISABLE_REDIS'] !== 'true') {
  redis.on('connect', () => {
    logger.info('Redis connecting...');
  });

  redis.on('ready', () => {
    logger.info('Redis connected successfully');
  });

  redis.on('error', (err: any) => {
    logger.error('Redis connection error', { error: err.message });
  });

  redis.on('close', () => {
    logger.info('Redis connection closed');
  });

  redis.on('reconnecting', () => {
    logger.info('Redis reconnecting...');
  });
}

// 缓存键前缀
export const CACHE_KEYS = {
  USER: 'user:',
  ANNOTATION: 'annotation:',
  COMMENT: 'comment:',
  STATS: 'stats:',
  SEARCH: 'search:',
  LOCATION: 'location:',
  POPULAR: 'popular:',
  TRENDING: 'trending:',
  SESSION: 'session:',
  RATE_LIMIT: 'rate_limit:',
  API_CACHE: 'api:',
} as const;

// 缓存TTL配置（秒）
export const CACHE_TTL = {
  SHORT: 60,           // 1分钟
  MEDIUM: 300,         // 5分钟
  LONG: 1800,          // 30分钟
  VERY_LONG: 3600,     // 1小时
  DAILY: 86400,        // 24小时
  WEEKLY: 604800,      // 7天
} as const;

// 缓存管理器类
export class CacheManager {
  private redis: Redis;

  constructor(redisInstance: Redis) {
    this.redis = redisInstance;
  }

  // 设置缓存
  async set(key: string, value: any, ttl: number = CACHE_TTL.MEDIUM): Promise<boolean> {
    try {
      const serializedValue = JSON.stringify(value);
      await this.redis.setex(key, ttl, serializedValue);
      logger.debug('Cache set', { key, ttl });
      return true;
    } catch (error) {
      logger.error('Cache set error', { key, error: (error as Error).message });
      return false;
    }
  }

  // 获取缓存
  async get<T>(key: string): Promise<T | null> {
    try {
      const value = await this.redis.get(key);
      if (value === null) {
        return null;
      }
      const parsed = JSON.parse(value);
      logger.debug('Cache hit', { key });
      return parsed as T;
    } catch (error) {
      logger.error('Cache get error', { key, error: (error as Error).message });
      return null;
    }
  }

  // 删除缓存
  async del(key: string): Promise<boolean> {
    try {
      await this.redis.del(key);
      logger.debug('Cache deleted', { key });
      return true;
    } catch (error) {
      logger.error('Cache delete error', { key, error: (error as Error).message });
      return false;
    }
  }

  // 批量删除缓存
  async delPattern(pattern: string): Promise<number> {
    try {
      const keys = await this.redis.keys(pattern);
      if (keys.length === 0) {
        return 0;
      }
      await this.redis.del(...keys);
      logger.debug('Cache pattern deleted', { pattern, count: keys.length });
      return keys.length;
    } catch (error) {
      logger.error('Cache pattern delete error', { pattern, error: (error as Error).message });
      return 0;
    }
  }

  // 检查缓存是否存在
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      logger.error('Cache exists check error', { key, error: (error as Error).message });
      return false;
    }
  }

  // 设置缓存过期时间
  async expire(key: string, ttl: number): Promise<boolean> {
    try {
      await this.redis.expire(key, ttl);
      return true;
    } catch (error) {
      logger.error('Cache expire error', { key, ttl, error: (error as Error).message });
      return false;
    }
  }

  // 获取缓存剩余时间
  async ttl(key: string): Promise<number> {
    try {
      return await this.redis.ttl(key);
    } catch (error) {
      logger.error('Cache TTL check error', { key, error: (error as Error).message });
      return -1;
    }
  }

  // 原子递增
  async incr(key: string, ttl?: number): Promise<number> {
    try {
      const result = await this.redis.incr(key);
      if (ttl && result === 1) {
        await this.redis.expire(key, ttl);
      }
      return result;
    } catch (error) {
      logger.error('Cache incr error', { key, error: (error as Error).message });
      return 0;
    }
  }

  // 原子递减
  async decr(key: string): Promise<number> {
    try {
      return await this.redis.decr(key);
    } catch (error) {
      logger.error('Cache decr error', { key, error: (error as Error).message });
      return 0;
    }
  }

  // 列表操作
  async lpush(key: string, ...values: any[]): Promise<number> {
    try {
      const serializedValues = values.map(v => JSON.stringify(v));
      return await this.redis.lpush(key, ...serializedValues);
    } catch (error) {
      logger.error('Cache lpush error', { key, error: (error as Error).message });
      return 0;
    }
  }

  async lrange<T>(key: string, start: number, stop: number): Promise<T[]> {
    try {
      const values = await this.redis.lrange(key, start, stop);
      return values.map(v => JSON.parse(v)) as T[];
    } catch (error) {
      logger.error('Cache lrange error', { key, error: (error as Error).message });
      return [];
    }
  }

  // 集合操作
  async sadd(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.redis.sadd(key, ...members);
    } catch (error) {
      logger.error('Cache sadd error', { key, error: (error as Error).message });
      return 0;
    }
  }

  async smembers(key: string): Promise<string[]> {
    try {
      return await this.redis.smembers(key);
    } catch (error) {
      logger.error('Cache smembers error', { key, error: (error as Error).message });
      return [];
    }
  }

  // 有序集合操作
  async zadd(key: string, score: number, member: string): Promise<number> {
    try {
      return await this.redis.zadd(key, score, member);
    } catch (error) {
      logger.error('Cache zadd error', { key, error: (error as Error).message });
      return 0;
    }
  }

  async zrevrange(key: string, start: number, stop: number, withScores: boolean = false): Promise<string[]> {
    try {
      if (withScores) {
        return await this.redis.zrevrange(key, start, stop, 'WITHSCORES');
      }
      return await this.redis.zrevrange(key, start, stop);
    } catch (error) {
      logger.error('Cache zrevrange error', { key, error: (error as Error).message });
      return [];
    }
  }

  // 哈希操作
  async hset(key: string, field: string, value: any): Promise<number> {
    try {
      const serializedValue = JSON.stringify(value);
      return await this.redis.hset(key, field, serializedValue);
    } catch (error) {
      logger.error('Cache hset error', { key, field, error: (error as Error).message });
      return 0;
    }
  }

  async hget<T>(key: string, field: string): Promise<T | null> {
    try {
      const value = await this.redis.hget(key, field);
      if (value === null) {
        return null;
      }
      return JSON.parse(value) as T;
    } catch (error) {
      logger.error('Cache hget error', { key, field, error: (error as Error).message });
      return null;
    }
  }

  async hgetall<T>(key: string): Promise<Record<string, T>> {
    try {
      const hash = await this.redis.hgetall(key);
      const result: Record<string, T> = {};
      for (const [field, value] of Object.entries(hash)) {
        result[field] = JSON.parse(value) as T;
      }
      return result;
    } catch (error) {
      logger.error('Cache hgetall error', { key, error: (error as Error).message });
      return {};
    }
  }

  // 获取缓存统计信息
  async getStats(): Promise<any> {
    try {
      const info = await this.redis.info('memory');
      const keyspace = await this.redis.info('keyspace');
      return {
        memory: info,
        keyspace,
        connected: this.redis.status === 'ready',
      };
    } catch (error) {
      logger.error('Cache stats error', { error: (error as Error).message });
      return null;
    }
  }
}

// 创建缓存管理器实例
export const cache = new CacheManager(redis);

// 缓存装饰器
export function Cacheable(key: string, ttl: number = CACHE_TTL.MEDIUM) {
  return function (_target: any, _propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const cacheKey = `${key}:${JSON.stringify(args)}`;

      // 尝试从缓存获取
      const cached = await cache.get(cacheKey);
      if (cached !== null) {
        return cached;
      }

      // 执行原方法
      const result = await method.apply(this, args);

      // 缓存结果
      await cache.set(cacheKey, result, ttl);

      return result;
    };
  };
}

// 缓存失效装饰器
export function CacheEvict(pattern: string) {
  return function (_target: any, _propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const result = await method.apply(this, args);

      // 清除相关缓存
      await cache.delPattern(pattern);

      return result;
    };
  };
}

// 预热缓存函数
export const warmupCache = async () => {
  try {
    logger.info('Starting cache warmup...');

    // 这里可以添加预热逻辑，比如：
    // - 预加载热门标注
    // - 预加载用户统计
    // - 预加载系统配置

    logger.info('Cache warmup completed');
  } catch (error) {
    logger.error('Cache warmup failed', { error: (error as Error).message });
  }
};

// 清理过期缓存
export const cleanupExpiredCache = async () => {
  try {
    // Redis会自动清理过期键，这里主要是记录日志
    const stats = await cache.getStats();
    logger.info('Cache cleanup check completed', { stats });
  } catch (error) {
    logger.error('Cache cleanup failed', { error: (error as Error).message });
  }
};

// 定期清理任务 - 只在非测试环境启动
if (process.env['NODE_ENV'] !== 'test' && process.env['DISABLE_CACHE'] !== 'true') {
  setInterval(cleanupExpiredCache, 60000); // 每分钟检查一次
}

export default cache;
