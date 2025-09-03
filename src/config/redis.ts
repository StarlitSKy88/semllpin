import Redis from 'ioredis';
import { config } from './config';
import { logger } from '@/utils/logger';
import RedisMock from '@/utils/redis-mock';

// Redis client instance
let redisClient: Redis | null = null;

// Redis configuration
const redisConfig: any = {
  host: config.redis.host,
  port: config.redis.port,
  ...(config.redis.password && { password: config.redis.password }),
  db: config.redis.db,
  retryDelayOnFailover: 100,
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  keepAlive: 30000,
  connectTimeout: 10000,
  commandTimeout: 5000,
  retryDelayOnClusterDown: 300,
};

// Create Redis client
export const createRedisClient = (): Redis => {
  if (redisClient) {
    return redisClient;
  }

  // Check if Redis mock is enabled
  if (process.env['REDIS_MOCK'] === 'true') {
    logger.info('使用Redis模拟器 (开发模式)');
    redisClient = RedisMock as any;
    return redisClient as Redis;
  }

  redisClient = new Redis(redisConfig);

  // Event listeners
  redisClient.on('connect', () => {
    logger.info('Redis连接已建立');
  });

  redisClient.on('ready', () => {
    logger.info('Redis连接就绪');
  });

  redisClient.on('error', (error) => {
    logger.error('Redis连接错误:', error);
  });

  redisClient.on('close', () => {
    logger.warn('Redis连接已关闭');
  });

  redisClient.on('reconnecting', () => {
    logger.info('Redis正在重新连接...');
  });

  redisClient.on('end', () => {
    logger.warn('Redis连接已结束');
  });

  return redisClient;
};

// Connect to Redis
export const connectRedis = async (): Promise<void> => {
  try {
    const client = createRedisClient();

    // Skip connect() for Redis mock
    if (process.env['REDIS_MOCK'] !== 'true') {
      await client.connect();
    }

    // Test the connection
    await client.ping();
    logger.info('Redis连接测试成功');
  } catch (error) {
    logger.error('Redis连接失败:', error);
    throw error;
  }
};

// Disconnect from Redis
export const disconnectRedis = async (): Promise<void> => {
  try {
    if (redisClient) {
      await redisClient.quit();
      logger.info('Redis连接已关闭');
    }
  } catch (error) {
    logger.error('关闭Redis连接时发生错误:', error);
    throw error;
  }
};

// Get Redis client
export const getRedisClient = (): Redis => {
  if (!redisClient) {
    redisClient = createRedisClient();
  }
  return redisClient;
};

// Health check function
export const checkRedisHealth = async (): Promise<boolean> => {
  try {
    const client = getRedisClient();
    const result = await client.ping();
    return result === 'PONG';
  } catch (error) {
    logger.error('Redis健康检查失败:', error);
    return false;
  }
};

// Cache helper functions
export class CacheService {
  private client: Redis;
  private defaultTTL: number;

  constructor(ttl: number = config.cache.ttl) {
    this.client = getRedisClient();
    this.defaultTTL = ttl;
  }

  // Set cache with TTL
  async set(
    key: string,
    value: string | number | object,
    ttl: number = this.defaultTTL,
  ): Promise<void> {
    try {
      const serializedValue = typeof value === 'string' ? value : JSON.stringify(value);
      await this.client.setex(key, ttl, serializedValue);
    } catch (error) {
      logger.error(`缓存设置失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Get cache
  async get<T = string>(key: string): Promise<T | null> {
    try {
      const value = await this.client.get(key);
      if (!value) {
        return null;
      }

      // Try to parse as JSON, fallback to string
      try {
        return JSON.parse(value) as T;
      } catch {
        return value as T;
      }
    } catch (error) {
      logger.error(`缓存获取失败 - Key: ${key}`, error);
      return null;
    }
  }

  // Delete cache
  async del(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (error) {
      logger.error(`缓存删除失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Check if key exists
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (error) {
      logger.error(`缓存检查失败 - Key: ${key}`, error);
      return false;
    }
  }

  // Set TTL for existing key
  async expire(key: string, ttl: number): Promise<void> {
    try {
      await this.client.expire(key, ttl);
    } catch (error) {
      logger.error(`设置缓存过期时间失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Get multiple keys
  async mget<T = string>(keys: string[]): Promise<(T | null)[]> {
    try {
      const values = await this.client.mget(...keys);
      return values.map(value => {
        if (!value) {
          return null;
        }
        try {
          return JSON.parse(value) as T;
        } catch {
          return value as T;
        }
      });
    } catch (error) {
      logger.error('批量获取缓存失败', error);
      return keys.map(() => null);
    }
  }

  // Set multiple keys
  async mset(keyValuePairs: Record<string, string | number | object>): Promise<void> {
    try {
      const pipeline = this.client.pipeline();

      Object.entries(keyValuePairs).forEach(([key, value]) => {
        const serializedValue = typeof value === 'string' ? value : JSON.stringify(value);
        pipeline.set(key, serializedValue);
      });

      await pipeline.exec();
    } catch (error) {
      logger.error('批量设置缓存失败', error);
      throw error;
    }
  }

  // Increment counter
  async incr(key: string): Promise<number> {
    try {
      return await this.client.incr(key);
    } catch (error) {
      logger.error(`计数器递增失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Decrement counter
  async decr(key: string): Promise<number> {
    try {
      return await this.client.decr(key);
    } catch (error) {
      logger.error(`计数器递减失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Add to set
  async sadd(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.client.sadd(key, ...members);
    } catch (error) {
      logger.error(`添加到集合失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Get set members
  async smembers(key: string): Promise<string[]> {
    try {
      return await this.client.smembers(key);
    } catch (error) {
      logger.error(`获取集合成员失败 - Key: ${key}`, error);
      return [];
    }
  }

  // Remove from set
  async srem(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.client.srem(key, ...members);
    } catch (error) {
      logger.error(`从集合移除失败 - Key: ${key}`, error);
      throw error;
    }
  }

  // Check if member exists in set
  async sismember(key: string, member: string): Promise<boolean> {
    try {
      const result = await this.client.sismember(key, member);
      return result === 1;
    } catch (error) {
      logger.error(`检查集合成员失败 - Key: ${key}`, error);
      return false;
    }
  }

  // Clear all cache (use with caution)
  async flushall(): Promise<void> {
    try {
      await this.client.flushall();
      logger.warn('所有缓存已清空');
    } catch (error) {
      logger.error('清空缓存失败', error);
      throw error;
    }
  }

  // Get cache statistics
  async getStats(): Promise<Record<string, string>> {
    try {
      const info = await this.client.info('memory');
      const stats: Record<string, string> = {};

      info.split('\r\n').forEach(line => {
        const [key, value] = line.split(':');
        if (key && value) {
          stats[key] = value;
        }
      });

      return stats;
    } catch (error) {
      logger.error('获取缓存统计失败', error);
      return {};
    }
  }
}

// Create default cache service instance
export const cacheService = new CacheService();

// Rate limiting helper
export class RateLimiter {
  private client: Redis;

  constructor() {
    this.client = getRedisClient();
  }

  async checkLimit(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    try {
      const now = Date.now();
      const window = Math.floor(now / windowMs);
      const redisKey = `rate_limit:${key}:${window}`;

      const current = await this.client.incr(redisKey);

      if (current === 1) {
        await this.client.expire(redisKey, Math.ceil(windowMs / 1000));
      }

      const remaining = Math.max(0, limit - current);
      const resetTime = (window + 1) * windowMs;

      return {
        allowed: current <= limit,
        remaining,
        resetTime,
      };
    } catch (error) {
      logger.error(`限流检查失败 - Key: ${key}`, error);
      // Fail open - allow request if Redis is down
      return {
        allowed: true,
        remaining: limit,
        resetTime: Date.now() + windowMs,
      };
    }
  }
}

export const rateLimiter = new RateLimiter();

export default redisClient;
