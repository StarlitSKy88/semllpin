import Redis from 'ioredis';
import { getRedisClient } from '../config/redis';
import { logger } from '../utils/logger';

/**
 * Redis Service wrapper class
 * Provides a consistent interface for Redis operations across the application
 */
export class RedisService {
  private client: Redis;

  constructor() {
    this.client = getRedisClient();
  }

  /**
   * Get a value from Redis
   */
  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key);
    } catch (error) {
      logger.error(`Redis GET error for key ${key}:`, error);
      return null;
    }
  }

  /**
   * Set a value in Redis with expiry
   */
  async setWithExpiry(key: string, value: string, ttlSeconds: number): Promise<void> {
    try {
      await this.client.setex(key, ttlSeconds, value);
    } catch (error) {
      logger.error(`Redis SETEX error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Set a value only if it doesn't exist (with TTL)
   */
  async setNX(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    try {
      const result = await this.client.set(key, value, 'EX', ttlSeconds, 'NX');
      return result === 'OK';
    } catch (error) {
      logger.error(`Redis SETNX error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Delete a key from Redis
   */
  async delete(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (error) {
      logger.error(`Redis DEL error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Check if a key exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (error) {
      logger.error(`Redis EXISTS error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Increment a counter
   */
  async incr(key: string): Promise<number> {
    try {
      return await this.client.incr(key);
    } catch (error) {
      logger.error(`Redis INCR error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Set expiry for a key
   */
  async expire(key: string, ttlSeconds: number): Promise<void> {
    try {
      await this.client.expire(key, ttlSeconds);
    } catch (error) {
      logger.error(`Redis EXPIRE error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get TTL for a key
   */
  async ttl(key: string): Promise<number> {
    try {
      return await this.client.ttl(key);
    } catch (error) {
      logger.error(`Redis TTL error for key ${key}:`, error);
      return -1;
    }
  }

  /**
   * Push to a list
   */
  async lpush(key: string, ...values: string[]): Promise<number> {
    try {
      return await this.client.lpush(key, ...values);
    } catch (error) {
      logger.error(`Redis LPUSH error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get range from a list
   */
  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    try {
      return await this.client.lrange(key, start, stop);
    } catch (error) {
      logger.error(`Redis LRANGE error for key ${key}:`, error);
      return [];
    }
  }

  /**
   * Add to a set
   */
  async sadd(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.client.sadd(key, ...members);
    } catch (error) {
      logger.error(`Redis SADD error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get all members of a set
   */
  async smembers(key: string): Promise<string[]> {
    try {
      return await this.client.smembers(key);
    } catch (error) {
      logger.error(`Redis SMEMBERS error for key ${key}:`, error);
      return [];
    }
  }

  /**
   * Add to a sorted set
   */
  async zadd(key: string, score: number, member: string): Promise<number> {
    try {
      return await this.client.zadd(key, score, member);
    } catch (error) {
      logger.error(`Redis ZADD error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get range from sorted set (reverse order)
   */
  async zrevrange(key: string, start: number, stop: number, withScores?: boolean): Promise<string[]> {
    try {
      if (withScores) {
        return await this.client.zrevrange(key, start, stop, 'WITHSCORES');
      }
      return await this.client.zrevrange(key, start, stop);
    } catch (error) {
      logger.error(`Redis ZREVRANGE error for key ${key}:`, error);
      return [];
    }
  }

  /**
   * Set hash field
   */
  async hset(key: string, field: string, value: string): Promise<number> {
    try {
      return await this.client.hset(key, field, value);
    } catch (error) {
      logger.error(`Redis HSET error for key ${key}, field ${field}:`, error);
      throw error;
    }
  }

  /**
   * Get hash field
   */
  async hget(key: string, field: string): Promise<string | null> {
    try {
      return await this.client.hget(key, field);
    } catch (error) {
      logger.error(`Redis HGET error for key ${key}, field ${field}:`, error);
      return null;
    }
  }

  /**
   * Get all hash fields
   */
  async hgetall(key: string): Promise<Record<string, string>> {
    try {
      return await this.client.hgetall(key);
    } catch (error) {
      logger.error(`Redis HGETALL error for key ${key}:`, error);
      return {};
    }
  }

  /**
   * Get keys matching pattern
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      return await this.client.keys(pattern);
    } catch (error) {
      logger.error(`Redis KEYS error for pattern ${pattern}:`, error);
      return [];
    }
  }

  /**
   * Get Redis info
   */
  async info(section?: string): Promise<string> {
    try {
      return await this.client.info(section);
    } catch (error) {
      logger.error(`Redis INFO error:`, error);
      return '';
    }
  }

  /**
   * Ping Redis
   */
  async ping(): Promise<string> {
    try {
      return await this.client.ping();
    } catch (error) {
      logger.error(`Redis PING error:`, error);
      return 'PONG';
    }
  }

  /**
   * Get pipeline for batch operations
   */
  pipeline(): Redis.Pipeline {
    return this.client.pipeline();
  }

  /**
   * Get Redis status
   */
  get status(): string {
    return this.client.status;
  }

  /**
   * Set with expiry using SETEX
   */
  async setex(key: string, seconds: number, value: string): Promise<string> {
    try {
      return await this.client.setex(key, seconds, value);
    } catch (error) {
      logger.error(`Redis SETEX error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Delete multiple keys
   */
  async del(...keys: string[]): Promise<number> {
    try {
      return await this.client.del(...keys);
    } catch (error) {
      logger.error(`Redis DEL error for keys ${keys.join(', ')}:`, error);
      throw error;
    }
  }
}

// Export a singleton instance
ex