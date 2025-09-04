import Redis, { Cluster } from 'ioredis';
import { config } from './config';
import { logger } from '@/utils/logger';

// Redis Cluster Configuration
export interface ClusterConfig {
  nodes: Array<{
    host: string;
    port: number;
  }>;
  options: {
    redisOptions: {
      password?: string;
      db: number;
      retryDelayOnFailover: number;
      maxRetriesPerRequest: number;
      connectTimeout: number;
      commandTimeout: number;
      lazyConnect: boolean;
      keepAlive: number;
    };
    enableOfflineQueue: boolean;
    scaleReads: string;
    maxRedirections: number;
  };
}

// Multi-tier Cache Architecture
export class MultiTierCache {
  private memoryCache: Map<string, { value: any; expires: number; hits: number }>;
  private redisClient: Redis | Cluster;
  private maxMemorySize: number;
  private memoryCacheStats: {
    hits: number;
    misses: number;
    size: number;
  };

  constructor(redisClient: Redis | Cluster, maxMemorySize = 100) {
    this.redisClient = redisClient;
    this.memoryCache = new Map();
    this.maxMemorySize = maxMemorySize;
    this.memoryCacheStats = { hits: 0, misses: 0, size: 0 };
    
    // Clean up expired memory cache entries every 5 minutes
    setInterval(() => this.cleanupMemoryCache(), 5 * 60 * 1000);
  }

  // L1 Cache: Memory Cache (Fastest)
  private getFromMemoryCache<T>(key: string): T | null {
    const entry = this.memoryCache.get(key);
    if (!entry) {
      this.memoryCacheStats.misses++;
      return null;
    }

    if (Date.now() > entry.expires) {
      this.memoryCache.delete(key);
      this.memoryCacheStats.misses++;
      this.memoryCacheStats.size = this.memoryCache.size;
      return null;
    }

    entry.hits++;
    this.memoryCacheStats.hits++;
    logger.debug('Memory cache hit', { key, hits: entry.hits });
    return entry.value as T;
  }

  private setToMemoryCache(key: string, value: any, ttlSeconds: number): void {
    // LRU eviction if cache is full
    if (this.memoryCache.size >= this.maxMemorySize) {
      this.evictLRU();
    }

    const expires = Date.now() + (ttlSeconds * 1000);
    this.memoryCache.set(key, { value, expires, hits: 0 });
    this.memoryCacheStats.size = this.memoryCache.size;
    logger.debug('Memory cache set', { key, ttl: ttlSeconds });
  }

  private evictLRU(): void {
    let lruKey = '';
    let lruHits = Infinity;

    for (const [key, entry] of this.memoryCache.entries()) {
      if (entry.hits < lruHits) {
        lruHits = entry.hits;
        lruKey = key;
      }
    }

    if (lruKey) {
      this.memoryCache.delete(lruKey);
      logger.debug('Memory cache LRU eviction', { key: lruKey, hits: lruHits });
    }
  }

  private cleanupMemoryCache(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, entry] of this.memoryCache.entries()) {
      if (now > entry.expires) {
        this.memoryCache.delete(key);
        cleanedCount++;
      }
    }

    this.memoryCacheStats.size = this.memoryCache.size;
    if (cleanedCount > 0) {
      logger.debug('Memory cache cleanup', { cleaned: cleanedCount, remaining: this.memoryCache.size });
    }
  }

  // L2 Cache: Redis Cache (Fast)
  private async getFromRedisCache<T>(key: string): Promise<T | null> {
    try {
      const value = await this.redisClient.get(key);
      if (!value) return null;

      const parsed = JSON.parse(value) as T;
      logger.debug('Redis cache hit', { key });
      return parsed;
    } catch (error) {
      logger.error('Redis cache get error', { key, error: (error as Error).message });
      return null;
    }
  }

  private async setToRedisCache(key: string, value: any, ttlSeconds: number): Promise<void> {
    try {
      const serialized = JSON.stringify(value);
      await this.redisClient.setex(key, ttlSeconds, serialized);
      logger.debug('Redis cache set', { key, ttl: ttlSeconds });
    } catch (error) {
      logger.error('Redis cache set error', { key, error: (error as Error).message });
    }
  }

  // Unified Cache Interface
  async get<T>(key: string, options?: { skipMemory?: boolean }): Promise<T | null> {
    // Try L1 (Memory) first
    if (!options?.skipMemory) {
      const memoryResult = this.getFromMemoryCache<T>(key);
      if (memoryResult !== null) {
        return memoryResult;
      }
    }

    // Try L2 (Redis)
    const redisResult = await this.getFromRedisCache<T>(key);
    if (redisResult !== null) {
      // Promote to memory cache
      if (!options?.skipMemory) {
        this.setToMemoryCache(key, redisResult, 300); // 5 minutes in memory
      }
      return redisResult;
    }

    return null;
  }

  async set(
    key: string,
    value: any,
    options: {
      ttl?: number;
      skipMemory?: boolean;
      skipRedis?: boolean;
    } = {}
  ): Promise<void> {
    const ttl = options.ttl || 900; // Default 15 minutes

    // Set to L2 (Redis)
    if (!options.skipRedis) {
      await this.setToRedisCache(key, value, ttl);
    }

    // Set to L1 (Memory) with shorter TTL
    if (!options.skipMemory) {
      const memoryTtl = Math.min(ttl, 300); // Max 5 minutes in memory
      this.setToMemoryCache(key, value, memoryTtl);
    }
  }

  async del(key: string): Promise<void> {
    // Delete from both layers
    this.memoryCache.delete(key);
    
    try {
      await this.redisClient.del(key);
      logger.debug('Cache deleted from all layers', { key });
    } catch (error) {
      logger.error('Redis cache delete error', { key, error: (error as Error).message });
    }
  }

  async delPattern(pattern: string): Promise<number> {
    // Clear memory cache entries matching pattern
    let memoryDeleted = 0;
    for (const key of this.memoryCache.keys()) {
      if (key.includes(pattern.replace('*', ''))) {
        this.memoryCache.delete(key);
        memoryDeleted++;
      }
    }

    // Clear Redis cache entries
    let redisDeleted = 0;
    try {
      const keys = await this.redisClient.keys(pattern);
      if (keys.length > 0) {
        redisDeleted = await this.redisClient.del(...keys);
      }
      logger.debug('Pattern deleted from all layers', { 
        pattern, 
        memory: memoryDeleted, 
        redis: redisDeleted 
      });
    } catch (error) {
      logger.error('Redis pattern delete error', { pattern, error: (error as Error).message });
    }

    this.memoryCacheStats.size = this.memoryCache.size;
    return memoryDeleted + redisDeleted;
  }

  // Cache-aside pattern with automatic fallback
  async getOrSet<T>(
    key: string,
    fetchFunction: () => Promise<T>,
    options: {
      ttl?: number;
      skipMemory?: boolean;
      forceRefresh?: boolean;
    } = {}
  ): Promise<T> {
    if (!options.forceRefresh) {
      const cached = await this.get<T>(key, options);
      if (cached !== null) {
        return cached;
      }
    }

    // Cache miss - fetch fresh data
    logger.debug('Cache miss - fetching fresh data', { key });
    const freshData = await fetchFunction();
    
    // Store in cache
    await this.set(key, freshData, options);
    
    return freshData;
  }

  // Batch operations for better performance
  async mget<T>(keys: string[]): Promise<(T | null)[]> {
    const results: (T | null)[] = [];
    const redisKeys: string[] = [];
    const redisIndexes: number[] = [];

    // Check memory cache first
    for (let i = 0; i < keys.length; i++) {
      const memoryResult = this.getFromMemoryCache<T>(keys[i]);
      if (memoryResult !== null) {
        results[i] = memoryResult;
      } else {
        results[i] = null;
        redisKeys.push(keys[i]);
        redisIndexes.push(i);
      }
    }

    // Batch get from Redis for cache misses
    if (redisKeys.length > 0) {
      try {
        const redisResults = await this.redisClient.mget(...redisKeys);
        
        for (let i = 0; i < redisResults.length; i++) {
          const index = redisIndexes[i];
          const value = redisResults[i];
          
          if (value) {
            const parsed = JSON.parse(value) as T;
            results[index] = parsed;
            // Promote to memory cache
            this.setToMemoryCache(keys[index], parsed, 300);
          }
        }
      } catch (error) {
        logger.error('Redis mget error', { keys: redisKeys, error: (error as Error).message });
      }
    }

    return results;
  }

  // Cache statistics
  getStats() {
    const totalRequests = this.memoryCacheStats.hits + this.memoryCacheStats.misses;
    const hitRate = totalRequests > 0 ? (this.memoryCacheStats.hits / totalRequests) * 100 : 0;

    return {
      memory: {
        ...this.memoryCacheStats,
        hitRate: hitRate.toFixed(2) + '%',
        maxSize: this.maxMemorySize,
      },
      redis: {
        status: this.redisClient.status,
      }
    };
  }

  // Cache warming
  async warmup(warmupData: Array<{ key: string; value: any; ttl?: number }>): Promise<void> {
    logger.info('Starting cache warmup', { entries: warmupData.length });
    
    const promises = warmupData.map(async ({ key, value, ttl = 900 }) => {
      try {
        await this.set(key, value, { ttl });
      } catch (error) {
        logger.error('Cache warmup error', { key, error: (error as Error).message });
      }
    });

    await Promise.allSettled(promises);
    logger.info('Cache warmup completed');
  }

  // Graceful shutdown
  async disconnect(): Promise<void> {
    this.memoryCache.clear();
    
    if (this.redisClient.status === 'ready') {
      await this.redisClient.quit();
      logger.info('Cache disconnected gracefully');
    }
  }
}

// Create Redis Cluster or single instance based on configuration
export const createCacheCluster = (): Redis | Cluster => {
  const redisConfig = {
    password: config.redis?.password,
    db: config.redis?.db || 0,
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3,
    connectTimeout: 10000,
    commandTimeout: 5000,
    lazyConnect: true,
    keepAlive: 30000,
  };

  // Check if cluster mode is enabled
  const clusterNodes = process.env['REDIS_CLUSTER_NODES'];
  
  if (clusterNodes) {
    const nodes = clusterNodes.split(',').map(node => {
      const [host, port] = node.split(':');
      return { host, port: parseInt(port) };
    });

    logger.info('Initializing Redis Cluster', { nodes: nodes.length });
    
    return new Cluster(nodes, {
      redisOptions: redisConfig,
      enableOfflineQueue: false,
      scaleReads: 'slave',
      maxRedirections: 3,
    });
  } else {
    logger.info('Initializing single Redis instance');
    
    return new Redis({
      host: config.redis?.host || 'localhost',
      port: config.redis?.port || 6379,
      ...redisConfig,
    });
  }
};

// Initialize multi-tier cache
export const initMultiTierCache = (): MultiTierCache => {
  const redisClient = createCacheCluster();
  const maxMemoryCacheSize = parseInt(process.env['MAX_MEMORY_CACHE_SIZE'] || '200');
  
  const multiTierCache = new MultiTierCache(redisClient, maxMemoryCacheSize);
  
  // Handle Redis events
  redisClient.on('connect', () => logger.info('Cache cluster connecting...'));
  redisClient.on('ready', () => logger.info('Cache cluster ready'));
  redisClient.on('error', (err) => logger.error('Cache cluster error', { error: err.message }));
  redisClient.on('close', () => logger.info('Cache cluster connection closed'));
  redisClient.on('reconnecting', () => logger.info('Cache cluster reconnecting...'));
  
  return multiTierCache;
};

// Export singleton instance
export const multiTierCache = initMultiTierCache();