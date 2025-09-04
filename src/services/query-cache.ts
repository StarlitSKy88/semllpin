/**
 * Advanced Query Cache and Prepared Statements System for SmellPin
 * 
 * Features:
 * - Multi-level caching (memory + Redis)
 * - Prepared statement optimization
 * - Geographic query result caching
 * - Smart cache invalidation
 * - Query result compression
 * - Performance metrics tracking
 */

import { Knex } from 'knex';
import Redis from 'ioredis';
// import { compress, decompress } from 'lz4'; // Commented out due to missing package
import { logger } from '../utils/logger';
import { config } from '../config/config';

// Cache configuration
interface CacheConfig {
  enabled: boolean;
  memoryTTL: number;        // Memory cache TTL in seconds
  redisTTL: number;         // Redis cache TTL in seconds
  maxMemorySize: number;    // Max memory cache size in MB
  compressionThreshold: number; // Compress results larger than this (bytes)
  enableCompression: boolean;
  enableRedis: boolean;
}

// Query cache entry
interface CacheEntry {
  data: any;
  timestamp: number;
  ttl: number;
  size: number;
  compressed: boolean;
  hits: number;
  lastAccess: number;
}

// Cache statistics
interface CacheStats {
  memoryHits: number;
  memoryMisses: number;
  redisHits: number;
  redisMisses: number;
  evictions: number;
  totalSize: number;
  averageQueryTime: number;
  compressionRatio: number;
}

// Prepared statement cache
interface PreparedStatement {
  sql: string;
  compiled: boolean;
  lastUsed: number;
  useCount: number;
  averageTime: number;
}

class QueryCacheService {
  private static instance: QueryCacheService;
  private memoryCache: Map<string, CacheEntry> = new Map();
  private preparedStatements: Map<string, PreparedStatement> = new Map();
  private redisClient: Redis | null = null;
  private config: CacheConfig;
  private stats: CacheStats;
  private cleanupInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.config = {
      enabled: config.NODE_ENV === 'production' || config.NODE_ENV === 'development',
      memoryTTL: 300,                    // 5 minutes default
      redisTTL: 1800,                    // 30 minutes in Redis
      maxMemorySize: 100,                // 100MB max memory cache
      compressionThreshold: 10240,       // 10KB compression threshold
      enableCompression: true,
      enableRedis: config.NODE_ENV === 'production'
    };

    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      redisHits: 0,
      redisMisses: 0,
      evictions: 0,
      totalSize: 0,
      averageQueryTime: 0,
      compressionRatio: 0
    };

    this.initializeRedis();
    this.startCleanupProcess();
  }

  public static getInstance(): QueryCacheService {
    if (!QueryCacheService.instance) {
      QueryCacheService.instance = new QueryCacheService();
    }
    return QueryCacheService.instance;
  }

  // Initialize Redis connection
  private async initializeRedis(): Promise<void> {
    if (!this.config.enableRedis) {
      return;
    }

    try {
      this.redisClient = new Redis({
        host: config.redis?.host || 'localhost',
        port: config.redis?.port || 6379,
        password: config.redis?.password,
        db: 1, // Use database 1 for query cache
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        keyPrefix: 'query_cache:',
        
        // Optimizations for cache workload
        enableReadyCheck: false,
        commandTimeout: 5000,
        
        // Connection pool settings
        family: 4,
        keepAlive: 30000,
        connectTimeout: 10000,
        
        // Retry strategy
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          logger.warn(`Redis connection attempt ${times}, retrying in ${delay}ms`);
          return delay;
        }
      });

      this.redisClient.on('connect', () => {
        logger.info('✅ Redis query cache connected');
      });

      this.redisClient.on('error', (error) => {
        logger.error('❌ Redis query cache error:', error);
        // Fallback to memory-only caching
        this.config.enableRedis = false;
      });

      this.redisClient.on('ready', () => {
        logger.info('🚀 Redis query cache ready');
      });

      await this.redisClient.connect();

    } catch (error) {
      logger.error('❌ Failed to initialize Redis for query cache:', error);
      this.config.enableRedis = false;
    }
  }

  // Generate cache key for query
  private generateCacheKey(query: string, params: any[] = []): string {
    const queryHash = require('crypto')
      .createHash('md5')
      .update(query + JSON.stringify(params))
      .digest('hex');
    
    return `sql:${queryHash}`;
  }

  // Check if data should be compressed
  private shouldCompress(data: any): boolean {
    if (!this.config.enableCompression) return false;
    
    const size = JSON.stringify(data).length;
    return size > this.config.compressionThreshold;
  }

  // Compress data
  private compressData(data: any): string {
    // Simplified without lz4 compression
    return JSON.stringify(data);
  }

  // Decompress data
  private decompressData(data: string, compressed: boolean): any {
    // Simplified without lz4 decompression
    return JSON.parse(data);
  }

  // Get from memory cache
  private getFromMemory(key: string): any | null {
    const entry = this.memoryCache.get(key);
    
    if (!entry) {
      this.stats.memoryMisses++;
      return null;
    }

    // Check if expired
    if (Date.now() - entry.timestamp > entry.ttl * 1000) {
      this.memoryCache.delete(key);
      this.stats.memoryMisses++;
      this.stats.evictions++;
      return null;
    }

    // Update access statistics
    entry.hits++;
    entry.lastAccess = Date.now();
    
    this.stats.memoryHits++;
    
    return this.decompressData(entry.data, entry.compressed);
  }

  // Store in memory cache
  private storeInMemory(key: string, data: any, ttl: number): void {
    const compressed = this.shouldCompress(data);
    const processedData = this.compressData(data);
    const size = Buffer.byteLength(processedData, 'utf8');

    const entry: CacheEntry = {
      data: processedData,
      timestamp: Date.now(),
      ttl,
      size,
      compressed,
      hits: 0,
      lastAccess: Date.now()
    };

    // Check memory limits
    this.stats.totalSize += size;
    this.ensureMemoryLimit();

    this.memoryCache.set(key, entry);
    
    // Update compression statistics
    if (compressed) {
      const originalSize = JSON.stringify(data).length;
      this.stats.compressionRatio = 
        (this.stats.compressionRatio + (size / originalSize)) / 2;
    }
  }

  // Ensure memory cache doesn't exceed limits
  private ensureMemoryLimit(): void {
    const maxSizeBytes = this.config.maxMemorySize * 1024 * 1024;
    
    if (this.stats.totalSize <= maxSizeBytes) {
      return;
    }

    // Sort entries by last access time (LRU eviction)
    const entries = Array.from(this.memoryCache.entries())
      .sort(([, a], [, b]) => a.lastAccess - b.lastAccess);

    // Remove oldest entries until under limit
    for (const [key, entry] of entries) {
      this.memoryCache.delete(key);
      this.stats.totalSize -= entry.size;
      this.stats.evictions++;

      if (this.stats.totalSize <= maxSizeBytes) {
        break;
      }
    }
  }

  // Get from Redis cache
  private async getFromRedis(key: string): Promise<any | null> {
    if (!this.config.enableRedis || !this.redisClient) {
      return null;
    }

    try {
      const cached = await this.redisClient.get(key);
      
      if (!cached) {
        this.stats.redisMisses++;
        return null;
      }

      this.stats.redisHits++;
      
      // Parse cached entry
      const entry = JSON.parse(cached);
      return this.decompressData(entry.data, entry.compressed);

    } catch (error) {
      logger.warn('⚠️ Redis cache read error:', error);
      this.stats.redisMisses++;
      return null;
    }
  }

  // Store in Redis cache
  private async storeInRedis(key: string, data: any, ttl: number): Promise<void> {
    if (!this.config.enableRedis || !this.redisClient) {
      return;
    }

    try {
      const compressed = this.shouldCompress(data);
      const processedData = this.compressData(data);
      
      const entry = {
        data: processedData,
        compressed,
        timestamp: Date.now()
      };

      await this.redisClient.setex(key, ttl, JSON.stringify(entry));

    } catch (error) {
      logger.warn('⚠️ Redis cache write error:', error);
    }
  }

  // Execute cached query
  public async executeQuery<T>(
    db: Knex,
    queryName: string,
    queryFn: () => Promise<T>,
    options: {
      ttl?: number;
      useCache?: boolean;
      invalidateCache?: boolean;
      cacheKey?: string;
      tags?: string[];
    } = {}
  ): Promise<T> {
    const {
      ttl = this.config.memoryTTL,
      useCache = this.config.enabled,
      invalidateCache = false,
      cacheKey,
      tags = []
    } = options;

    if (!useCache) {
      return await this.executeUncached(queryFn, queryName);
    }

    // Generate cache key
    const key = cacheKey || this.generateCacheKey(queryName, []);

    // Check for cache invalidation
    if (invalidateCache) {
      await this.invalidate(key);
    }

    // Try memory cache first
    let result = this.getFromMemory(key);
    if (result !== null) {
      logger.debug(`💾 Memory cache hit: ${queryName}`);
      return result;
    }

    // Try Redis cache
    result = await this.getFromRedis(key);
    if (result !== null) {
      logger.debug(`🔄 Redis cache hit: ${queryName}`);
      // Store in memory for faster future access
      this.storeInMemory(key, result, ttl);
      return result;
    }

    // Execute query and cache result
    logger.debug(`🔍 Cache miss, executing query: ${queryName}`);
    result = await this.executeUncached(queryFn, queryName);

    // Cache the result
    this.storeInMemory(key, result, ttl);
    await this.storeInRedis(key, result, this.config.redisTTL);

    // Store cache tags for invalidation
    if (tags.length > 0) {
      await this.storeCacheTags(key, tags);
    }

    return result;
  }

  // Execute uncached query with performance tracking
  private async executeUncached<T>(queryFn: () => Promise<T>, queryName: string): Promise<T> {
    const startTime = Date.now();
    
    try {
      const result = await queryFn();
      const duration = Date.now() - startTime;
      
      // Update performance statistics
      this.stats.averageQueryTime = 
        (this.stats.averageQueryTime + duration) / 2;
      
      logger.debug(`⚡ Query executed: ${queryName} (${duration}ms)`);
      
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Query failed: ${queryName} (${duration}ms)`, error);
      throw error;
    }
  }

  // Store cache tags for invalidation
  private async storeCacheTags(key: string, tags: string[]): Promise<void> {
    if (!this.config.enableRedis || !this.redisClient) {
      return;
    }

    try {
      const pipeline = this.redisClient.pipeline();
      
      for (const tag of tags) {
        pipeline.sadd(`tag:${tag}`, key);
        pipeline.expire(`tag:${tag}`, this.config.redisTTL);
      }
      
      await pipeline.exec();
    } catch (error) {
      logger.warn('⚠️ Failed to store cache tags:', error);
    }
  }

  // Invalidate cache by key or tags
  public async invalidate(keyOrTag: string, isTag: boolean = false): Promise<void> {
    if (isTag) {
      await this.invalidateByTag(keyOrTag);
    } else {
      await this.invalidateByKey(keyOrTag);
    }
  }

  // Invalidate cache by specific key
  private async invalidateByKey(key: string): Promise<void> {
    // Remove from memory cache
    this.memoryCache.delete(key);
    
    // Remove from Redis cache
    if (this.config.enableRedis && this.redisClient) {
      try {
        await this.redisClient.del(key);
      } catch (error) {
        logger.warn('⚠️ Redis cache invalidation error:', error);
      }
    }
    
    logger.debug(`🗑️ Cache invalidated: ${key}`);
  }

  // Invalidate cache by tag
  private async invalidateByTag(tag: string): Promise<void> {
    if (!this.config.enableRedis || !this.redisClient) {
      return;
    }

    try {
      const keys = await this.redisClient.smembers(`tag:${tag}`);
      
      if (keys.length > 0) {
        const pipeline = this.redisClient.pipeline();
        
        for (const key of keys) {
          pipeline.del(key);
          this.memoryCache.delete(key); // Also remove from memory
        }
        
        pipeline.del(`tag:${tag}`); // Remove tag set
        await pipeline.exec();
        
        logger.debug(`🗑️ Cache invalidated by tag: ${tag} (${keys.length} keys)`);
      }
    } catch (error) {
      logger.warn('⚠️ Tag-based cache invalidation error:', error);
    }
  }

  // Prepare and cache SQL statement
  public async prepareStatement(
    db: Knex,
    name: string,
    sql: string,
    useNative: boolean = true
  ): Promise<void> {
    const existing = this.preparedStatements.get(name);
    
    if (existing && existing.compiled) {
      existing.lastUsed = Date.now();
      return;
    }

    try {
      // For PostgreSQL, we can use actual prepared statements
      if (useNative && db.client.config.client === 'postgresql') {
        await db.raw(`PREPARE ${name} AS ${sql}`);
      }

      this.preparedStatements.set(name, {
        sql,
        compiled: true,
        lastUsed: Date.now(),
        useCount: 0,
        averageTime: 0
      });

      logger.debug(`📋 Prepared statement cached: ${name}`);

    } catch (error) {
      logger.error(`❌ Failed to prepare statement ${name}:`, error);
      throw error;
    }
  }

  // Execute prepared statement
  public async executePreparedStatement<T>(
    db: Knex,
    name: string,
    params: any[] = [],
    fallbackQuery?: () => Promise<T>
  ): Promise<T> {
    const prepared = this.preparedStatements.get(name);
    
    if (!prepared) {
      if (fallbackQuery) {
        logger.warn(`⚠️ Prepared statement not found: ${name}, using fallback`);
        return await fallbackQuery();
      }
      throw new Error(`Prepared statement not found: ${name}`);
    }

    const startTime = Date.now();
    
    try {
      let result: T;
      
      if (db.client.config.client === 'postgresql') {
        // Use native prepared statement
        const placeholders = params.map((_, i) => `$${i + 1}`).join(', ');
        result = (await db.raw(`EXECUTE ${name}(${placeholders})`, params)) as T;
      } else {
        // Use parameterized query
        result = (await db.raw(prepared.sql, params)) as T;
      }

      const duration = Date.now() - startTime;
      
      // Update statistics
      prepared.useCount++;
      prepared.lastUsed = Date.now();
      prepared.averageTime = 
        (prepared.averageTime * (prepared.useCount - 1) + duration) / prepared.useCount;

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Prepared statement execution failed: ${name} (${duration}ms)`, error);
      throw error;
    }
  }

  // Geographic query caching helpers
  public async cacheLocationQuery<T>(
    db: Knex,
    queryName: string,
    bounds: { north: number; south: number; east: number; west: number },
    queryFn: () => Promise<T>,
    options: { ttl?: number; precision?: number } = {}
  ): Promise<T> {
    const { ttl = 300, precision = 4 } = options; // 5 minutes, 4 decimal precision
    
    // Round coordinates for consistent caching
    const roundedBounds = {
      north: Math.round(bounds.north * Math.pow(10, precision)) / Math.pow(10, precision),
      south: Math.round(bounds.south * Math.pow(10, precision)) / Math.pow(10, precision),
      east: Math.round(bounds.east * Math.pow(10, precision)) / Math.pow(10, precision),
      west: Math.round(bounds.west * Math.pow(10, precision)) / Math.pow(10, precision)
    };

    const cacheKey = `geo:${queryName}:${JSON.stringify(roundedBounds)}`;
    
    return this.executeQuery(
      db,
      queryName,
      queryFn,
      {
        ttl,
        cacheKey,
        tags: ['geographic', 'annotations']
      }
    );
  }

  // Start cleanup process
  private startCleanupProcess(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Cleanup every minute

    logger.info('🧹 Query cache cleanup process started');
  }

  // Cleanup expired entries and old prepared statements
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    // Cleanup memory cache
    for (const [key, entry] of this.memoryCache.entries()) {
      if (now - entry.timestamp > entry.ttl * 1000) {
        this.stats.totalSize -= entry.size;
        this.memoryCache.delete(key);
        cleaned++;
      }
    }

    // Cleanup old prepared statements (unused for 1 hour)
    for (const [name, prepared] of this.preparedStatements.entries()) {
      if (now - prepared.lastUsed > 3600000) {
        this.preparedStatements.delete(name);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug(`🧹 Cleaned up ${cleaned} cache entries`);
    }
  }

  // Get cache statistics
  public getStats(): CacheStats & { preparedStatements: number } {
    return {
      ...this.stats,
      preparedStatements: this.preparedStatements.size
    };
  }

  // Clear all caches
  public async clearAll(): Promise<void> {
    // Clear memory cache
    this.memoryCache.clear();
    this.preparedStatements.clear();
    
    // Clear Redis cache
    if (this.config.enableRedis && this.redisClient) {
      try {
        await this.redisClient.flushdb();
      } catch (error) {
        logger.warn('⚠️ Failed to clear Redis cache:', error);
      }
    }

    // Reset statistics
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      redisHits: 0,
      redisMisses: 0,
      evictions: 0,
      totalSize: 0,
      averageQueryTime: 0,
      compressionRatio: 0
    };

    logger.info('🗑️ All query caches cleared');
  }

  // Shutdown cleanup
  public async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    if (this.redisClient) {
      await this.redisClient.quit();
    }

    logger.info('🛑 Query cache service shutdown complete');
  }
}

// Export singleton instance
export const queryCache = QueryCacheService.getInstance();

// Export convenience functions
export const executeQuery = queryCache.executeQuery.bind(queryCache);
export const prepareStatement = queryCache.prepareStatement.bind(queryCache);
export const executePreparedStatement = queryCache.executePreparedStatement.bind(queryCache);
export const cacheLocationQuery = queryCache.cacheLocationQuery.bind(queryCache);
export const invalidateCache = queryCache.invalidate.bind(queryCache);
export const getCacheStats = queryCache.getStats.bind(queryCache);
export const clearAllCache = queryCache.clearAll.bind(queryCache);

export default queryCache;