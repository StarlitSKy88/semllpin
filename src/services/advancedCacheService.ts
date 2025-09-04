import { Request, Response, NextFunction } from 'express';
import { cacheService, CacheService } from '../config/redis';
import { logger } from '../utils/logger';
import { createHash } from 'crypto';

// 高级缓存策略枚举
export enum CacheStrategy {
  WRITE_THROUGH = 'write_through',
  WRITE_BEHIND = 'write_behind',
  CACHE_ASIDE = 'cache_aside',
  REFRESH_AHEAD = 'refresh_ahead',
}

// 缓存标签系统
export interface CacheTags {
  entity?: string;
  id?: string;
  userId?: string;
  location?: string;
  custom?: string[];
}

// 缓存配置接口
export interface CacheConfig {
  ttl: number;
  strategy: CacheStrategy;
  tags?: CacheTags;
  refreshThreshold?: number; // 提前刷新阈值（秒）
  staleWhileRevalidate?: boolean; // 返回过期数据同时后台刷新
  compressionEnabled?: boolean;
  version?: string;
}

// 高级缓存服务类
export class AdvancedCacheService extends CacheService {
  private refreshQueue: Map<string, Promise<any>> = new Map();
  private tagIndex: Map<string, Set<string>> = new Map();

  // 生成缓存键
  private generateCacheKey(baseKey: string, params?: Record<string, any>): string {
    if (!params) return baseKey;
    
    const sortedParams = Object.keys(params)
      .sort()
      .reduce((obj, key) => {
        obj[key] = params[key];
        return obj;
      }, {} as Record<string, any>);
    
    const paramsHash = createHash('md5')
      .update(JSON.stringify(sortedParams))
      .digest('hex')
      .substring(0, 8);
    
    return `${baseKey}:${paramsHash}`;
  }

  // 管理缓存标签索引
  private manageTags(key: string, tags?: CacheTags): void {
    if (!tags) return;

    const tagKeys: string[] = [];
    
    if (tags.entity) tagKeys.push(`entity:${tags.entity}`);
    if (tags.id) tagKeys.push(`id:${tags.id}`);
    if (tags.userId) tagKeys.push(`user:${tags.userId}`);
    if (tags.location) tagKeys.push(`location:${tags.location}`);
    if (tags.custom) {
      tagKeys.push(...tags.custom.map(tag => `custom:${tag}`));
    }

    // 为每个标签添加缓存键
    tagKeys.forEach(tagKey => {
      if (!this.tagIndex.has(tagKey)) {
        this.tagIndex.set(tagKey, new Set());
      }
      this.tagIndex.get(tagKey)!.add(key);
    });
  }

  // 高级缓存设置
  async setAdvanced<T>(
    baseKey: string,
    value: T,
    config: CacheConfig,
    params?: Record<string, any>
  ): Promise<void> {
    const key = this.generateCacheKey(baseKey, params);
    
    // 管理标签
    this.manageTags(key, config.tags);
    
    // 准备缓存数据
    const cacheData = {
      value,
      createdAt: Date.now(),
      version: config.version || '1.0',
      strategy: config.strategy,
      refreshThreshold: config.refreshThreshold,
    };

    // 压缩处理
    let finalData: string;
    if (config.compressionEnabled) {
      const gzip = require('zlib').gzipSync;
      const compressed = gzip(JSON.stringify(cacheData));
      finalData = compressed.toString('base64');
      await this.set(`${key}:compressed`, 'true', config.ttl);
    } else {
      finalData = JSON.stringify(cacheData);
    }

    await this.set(key, finalData, config.ttl);
    
    logger.info('Advanced cache set', {
      key: baseKey,
      ttl: config.ttl,
      strategy: config.strategy,
      compressed: config.compressionEnabled,
      tags: config.tags,
    });
  }

  // 高级缓存获取
  async getAdvanced<T>(
    baseKey: string,
    config: CacheConfig,
    params?: Record<string, any>,
    refreshFunction?: () => Promise<T>
  ): Promise<T | null> {
    const key = this.generateCacheKey(baseKey, params);
    
    try {
      // 检查是否压缩
      const isCompressed = await this.exists(`${key}:compressed`);
      let rawData = await this.get<string>(key);
      
      if (!rawData) return null;

      // 解压缩
      if (isCompressed) {
        const gzip = require('zlib').gunzipSync;
        const compressed = Buffer.from(rawData, 'base64');
        rawData = gzip(compressed).toString();
      }

      const cacheData = JSON.parse(rawData as string);
      const now = Date.now();
      const age = now - cacheData.createdAt;
      const ttl = config.ttl * 1000; // 转换为毫秒

      // 检查是否需要刷新
      const shouldRefresh = config.refreshThreshold && 
        age > (ttl - config.refreshThreshold * 1000) &&
        refreshFunction;

      if (shouldRefresh && !this.refreshQueue.has(key)) {
        // 异步刷新缓存
        const refreshPromise = this.refreshCache(key, config, refreshFunction, params);
        this.refreshQueue.set(key, refreshPromise);
        
        // 清理完成的刷新任务
        refreshPromise.finally(() => {
          this.refreshQueue.delete(key);
        });
      }

      // 返回缓存数据（可能是过期的，如果启用了staleWhileRevalidate）
      if (config.staleWhileRevalidate || age < ttl) {
        logger.info('Advanced cache hit', {
          key: baseKey,
          age: Math.round(age / 1000),
          shouldRefresh,
        });
        return cacheData.value;
      }

      return null;
    } catch (error) {
      logger.error('Advanced cache get error', {
        key: baseKey,
        error: (error as Error).message,
      });
      return null;
    }
  }

  // 刷新缓存
  private async refreshCache<T>(
    key: string,
    config: CacheConfig,
    refreshFunction: () => Promise<T>,
    params?: Record<string, any>
  ): Promise<void> {
    try {
      logger.info('Refreshing cache', { key });
      const freshData = await refreshFunction();
      
      // 从完整键中提取基础键
      const baseKey = key.split(':')[0];
      await this.setAdvanced(baseKey, freshData, config, params);
      
      logger.info('Cache refreshed', { key });
    } catch (error) {
      logger.error('Cache refresh failed', {
        key,
        error: (error as Error).message,
      });
    }
  }

  // 获取pipeline实例
  protected getPipeline() {
    return (this as any).client.pipeline();
  }

  // 按标签清除缓存
  async invalidateByTags(tags: Partial<CacheTags>): Promise<number> {
    const keysToInvalidate = new Set<string>();
    
    // 构建标签键列表
    const tagKeys: string[] = [];
    if (tags.entity) tagKeys.push(`entity:${tags.entity}`);
    if (tags.id) tagKeys.push(`id:${tags.id}`);
    if (tags.userId) tagKeys.push(`user:${tags.userId}`);
    if (tags.location) tagKeys.push(`location:${tags.location}`);
    if (tags.custom) {
      tagKeys.push(...tags.custom.map(tag => `custom:${tag}`));
    }

    // 收集要删除的缓存键
    tagKeys.forEach(tagKey => {
      const keys = this.tagIndex.get(tagKey);
      if (keys) {
        keys.forEach(key => keysToInvalidate.add(key));
      }
    });

    // 批量删除
    const pipeline = this.getPipeline();
    keysToInvalidate.forEach(key => {
      pipeline.del(key);
      pipeline.del(`${key}:compressed`);
    });

    const results = await pipeline.exec();
    const deletedCount = results ? results.length / 2 : 0;

    // 清理标签索引
    tagKeys.forEach(tagKey => {
      this.tagIndex.delete(tagKey);
    });

    logger.info('Cache invalidated by tags', {
      tags,
      deletedCount,
      tagKeys,
    });

    return deletedCount;
  }

  // 缓存预热
  async warmupCache<T>(
    baseKey: string,
    config: CacheConfig,
    dataProvider: () => Promise<T>,
    paramsList: Record<string, any>[] = [{}]
  ): Promise<void> {
    logger.info('Starting cache warmup', { baseKey, count: paramsList.length });
    
    const warmupPromises = paramsList.map(async (params) => {
      try {
        const data = await dataProvider();
        await this.setAdvanced(baseKey, data, config, params);
      } catch (error) {
        logger.error('Cache warmup failed for params', {
          baseKey,
          params,
          error: (error as Error).message,
        });
      }
    });

    await Promise.allSettled(warmupPromises);
    logger.info('Cache warmup completed', { baseKey });
  }

  // 获取缓存统计信息
  async getCacheStats(): Promise<{
    memory: Record<string, string>;
    hitRate: number;
    missRate: number;
    totalRequests: number;
    tagIndexSize: number;
    refreshQueueSize: number;
  }> {
    const memoryStats = await super.getStats();
    
    // 这里应该从Redis或内存中获取实际的统计数据
    // 为了演示，我们返回模拟数据
    return {
      memory: memoryStats,
      hitRate: 0, // 需要实现命中率统计
      missRate: 0, // 需要实现未命中率统计
      totalRequests: 0, // 需要实现总请求数统计
      tagIndexSize: this.tagIndex.size,
      refreshQueueSize: this.refreshQueue.size,
    };
  }
}

// 创建增强的缓存服务实例
export const advancedCacheService = new AdvancedCacheService();

// 智能缓存中间件
export const smartCacheMiddleware = (config: CacheConfig) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // 只处理GET请求
    if (req.method !== 'GET') {
      return next();
    }

    const baseKey = `api:${req.route?.path || req.path}`;
    const params = { ...req.query, ...req.params };
    
    // 尝试从缓存获取数据
    const cachedData = await advancedCacheService.getAdvanced(
      baseKey,
      config,
      params
    );

    if (cachedData !== null) {
      logger.info('Smart cache hit', {
        path: req.path,
        method: req.method,
        params: Object.keys(params),
      });
      
      // 设置缓存命中头
      res.setHeader('X-Cache', 'HIT');
      res.setHeader('X-Cache-Key', baseKey);
      
      return res.json(cachedData);
    }

    // 缓存未命中，继续处理请求
    res.setHeader('X-Cache', 'MISS');
    
    // 重写res.json以缓存响应
    const originalJson = res.json;
    res.json = function(data: any) {
      if (res.statusCode === 200) {
        // 异步缓存响应数据
        setImmediate(async () => {
          try {
            await advancedCacheService.setAdvanced(baseKey, data, config, params);
            logger.info('Response cached', { path: req.path, baseKey });
          } catch (error) {
            logger.error('Failed to cache response', {
              path: req.path,
              error: (error as Error).message,
            });
          }
        });
      }
      return originalJson.call(this, data);
    };

    next();
  };
};

// 预定义的缓存配置
export const CacheConfigs = {
  // 短期缓存 - 用于频繁变化的数据
  SHORT_TERM: {
    ttl: 300, // 5分钟
    strategy: CacheStrategy.CACHE_ASIDE,
    refreshThreshold: 60, // 提前1分钟刷新
    staleWhileRevalidate: true,
  } as CacheConfig,

  // 中期缓存 - 用于相对稳定的数据
  MEDIUM_TERM: {
    ttl: 1800, // 30分钟
    strategy: CacheStrategy.CACHE_ASIDE,
    refreshThreshold: 300, // 提前5分钟刷新
    staleWhileRevalidate: true,
    compressionEnabled: true,
  } as CacheConfig,

  // 长期缓存 - 用于很少变化的数据
  LONG_TERM: {
    ttl: 3600, // 1小时
    strategy: CacheStrategy.REFRESH_AHEAD,
    refreshThreshold: 600, // 提前10分钟刷新
    staleWhileRevalidate: true,
    compressionEnabled: true,
  } as CacheConfig,

  // 静态内容缓存
  STATIC: {
    ttl: 86400, // 24小时
    strategy: CacheStrategy.CACHE_ASIDE,
    compressionEnabled: true,
  } as CacheConfig,

  // 用户相关缓存
  USER_DATA: {
    ttl: 1800, // 30分钟
    strategy: CacheStrategy.WRITE_THROUGH,
    refreshThreshold: 300,
    staleWhileRevalidate: true,
  } as CacheConfig,
};