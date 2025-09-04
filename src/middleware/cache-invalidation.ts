import { Request, Response, NextFunction } from 'express';
import { multiTierCache } from '@/config/cache-cluster';
import { cdnManager } from '@/services/cdn-optimizer';
import { logger } from '@/utils/logger';

export interface InvalidationRule {
  pattern: string;
  triggers: string[];
  dependencies: string[];
  priority: 'high' | 'medium' | 'low';
  delay?: number; // Delayed invalidation in milliseconds
}

// Smart Cache Invalidation Strategy
export class CacheInvalidationStrategy {
  private rules: Map<string, InvalidationRule>;
  private pendingInvalidations: Map<string, NodeJS.Timeout>;

  constructor() {
    this.rules = new Map();
    this.pendingInvalidations = new Map();
    this.initializeRules();
  }

  private initializeRules(): void {
    // Annotation-related invalidation rules
    this.addRule('annotation-list', {
      pattern: 'annotations:list:*',
      triggers: ['annotation.created', 'annotation.updated', 'annotation.deleted'],
      dependencies: ['annotations:nearby:*', 'annotations:popular:*', 'stats:*'],
      priority: 'high',
    });

    this.addRule('annotation-details', {
      pattern: 'annotation:*',
      triggers: ['annotation.updated', 'annotation.deleted', 'comment.created'],
      dependencies: ['user:annotations:*'],
      priority: 'high',
    });

    // User-related invalidation rules
    this.addRule('user-profile', {
      pattern: 'user:profile:*',
      triggers: ['user.updated', 'user.avatar_changed'],
      dependencies: ['user:annotations:*', 'leaderboard:*'],
      priority: 'medium',
    });

    this.addRule('user-stats', {
      pattern: 'user:stats:*',
      triggers: ['annotation.created', 'annotation.deleted', 'reward.claimed'],
      dependencies: ['stats:global:*', 'leaderboard:*'],
      priority: 'low',
      delay: 60000, // Delay 1 minute for batch updates
    });

    // Location-based invalidation rules
    this.addRule('nearby-annotations', {
      pattern: 'annotations:nearby:*',
      triggers: ['annotation.created', 'annotation.deleted', 'annotation.location_changed'],
      dependencies: ['search:geo:*'],
      priority: 'high',
    });

    // Search and discovery rules
    this.addRule('search-results', {
      pattern: 'search:*',
      triggers: ['annotation.created', 'annotation.updated', 'annotation.deleted'],
      dependencies: ['trending:*', 'popular:*'],
      priority: 'medium',
      delay: 30000, // Delay 30 seconds for search index updates
    });

    // Statistics and analytics rules
    this.addRule('global-stats', {
      pattern: 'stats:global:*',
      triggers: ['annotation.created', 'user.registered', 'payment.completed'],
      dependencies: ['dashboard:stats:*'],
      priority: 'low',
      delay: 300000, // Delay 5 minutes for analytics
    });

    // CDN asset invalidation rules
    this.addRule('user-assets', {
      pattern: 'assets:user:*',
      triggers: ['user.avatar_changed', 'annotation.image_updated'],
      dependencies: [],
      priority: 'medium',
    });
  }

  addRule(name: string, rule: InvalidationRule): void {
    this.rules.set(name, rule);
    logger.debug('Cache invalidation rule added', { name, rule });
  }

  async invalidate(trigger: string, context: Record<string, any> = {}): Promise<void> {
    logger.info('Cache invalidation triggered', { trigger, context });

    const matchingRules = Array.from(this.rules.entries()).filter(([_, rule]) =>
      rule.triggers.includes(trigger)
    );

    if (matchingRules.length === 0) {
      logger.debug('No matching invalidation rules found', { trigger });
      return;
    }

    // Process rules by priority
    const rulesByPriority = this.groupByPriority(matchingRules);
    
    // High priority - immediate invalidation
    await this.processRules(rulesByPriority['high'], context, 0);
    
    // Medium priority - slight delay
    await this.processRules(rulesByPriority['medium'], context, 1000);
    
    // Low priority - longer delay
    await this.processRules(rulesByPriority['low'], context, 5000);
  }

  private groupByPriority(
    rules: Array<[string, InvalidationRule]>
  ): Record<string, Array<[string, InvalidationRule]>> {
    return rules.reduce((acc, rule) => {
      const priority = rule[1].priority;
      if (!acc[priority]) acc[priority] = [];
      acc[priority].push(rule);
      return acc;
    }, {} as Record<string, Array<[string, InvalidationRule]>>);
  }

  private async processRules(
    rules: Array<[string, InvalidationRule]>,
    context: Record<string, any>,
    baseDelay: number
  ): Promise<void> {
    for (const [name, rule] of rules) {
      const delay = rule.delay || baseDelay;
      
      if (delay > 0) {
        // Cancel any pending invalidation for this rule
        const existingTimeout = this.pendingInvalidations.get(name);
        if (existingTimeout) {
          clearTimeout(existingTimeout);
        }

        // Schedule delayed invalidation
        const timeout = setTimeout(async () => {
          await this.executeInvalidation(name, rule, context);
          this.pendingInvalidations.delete(name);
        }, delay);

        this.pendingInvalidations.set(name, timeout);
        
        logger.debug('Scheduled delayed cache invalidation', { name, delay });
      } else {
        // Immediate invalidation
        await this.executeInvalidation(name, rule, context);
      }
    }
  }

  private async executeInvalidation(
    name: string,
    rule: InvalidationRule,
    context: Record<string, any>
  ): Promise<void> {
    try {
      const pattern = this.interpolatePattern(rule.pattern, context);
      
      logger.info('Executing cache invalidation', { name, pattern, priority: rule.priority });

      // Invalidate main pattern
      const deletedCount = await multiTierCache.delPattern(pattern);
      
      // Invalidate dependencies
      for (const depPattern of rule.dependencies) {
        const interpolatedDepPattern = this.interpolatePattern(depPattern, context);
        await multiTierCache.delPattern(interpolatedDepPattern);
      }

      // Invalidate CDN if pattern matches assets
      if (pattern.includes('assets:') || pattern.includes('images:')) {
        await this.invalidateCDNAssets(pattern, context);
      }

      logger.info('Cache invalidation completed', {
        name,
        pattern,
        deletedCount,
        dependencies: rule.dependencies.length,
      });

    } catch (error) {
      logger.error('Cache invalidation failed', {
        name,
        pattern: rule.pattern,
        error: (error as Error).message,
      });
    }
  }

  private interpolatePattern(pattern: string, context: Record<string, any>): string {
    let interpolated = pattern;

    // Replace context variables in pattern
    Object.entries(context).forEach(([key, value]) => {
      const placeholder = `{${key}}`;
      if (interpolated.includes(placeholder)) {
        interpolated = interpolated.replace(new RegExp(placeholder, 'g'), String(value));
      }
    });

    return interpolated;
  }

  private async invalidateCDNAssets(pattern: string, context: Record<string, any>): Promise<void> {
    try {
      // Extract URLs from pattern and context
      const urls = this.extractCDNUrls(pattern, context);
      
      if (urls.length > 0) {
        const success = await cdnManager.purgeCache(urls);
        
        if (success) {
          logger.info('CDN cache purged', { urls: urls.length });
        } else {
          logger.warn('CDN cache purge failed', { urls });
        }
      }
    } catch (error) {
      logger.error('CDN invalidation failed', {
        pattern,
        error: (error as Error).message,
      });
    }
  }

  private extractCDNUrls(pattern: string, context: Record<string, any>): string[] {
    const urls: string[] = [];
    
    // Extract URLs based on context
    if (context['userId'] && pattern.includes('user:')) {
      urls.push(`/assets/users/${context['userId']}/avatar.webp`);
      urls.push(`/assets/users/${context['userId']}/avatar.avif`);
    }

    if (context['annotationId'] && pattern.includes('annotation:')) {
      urls.push(`/assets/annotations/${context['annotationId']}.webp`);
      urls.push(`/assets/annotations/${context['annotationId']}.avif`);
    }

    return urls;
  }

  // Get invalidation statistics
  getStats(): {
    rules: number;
    pendingInvalidations: number;
    rulesByPriority: Record<string, number>;
  } {
    const rulesByPriority = Array.from(this.rules.values()).reduce((acc, rule) => {
      acc[rule.priority] = (acc[rule.priority] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      rules: this.rules.size,
      pendingInvalidations: this.pendingInvalidations.size,
      rulesByPriority,
    };
  }

  // Force clear all pending invalidations
  clearPendingInvalidations(): void {
    this.pendingInvalidations.forEach(timeout => clearTimeout(timeout));
    this.pendingInvalidations.clear();
    logger.info('All pending invalidations cleared');
  }
}

export const cacheInvalidationStrategy = new CacheInvalidationStrategy();

// Express middleware for automatic cache invalidation
export const cacheInvalidationMiddleware = (
  trigger: string,
  contextExtractor?: (req: Request) => Record<string, any>
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Store original json method
    const originalJson = res.json;

    // Override json method to trigger invalidation after successful response
    res.json = function (body: any) {
      const result = originalJson.call(this, body);

      // Trigger invalidation only for successful responses
      if (res.statusCode >= 200 && res.statusCode < 300) {
        setImmediate(async () => {
          try {
            const context = contextExtractor ? contextExtractor(req) : {};
            await cacheInvalidationStrategy.invalidate(trigger, context);
          } catch (error) {
            logger.error('Middleware cache invalidation failed', {
              trigger,
              error: (error as Error).message,
            });
          }
        });
      }

      return result;
    };

    next();
  };
};

// Specific middleware factories for common operations
export const annotationCacheInvalidation = (action: 'created' | 'updated' | 'deleted') =>
  cacheInvalidationMiddleware(`annotation.${action}`, (req) => ({
    annotationId: req.params['id'] || req.body.id,
    userId: req.user?.id,
    location: req.body.location,
  }));

export const userCacheInvalidation = (action: 'updated' | 'avatar_changed') =>
  cacheInvalidationMiddleware(`user.${action}`, (req) => ({
    userId: req.params['id'] || req.user?.id,
  }));

export const commentCacheInvalidation = cacheInvalidationMiddleware('comment.created', (req) => ({
  annotationId: req.params['annotationId'] || req.body.annotationId,
  userId: req.user?.id,
}));

// Cache warming middleware
export const cacheWarmingMiddleware = (
  cacheKey: string,
  dataFetcher: (req: Request) => Promise<any>,
  ttl: number = 3600
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check if cache warming is needed (cache miss or near expiration)
      const existingData = await multiTierCache.get(cacheKey);
      
      if (!existingData) {
        logger.debug('Cache warming initiated', { key: cacheKey });
        
        // Fetch fresh data asynchronously
        setImmediate(async () => {
          try {
            const freshData = await dataFetcher(req);
            await multiTierCache.set(cacheKey, freshData, { ttl });
            logger.debug('Cache warming completed', { key: cacheKey });
          } catch (error) {
            logger.error('Cache warming failed', {
              key: cacheKey,
              error: (error as Error).message,
            });
          }
        });
      }

      next();
    } catch (error) {
      logger.error('Cache warming middleware error', {
        key: cacheKey,
        error: (error as Error).message,
      });
      next();
    }
  };
};

// Cache penetration protection middleware
export const cachePenetrationProtection = (
  cacheKeyExtractor: (req: Request) => string,
  maxAttempts: number = 10,
  windowMs: number = 60000
) => {
  const attemptCounts = new Map<string, { count: number; resetTime: number }>();

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const cacheKey = cacheKeyExtractor(req);
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    const protectionKey = `${clientIp}:${cacheKey}`;

    try {
      const now = Date.now();
      const attempts = attemptCounts.get(protectionKey);

      // Clean up expired attempts
      if (attempts && now > attempts.resetTime) {
        attemptCounts.delete(protectionKey);
      }

      // Check current attempts
      const currentAttempts = attemptCounts.get(protectionKey) || { count: 0, resetTime: now + windowMs };

      if (currentAttempts.count >= maxAttempts) {
        logger.warn('Cache penetration protection triggered', {
          key: cacheKey,
          clientIp,
          attempts: currentAttempts.count,
        });

        res.status(429).json({
          error: 'Too many requests for this resource',
          retryAfter: Math.ceil((currentAttempts.resetTime - now) / 1000),
        });
        return;
      }

      // Check if data exists in cache
      const cachedData = await multiTierCache.get(cacheKey);
      
      if (!cachedData) {
        // Increment attempt count for cache misses
        currentAttempts.count++;
        attemptCounts.set(protectionKey, currentAttempts);
        
        logger.debug('Cache miss recorded for penetration protection', {
          key: cacheKey,
          clientIp,
          attempts: currentAttempts.count,
        });
      }

      next();
    } catch (error) {
      logger.error('Cache penetration protection error', {
        key: cacheKey,
        error: (error as Error).message,
      });
      next();
    }
  };
};