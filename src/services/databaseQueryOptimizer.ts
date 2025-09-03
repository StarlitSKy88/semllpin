import { Knex } from 'knex';
import { db } from '../config/database';
import { logger } from '../utils/logger';
import { advancedCacheService, CacheConfigs } from './advancedCacheService';

// 查询性能监控接口
interface QueryMetrics {
  queryName: string;
  executionTime: number;
  timestamp: Date;
  sql?: string;
  params?: any[];
  success: boolean;
  error?: string;
}

// 查询优化建议
interface QueryOptimizationSuggestion {
  queryName: string;
  currentExecutionTime: number;
  suggestion: string;
  priority: 'high' | 'medium' | 'low';
  improvement: string;
}

// 数据库查询优化器类
export class DatabaseQueryOptimizer {
  private queryMetrics: QueryMetrics[] = [];
  private readonly MAX_METRICS = 1000;
  private readonly SLOW_QUERY_THRESHOLD = 1000; // 1秒

  // 记录查询性能
  recordQueryMetrics(metrics: QueryMetrics): void {
    this.queryMetrics.push(metrics);
    
    // 保持最大记录数
    if (this.queryMetrics.length > this.MAX_METRICS) {
      this.queryMetrics = this.queryMetrics.slice(-this.MAX_METRICS);
    }

    // 记录慢查询
    if (metrics.executionTime > this.SLOW_QUERY_THRESHOLD) {
      logger.warn('Slow query detected', {
        queryName: metrics.queryName,
        executionTime: metrics.executionTime,
        sql: metrics.sql,
      });
    }
  }

  // 执行带监控的查询
  async executeWithMonitoring<T>(
    queryName: string,
    queryFn: () => Promise<T>
  ): Promise<T> {
    const startTime = Date.now();
    let success = true;
    let error: string | undefined;

    try {
      const result = await queryFn();
      return result;
    } catch (err) {
      success = false;
      error = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      const executionTime = Date.now() - startTime;
      
      this.recordQueryMetrics({
        queryName,
        executionTime,
        timestamp: new Date(),
        success,
        error,
      });
    }
  }

  // 获取性能统计
  getPerformanceStats(): {
    totalQueries: number;
    slowQueries: number;
    averageExecutionTime: number;
    topSlowQueries: QueryMetrics[];
    recentErrors: QueryMetrics[];
  } {
    const slowQueries = this.queryMetrics.filter(
      m => m.executionTime > this.SLOW_QUERY_THRESHOLD
    );
    
    const totalExecutionTime = this.queryMetrics.reduce(
      (sum, m) => sum + m.executionTime, 0
    );
    
    const averageExecutionTime = this.queryMetrics.length > 0 
      ? totalExecutionTime / this.queryMetrics.length 
      : 0;

    const topSlowQueries = [...this.queryMetrics]
      .sort((a, b) => b.executionTime - a.executionTime)
      .slice(0, 10);

    const recentErrors = this.queryMetrics
      .filter(m => !m.success)
      .slice(-10);

    return {
      totalQueries: this.queryMetrics.length,
      slowQueries: slowQueries.length,
      averageExecutionTime,
      topSlowQueries,
      recentErrors,
    };
  }

  // 生成优化建议
  generateOptimizationSuggestions(): QueryOptimizationSuggestion[] {
    const suggestions: QueryOptimizationSuggestion[] = [];
    const stats = this.getPerformanceStats();

    // 分析慢查询模式
    const queryStats = new Map<string, {
      count: number;
      totalTime: number;
      maxTime: number;
    }>();

    this.queryMetrics.forEach(metric => {
      const stat = queryStats.get(metric.queryName) || {
        count: 0,
        totalTime: 0,
        maxTime: 0,
      };
      
      stat.count++;
      stat.totalTime += metric.executionTime;
      stat.maxTime = Math.max(stat.maxTime, metric.executionTime);
      
      queryStats.set(metric.queryName, stat);
    });

    // 生成建议
    queryStats.forEach((stat, queryName) => {
      const avgTime = stat.totalTime / stat.count;
      
      if (avgTime > this.SLOW_QUERY_THRESHOLD) {
        let suggestion = '';
        let priority: 'high' | 'medium' | 'low' = 'medium';
        
        if (queryName.includes('user_stats')) {
          suggestion = '考虑将用户统计信息缓存化，避免每次都计算复杂的联表查询';
          priority = 'high';
        } else if (queryName.includes('location') || queryName.includes('nearby')) {
          suggestion = '优化地理位置查询，确保PostGIS索引已创建并启用';
          priority = 'high';
        } else if (queryName.includes('list') || queryName.includes('pagination')) {
          suggestion = '考虑添加复合索引和分页优化';
          priority = 'medium';
        } else if (avgTime > 2000) {
          suggestion = '该查询执行时间过长，建议拆分为多个简单查询或添加索引';
          priority = 'high';
        } else {
          suggestion = '考虑添加适当的数据库索引';
          priority = 'low';
        }

        suggestions.push({
          queryName,
          currentExecutionTime: avgTime,
          suggestion,
          priority,
          improvement: `可能减少 ${Math.round((1 - 100 / avgTime) * 100)}% 的查询时间`,
        });
      }
    });

    return suggestions.sort((a, b) => {
      const priorityOrder = { high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  // 优化用户统计查询
  async getOptimizedUserStats(userId: string): Promise<any> {
    return this.executeWithMonitoring('user_stats_optimized', async () => {
      const cacheKey = `user_stats_${userId}`;
      
      // 尝试从缓存获取
      const cached = await advancedCacheService.get(cacheKey);
      if (cached) {
        return cached;
      }

      // 使用预聚合的方式获取统计
      const baseUser = await db('users')
        .where('id', userId)
        .first()
        .timeout(3000);

      if (!baseUser) {
        throw new Error('用户不存在');
      }

      // 并行查询所有统计数据
      const [
        annotationsStats,
        likesStats,
        followStats,
        activityStats
      ] = await Promise.all([
        // 注释统计
        db('annotations')
          .where('user_id', userId)
          .where('status', 'approved')
          .count('* as total_annotations')
          .first()
          .timeout(2000),
        
        // 点赞统计
        Promise.all([
          db('annotation_likes as al')
            .join('annotations as a', 'al.annotation_id', 'a.id')
            .where('a.user_id', userId)
            .count('* as likes_received')
            .first()
            .timeout(2000),
          
          db('annotation_likes')
            .where('user_id', userId)
            .count('* as likes_given')
            .first()
            .timeout(2000)
        ]),
        
        // 关注统计
        Promise.all([
          db('user_follows')
            .where('following_id', userId)
            .count('* as followers_count')
            .first()
            .timeout(2000),
          
          db('user_follows')
            .where('follower_id', userId)
            .count('* as following_count')
            .first()
            .timeout(2000)
        ]),
        
        // 活跃度统计
        Promise.all([
          db('annotations')
            .where('user_id', userId)
            .where('created_at', '>=', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))
            .count('* as weekly_posts')
            .first()
            .timeout(2000),
          
          db('annotations')
            .where('user_id', userId)
            .where('created_at', '>=', new Date(Date.now() - 30 * 24 * 60 * 60 * 1000))
            .count('* as monthly_posts')
            .first()
            .timeout(2000)
        ])
      ]);

      const [likesReceived, likesGiven] = likesStats;
      const [followersCount, followingCount] = followStats;
      const [weeklyPosts, monthlyPosts] = activityStats;

      const stats = {
        total_annotations: parseInt(annotationsStats?.['total_annotations'] as string) || 0,
        total_comments: 0,
        total_payments: 0,
        reputation_score: (parseInt(annotationsStats?.['total_annotations'] as string) || 0) * 10 + 
                         (parseInt(likesReceived?.['likes_received'] as string) || 0) * 2,
        followers_count: parseInt(followersCount?.['followers_count'] as string) || 0,
        following_count: parseInt(followingCount?.['following_count'] as string) || 0,
        likes_received: parseInt(likesReceived?.['likes_received'] as string) || 0,
        likes_given: parseInt(likesGiven?.['likes_given'] as string) || 0,
        favorites_count: 0,
        shares_count: 0,
        activity_score: (parseInt(weeklyPosts?.['weekly_posts'] as string) || 0) * 10 + 
                       (parseInt(monthlyPosts?.['monthly_posts'] as string) || 0) * 3,
        weekly_posts: parseInt(weeklyPosts?.['weekly_posts'] as string) || 0,
        monthly_posts: parseInt(monthlyPosts?.['monthly_posts'] as string) || 0,
      };

      // 缓存结果
      await advancedCacheService.set(
        cacheKey,
        stats,
        CacheConfigs.MEDIUM_TERM.ttl
      );

      return stats;
    });
  }

  // 优化注释列表查询
  async getOptimizedAnnotationsList(filters: any, pagination: any): Promise<any> {
    return this.executeWithMonitoring('annotations_list_optimized', async () => {
      const cacheKey = `annotations_list_${JSON.stringify({ filters, pagination })}`;
      
      const cached = await advancedCacheService.get(cacheKey);
      if (cached) {
        return cached;
      }

      let query = db('annotations as a')
        .leftJoin('users as u', 'a.user_id', 'u.id')
        .where('a.deleted_at', null)
        .where('a.status', 'approved')
        .select(
          'a.*',
          'u.username',
          'u.avatar_url',
          'u.created_at as user_created_at'
        );

      // 应用地理筛选（使用索引优化）
      if (filters.latitude && filters.longitude && filters.radius) {
        if (db.client.config.client === 'postgresql') {
          // PostGIS 优化查询
          query = query
            .whereRaw(
              'ST_DWithin(a.location_point, ST_Point(?, ?), ?)',
              [filters.longitude, filters.latitude, filters.radius]
            )
            .orderByRaw(
              'ST_Distance(a.location_point, ST_Point(?, ?)) ASC',
              [filters.longitude, filters.latitude]
            );
        } else {
          // SQLite 简化实现
          const latRange = filters.radius / 111000;
          const lonRange = filters.radius / (111000 * Math.cos(filters.latitude * Math.PI / 180));
          
          query = query
            .whereBetween('a.latitude', [filters.latitude - latRange, filters.latitude + latRange])
            .whereBetween('a.longitude', [filters.longitude - lonRange, filters.longitude + lonRange]);
        }
      }

      // 其他筛选条件
      if (filters.intensityMin) {
        query = query.where('a.smell_intensity', '>=', filters.intensityMin);
      }
      
      if (filters.intensityMax) {
        query = query.where('a.smell_intensity', '<=', filters.intensityMax);
      }

      if (filters.startDate) {
        query = query.where('a.created_at', '>=', filters.startDate);
      }

      if (filters.endDate) {
        query = query.where('a.created_at', '<=', filters.endDate);
      }

      // 获取总数（优化版本）
      const countQuery = query.clone()
        .select(db.raw('COUNT(DISTINCT a.id) as count'))
        .first();

      // 应用分页和排序
      const offset = (pagination.page - 1) * pagination.limit;
      const dataQuery = query
        .orderBy('a.created_at', 'desc')
        .limit(pagination.limit)
        .offset(offset)
        .timeout(5000);

      const [countResult, annotations] = await Promise.all([
        countQuery,
        dataQuery
      ]);

      const total = Number(countResult?.['count'] || 0);

      // 批量获取媒体文件和点赞数
      if (annotations.length > 0) {
        const annotationIds = annotations.map((a: any) => a.id);
        
        const [mediaFiles, likeCounts] = await Promise.all([
          db('media_files')
            .whereIn('annotation_id', annotationIds)
            .where('deleted_at', null)
            .select('*')
            .timeout(3000),
          
          db('annotation_likes')
            .whereIn('annotation_id', annotationIds)
            .groupBy('annotation_id')
            .select('annotation_id', db.raw('COUNT(*) as count'))
            .timeout(3000)
        ]);

        // 组装数据
        const mediaMap = new Map();
        const likesMap = new Map();
        
        mediaFiles.forEach((file: any) => {
          if (!mediaMap.has(file.annotation_id)) {
            mediaMap.set(file.annotation_id, []);
          }
          mediaMap.get(file.annotation_id).push(file);
        });

        likeCounts.forEach((like: any) => {
          likesMap.set(like.annotation_id, Number(like.count));
        });

        // 添加关联数据
        annotations.forEach((annotation: any) => {
          annotation.mediaFiles = mediaMap.get(annotation.id) || [];
          annotation.likesCount = likesMap.get(annotation.id) || 0;
          annotation.user = {
            id: annotation.user_id,
            username: annotation.username,
            avatarUrl: annotation.avatar_url,
            memberSince: annotation.user_created_at,
          };
          
          // 清理重复字段
          delete annotation.username;
          delete annotation.avatar_url;
          delete annotation.user_created_at;
        });
      }

      const result = {
        annotations,
        total,
        hasMore: offset + annotations.length < total,
      };

      // 缓存结果（短期缓存）
      await advancedCacheService.set(
        cacheKey,
        result,
        CacheConfigs.SHORT_TERM.ttl
      );

      logger.info('Optimized annotations list query completed', {
        total,
        returned: annotations.length,
        page: pagination.page,
        limit: pagination.limit,
      });

      return result;
    });
  }

  // 优化地理位置查询
  async getOptimizedNearbyAnnotations(
    latitude: number,
    longitude: number,
    radius: number = 1000,
    limit: number = 20
  ): Promise<any[]> {
    return this.executeWithMonitoring('nearby_annotations_optimized', async () => {
      const cacheKey = `nearby_${latitude}_${longitude}_${radius}_${limit}`;
      
      const cached = await advancedCacheService.get(cacheKey);
      if (cached && Array.isArray(cached)) {
        return cached;
      }

      let query = db('annotations')
        .where('status', 'approved')
        .where('deleted_at', null);

      if (db.client.config.client === 'postgresql') {
        // 使用 PostGIS 优化查询
        const result = await query
          .whereRaw(
            'ST_DWithin(location_point, ST_Point(?, ?), ?)',
            [longitude, latitude, radius]
          )
          .select('*')
          .select(db.raw(
            'ST_Distance(location_point, ST_Point(?, ?)) as distance',
            [longitude, latitude]
          ))
          .orderBy('distance')
          .limit(limit)
          .timeout(3000);

        // 缓存结果
        await advancedCacheService.set(
          cacheKey,
          result,
          CacheConfigs.SHORT_TERM.ttl
        );

        return result;
      } else {
        // SQLite 简化实现
        const latRange = radius / 111000;
        const lonRange = radius / (111000 * Math.cos(latitude * Math.PI / 180));
        
        const result = await query
          .whereBetween('latitude', [latitude - latRange, latitude + latRange])
          .whereBetween('longitude', [longitude - lonRange, longitude + lonRange])
          .orderByRaw(
            '((latitude - ?) * (latitude - ?) + (longitude - ?) * (longitude - ?))',
            [latitude, latitude, longitude, longitude]
          )
          .limit(limit)
          .timeout(3000);

        await advancedCacheService.set(
          cacheKey,
          result,
          CacheConfigs.SHORT_TERM.ttl
        );

        return result;
      }
    });
  }

  // 获取性能报告
  getPerformanceReport(): {
    stats: ReturnType<DatabaseQueryOptimizer['getPerformanceStats']>;
    suggestions: QueryOptimizationSuggestion[];
    databaseHealth: any;
  } {
    const stats = this.getPerformanceStats();
    const suggestions = this.generateOptimizationSuggestions();
    
    // 简单的数据库健康评估
    const healthScore = Math.max(0, 100 - (stats.slowQueries / stats.totalQueries) * 100);
    const databaseHealth = {
      score: Math.round(healthScore),
      status: healthScore >= 90 ? 'excellent' : 
              healthScore >= 70 ? 'good' : 
              healthScore >= 50 ? 'fair' : 'poor',
      recommendations: suggestions.slice(0, 3).map(s => s.suggestion),
    };

    return {
      stats,
      suggestions,
      databaseHealth,
    };
  }

  // 清理旧的性能指标
  cleanupMetrics(olderThanHours: number = 24): void {
    const cutoff = new Date(Date.now() - olderThanHours * 60 * 60 * 1000);
    this.queryMetrics = this.queryMetrics.filter(
      m => m.timestamp > cutoff
    );
    
    logger.info('Query metrics cleaned up', {
      remaining: this.queryMetrics.length,
      cutoffHours: olderThanHours,
    });
  }

  // 重置所有指标
  resetMetrics(): void {
    this.queryMetrics = [];
    logger.info('All query metrics have been reset');
  }
}

// 创建单例实例
export const databaseQueryOptimizer = new DatabaseQueryOptimizer();

// 数据库索引管理器
export class DatabaseIndexManager {
  // 检查现有索引
  async checkExistingIndexes(): Promise<any[]> {
    try {
      if (db.client.config.client === 'postgresql') {
        const result = await db.raw(`
          SELECT 
            schemaname,
            tablename,
            indexname,
            indexdef
          FROM pg_indexes 
          WHERE schemaname = 'public'
          ORDER BY tablename, indexname;
        `);
        return result.rows;
      } else {
        // SQLite
        const tables = await db.raw("SELECT name FROM sqlite_master WHERE type='table'");
        const indexes = [];
        
        for (const table of tables) {
          const tableIndexes = await db.raw(`PRAGMA index_list('${table.name}')`);
          for (const index of tableIndexes) {
            const indexInfo = await db.raw(`PRAGMA index_info('${index.name}')`);
            indexes.push({
              tablename: table.name,
              indexname: index.name,
              unique: index.unique,
              columns: indexInfo.map((col: any) => col.name)
            });
          }
        }
        
        return indexes;
      }
    } catch (error) {
      logger.error('Failed to check existing indexes', { error });
      return [];
    }
  }

  // 分析表统计信息
  async analyzeTableStats(): Promise<any[]> {
    try {
      if (db.client.config.client === 'postgresql') {
        const result = await db.raw(`
          SELECT 
            schemaname,
            tablename,
            n_tup_ins as inserts,
            n_tup_upd as updates,
            n_tup_del as deletes,
            n_live_tup as live_tuples,
            n_dead_tup as dead_tuples,
            last_vacuum,
            last_autovacuum,
            last_analyze,
            last_autoanalyze
          FROM pg_stat_user_tables
          ORDER BY n_live_tup DESC;
        `);
        return result.rows;
      } else {
        // SQLite 没有详细的统计信息，返回基本表信息
        const tables = await db.raw("SELECT name FROM sqlite_master WHERE type='table'");
        const stats = [];
        
        for (const table of tables) {
          const count = await db(table.name).count('* as count').first();
          stats.push({
            tablename: table.name,
            live_tuples: count?.['count'] || 0,
          });
        }
        
        return stats;
      }
    } catch (error) {
      logger.error('Failed to analyze table stats', { error });
      return [];
    }
  }

  // 建议缺失的索引
  suggestMissingIndexes(): Array<{ table: string; columns: string[]; reason: string; sql: string }> {
    const suggestions = [
      {
        table: 'annotations',
        columns: ['status', 'created_at'],
        reason: '用于筛选已批准的注释并按时间排序',
        sql: 'CREATE INDEX IF NOT EXISTS idx_annotations_status_created ON annotations(status, created_at);'
      },
      {
        table: 'annotations',
        columns: ['user_id', 'status'],
        reason: '用于获取用户的注释列表',
        sql: 'CREATE INDEX IF NOT EXISTS idx_annotations_user_status ON annotations(user_id, status);'
      },
      {
        table: 'annotations',
        columns: ['latitude', 'longitude'],
        reason: '用于地理位置查询',
        sql: 'CREATE INDEX IF NOT EXISTS idx_annotations_location ON annotations(latitude, longitude);'
      },
      {
        table: 'annotation_likes',
        columns: ['annotation_id', 'user_id'],
        reason: '用于点赞查询和防重复点赞',
        sql: 'CREATE UNIQUE INDEX IF NOT EXISTS idx_annotation_likes_unique ON annotation_likes(annotation_id, user_id);'
      },
      {
        table: 'annotation_likes',
        columns: ['user_id', 'created_at'],
        reason: '用于获取用户点赞历史',
        sql: 'CREATE INDEX IF NOT EXISTS idx_annotation_likes_user_time ON annotation_likes(user_id, created_at);'
      },
      {
        table: 'media_files',
        columns: ['annotation_id', 'deleted_at'],
        reason: '用于获取注释的媒体文件',
        sql: 'CREATE INDEX IF NOT EXISTS idx_media_files_annotation_active ON media_files(annotation_id, deleted_at);'
      },
      {
        table: 'user_follows',
        columns: ['follower_id', 'status'],
        reason: '用于获取关注列表',
        sql: 'CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id, status);'
      },
      {
        table: 'user_follows',
        columns: ['following_id', 'status'],
        reason: '用于获取粉丝列表',
        sql: 'CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id, status);'
      }
    ];

    return suggestions;
  }
}

// 创建索引管理器实例
export const databaseIndexManager = new DatabaseIndexManager();

export default databaseQueryOptimizer;