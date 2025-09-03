import { Knex } from 'knex';
import { db } from '../config/database';
import { logger } from '../utils/logger';
import { advancedCacheService, CacheConfigs, CacheTags } from './advancedCacheService';

// 查询优化配置
interface QueryOptimization {
  useIndex?: string;
  forceIndex?: string;
  hint?: string;
  batchSize?: number;
  enableCache?: boolean;
  cacheConfig?: any;
  cacheTags?: CacheTags;
}

// 批量加载器类
class BatchLoader<T, K = string> {
  private queue: Array<{
    key: K;
    resolve: (value: T | null) => void;
    reject: (error: Error) => void;
  }> = [];
  
  private timer: NodeJS.Timeout | null = null;
  private readonly batchSize: number;
  private readonly delay: number;
  private readonly loader: (keys: K[]) => Promise<Map<K, T>>;

  constructor(
    loader: (keys: K[]) => Promise<Map<K, T>>,
    batchSize = 100,
    delay = 10
  ) {
    this.loader = loader;
    this.batchSize = batchSize;
    this.delay = delay;
  }

  load(key: K): Promise<T | null> {
    return new Promise((resolve, reject) => {
      this.queue.push({ key, resolve, reject });
      
      if (this.queue.length >= this.batchSize) {
        this.flush();
      } else if (!this.timer) {
        this.timer = setTimeout(() => this.flush(), this.delay);
      }
    });
  }

  private async flush() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    const currentQueue = [...this.queue];
    this.queue = [];

    if (currentQueue.length === 0) return;

    try {
      const keys = currentQueue.map(item => item.key);
      const results = await this.loader(keys);
      
      currentQueue.forEach(item => {
        const result = results.get(item.key) || null;
        item.resolve(result);
      });
    } catch (error) {
      currentQueue.forEach(item => {
        item.reject(error as Error);
      });
    }
  }
}

// 优化的查询服务
export class OptimizedQueryService {
  private userLoader: BatchLoader<any, string>;
  private mediaLoader: BatchLoader<any[], string>;
  private likesLoader: BatchLoader<number, string>;
  private commentsLoader: BatchLoader<number, string>;

  constructor() {
    // 初始化批量加载器
    this.userLoader = new BatchLoader(this.batchLoadUsers.bind(this), 50, 5);
    this.mediaLoader = new BatchLoader(this.batchLoadMedia.bind(this), 50, 5);
    this.likesLoader = new BatchLoader(this.batchLoadLikes.bind(this), 100, 5);
    this.commentsLoader = new BatchLoader(this.batchLoadComments.bind(this), 100, 5);
  }

  // 批量加载用户信息
  private async batchLoadUsers(userIds: string[]): Promise<Map<string, any>> {
    const cacheKey = 'batch_users';
    const cacheParams = { ids: userIds.sort().join(',') };
    
    // 尝试从缓存获取
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.MEDIUM_TERM,
      cacheParams
    );
    
    if (cached) {
      return new Map(cached || []);
    }

    // 从数据库查询
    const users = await db('users')
      .whereIn('id', userIds)
      .select('id', 'username', 'avatar_url', 'created_at', 'email')
      .timeout(5000);

    const userMap = new Map();
    users.forEach(user => {
      userMap.set(user.id, {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url,
        memberSince: user.created_at,
        email: user.email,
      });
    });

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      Array.from(userMap.entries()),
      {
        ...CacheConfigs.MEDIUM_TERM,
        tags: { entity: 'users', custom: ['batch_load'] }
      },
      cacheParams
    );

    logger.info('Batch loaded users', { 
      requested: userIds.length, 
      found: users.length 
    });

    return userMap;
  }

  // 批量加载媒体文件
  private async batchLoadMedia(annotationIds: string[]): Promise<Map<string, any[]>> {
    const cacheKey = 'batch_media';
    const cacheParams = { ids: annotationIds.sort().join(',') };
    
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.MEDIUM_TERM,
      cacheParams
    );
    
    if (cached) {
      return new Map(cached || []);
    }

    const mediaFiles = await db('media_files')
      .whereIn('annotation_id', annotationIds)
      .where('deleted_at', null)
      .select('*')
      .timeout(5000);

    const mediaMap = new Map();
    annotationIds.forEach(id => mediaMap.set(id, []));
    
    mediaFiles.forEach(file => {
      const annotationMedia = mediaMap.get(file.annotation_id) || [];
      annotationMedia.push({
        id: file.id,
        filename: file.filename,
        originalName: file.original_name || file.original_filename,
        fileUrl: file.file_url,
        fileSize: file.file_size,
        mimeType: file.mime_type,
        fileType: file.file_type,
        width: file.width,
        height: file.height,
        duration: file.duration,
        thumbnailUrl: file.thumbnail_url,
        createdAt: file.created_at,
      });
      mediaMap.set(file.annotation_id, annotationMedia);
    });

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      Array.from(mediaMap.entries()),
      {
        ...CacheConfigs.MEDIUM_TERM,
        tags: { entity: 'media', custom: ['batch_load'] }
      },
      cacheParams
    );

    logger.info('Batch loaded media', { 
      annotations: annotationIds.length, 
      mediaFiles: mediaFiles.length 
    });

    return mediaMap;
  }

  // 批量加载点赞数
  private async batchLoadLikes(annotationIds: string[]): Promise<Map<string, number>> {
    const cacheKey = 'batch_likes';
    const cacheParams = { ids: annotationIds.sort().join(',') };
    
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.SHORT_TERM,
      cacheParams
    );
    
    if (cached) {
      return new Map(cached || []);
    }

    const likes = await db('annotation_likes')
      .whereIn('annotation_id', annotationIds)
      .groupBy('annotation_id')
      .select('annotation_id', db.raw('COUNT(*) as count'))
      .timeout(5000);

    const likesMap = new Map();
    annotationIds.forEach(id => likesMap.set(id, 0));
    
    likes.forEach(like => {
      likesMap.set(like.annotation_id, Number(like.count));
    });

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      Array.from(likesMap.entries()),
      {
        ...CacheConfigs.SHORT_TERM,
        tags: { entity: 'likes', custom: ['batch_load'] }
      },
      cacheParams
    );

    logger.info('Batch loaded likes', { 
      annotations: annotationIds.length 
    });

    return likesMap;
  }

  // 批量加载评论数
  private async batchLoadComments(annotationIds: string[]): Promise<Map<string, number>> {
    const cacheKey = 'batch_comments';
    const cacheParams = { ids: annotationIds.sort().join(',') };
    
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.SHORT_TERM,
      cacheParams
    );
    
    if (cached) {
      return new Map(cached || []);
    }

    const comments = await db('annotation_comments')
      .whereIn('annotation_id', annotationIds)
      .where('deleted_at', null)
      .groupBy('annotation_id')
      .select('annotation_id', db.raw('COUNT(*) as count'))
      .timeout(5000);

    const commentsMap = new Map();
    annotationIds.forEach(id => commentsMap.set(id, 0));
    
    comments.forEach(comment => {
      commentsMap.set(comment.annotation_id, Number(comment.count));
    });

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      Array.from(commentsMap.entries()),
      {
        ...CacheConfigs.SHORT_TERM,
        tags: { entity: 'comments', custom: ['batch_load'] }
      },
      cacheParams
    );

    logger.info('Batch loaded comments', { 
      annotations: annotationIds.length 
    });

    return commentsMap;
  }

  // 优化的注释详情查询
  async getOptimizedAnnotationDetails(
    annotationId: string,
    userId?: string
  ): Promise<any> {
    const cacheKey = 'annotation_details_optimized';
    const cacheParams = { id: annotationId, userId: userId || 'anonymous' };
    
    // 尝试从缓存获取
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.MEDIUM_TERM,
      cacheParams
    );
    
    if (cached) {
      return cached;
    }

    // 获取基本注释信息
    const annotation = await db('annotations')
      .where('id', annotationId)
      .where('deleted_at', null)
      .first()
      .timeout(3000);

    if (!annotation) {
      throw new Error('Annotation not found');
    }

    // 使用批量加载器获取相关数据
    const [user, mediaFiles, likesCount, commentsCount] = await Promise.all([
      this.userLoader.load(annotation.user_id),
      this.mediaLoader.load(annotationId),
      this.likesLoader.load(annotationId),
      this.commentsLoader.load(annotationId),
    ]);

    // 检查用户点赞状态
    let isLikedByUser = false;
    if (userId) {
      const userLike = await db('annotation_likes')
        .where('annotation_id', annotationId)
        .where('user_id', userId)
        .first();
      isLikedByUser = !!userLike;
    }

    // 获取支付信息
    let paymentInfo = null;
    if (annotation.payment_id) {
      const payment = await db('payments')
        .where('id', annotation.payment_id)
        .first();
      
      if (payment) {
        paymentInfo = {
          id: payment.id,
          amount: payment.amount,
          currency: payment.currency,
          status: payment.status,
          paymentMethod: payment.payment_method,
          description: payment.description,
          processedAt: payment.processed_at,
          createdAt: payment.created_at,
        };
      }
    }

    const result = {
      ...annotation,
      user,
      mediaFiles: mediaFiles || [],
      paymentInfo,
      likesCount,
      isLikedByUser,
      commentsCount,
    };

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      result,
      {
        ...CacheConfigs.MEDIUM_TERM,
        tags: { 
          entity: 'annotations', 
          id: annotationId,
          userId: annotation.user_id 
        }
      },
      cacheParams
    );

    return result;
  }

  // 优化的注释列表查询
  async getOptimizedAnnotationsList(
    filters: any,
    pagination: { page: number; limit: number },
    userId?: string
  ): Promise<{ annotations: any[]; total: number; hasMore: boolean }> {
    const cacheKey = 'annotations_list_optimized';
    const cacheParams = { 
      filters: JSON.stringify(filters), 
      pagination: JSON.stringify(pagination),
      userId: userId || 'anonymous'
    };
    
    // 尝试从缓存获取
    const cached = await advancedCacheService.getAdvanced(
      cacheKey,
      CacheConfigs.SHORT_TERM,
      cacheParams
    );
    
    if (cached) {
      return cached;
    }

    // 构建基础查询
    let query = db('annotations')
      .where('deleted_at', null)
      .where('status', 'approved');

    // 应用筛选器
    if (filters.latitude && filters.longitude && filters.radius) {
      // PostGIS地理查询
      if (db.client.config.client === 'postgresql') {
        query = query.whereRaw(
          'ST_DWithin(location_point, ST_Point(?, ?), ?)',
          [filters.longitude, filters.latitude, filters.radius]
        );
      }
    }

    if (filters.intensityMin) {
      query = query.where('smell_intensity', '>=', filters.intensityMin);
    }

    if (filters.intensityMax) {
      query = query.where('smell_intensity', '<=', filters.intensityMax);
    }

    if (filters.startDate) {
      query = query.where('created_at', '>=', filters.startDate);
    }

    if (filters.endDate) {
      query = query.where('created_at', '<=', filters.endDate);
    }

    // 获取总数（用于分页）
    const totalQuery = query.clone();
    const totalResult = await totalQuery.count('* as count').first();
    const total = Number(totalResult?.['count'] || 0);

    // 应用分页和排序
    const offset = (pagination.page - 1) * pagination.limit;
    const annotations = await query
      .orderBy('created_at', 'desc')
      .limit(pagination.limit)
      .offset(offset)
      .select('*')
      .timeout(5000);

    if (annotations.length === 0) {
      return { annotations: [], total, hasMore: false };
    }

    // 批量加载相关数据
    const annotationIds = annotations.map(a => a.id);
    const userIds = [...new Set(annotations.map(a => a.user_id))];

    const [usersMap, mediaMap, likesMap, commentsMap] = await Promise.all([
      this.batchLoadUsers(userIds),
      this.batchLoadMedia(annotationIds),
      this.batchLoadLikes(annotationIds),
      this.batchLoadComments(annotationIds),
    ]);

    // 检查用户点赞状态（如果已登录）
    let userLikesMap = new Map();
    if (userId) {
      const userLikes = await db('annotation_likes')
        .whereIn('annotation_id', annotationIds)
        .where('user_id', userId)
        .select('annotation_id');
      
      userLikes.forEach(like => {
        userLikesMap.set(like.annotation_id, true);
      });
    }

    // 组装结果
    const enrichedAnnotations = annotations.map(annotation => ({
      ...annotation,
      user: usersMap.get(annotation.user_id) || null,
      mediaFiles: mediaMap.get(annotation.id) || [],
      likesCount: likesMap.get(annotation.id) || 0,
      commentsCount: commentsMap.get(annotation.id) || 0,
      isLikedByUser: userLikesMap.has(annotation.id),
    }));

    const result = {
      annotations: enrichedAnnotations,
      total,
      hasMore: offset + annotations.length < total,
    };

    // 缓存结果
    await advancedCacheService.setAdvanced(
      cacheKey,
      result,
      {
        ...CacheConfigs.SHORT_TERM,
        tags: { 
          entity: 'annotations', 
          custom: ['list', 'batch']
        }
      },
      cacheParams
    );

    logger.info('Optimized annotations list query', {
      total,
      returned: annotations.length,
      page: pagination.page,
      limit: pagination.limit,
      filters: Object.keys(filters),
    });

    return result;
  }

  // 清理相关缓存
  async invalidateAnnotationCaches(annotationId?: string, userId?: string): Promise<void> {
    const tags: any = { entity: 'annotations' };
    
    if (annotationId) {
      tags.id = annotationId;
    }
    
    if (userId) {
      tags.userId = userId;
    }

    await advancedCacheService.invalidateByTags(tags);
    
    // 清理相关的批量加载缓存
    await advancedCacheService.invalidateByTags({ 
      custom: ['batch_load'] 
    });

    logger.info('Annotation caches invalidated', { annotationId, userId });
  }

  // 预热常用查询的缓存
  async warmupCommonQueries(): Promise<void> {
    logger.info('Starting cache warmup for common queries');
    
    try {
      // 预热热门地区的注释
      const popularLocations = [
        { latitude: 40.7128, longitude: -74.0060, radius: 10000 }, // NYC
        { latitude: 34.0522, longitude: -118.2437, radius: 10000 }, // LA
        { latitude: 51.5074, longitude: -0.1278, radius: 10000 }, // London
      ];

      const warmupPromises = popularLocations.map(location => 
        this.getOptimizedAnnotationsList(
          location,
          { page: 1, limit: 20 }
        )
      );

      await Promise.allSettled(warmupPromises);
      logger.info('Cache warmup completed');
    } catch (error) {
      logger.error('Cache warmup failed', {
        error: (error as Error).message,
      });
    }
  }
}

// 创建优化查询服务实例
export const optimizedQueryService = new OptimizedQueryService();

// 数据库查询优化工具
export class QueryOptimizer {
  // 添加查询提示
  static addHints(query: Knex.QueryBuilder, optimization: QueryOptimization): Knex.QueryBuilder {
    if (optimization.useIndex) {
      query = query.select(db.raw(`/*+ USE INDEX (${optimization.useIndex}) */`));
    }
    
    if (optimization.forceIndex) {
      query = query.select(db.raw(`/*+ FORCE INDEX (${optimization.forceIndex}) */`));
    }
    
    if (optimization.hint) {
      query = query.select(db.raw(`/*+ ${optimization.hint} */`));
    }

    return query;
  }

  // 分页优化
  static optimizePagination(
    query: Knex.QueryBuilder,
    page: number,
    limit: number,
    maxLimit = 100
  ): Knex.QueryBuilder {
    const safeLimit = Math.min(limit, maxLimit);
    const offset = (page - 1) * safeLimit;
    
    return query.limit(safeLimit).offset(offset);
  }

  // 地理查询优化
  static optimizeGeoQuery(
    query: Knex.QueryBuilder,
    latitude: number,
    longitude: number,
    radius: number
  ): Knex.QueryBuilder {
    if (db.client.config.client === 'postgresql') {
      // 使用PostGIS优化地理查询
      return query.whereRaw(
        'ST_DWithin(location_point, ST_Point(?, ?), ?)',
        [longitude, latitude, radius]
      ).orderByRaw(
        'ST_Distance(location_point, ST_Point(?, ?))',
        [longitude, latitude]
      );
    } else {
      // SQLite的简单实现
      const latRange = radius / 111000; // 约111km每度
      const lonRange = radius / (111000 * Math.cos(latitude * Math.PI / 180));
      
      return query
        .whereBetween('latitude', [latitude - latRange, latitude + latRange])
        .whereBetween('longitude', [longitude - lonRange, longitude + lonRange])
        .orderByRaw(
          '((latitude - ?) * (latitude - ?) + (longitude - ?) * (longitude - ?))',
          [latitude, latitude, longitude, longitude]
        );
    }
  }
}