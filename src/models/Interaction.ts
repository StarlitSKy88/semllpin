import { db } from '../config/database';
import { logger } from '../utils/logger';

// 点赞类型枚举
export enum LikeType {
  ANNOTATION = 'annotation',
  COMMENT = 'comment',
  USER = 'user'
}

// 收藏类型枚举
export enum FavoriteType {
  ANNOTATION = 'annotation',
  USER = 'user'
}

// 点赞接口
export interface Like {
  id: string;
  userId: string;
  targetId: string;
  targetType: LikeType;
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    username: string;
    avatar?: string;
  };
}

// 收藏接口
export interface Favorite {
  id: string;
  userId: string;
  targetId: string;
  targetType: FavoriteType;
  createdAt: Date;
  updatedAt: Date;
  annotation?: {
    id: string;
    title: string;
    description: string;
    imageUrl?: string;
    location: string;
    latitude: number;
    longitude: number;
  };
  user?: {
    id: string;
    username: string;
    avatar?: string;
  };
}

// 互动统计接口
export interface InteractionStats {
  targetId: string;
  targetType: string;
  likeCount: number;
  favoriteCount: number;
  isLiked: boolean;
  isFavorited: boolean;
}

// 创建点赞数据接口
export interface CreateLikeData {
  userId: string;
  targetId: string;
  targetType: LikeType;
}

// 创建收藏数据接口
export interface CreateFavoriteData {
  userId: string;
  targetId: string;
  targetType: FavoriteType;
}

// 用户活动统计接口
export interface UserActivityStats {
  timeRange: string;
  totalLikes: number;
  totalFavorites: number;
  totalActivity: number;
  likesByType: Record<string, number>;
  favoritesByType: Record<string, number>;
  dailyActivity: Array<{
    date: string;
    likes: number;
    favorites: number;
    total: number;
  }>;
  averageDailyActivity: number;
}

// 热门内容接口
export interface PopularContent {
  targetId: string;
  targetType: string;
  likeCount: number;
  recentLikes: Like[];
}

// 点赞模型类
export class LikeModel {
  // 创建点赞
  static async create(data: CreateLikeData): Promise<Like> {
    try {
      const id = `like_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();

      const query = `
        INSERT INTO likes (id, user_id, target_id, target_type, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `;

      const result = await db.raw(query, [
        id,
        data.userId,
        data.targetId,
        data.targetType,
        now,
        now,
      ]);

      logger.info('点赞创建成功', { likeId: id, userId: data.userId, targetId: data.targetId });
      return this.mapRowToLike(result.rows[0]);
    } catch (error) {
      logger.error('创建点赞失败', { error, data });
      throw error;
    }
  }

  // 删除点赞
  static async delete(userId: string, targetId: string, targetType: LikeType): Promise<boolean> {
    try {
      const query = `
        DELETE FROM likes 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;

      const result = await db.raw(query, [userId, targetId, targetType]);

      logger.info('点赞删除成功', { userId, targetId, targetType });
      return result.rowCount > 0;
    } catch (error) {
      logger.error('删除点赞失败', { error, userId, targetId, targetType });
      throw error;
    }
  }

  // 检查是否已点赞
  static async exists(userId: string, targetId: string, targetType: LikeType): Promise<boolean> {
    try {
      const query = `
        SELECT 1 FROM likes 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;

      const result = await db.raw(query, [userId, targetId, targetType]);
      return result.rowCount > 0;
    } catch (error) {
      logger.error('检查点赞状态失败', { error, userId, targetId, targetType });
      throw error;
    }
  }

  // 获取用户点赞列表
  static async getUserLikes(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      targetType?: LikeType;
    } = {},
  ): Promise<{ likes: Like[]; total: number }> {
    try {
      const { page = 1, limit = 20, targetType } = options;
      const offset = (page - 1) * limit;

      let whereClause = 'WHERE l.user_id = $1';
      const params: any[] = [userId];

      if (targetType) {
        whereClause += ' AND l.target_type = $2';
        params.push(targetType);
      }

      // 获取总数
      const countQuery = `
        SELECT COUNT(*) as total
        FROM likes l
        ${whereClause}
      `;
      const countResult = await db.raw(countQuery, params);
      const total = parseInt(countResult.rows[0].total);

      // 获取数据
      const dataQuery = `
        SELECT l.*, u.username, u.avatar
        FROM likes l
        LEFT JOIN users u ON l.user_id = u.id
        ${whereClause}
        ORDER BY l.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
      params.push(limit, offset);

      const result = await db.raw(dataQuery, params);
      const likes = result.rows.map((row: any) => this.mapRowToLike(row));

      return { likes, total };
    } catch (error) {
      logger.error('获取用户点赞列表失败', { error, userId, options });
      throw error;
    }
  }

  // 获取目标的点赞统计
  static async getTargetLikeCount(targetId: string, targetType: LikeType): Promise<number> {
    try {
      const query = `
        SELECT COUNT(*) as count
        FROM likes
        WHERE target_id = $1 AND target_type = $2
      `;

      const result = await db.raw(query, [targetId, targetType]);
      return parseInt(result.rows[0].count);
    } catch (error) {
      logger.error('获取点赞统计失败', { error, targetId, targetType });
      throw error;
    }
  }

  // 获取热门内容
  static async getPopularContent(
    options: {
      targetType?: LikeType;
      limit?: number;
      timeRange?: string;
    } = {},
  ): Promise<PopularContent[]> {
    try {
      const { targetType, limit = 10, timeRange = '7d' } = options;

      // 计算时间范围
      let timeFilter = '';
      if (timeRange !== 'all') {
        const days = timeRange === '1d' ? 1 : timeRange === '7d' ? 7 : 30;
        timeFilter = `AND l.created_at >= NOW() - INTERVAL '${days} days'`;
      }

      let whereClause = 'WHERE 1=1';
      const params: any[] = [];

      if (targetType) {
        whereClause += ' AND l.target_type = $1';
        params.push(targetType);
      }

      const query = `
        SELECT 
          l.target_id,
          l.target_type,
          COUNT(*) as like_count,
          ARRAY_AGG(
            JSON_BUILD_OBJECT(
              'id', l.id,
              'userId', l.user_id,
              'createdAt', l.created_at,
              'user', JSON_BUILD_OBJECT(
                'id', u.id,
                'username', u.username,
                'avatar', u.avatar
              )
            ) ORDER BY l.created_at DESC
          ) as recent_likes
        FROM likes l
        LEFT JOIN users u ON l.user_id = u.id
        ${whereClause} ${timeFilter}
        GROUP BY l.target_id, l.target_type
        ORDER BY like_count DESC
        LIMIT $${params.length + 1}
      `;
      params.push(limit);

      const result = await db.raw(query, params);

      return result.rows.map((row: any) => ({
        targetId: row.target_id,
        targetType: row.target_type,
        likeCount: parseInt(row.like_count),
        recentLikes: row.recent_likes.slice(0, 5), // 只返回最近5个
      }));
    } catch (error) {
      logger.error('获取热门内容失败', { error, options });
      throw error;
    }
  }

  // 映射数据库行到Like对象
  private static mapRowToLike(row: any): Like {
    const like: Like = {
      id: row.id,
      userId: row.user_id,
      targetId: row.target_id,
      targetType: row.target_type as LikeType,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };

    if (row.username) {
      like.user = {
        id: row.user_id,
        username: row.username,
        avatar: row.avatar,
      };
    }

    return like;
  }
}

// 收藏模型类
export class FavoriteModel {
  // 创建收藏
  static async create(data: CreateFavoriteData): Promise<Favorite> {
    try {
      const id = `favorite_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();

      const query = `
        INSERT INTO favorites (id, user_id, target_id, target_type, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `;

      const result = await db.raw(query, [
        id,
        data.userId,
        data.targetId,
        data.targetType,
        now,
        now,
      ]);

      logger.info('收藏创建成功', { favoriteId: id, userId: data.userId, targetId: data.targetId });
      return this.mapRowToFavorite(result.rows[0]);
    } catch (error) {
      logger.error('创建收藏失败', { error, data });
      throw error;
    }
  }

  // 删除收藏
  static async delete(userId: string, targetId: string, targetType: FavoriteType): Promise<boolean> {
    try {
      const query = `
        DELETE FROM favorites 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;

      const result = await db.raw(query, [userId, targetId, targetType]);

      logger.info('收藏删除成功', { userId, targetId, targetType });
      return result.rowCount > 0;
    } catch (error) {
      logger.error('删除收藏失败', { error, userId, targetId, targetType });
      throw error;
    }
  }

  // 检查是否已收藏
  static async exists(userId: string, targetId: string, targetType: FavoriteType): Promise<boolean> {
    try {
      const query = `
        SELECT 1 FROM favorites 
        WHERE user_id = $1 AND target_id = $2 AND target_type = $3
      `;

      const result = await db.raw(query, [userId, targetId, targetType]);
      return result.rowCount > 0;
    } catch (error) {
      logger.error('检查收藏状态失败', { error, userId, targetId, targetType });
      throw error;
    }
  }

  // 获取用户收藏列表
  static async getUserFavorites(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      targetType?: FavoriteType;
    } = {},
  ): Promise<{ favorites: Favorite[]; total: number }> {
    try {
      const { page = 1, limit = 20, targetType } = options;
      const offset = (page - 1) * limit;

      let whereClause = 'WHERE f.user_id = $1';
      const params: any[] = [userId];

      if (targetType) {
        whereClause += ' AND f.target_type = $2';
        params.push(targetType);
      }

      // 获取总数
      const countQuery = `
        SELECT COUNT(*) as total
        FROM favorites f
        ${whereClause}
      `;
      const countResult = await db.raw(countQuery, params);
      const total = parseInt(countResult.rows[0].total);

      // 获取数据
      const dataQuery = `
        SELECT 
          f.*,
          u.username,
          u.avatar,
          a.description as annotation_description,
          a.latitude as annotation_latitude,
          a.longitude as annotation_longitude,
          a.address as annotation_address
        FROM favorites f
        LEFT JOIN users u ON f.user_id = u.id
        LEFT JOIN annotations a ON f.target_type = 'annotation' AND f.target_id = a.id
        ${whereClause}
        ORDER BY f.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
      params.push(limit, offset);

      const result = await db.raw(dataQuery, params);
      const favorites = result.rows.map((row: any) => this.mapRowToFavorite(row));

      return { favorites, total };
    } catch (error) {
      logger.error('获取用户收藏列表失败', { error, userId, options });
      throw error;
    }
  }

  // 获取目标的收藏统计
  static async getTargetFavoriteCount(targetId: string, targetType: FavoriteType): Promise<number> {
    try {
      const query = `
        SELECT COUNT(*) as count
        FROM favorites
        WHERE target_id = $1 AND target_type = $2
      `;

      const result = await db.raw(query, [targetId, targetType]);
      return parseInt(result.rows[0].count);
    } catch (error) {
      logger.error('获取收藏统计失败', { error, targetId, targetType });
      throw error;
    }
  }

  // 映射数据库行到Favorite对象
  private static mapRowToFavorite(row: any): Favorite {
    const favorite: Favorite = {
      id: row.id,
      userId: row.user_id,
      targetId: row.target_id,
      targetType: row.target_type as FavoriteType,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };

    // 添加用户信息
    if (row.username) {
      favorite.user = {
        id: row.user_id,
        username: row.username,
        avatar: row.avatar,
      };
    }

    // 添加标注信息
    if (row.target_type === 'annotation' && row.annotation_description) {
      favorite.annotation = {
        id: row.target_id,
        title: `标注 ${row.target_id.slice(-4)}`,
        description: row.annotation_description,
        location: row.annotation_address || '未知位置',
        latitude: parseFloat(row.annotation_latitude) || 0,
        longitude: parseFloat(row.annotation_longitude) || 0,
      };
    }

    return favorite;
  }
}

// 交互统计模型类
export class InteractionModel {
  // 获取互动统计
  static async getInteractionStats(
    targetId: string,
    targetType: string,
    userId?: string,
  ): Promise<InteractionStats> {
    try {
      // 获取点赞数
      const likeCount = await LikeModel.getTargetLikeCount(targetId, targetType as LikeType);

      // 获取收藏数
      const favoriteCount = await FavoriteModel.getTargetFavoriteCount(targetId, targetType as FavoriteType);

      // 检查用户是否已点赞和收藏
      let isLiked = false;
      let isFavorited = false;

      if (userId) {
        isLiked = await LikeModel.exists(userId, targetId, targetType as LikeType);
        isFavorited = await FavoriteModel.exists(userId, targetId, targetType as FavoriteType);
      }

      return {
        targetId,
        targetType,
        likeCount,
        favoriteCount,
        isLiked,
        isFavorited,
      };
    } catch (error) {
      logger.error('获取互动统计失败', { error, targetId, targetType, userId });
      throw error;
    }
  }

  // 获取用户活动统计
  static async getUserActivityStats(
    userId: string,
    timeRange: string = '7d',
  ): Promise<UserActivityStats> {
    try {
      // 计算时间范围
      let timeFilter = '';
      let days = 7;

      if (timeRange !== 'all') {
        days = timeRange === '1d' ? 1 : timeRange === '7d' ? 7 : 30;
        timeFilter = `AND created_at >= NOW() - INTERVAL '${days} days'`;
      }

      // 获取点赞统计
      const likeQuery = `
        SELECT 
          COUNT(*) as total,
          target_type,
          DATE(created_at) as date
        FROM likes
        WHERE user_id = $1 ${timeFilter}
        GROUP BY target_type, DATE(created_at)
        ORDER BY date DESC
      `;
      const likeResult = await db.raw(likeQuery, [userId]);

      // 获取收藏统计
      const favoriteQuery = `
        SELECT 
          COUNT(*) as total,
          target_type,
          DATE(created_at) as date
        FROM favorites
        WHERE user_id = $1 ${timeFilter}
        GROUP BY target_type, DATE(created_at)
        ORDER BY date DESC
      `;
      const favoriteResult = await db.raw(favoriteQuery, [userId]);

      // 处理统计数据
      const likesByType: Record<string, number> = {};
      const favoritesByType: Record<string, number> = {};
      const dailyData: Record<string, { likes: number; favorites: number }> = {};

      let totalLikes = 0;
      let totalFavorites = 0;

      // 处理点赞数据
      likeResult.rows.forEach((row: any) => {
        const count = parseInt(row.total);
        totalLikes += count;
        likesByType[row.target_type] = (likesByType[row.target_type] || 0) + count;

        const date = row.date.toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = { likes: 0, favorites: 0 };
        }
        dailyData[date].likes += count;
      });

      // 处理收藏数据
      favoriteResult.rows.forEach((row: any) => {
        const count = parseInt(row.total);
        totalFavorites += count;
        favoritesByType[row.target_type] = (favoritesByType[row.target_type] || 0) + count;

        const date = row.date.toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = { likes: 0, favorites: 0 };
        }
        dailyData[date].favorites += count;
      });

      // 生成每日活动数据
      const dailyActivity = [];
      const now = new Date();

      for (let i = days - 1; i >= 0; i--) {
        const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        const dateStr = date.toISOString().split('T')[0];
        const dayData = dailyData[dateStr!] || { likes: 0, favorites: 0 };

        dailyActivity.push({
          date: dateStr!,
          likes: dayData.likes,
          favorites: dayData.favorites,
          total: dayData.likes + dayData.favorites,
        });
      }

      return {
        timeRange,
        totalLikes,
        totalFavorites,
        totalActivity: totalLikes + totalFavorites,
        likesByType,
        favoritesByType,
        dailyActivity,
        averageDailyActivity: Math.round((totalLikes + totalFavorites) / days * 10) / 10,
      };
    } catch (error) {
      logger.error('获取用户活动统计失败', { error, userId, timeRange });
      throw error;
    }
  }
}
