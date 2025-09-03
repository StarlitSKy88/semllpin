import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface RecommendationUser {
  id: string;
  username: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  followers_count: number;
  following_count: number;
  annotations_count: number;
  similarity_score: number;
  recommendation_reason: string[];
  mutual_follows: number;
}

export interface RecommendationContent {
  id: string;
  type: 'annotation' | 'comment';
  title?: string;
  content: string;
  author: {
    id: string;
    username: string;
    display_name?: string;
    avatar_url?: string;
  };
  location?: {
    latitude: number;
    longitude: number;
    city?: string;
  };
  engagement: {
    likes: number;
    comments: number;
    shares: number;
  };
  relevance_score: number;
  recommendation_reason: string[];
  created_at: Date;
}

export class SocialRecommendationModel {
  // 推荐用户关注
  static async recommendUsers(
    userId: string,
    options: {
      limit?: number;
      excludeFollowing?: boolean;
      includeLocationBased?: boolean;
      userLat?: number;
      userLon?: number;
      radius?: number; // 公里
    } = {}
  ): Promise<RecommendationUser[]> {
    try {
      const {
        limit = 10,
        excludeFollowing = true,
        includeLocationBased = false,
        userLat,
        userLon,
        radius = 50
      } = options;

      // 获取用户当前关注的人
      const currentFollowing = excludeFollowing
        ? await db('user_follows')
            .where('follower_id', userId)
            .pluck('following_id')
        : [];

      // 获取用户的兴趣标签（基于他们的标注和互动）
      const userInterests = await this.getUserInterests(userId);
      
      // 构建推荐查询
      let recommendations: RecommendationUser[] = [];

      // 1. 基于共同关注的推荐
      const mutualFollowsRecs = await this.getRecommendationsByMutualFollows(
        userId,
        currentFollowing,
        Math.ceil(limit * 0.4)
      );
      recommendations = [...recommendations, ...mutualFollowsRecs];

      // 2. 基于相似兴趣的推荐
      const interestBasedRecs = await this.getRecommendationsByInterests(
        userId,
        userInterests,
        currentFollowing,
        Math.ceil(limit * 0.4)
      );
      recommendations = [...recommendations, ...interestBasedRecs];

      // 3. 基于地理位置的推荐
      if (includeLocationBased && userLat && userLon) {
        const locationBasedRecs = await this.getRecommendationsByLocation(
          userId,
          userLat,
          userLon,
          radius,
          currentFollowing,
          Math.ceil(limit * 0.3)
        );
        recommendations = [...recommendations, ...locationBasedRecs];
      }

      // 4. 活跃用户推荐
      const activeUsersRecs = await this.getActiveUsersRecommendations(
        userId,
        currentFollowing,
        Math.ceil(limit * 0.3)
      );
      recommendations = [...recommendations, ...activeUsersRecs];

      // 去重并按相似度排序
      const uniqueRecs = this.deduplicateAndSort(recommendations, limit);

      logger.info('用户推荐生成成功', { userId, count: uniqueRecs.length });
      return uniqueRecs;
    } catch (error) {
      logger.error('生成用户推荐失败', { userId, error });
      throw error;
    }
  }

  // 推荐内容
  static async recommendContent(
    userId: string,
    options: {
      limit?: number;
      contentType?: 'annotation' | 'comment' | 'all';
      includeLocationBased?: boolean;
      userLat?: number;
      userLon?: number;
      radius?: number;
    } = {}
  ): Promise<RecommendationContent[]> {
    try {
      const {
        limit = 20,
        contentType = 'all',
        includeLocationBased = false,
        userLat,
        userLon,
        radius = 20
      } = options;

      // 获取用户兴趣
      const userInterests = await this.getUserInterests(userId);
      
      let recommendations: RecommendationContent[] = [];

      // 1. 基于关注用户的内容推荐
      const followingContentRecs = await this.getContentFromFollowing(
        userId,
        contentType,
        Math.ceil(limit * 0.4)
      );
      recommendations = [...recommendations, ...followingContentRecs];

      // 2. 基于兴趣的内容推荐
      const interestContentRecs = await this.getContentByInterests(
        userId,
        userInterests,
        contentType,
        Math.ceil(limit * 0.3)
      );
      recommendations = [...recommendations, ...interestContentRecs];

      // 3. 基于地理位置的内容推荐
      if (includeLocationBased && userLat && userLon) {
        const locationContentRecs = await this.getContentByLocation(
          userId,
          userLat,
          userLon,
          radius,
          contentType,
          Math.ceil(limit * 0.4)
        );
        recommendations = [...recommendations, ...locationContentRecs];
      }

      // 4. 热门内容推荐
      const trendingContentRecs = await this.getTrendingContent(
        userId,
        contentType,
        Math.ceil(limit * 0.3)
      );
      recommendations = [...recommendations, ...trendingContentRecs];

      // 去重并按相关性排序
      const uniqueContentRecs = this.deduplicateContentAndSort(recommendations, limit);

      logger.info('内容推荐生成成功', { userId, count: uniqueContentRecs.length });
      return uniqueContentRecs;
    } catch (error) {
      logger.error('生成内容推荐失败', { userId, error });
      throw error;
    }
  }

  // 获取用户兴趣标签
  private static async getUserInterests(userId: string): Promise<string[]> {
    try {
      // 基于用户的标注分析兴趣
      const annotations = await db('annotations')
        .where('user_id', userId)
        .where('status', 'approved')
        .select('smell_intensity', 'description', 'city', 'country')
        .orderBy('created_at', 'desc')
        .limit(50);

      const interests: string[] = [];

      // 分析气味强度偏好
      const avgIntensity = annotations.reduce((sum, a) => sum + a.smell_intensity, 0) / annotations.length;
      if (avgIntensity >= 7) {
        interests.push('high_intensity');
      } else if (avgIntensity <= 3) {
        interests.push('low_intensity');
      } else {
        interests.push('medium_intensity');
      }

      // 分析地理偏好
      const cities = annotations.map(a => a.city).filter(Boolean);
      const uniqueCities = [...new Set(cities)];
      if (uniqueCities.length <= 2) {
        interests.push('local_focused');
      } else {
        interests.push('explorer');
      }

      // 分析描述关键词
      const descriptions = annotations.map(a => a.description).filter(Boolean).join(' ');
      if (descriptions.includes('工业') || descriptions.includes('化工')) {
        interests.push('industrial');
      }
      if (descriptions.includes('餐厅') || descriptions.includes('食物')) {
        interests.push('food_related');
      }
      if (descriptions.includes('垃圾') || descriptions.includes('污染')) {
        interests.push('environmental');
      }

      return interests;
    } catch (error) {
      logger.error('获取用户兴趣失败', { userId, error });
      return [];
    }
  }

  // 基于共同关注推荐用户
  private static async getRecommendationsByMutualFollows(
    userId: string,
    excludeIds: string[],
    limit: number
  ): Promise<RecommendationUser[]> {
    const query = `
      SELECT 
        u.id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.bio,
        COUNT(DISTINCT f1.following_id) as mutual_follows,
        COUNT(DISTINCT followers.follower_id) as followers_count,
        COUNT(DISTINCT following.following_id) as following_count,
        COUNT(DISTINCT a.id) as annotations_count
      FROM users u
      JOIN user_follows f2 ON f2.following_id = u.id
      JOIN user_follows f1 ON f1.following_id = f2.follower_id
      LEFT JOIN user_follows followers ON followers.following_id = u.id
      LEFT JOIN user_follows following ON following.follower_id = u.id
      LEFT JOIN annotations a ON a.user_id = u.id AND a.status = 'approved'
      WHERE f1.follower_id = ?
        AND u.id != ?
        AND u.status = 'active'
        ${excludeIds.length > 0 ? `AND u.id NOT IN (${excludeIds.map(() => '?').join(',')})` : ''}
      GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
      HAVING mutual_follows >= 2
      ORDER BY mutual_follows DESC, followers_count DESC
      LIMIT ?
    `;

    const params = [userId, userId, ...excludeIds, limit];
    
    const results = await db.raw(query, params);
    
    return results.map((row: any) => ({
      id: row.id,
      username: row.username,
      display_name: row.display_name,
      avatar_url: row.avatar_url,
      bio: row.bio,
      followers_count: parseInt(row.followers_count) || 0,
      following_count: parseInt(row.following_count) || 0,
      annotations_count: parseInt(row.annotations_count) || 0,
      mutual_follows: parseInt(row.mutual_follows) || 0,
      similarity_score: Math.min(parseInt(row.mutual_follows) * 0.3 + parseInt(row.followers_count) * 0.001, 1),
      recommendation_reason: [`${row.mutual_follows}个共同关注`]
    }));
  }

  // 基于兴趣推荐用户
  private static async getRecommendationsByInterests(
    userId: string,
    _userInterests: string[],
    excludeIds: string[],
    limit: number
  ): Promise<RecommendationUser[]> {
    // 这里简化处理，实际可以基于更复杂的兴趣匹配算法
    const query = `
      SELECT 
        u.id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.bio,
        COUNT(DISTINCT followers.follower_id) as followers_count,
        COUNT(DISTINCT following.following_id) as following_count,
        COUNT(DISTINCT a.id) as annotations_count,
        AVG(a.smell_intensity) as avg_intensity
      FROM users u
      LEFT JOIN user_follows followers ON followers.following_id = u.id
      LEFT JOIN user_follows following ON following.follower_id = u.id
      LEFT JOIN annotations a ON a.user_id = u.id AND a.status = 'approved'
      WHERE u.id != ?
        AND u.status = 'active'
        ${excludeIds.length > 0 ? `AND u.id NOT IN (${excludeIds.map(() => '?').join(',')})` : ''}
      GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
      HAVING annotations_count > 0
      ORDER BY annotations_count DESC, followers_count DESC
      LIMIT ?
    `;

    const params = [userId, ...excludeIds, limit];
    const results = await db.raw(query, params);
    
    return results.map((row: any) => ({
      id: row.id,
      username: row.username,
      display_name: row.display_name,
      avatar_url: row.avatar_url,
      bio: row.bio,
      followers_count: parseInt(row.followers_count) || 0,
      following_count: parseInt(row.following_count) || 0,
      annotations_count: parseInt(row.annotations_count) || 0,
      mutual_follows: 0,
      similarity_score: Math.min(parseInt(row.annotations_count) * 0.05, 1),
      recommendation_reason: ['相似的标注偏好']
    }));
  }

  // 基于地理位置推荐用户
  private static async getRecommendationsByLocation(
    userId: string,
    userLat: number,
    userLon: number,
    radius: number,
    excludeIds: string[],
    limit: number
  ): Promise<RecommendationUser[]> {
    // 简化的地理位置推荐
    const latDelta = radius / 111; // 1度约111公里
    const lonDelta = radius / (111 * Math.cos(userLat * Math.PI / 180));

    const query = `
      SELECT DISTINCT
        u.id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.bio,
        COUNT(DISTINCT followers.follower_id) as followers_count,
        COUNT(DISTINCT following.following_id) as following_count,
        COUNT(DISTINCT a.id) as annotations_count
      FROM users u
      JOIN annotations a ON a.user_id = u.id AND a.status = 'approved'
      LEFT JOIN user_follows followers ON followers.following_id = u.id
      LEFT JOIN user_follows following ON following.follower_id = u.id
      WHERE u.id != ?
        AND u.status = 'active'
        AND a.latitude BETWEEN ? AND ?
        AND a.longitude BETWEEN ? AND ?
        ${excludeIds.length > 0 ? `AND u.id NOT IN (${excludeIds.map(() => '?').join(',')})` : ''}
      GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
      ORDER BY annotations_count DESC
      LIMIT ?
    `;

    const params = [
      userId,
      userLat - latDelta,
      userLat + latDelta,
      userLon - lonDelta,
      userLon + lonDelta,
      ...excludeIds,
      limit
    ];

    const results = await db.raw(query, params);
    
    return results.map((row: any) => ({
      id: row.id,
      username: row.username,
      display_name: row.display_name,
      avatar_url: row.avatar_url,
      bio: row.bio,
      followers_count: parseInt(row.followers_count) || 0,
      following_count: parseInt(row.following_count) || 0,
      annotations_count: parseInt(row.annotations_count) || 0,
      mutual_follows: 0,
      similarity_score: Math.min(parseInt(row.annotations_count) * 0.05, 1),
      recommendation_reason: [`附近${radius}km内的活跃用户`]
    }));
  }

  // 获取活跃用户推荐
  private static async getActiveUsersRecommendations(
    userId: string,
    excludeIds: string[],
    limit: number
  ): Promise<RecommendationUser[]> {
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    const query = `
      SELECT 
        u.id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.bio,
        COUNT(DISTINCT followers.follower_id) as followers_count,
        COUNT(DISTINCT following.following_id) as following_count,
        COUNT(DISTINCT a.id) as annotations_count,
        COUNT(DISTINCT recent_a.id) as recent_annotations
      FROM users u
      LEFT JOIN user_follows followers ON followers.following_id = u.id
      LEFT JOIN user_follows following ON following.follower_id = u.id
      LEFT JOIN annotations a ON a.user_id = u.id AND a.status = 'approved'
      LEFT JOIN annotations recent_a ON recent_a.user_id = u.id AND recent_a.status = 'approved' AND recent_a.created_at > ?
      WHERE u.id != ?
        AND u.status = 'active'
        ${excludeIds.length > 0 ? `AND u.id NOT IN (${excludeIds.map(() => '?').join(',')})` : ''}
      GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
      HAVING recent_annotations > 0
      ORDER BY recent_annotations DESC, followers_count DESC
      LIMIT ?
    `;

    const params = [weekAgo, userId, ...excludeIds, limit];
    const results = await db.raw(query, params);
    
    return results.map((row: any) => ({
      id: row.id,
      username: row.username,
      display_name: row.display_name,
      avatar_url: row.avatar_url,
      bio: row.bio,
      followers_count: parseInt(row.followers_count) || 0,
      following_count: parseInt(row.following_count) || 0,
      annotations_count: parseInt(row.annotations_count) || 0,
      mutual_follows: 0,
      similarity_score: Math.min(parseInt(row.recent_annotations) * 0.1, 1),
      recommendation_reason: ['本周活跃用户']
    }));
  }

  // 获取关注用户的内容
  private static async getContentFromFollowing(
    userId: string,
    contentType: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    if (contentType === 'comment') {
      return this.getCommentsFromFollowing(userId, limit);
    } else {
      return this.getAnnotationsFromFollowing(userId, limit);
    }
  }

  // 获取关注用户的标注
  private static async getAnnotationsFromFollowing(
    userId: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    const query = `
      SELECT 
        a.id,
        a.description as content,
        a.latitude,
        a.longitude,
        a.city,
        a.like_count as likes,
        a.comment_count as comments,
        a.view_count,
        a.created_at,
        u.id as author_id,
        u.username as author_username,
        u.display_name as author_display_name,
        u.avatar_url as author_avatar_url,
        COALESCE(s.share_count, 0) as shares
      FROM annotations a
      JOIN user_follows f ON f.following_id = a.user_id
      JOIN users u ON u.id = a.user_id
      LEFT JOIN (
        SELECT annotation_id, COUNT(*) as share_count
        FROM share_records
        GROUP BY annotation_id
      ) s ON s.annotation_id = a.id
      WHERE f.follower_id = ?
        AND a.status = 'approved'
      ORDER BY a.created_at DESC, a.like_count DESC
      LIMIT ?
    `;

    const results = await db.raw(query, [userId, limit]);
    
    return results.map((row: any) => ({
      id: row.id,
      type: 'annotation' as const,
      content: row.content || '',
      author: {
        id: row.author_id,
        username: row.author_username,
        display_name: row.author_display_name,
        avatar_url: row.author_avatar_url,
      },
      location: row.latitude && row.longitude ? {
        latitude: row.latitude,
        longitude: row.longitude,
        city: row.city,
      } : undefined,
      engagement: {
        likes: parseInt(row.likes) || 0,
        comments: parseInt(row.comments) || 0,
        shares: parseInt(row.shares) || 0,
      },
      relevance_score: 0.8, // 关注用户的内容有较高相关性
      recommendation_reason: ['来自关注的用户'],
      created_at: row.created_at,
    }));
  }

  // 获取关注用户的评论
  private static async getCommentsFromFollowing(
    userId: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    const query = `
      SELECT 
        c.id,
        c.content,
        c.likes_count as likes,
        c.created_at,
        c.annotation_id,
        u.id as author_id,
        u.username as author_username,
        u.display_name as author_display_name,
        u.avatar_url as author_avatar_url
      FROM comments c
      JOIN user_follows f ON f.following_id = c.user_id
      JOIN users u ON u.id = c.user_id
      WHERE f.follower_id = ?
        AND c.status = 'active'
      ORDER BY c.created_at DESC, c.likes_count DESC
      LIMIT ?
    `;

    const results = await db.raw(query, [userId, limit]);
    
    return results.map((row: any) => ({
      id: row.id,
      type: 'comment' as const,
      content: row.content,
      author: {
        id: row.author_id,
        username: row.author_username,
        display_name: row.author_display_name,
        avatar_url: row.author_avatar_url,
      },
      engagement: {
        likes: parseInt(row.likes) || 0,
        comments: 0,
        shares: 0,
      },
      relevance_score: 0.7,
      recommendation_reason: ['来自关注用户的评论'],
      created_at: row.created_at,
    }));
  }

  // 基于兴趣获取内容
  private static async getContentByInterests(
    userId: string,
    _interests: string[],
    contentType: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    // 简化实现，实际应该基于更复杂的兴趣匹配
    return this.getTrendingContent(userId, contentType, limit);
  }

  // 基于位置获取内容
  private static async getContentByLocation(
    userId: string,
    userLat: number,
    userLon: number,
    radius: number,
    contentType: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    if (contentType === 'comment') return [];

    const latDelta = radius / 111;
    const lonDelta = radius / (111 * Math.cos(userLat * Math.PI / 180));

    const query = `
      SELECT 
        a.id,
        a.description as content,
        a.latitude,
        a.longitude,
        a.city,
        a.like_count as likes,
        a.comment_count as comments,
        a.view_count,
        a.created_at,
        u.id as author_id,
        u.username as author_username,
        u.display_name as author_display_name,
        u.avatar_url as author_avatar_url,
        COALESCE(s.share_count, 0) as shares
      FROM annotations a
      JOIN users u ON u.id = a.user_id
      LEFT JOIN (
        SELECT annotation_id, COUNT(*) as share_count
        FROM share_records
        GROUP BY annotation_id
      ) s ON s.annotation_id = a.id
      WHERE a.status = 'approved'
        AND a.user_id != ?
        AND a.latitude BETWEEN ? AND ?
        AND a.longitude BETWEEN ? AND ?
      ORDER BY a.created_at DESC, a.like_count DESC
      LIMIT ?
    `;

    const params = [
      userId,
      userLat - latDelta,
      userLat + latDelta,
      userLon - lonDelta,
      userLon + lonDelta,
      limit
    ];

    const results = await db.raw(query, params);
    
    return results.map((row: any) => ({
      id: row.id,
      type: 'annotation' as const,
      content: row.content || '',
      author: {
        id: row.author_id,
        username: row.author_username,
        display_name: row.author_display_name,
        avatar_url: row.author_avatar_url,
      },
      location: {
        latitude: row.latitude,
        longitude: row.longitude,
        city: row.city,
      },
      engagement: {
        likes: parseInt(row.likes) || 0,
        comments: parseInt(row.comments) || 0,
        shares: parseInt(row.shares) || 0,
      },
      relevance_score: 0.6,
      recommendation_reason: [`附近${radius}km内的内容`],
      created_at: row.created_at,
    }));
  }

  // 获取热门内容
  private static async getTrendingContent(
    userId: string,
    contentType: string,
    limit: number
  ): Promise<RecommendationContent[]> {
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    if (contentType === 'comment') {
      const query = `
        SELECT 
          c.id,
          c.content,
          c.likes_count as likes,
          c.created_at,
          c.annotation_id,
          u.id as author_id,
          u.username as author_username,
          u.display_name as author_display_name,
          u.avatar_url as author_avatar_url
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.status = 'active'
          AND c.user_id != ?
          AND c.created_at > ?
        ORDER BY c.likes_count DESC, c.created_at DESC
        LIMIT ?
      `;

      const results = await db.raw(query, [userId, weekAgo, limit]);
      
      return results.map((row: any) => ({
        id: row.id,
        type: 'comment' as const,
        content: row.content,
        author: {
          id: row.author_id,
          username: row.author_username,
          display_name: row.author_display_name,
          avatar_url: row.author_avatar_url,
        },
        engagement: {
          likes: parseInt(row.likes) || 0,
          comments: 0,
          shares: 0,
        },
        relevance_score: 0.5,
        recommendation_reason: ['本周热门评论'],
        created_at: row.created_at,
      }));
    } else {
      const query = `
        SELECT 
          a.id,
          a.description as content,
          a.latitude,
          a.longitude,
          a.city,
          a.like_count as likes,
          a.comment_count as comments,
          a.view_count,
          a.created_at,
          u.id as author_id,
          u.username as author_username,
          u.display_name as author_display_name,
          u.avatar_url as author_avatar_url,
          COALESCE(s.share_count, 0) as shares,
          (a.like_count * 2 + a.comment_count * 3 + COALESCE(s.share_count, 0) * 5) as engagement_score
        FROM annotations a
        JOIN users u ON u.id = a.user_id
        LEFT JOIN (
          SELECT annotation_id, COUNT(*) as share_count
          FROM share_records
          WHERE created_at > ?
          GROUP BY annotation_id
        ) s ON s.annotation_id = a.id
        WHERE a.status = 'approved'
          AND a.user_id != ?
          AND a.created_at > ?
        ORDER BY engagement_score DESC, a.created_at DESC
        LIMIT ?
      `;

      const results = await db.raw(query, [weekAgo, userId, weekAgo, limit]);
      
      return results.map((row: any) => ({
        id: row.id,
        type: 'annotation' as const,
        content: row.content || '',
        author: {
          id: row.author_id,
          username: row.author_username,
          display_name: row.author_display_name,
          avatar_url: row.author_avatar_url,
        },
        location: row.latitude && row.longitude ? {
          latitude: row.latitude,
          longitude: row.longitude,
          city: row.city,
        } : undefined,
        engagement: {
          likes: parseInt(row.likes) || 0,
          comments: parseInt(row.comments) || 0,
          shares: parseInt(row.shares) || 0,
        },
        relevance_score: 0.5,
        recommendation_reason: ['本周热门内容'],
        created_at: row.created_at,
      }));
    }
  }

  // 去重并排序用户推荐
  private static deduplicateAndSort(
    recommendations: RecommendationUser[],
    limit: number
  ): RecommendationUser[] {
    const uniqueUsers = new Map<string, RecommendationUser>();
    
    recommendations.forEach(rec => {
      if (!uniqueUsers.has(rec.id)) {
        uniqueUsers.set(rec.id, rec);
      } else {
        // 如果已存在，合并推荐理由并取更高的相似度分数
        const existing = uniqueUsers.get(rec.id)!;
        existing.similarity_score = Math.max(existing.similarity_score, rec.similarity_score);
        existing.recommendation_reason = [...new Set([...existing.recommendation_reason, ...rec.recommendation_reason])];
      }
    });

    return Array.from(uniqueUsers.values())
      .sort((a, b) => b.similarity_score - a.similarity_score)
      .slice(0, limit);
  }

  // 去重并排序内容推荐
  private static deduplicateContentAndSort(
    recommendations: RecommendationContent[],
    limit: number
  ): RecommendationContent[] {
    const uniqueContent = new Map<string, RecommendationContent>();
    
    recommendations.forEach(rec => {
      const key = `${rec.type}_${rec.id}`;
      if (!uniqueContent.has(key)) {
        uniqueContent.set(key, rec);
      } else {
        // 如果已存在，合并推荐理由并取更高的相关性分数
        const existing = uniqueContent.get(key)!;
        existing.relevance_score = Math.max(existing.relevance_score, rec.relevance_score);
        existing.recommendation_reason = [...new Set([...existing.recommendation_reason, ...rec.recommendation_reason])];
      }
    });

    return Array.from(uniqueContent.values())
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, limit);
  }
}

export default SocialRecommendationModel;