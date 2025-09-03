import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface UserFeed {
  id: string;
  user_id: string;
  actor_id: string; // 执行动作的用户ID
  action_type: 'annotation' | 'like' | 'comment' | 'follow' | 'share' | 'favorite';
  target_type: 'annotation' | 'user' | 'comment';
  target_id: string;
  metadata?: any; // 存储额外信息，如评论内容、标注描述等
  privacy_level: 'public' | 'followers' | 'private';
  created_at: Date;
}

export interface CreateFeedData {
  user_id: string;
  actor_id: string;
  action_type: 'annotation' | 'like' | 'comment' | 'follow' | 'share' | 'favorite';
  target_type: 'annotation' | 'user' | 'comment';
  target_id: string;
  metadata?: any;
  privacy_level?: 'public' | 'followers' | 'private';
}

export interface FeedItem {
  id: string;
  action_type: string;
  target_type: string;
  target_id: string;
  metadata: any;
  privacy_level: string;
  created_at: Date;
  // Actor information
  actor: {
    id: string;
    username: string;
    display_name?: string;
    avatar_url?: string;
  };
  // Target information (annotation, user, etc.)
  target?: {
    id: string;
    [key: string]: any;
  };
}

const TABLE_NAME = 'user_feeds';

export class UserFeedModel {
  // 创建动态记录
  static async create(feedData: CreateFeedData): Promise<string> {
    try {
      const feedId = uuidv4();
      
      await db(TABLE_NAME).insert({
        id: feedId,
        user_id: feedData.user_id,
        actor_id: feedData.actor_id,
        action_type: feedData.action_type,
        target_type: feedData.target_type,
        target_id: feedData.target_id,
        metadata: JSON.stringify(feedData.metadata || {}),
        privacy_level: feedData.privacy_level || 'public',
        created_at: new Date(),
      });

      logger.info('用户动态创建成功', { feedId, userId: feedData.user_id });
      return feedId;
    } catch (error) {
      logger.error('用户动态创建失败', error);
      throw error;
    }
  }

  // 获取用户的关注动态流
  static async getFeedForUser(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      includeOwnActivity?: boolean;
    } = {}
  ): Promise<{ feeds: FeedItem[]; total: number }> {
    try {
      const { page = 1, limit = 20, includeOwnActivity = false } = options;
      const offset = (page - 1) * limit;

      // 构建查询，获取用户关注的人的动态
      let query = db(TABLE_NAME)
        .select(
          `${TABLE_NAME}.*`,
          'actors.username as actor_username',
          'actors.display_name as actor_display_name',
          'actors.avatar_url as actor_avatar_url'
        )
        .leftJoin('users as actors', `${TABLE_NAME}.actor_id`, 'actors.id')
        .where(function() {
          // 获取关注用户的动态
          this.whereIn(`${TABLE_NAME}.actor_id`, function() {
            this.select('following_id')
              .from('user_follows')
              .where('follower_id', userId);
          });
          
          // 如果包含自己的动态
          if (includeOwnActivity) {
            this.orWhere(`${TABLE_NAME}.actor_id`, userId);
          }
        })
        .where(function() {
          // 隐私级别过滤
          this.where('privacy_level', 'public')
            .orWhere(function() {
              // followers级别：用户关注了actor或者是actor本人
              this.where('privacy_level', 'followers')
                .where(function() {
                  this.whereExists(function() {
                    this.select('*')
                      .from('user_follows')
                      .whereRaw(`user_follows.follower_id = '${userId}'`)
                      .whereRaw(`user_follows.following_id = ${TABLE_NAME}.actor_id`);
                  }).orWhere(`${TABLE_NAME}.actor_id`, userId);
                });
            });
        })
        .orderBy(`${TABLE_NAME}.created_at`, 'desc');

      // 获取总数
      const countResult = await query.clone().count('* as count');
      const total = parseInt((countResult[0] as any).count, 10);

      // 获取动态列表
      const feeds = await query
        .limit(limit)
        .offset(offset);

      // 为每个动态获取目标对象的详细信息
      const feedItems: FeedItem[] = await Promise.all(
        feeds.map(async (feed) => {
          const target = await this.getTargetDetails(feed.target_type, feed.target_id);
          
          return {
            id: feed.id,
            action_type: feed.action_type,
            target_type: feed.target_type,
            target_id: feed.target_id,
            metadata: JSON.parse(feed.metadata || '{}'),
            privacy_level: feed.privacy_level,
            created_at: feed.created_at,
            actor: {
              id: feed.actor_id,
              username: feed.actor_username,
              display_name: feed.actor_display_name,
              avatar_url: feed.actor_avatar_url,
            },
            target,
          };
        })
      );

      return { feeds: feedItems, total };
    } catch (error) {
      logger.error('获取用户动态流失败', { userId, error });
      throw error;
    }
  }

  // 获取用户自己的动态历史
  static async getUserActivity(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      actionType?: string;
    } = {}
  ): Promise<{ feeds: FeedItem[]; total: number }> {
    try {
      const { page = 1, limit = 20, actionType } = options;
      const offset = (page - 1) * limit;

      let query = db(TABLE_NAME)
        .select(
          `${TABLE_NAME}.*`,
          'actors.username as actor_username',
          'actors.display_name as actor_display_name',
          'actors.avatar_url as actor_avatar_url'
        )
        .leftJoin('users as actors', `${TABLE_NAME}.actor_id`, 'actors.id')
        .where(`${TABLE_NAME}.actor_id`, userId);

      if (actionType) {
        query = query.where('action_type', actionType);
      }

      query = query.orderBy(`${TABLE_NAME}.created_at`, 'desc');

      // 获取总数
      const countResult = await query.clone().count('* as count');
      const total = parseInt((countResult[0] as any).count, 10);

      // 获取动态列表
      const feeds = await query
        .limit(limit)
        .offset(offset);

      // 为每个动态获取目标对象的详细信息
      const feedItems: FeedItem[] = await Promise.all(
        feeds.map(async (feed) => {
          const target = await this.getTargetDetails(feed.target_type, feed.target_id);
          
          return {
            id: feed.id,
            action_type: feed.action_type,
            target_type: feed.target_type,
            target_id: feed.target_id,
            metadata: JSON.parse(feed.metadata || '{}'),
            privacy_level: feed.privacy_level,
            created_at: feed.created_at,
            actor: {
              id: feed.actor_id,
              username: feed.actor_username,
              display_name: feed.actor_display_name,
              avatar_url: feed.actor_avatar_url,
            },
            target,
          };
        })
      );

      return { feeds: feedItems, total };
    } catch (error) {
      logger.error('获取用户活动历史失败', { userId, error });
      throw error;
    }
  }

  // 获取目标对象详细信息
  private static async getTargetDetails(targetType: string, targetId: string): Promise<any> {
    try {
      switch (targetType) {
        case 'annotation':
          const annotation = await db('annotations')
            .select(
              'id',
              'user_id',
              'latitude',
              'longitude',
              'smell_intensity',
              'description',
              'status',
              'view_count',
              'like_count',
              'comment_count',
              'created_at'
            )
            .where('id', targetId)
            .first();
          
          if (annotation) {
            // 获取标注作者信息
            const author = await db('users')
              .select('id', 'username', 'display_name', 'avatar_url')
              .where('id', annotation.user_id)
              .first();
            
            return {
              ...annotation,
              author
            };
          }
          break;

        case 'user':
          const user = await db('users')
            .select('id', 'username', 'display_name', 'avatar_url', 'bio')
            .where('id', targetId)
            .first();
          return user;

        case 'comment':
          const comment = await db('comments')
            .select(
              'id',
              'annotation_id',
              'user_id',
              'content',
              'likes_count',
              'created_at'
            )
            .where('id', targetId)
            .first();
          
          if (comment) {
            // 获取评论作者信息
            const author = await db('users')
              .select('id', 'username', 'display_name', 'avatar_url')
              .where('id', comment.user_id)
              .first();
            
            return {
              ...comment,
              author
            };
          }
          break;
      }
      
      return null;
    } catch (error) {
      logger.error('获取目标详情失败', { targetType, targetId, error });
      return null;
    }
  }

  // 创建标注动态
  static async createAnnotationFeed(userId: string, annotationId: string, metadata?: any): Promise<string> {
    return this.create({
      user_id: userId,
      actor_id: userId,
      action_type: 'annotation',
      target_type: 'annotation',
      target_id: annotationId,
      metadata,
      privacy_level: 'public'
    });
  }

  // 创建点赞动态
  static async createLikeFeed(userId: string, targetType: 'annotation' | 'comment', targetId: string, targetOwnerId: string): Promise<string> {
    return this.create({
      user_id: targetOwnerId, // 动态显示在被点赞内容的作者的feed中
      actor_id: userId,
      action_type: 'like',
      target_type: targetType,
      target_id: targetId,
      privacy_level: 'public'
    });
  }

  // 创建评论动态
  static async createCommentFeed(userId: string, commentId: string, annotationId: string, annotationOwnerId: string, metadata?: any): Promise<string> {
    return this.create({
      user_id: annotationOwnerId,
      actor_id: userId,
      action_type: 'comment',
      target_type: 'comment',
      target_id: commentId,
      metadata: { annotationId, ...metadata },
      privacy_level: 'public'
    });
  }

  // 创建关注动态
  static async createFollowFeed(followerId: string, followingId: string): Promise<string> {
    return this.create({
      user_id: followingId,
      actor_id: followerId,
      action_type: 'follow',
      target_type: 'user',
      target_id: followingId,
      privacy_level: 'followers'
    });
  }

  // 创建分享动态
  static async createShareFeed(userId: string, annotationId: string, platform: string, annotationOwnerId: string): Promise<string> {
    return this.create({
      user_id: annotationOwnerId,
      actor_id: userId,
      action_type: 'share',
      target_type: 'annotation',
      target_id: annotationId,
      metadata: { platform },
      privacy_level: 'public'
    });
  }

  // 创建收藏动态
  static async createFavoriteFeed(userId: string, annotationId: string, annotationOwnerId: string): Promise<string> {
    return this.create({
      user_id: annotationOwnerId,
      actor_id: userId,
      action_type: 'favorite',
      target_type: 'annotation',
      target_id: annotationId,
      privacy_level: 'followers'
    });
  }

  // 清理过期动态（可以定期运行）
  static async cleanOldFeeds(daysToKeep: number = 90): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const deletedCount = await db(TABLE_NAME)
        .where('created_at', '<', cutoffDate)
        .del();

      logger.info(`清理了 ${deletedCount} 条过期动态`);
      return deletedCount;
    } catch (error) {
      logger.error('清理过期动态失败', error);
      throw error;
    }
  }

  // 删除特定用户的动态
  static async deleteUserFeeds(userId: string): Promise<number> {
    try {
      const deletedCount = await db(TABLE_NAME)
        .where('actor_id', userId)
        .del();

      logger.info(`删除了用户 ${userId} 的 ${deletedCount} 条动态`);
      return deletedCount;
    } catch (error) {
      logger.error('删除用户动态失败', { userId, error });
      throw error;
    }
  }
}

export default UserFeedModel;