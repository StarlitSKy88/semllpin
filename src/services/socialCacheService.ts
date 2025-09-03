import { cacheService } from '../config/redis';
import { UserStats } from '../models/User';
import { logger } from '../utils/logger';

/**
 * 社交功能缓存服务
 * 提供高效的缓存策略以提升社交功能性能
 */
export class SocialCacheService {
  // 缓存过期时间配置
  private static readonly CACHE_TTL = {
    USER_STATS: 300, // 5分钟
    FEED: 600, // 10分钟
    RECOMMENDATIONS: 1800, // 30分钟
    FOLLOWING_LIST: 900, // 15分钟
    FOLLOWERS_LIST: 900, // 15分钟
    USER_PROFILE: 1800, // 30分钟
    TRENDING_CONTENT: 3600, // 1小时
  };

  // 缓存键前缀
  private static readonly CACHE_PREFIX = {
    USER_STATS: 'user_stats',
    FEED: 'user_feed',
    RECOMMENDATIONS: 'recommendations',
    FOLLOWING: 'user_following',
    FOLLOWERS: 'user_followers',
    PROFILE: 'user_profile',
    TRENDING: 'trending_content',
    ACTIVITY: 'user_activity',
  };

  // 用户统计数据缓存
  static async getUserStats(userId: string): Promise<UserStats | null> {
    try {
      const key = `${this.CACHE_PREFIX.USER_STATS}:${userId}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取用户统计缓存失败', { userId, error });
      return null;
    }
  }

  static async setUserStats(userId: string, stats: UserStats): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.USER_STATS}:${userId}`;
      await cacheService.setex(key, this.CACHE_TTL.USER_STATS, JSON.stringify(stats));
    } catch (error) {
      logger.error('设置用户统计缓存失败', { userId, error });
    }
  }

  static async invalidateUserStats(userId: string): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.USER_STATS}:${userId}`;
      await cacheService.del(key);
    } catch (error) {
      logger.error('清除用户统计缓存失败', { userId, error });
    }
  }

  // 用户动态流缓存
  static async getUserFeed(userId: string, page: number = 1): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.FEED}:${userId}:page_${page}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取用户动态缓存失败', { userId, page, error });
      return null;
    }
  }

  static async setUserFeed(userId: string, page: number, feedData: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.FEED}:${userId}:page_${page}`;
      await cacheService.setex(key, this.CACHE_TTL.FEED, JSON.stringify(feedData));
    } catch (error) {
      logger.error('设置用户动态缓存失败', { userId, page, error });
    }
  }

  static async invalidateUserFeed(userId: string): Promise<void> {
    try {
      // 清除该用户所有页面的动态缓存
      const pattern = `${this.CACHE_PREFIX.FEED}:${userId}:*`;
      const keys = await cacheService.keys(pattern);
      
      if (keys.length > 0) {
        await cacheService.del(...keys);
      }
    } catch (error) {
      logger.error('清除用户动态缓存失败', { userId, error });
    }
  }

  // 推荐内容缓存
  static async getRecommendations(
    userId: string, 
    type: 'users' | 'content',
    options: string = 'default'
  ): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.RECOMMENDATIONS}:${type}:${userId}:${options}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取推荐缓存失败', { userId, type, error });
      return null;
    }
  }

  static async setRecommendations(
    userId: string,
    type: 'users' | 'content',
    options: string,
    data: any
  ): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.RECOMMENDATIONS}:${type}:${userId}:${options}`;
      await cacheService.setex(key, this.CACHE_TTL.RECOMMENDATIONS, JSON.stringify(data));
    } catch (error) {
      logger.error('设置推荐缓存失败', { userId, type, error });
    }
  }

  static async invalidateRecommendations(userId: string): Promise<void> {
    try {
      const pattern = `${this.CACHE_PREFIX.RECOMMENDATIONS}:*:${userId}:*`;
      const keys = await cacheService.keys(pattern);
      
      if (keys.length > 0) {
        await cacheService.del(...keys);
      }
    } catch (error) {
      logger.error('清除推荐缓存失败', { userId, error });
    }
  }

  // 关注列表缓存
  static async getFollowingList(userId: string, page: number = 1): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.FOLLOWING}:${userId}:page_${page}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取关注列表缓存失败', { userId, page, error });
      return null;
    }
  }

  static async setFollowingList(userId: string, page: number, data: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.FOLLOWING}:${userId}:page_${page}`;
      await cacheService.setex(key, this.CACHE_TTL.FOLLOWING_LIST, JSON.stringify(data));
    } catch (error) {
      logger.error('设置关注列表缓存失败', { userId, page, error });
    }
  }

  // 粉丝列表缓存
  static async getFollowersList(userId: string, page: number = 1): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.FOLLOWERS}:${userId}:page_${page}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取粉丝列表缓存失败', { userId, page, error });
      return null;
    }
  }

  static async setFollowersList(userId: string, page: number, data: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.FOLLOWERS}:${userId}:page_${page}`;
      await cacheService.setex(key, this.CACHE_TTL.FOLLOWERS_LIST, JSON.stringify(data));
    } catch (error) {
      logger.error('设置粉丝列表缓存失败', { userId, page, error });
    }
  }

  // 清除关注相关缓存（关注/取消关注时调用）
  static async invalidateFollowCache(followerId: string, followingId: string): Promise<void> {
    try {
      const promises = [
        // 清除关注者的关注列表缓存
        this.invalidateFollowingCache(followerId),
        // 清除被关注者的粉丝列表缓存
        this.invalidateFollowersCache(followingId),
        // 清除双方的统计缓存
        this.invalidateUserStats(followerId),
        this.invalidateUserStats(followingId),
        // 清除双方的推荐缓存
        this.invalidateRecommendations(followerId),
        this.invalidateRecommendations(followingId),
        // 清除动态流缓存
        this.invalidateUserFeed(followerId),
      ];

      await Promise.all(promises);
    } catch (error) {
      logger.error('清除关注缓存失败', { followerId, followingId, error });
    }
  }

  private static async invalidateFollowingCache(userId: string): Promise<void> {
    try {
      const pattern = `${this.CACHE_PREFIX.FOLLOWING}:${userId}:*`;
      const keys = await cacheService.keys(pattern);
      if (keys.length > 0) {
        await cacheService.del(...keys);
      }
    } catch (error) {
      logger.error('清除关注列表缓存失败', { userId, error });
    }
  }

  private static async invalidateFollowersCache(userId: string): Promise<void> {
    try {
      const pattern = `${this.CACHE_PREFIX.FOLLOWERS}:${userId}:*`;
      const keys = await cacheService.keys(pattern);
      if (keys.length > 0) {
        await cacheService.del(...keys);
      }
    } catch (error) {
      logger.error('清除粉丝列表缓存失败', { userId, error });
    }
  }

  // 用户资料缓存
  static async getUserProfile(userId: string): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.PROFILE}:${userId}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取用户资料缓存失败', { userId, error });
      return null;
    }
  }

  static async setUserProfile(userId: string, profile: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.PROFILE}:${userId}`;
      await cacheService.setex(key, this.CACHE_TTL.USER_PROFILE, JSON.stringify(profile));
    } catch (error) {
      logger.error('设置用户资料缓存失败', { userId, error });
    }
  }

  static async invalidateUserProfile(userId: string): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.PROFILE}:${userId}`;
      await cacheService.del(key);
    } catch (error) {
      logger.error('清除用户资料缓存失败', { userId, error });
    }
  }

  // 热门内容缓存
  static async getTrendingContent(contentType: string = 'all'): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.TRENDING}:${contentType}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取热门内容缓存失败', { contentType, error });
      return null;
    }
  }

  static async setTrendingContent(contentType: string, data: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.TRENDING}:${contentType}`;
      await cacheService.setex(key, this.CACHE_TTL.TRENDING_CONTENT, JSON.stringify(data));
    } catch (error) {
      logger.error('设置热门内容缓存失败', { contentType, error });
    }
  }

  // 用户活动缓存
  static async getUserActivity(userId: string, page: number = 1): Promise<any> {
    try {
      const key = `${this.CACHE_PREFIX.ACTIVITY}:${userId}:page_${page}`;
      const cached = await cacheService.get(key);
      
      if (cached) {
        return JSON.parse(cached);
      }
      
      return null;
    } catch (error) {
      logger.error('获取用户活动缓存失败', { userId, page, error });
      return null;
    }
  }

  static async setUserActivity(userId: string, page: number, data: any): Promise<void> {
    try {
      const key = `${this.CACHE_PREFIX.ACTIVITY}:${userId}:page_${page}`;
      await cacheService.setex(key, this.CACHE_TTL.FEED, JSON.stringify(data));
    } catch (error) {
      logger.error('设置用户活动缓存失败', { userId, page, error });
    }
  }

  static async invalidateUserActivity(userId: string): Promise<void> {
    try {
      const pattern = `${this.CACHE_PREFIX.ACTIVITY}:${userId}:*`;
      const keys = await cacheService.keys(pattern);
      if (keys.length > 0) {
        await cacheService.del(...keys);
      }
    } catch (error) {
      logger.error('清除用户活动缓存失败', { userId, error });
    }
  }

  // 清除与用户相关的所有缓存
  static async invalidateAllUserCache(userId: string): Promise<void> {
    try {
      const promises = [
        this.invalidateUserStats(userId),
        this.invalidateUserFeed(userId),
        this.invalidateRecommendations(userId),
        this.invalidateFollowingCache(userId),
        this.invalidateFollowersCache(userId),
        this.invalidateUserProfile(userId),
        this.invalidateUserActivity(userId),
      ];

      await Promise.all(promises);
      logger.info('清除用户所有缓存完成', { userId });
    } catch (error) {
      logger.error('清除用户所有缓存失败', { userId, error });
    }
  }

  // 预热热门内容缓存
  static async warmupTrendingCache(): Promise<void> {
    try {
      logger.info('开始预热热门内容缓存');
      // 这里可以实现预热逻辑，比如定时更新热门内容
      // 现在只是一个占位符
    } catch (error) {
      logger.error('预热热门内容缓存失败', error);
    }
  }

  // 批量操作缓存清理
  static async batchInvalidateCache(operations: Array<{
    type: 'user_stats' | 'user_feed' | 'recommendations' | 'profile' | 'activity';
    userId: string;
  }>): Promise<void> {
    try {
      const promises = operations.map(op => {
        switch (op.type) {
          case 'user_stats':
            return this.invalidateUserStats(op.userId);
          case 'user_feed':
            return this.invalidateUserFeed(op.userId);
          case 'recommendations':
            return this.invalidateRecommendations(op.userId);
          case 'profile':
            return this.invalidateUserProfile(op.userId);
          case 'activity':
            return this.invalidateUserActivity(op.userId);
          default:
            return Promise.resolve();
        }
      });

      await Promise.all(promises);
      logger.info('批量清除缓存完成', { operationsCount: operations.length });
    } catch (error) {
      logger.error('批量清除缓存失败', { operations, error });
    }
  }

  // 获取缓存统计信息
  static async getCacheStats(): Promise<{
    totalKeys: number;
    socialKeys: number;
    memoryUsage?: string;
  }> {
    try {
      const allKeys = await cacheService.keys('*');
      const socialKeys = allKeys.filter(key => 
        Object.values(this.CACHE_PREFIX).some(prefix => key.startsWith(prefix))
      );

      return {
        totalKeys: allKeys.length,
        socialKeys: socialKeys.length,
      };
    } catch (error) {
      logger.error('获取缓存统计失败', error);
      return {
        totalKeys: 0,
        socialKeys: 0,
      };
    }
  }
}

export default SocialCacheService;