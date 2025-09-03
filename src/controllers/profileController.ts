import { Request, Response } from 'express';
import { UserModel, UserStats } from '../models/User';
import { AnnotationModel } from '../models/Annotation';
import { UserFeedModel } from '../models/UserFeed';
import { logger } from '../utils/logger';
import { db } from '../config/database';

interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

export interface UserProfile {
  id: string;
  username: string;
  display_name?: string;
  bio?: string;
  avatar_url?: string;
  university?: string;
  graduation_year?: number;
  role: string;
  created_at: Date;
  // 统计信息
  stats: UserStats;
  // 社交关系
  social: {
    is_following: boolean;
    is_followed_by: boolean;
    mutual_follows: number;
  };
  // 隐私设置
  privacy: {
    profile_visibility: 'public' | 'followers' | 'private';
    activity_visibility: 'public' | 'followers' | 'private';
    location_visibility: 'public' | 'followers' | 'private';
  };
}

export interface UserAchievement {
  id: string;
  type: 'first_annotation' | 'milestone_posts' | 'popular_content' | 'social_butterfly' | 'explorer' | 'consistency';
  title: string;
  description: string;
  icon: string;
  earned_at: Date;
  progress?: number;
  target?: number;
}

/**
 * 用户资料控制器
 * 处理用户个人资料的展示和管理
 */
export class ProfileController {
  // 获取用户资料
  static async getUserProfile(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      // 获取基本用户信息
      const user = await UserModel.findById(userId as string);
      if (!user) {
        return res.status(404).json({ error: '用户不存在' });
      }

      // 检查隐私设置和权限
      const canViewProfile = await this.checkProfileViewPermission(userId as string, currentUserId);
      if (!canViewProfile) {
        return res.status(403).json({ error: '该用户的资料不公开' });
      }

      // 获取用户统计信息
      const stats = await UserModel.getStats(userId as string);

      // 获取社交关系信息
      const social = await this.getSocialRelationship(userId as string, currentUserId);

      // 获取隐私设置
      const privacy = await this.getUserPrivacySettings(userId as string);

      const profile: UserProfile = {
        id: user.id,
        username: user.username,
        ...(user.display_name && { display_name: user.display_name }),
        ...(user.bio && { bio: user.bio }),
        ...(user.avatar_url && { avatar_url: user.avatar_url }),
        ...(user.university && { university: user.university }),
        ...(user.graduation_year && { graduation_year: user.graduation_year }),
        role: user.role,
        created_at: user.created_at,
        stats,
        social,
        privacy
      };

      return res.json({
        success: true,
        data: { profile }
      });
    } catch (error) {
      logger.error('获取用户资料失败', error);
      return res.status(500).json({ 
        error: '获取用户资料失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 更新用户资料
  static async updateUserProfile(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      if (!userId) {
        return res.status(400).json({ error: '用户ID不能为空' });
      }

      // 检查权限：只有用户本人可以更新资料
      if (currentUserId !== userId) {
        return res.status(403).json({ error: '只能更新自己的资料' });
      }

      const {
        display_name,
        bio,
        avatar_url
      } = req.body;

      // 验证输入
      if (display_name && display_name.length > 50) {
        return res.status(400).json({ error: '显示名称不能超过50个字符' });
      }

      if (bio && bio.length > 500) {
        return res.status(400).json({ error: '个人简介不能超过500个字符' });
      }



      // 更新用户信息
      const updatedUser = await UserModel.update(userId as string, {
        display_name,
        bio,
        avatar_url
      });

      if (!updatedUser) {
        return res.status(404).json({ error: '用户不存在' });
      }

      return res.json({
        success: true,
        data: {
          user: {
            id: updatedUser.id,
            username: updatedUser.username,
            display_name: updatedUser.display_name,
            bio: updatedUser.bio,
            avatar_url: updatedUser.avatar_url,
            university: updatedUser.university,
            graduation_year: updatedUser.graduation_year,
            updated_at: updatedUser.updated_at
          }
        },
        message: '资料更新成功'
      });
    } catch (error) {
      logger.error('更新用户资料失败', error);
      return res.status(500).json({ 
        error: '更新用户资料失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户的标注历史
  static async getUserAnnotations(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      if (!userId) {
        return res.status(400).json({ error: '用户ID不能为空' });
      }

      const {
        page = 1,
        limit = 20,
        status = 'approved'
      } = req.query;

      // 检查查看权限
      const canViewActivity = await this.checkActivityViewPermission(userId as string, currentUserId);
      if (!canViewActivity) {
        return res.status(403).json({ error: '无法查看该用户的标注' });
      }

      const result = await AnnotationModel.getUserAnnotations(userId as string, {
        page: Number(page),
        limit: Number(limit),
        status: status as string
      });

      return res.json({
        success: true,
        data: {
          annotations: result.annotations,
          pagination: {
            page: Number(page),
            limit: Number(limit),
            total: result.total,
            totalPages: Math.ceil(result.total / Number(limit)),
            hasNext: Number(page) * Number(limit) < result.total,
            hasPrev: Number(page) > 1
          }
        }
      });
    } catch (error) {
      logger.error('获取用户标注失败', error);
      return res.status(500).json({ 
        error: '获取用户标注失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户成就
  static async getUserAchievements(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      if (!userId) {
        return res.status(400).json({ error: '用户ID不能为空' });
      }

      // 检查查看权限
      const canViewProfile = await this.checkProfileViewPermission(userId as string, currentUserId);
      if (!canViewProfile) {
        return res.status(403).json({ error: '无法查看该用户的成就' });
      }

      const achievements = await this.calculateUserAchievements(userId as string);

      return res.json({
        success: true,
        data: {
          achievements,
          count: achievements.length
        }
      });
    } catch (error) {
      logger.error('获取用户成就失败', error);
      return res.status(500).json({ 
        error: '获取用户成就失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户活动时间线
  static async getUserActivityTimeline(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      if (!userId) {
        return res.status(400).json({ error: '用户ID不能为空' });
      }

      const { page = 1, limit = 20 } = req.query;

      // 检查查看权限
      const canViewActivity = await this.checkActivityViewPermission(userId as string, currentUserId);
      if (!canViewActivity) {
        return res.status(403).json({ error: '无法查看该用户的活动' });
      }

      const result = await UserFeedModel.getUserActivity(userId as string, {
        page: Number(page),
        limit: Number(limit)
      });

      return res.json({
        success: true,
        data: {
          activities: result.feeds,
          pagination: {
            page: Number(page),
            limit: Number(limit),
            total: result.total,
            totalPages: Math.ceil(result.total / Number(limit)),
            hasNext: Number(page) * Number(limit) < result.total,
            hasPrev: Number(page) > 1
          }
        }
      });
    } catch (error) {
      logger.error('获取用户活动时间线失败', error);
      return res.status(500).json({ 
        error: '获取活动时间线失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户隐私设置
  static async getUserPrivacySettings(userId: string) {
    try {
      // 从数据库获取隐私设置，如果不存在则使用默认设置
      const settings = await db('user_privacy_settings')
        .where('user_id', userId)
        .first();

      return settings || {
        profile_visibility: 'public',
        activity_visibility: 'public', 
        location_visibility: 'followers'
      };
    } catch (error) {
      logger.error('获取隐私设置失败', { userId, error });
      return {
        profile_visibility: 'public',
        activity_visibility: 'public',
        location_visibility: 'followers'
      };
    }
  }

  // 更新隐私设置
  static async updatePrivacySettings(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        profile_visibility,
        activity_visibility,
        location_visibility
      } = req.body;

      const validVisibilityOptions = ['public', 'followers', 'private'];

      // 验证输入
      if (profile_visibility && !validVisibilityOptions.includes(profile_visibility)) {
        return res.status(400).json({ error: '无效的资料可见性设置' });
      }

      if (activity_visibility && !validVisibilityOptions.includes(activity_visibility)) {
        return res.status(400).json({ error: '无效的活动可见性设置' });
      }

      if (location_visibility && !validVisibilityOptions.includes(location_visibility)) {
        return res.status(400).json({ error: '无效的位置可见性设置' });
      }

      // 更新或插入隐私设置
      const existingSettings = await db('user_privacy_settings')
        .where('user_id', userId)
        .first();

      const settingsData = {
        profile_visibility: profile_visibility || 'public',
        activity_visibility: activity_visibility || 'public',
        location_visibility: location_visibility || 'followers',
        updated_at: new Date()
      };

      if (existingSettings) {
        await db('user_privacy_settings')
          .where('user_id', userId)
          .update(settingsData);
      } else {
        await db('user_privacy_settings')
          .insert({
            user_id: userId,
            ...settingsData,
            created_at: new Date()
          });
      }

      return res.json({
        success: true,
        data: settingsData,
        message: '隐私设置更新成功'
      });
    } catch (error) {
      logger.error('更新隐私设置失败', error);
      return res.status(500).json({ 
        error: '更新隐私设置失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 检查资料查看权限
  private static async checkProfileViewPermission(
    targetUserId: string, 
    currentUserId?: string
  ): Promise<boolean> {
    try {
      const privacy = await this.getUserPrivacySettings(targetUserId);
      
      // 公开资料，任何人都可以查看
      if (privacy.profile_visibility === 'public') {
        return true;
      }

      // 如果未登录，只能查看公开资料
      if (!currentUserId) {
        return false;
      }

      // 用户本人可以查看自己的资料
      if (targetUserId === currentUserId) {
        return true;
      }

      // 仅关注者可见
      if (privacy.profile_visibility === 'followers') {
        const isFollowing = await db('user_follows')
          .where('follower_id', currentUserId)
          .where('following_id', targetUserId)
          .first();
        return !!isFollowing;
      }

      // 私有资料，只有本人可以查看
      return false;
    } catch (error) {
      logger.error('检查资料查看权限失败', error);
      return false;
    }
  }

  // 检查活动查看权限
  private static async checkActivityViewPermission(
    targetUserId: string,
    currentUserId?: string
  ): Promise<boolean> {
    try {
      const privacy = await this.getUserPrivacySettings(targetUserId);
      
      // 公开活动，任何人都可以查看
      if (privacy.activity_visibility === 'public') {
        return true;
      }

      // 如果未登录，只能查看公开活动
      if (!currentUserId) {
        return false;
      }

      // 用户本人可以查看自己的活动
      if (targetUserId === currentUserId) {
        return true;
      }

      // 仅关注者可见
      if (privacy.activity_visibility === 'followers') {
        const isFollowing = await db('user_follows')
          .where('follower_id', currentUserId)
          .where('following_id', targetUserId)
          .first();
        return !!isFollowing;
      }

      // 私有活动，只有本人可以查看
      return false;
    } catch (error) {
      logger.error('检查活动查看权限失败', error);
      return false;
    }
  }

  // 获取社交关系
  private static async getSocialRelationship(
    targetUserId: string, 
    currentUserId?: string
  ) {
    try {
      if (!currentUserId || targetUserId === currentUserId) {
        return {
          is_following: false,
          is_followed_by: false,
          mutual_follows: 0
        };
      }

      // 检查是否关注目标用户
      const isFollowing = await db('user_follows')
        .where('follower_id', currentUserId)
        .where('following_id', targetUserId)
        .first();

      // 检查是否被目标用户关注
      const isFollowedBy = await db('user_follows')
        .where('follower_id', targetUserId)
        .where('following_id', currentUserId)
        .first();

      // 获取共同关注数量
      const mutualFollowsResult = await db('user_follows as f1')
        .join('user_follows as f2', 'f1.following_id', 'f2.following_id')
        .where('f1.follower_id', currentUserId)
        .where('f2.follower_id', targetUserId)
        .count('* as count');

      const mutual_follows = parseInt(mutualFollowsResult[0]?.['count'] as string) || 0;

      return {
        is_following: !!isFollowing,
        is_followed_by: !!isFollowedBy,
        mutual_follows
      };
    } catch (error) {
      logger.error('获取社交关系失败', error);
      return {
        is_following: false,
        is_followed_by: false,
        mutual_follows: 0
      };
    }
  }

  // 计算用户成就
  private static async calculateUserAchievements(userId: string): Promise<UserAchievement[]> {
    try {
      const achievements: UserAchievement[] = [];
      const stats = await UserModel.getStats(userId);
      const user = await UserModel.findById(userId);

      if (!user) return achievements;

      // 第一个标注成就
      if (stats.total_annotations > 0) {
        const firstAnnotation = await db('annotations')
          .where('user_id', userId)
          .orderBy('created_at', 'asc')
          .first();

        if (firstAnnotation) {
          achievements.push({
            id: 'first_annotation',
            type: 'first_annotation',
            title: '初次探索',
            description: '发布了第一个气味标注',
            icon: '🎯',
            earned_at: firstAnnotation.created_at
          });
        }
      }

      // 里程碑成就（标注数量）
      const milestones = [10, 50, 100, 500, 1000];
      for (const milestone of milestones) {
        if (stats.total_annotations >= milestone) {
          achievements.push({
            id: `milestone_${milestone}`,
            type: 'milestone_posts',
            title: `标注达人 ${milestone}`,
            description: `发布了 ${milestone} 个标注`,
            icon: milestone >= 100 ? '🏆' : '🎖️',
            earned_at: new Date(), // 实际应该查询达到里程碑的时间
            progress: stats.total_annotations,
            target: milestone
          });
        }
      }

      // 受欢迎内容成就
      if (stats.likes_received >= 100) {
        achievements.push({
          id: 'popular_content',
          type: 'popular_content',
          title: '人气王',
          description: `获得了 ${stats.likes_received} 个点赞`,
          icon: '⭐',
          earned_at: new Date()
        });
      }

      // 社交达人成就
      if (stats.followers_count >= 50) {
        achievements.push({
          id: 'social_butterfly',
          type: 'social_butterfly',
          title: '社交达人',
          description: `拥有 ${stats.followers_count} 个关注者`,
          icon: '🦋',
          earned_at: new Date()
        });
      }

      // 探索者成就（基于不同城市的标注）
      const cityCount = await db('annotations')
        .where('user_id', userId)
        .whereNotNull('city')
        .distinct('city')
        .count('city as count');

      const uniqueCities = parseInt(cityCount[0]?.['count'] as string) || 0;
      if (uniqueCities >= 10) {
        achievements.push({
          id: 'explorer',
          type: 'explorer',
          title: '城市探索家',
          description: `在 ${uniqueCities} 个城市发布了标注`,
          icon: '🗺️',
          earned_at: new Date()
        });
      }

      // 持续活跃成就
      if (stats.weekly_posts >= 7) {
        achievements.push({
          id: 'consistency',
          type: 'consistency',
          title: '持续活跃',
          description: '本周每天都有发布',
          icon: '🔥',
          earned_at: new Date()
        });
      }

      return achievements.sort((a, b) => b.earned_at.getTime() - a.earned_at.getTime());
    } catch (error) {
      logger.error('计算用户成就失败', error);
      return [];
    }
  }
}

export default ProfileController;