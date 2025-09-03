import { Request, Response } from 'express';
import { UserFeedModel } from '../models/UserFeed';
import { logger } from '../utils/logger';

interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

/**
 * 用户动态流控制器
 * 处理用户动态的获取和管理
 */
export class FeedController {
  // 获取用户的关注动态流
  static async getUserFeed(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const { 
        page = 1, 
        limit = 20, 
        include_own = 'false' 
      } = req.query;

      const includeOwnActivity = include_own === 'true';

      const result = await UserFeedModel.getFeedForUser(userId, {
        page: Number(page),
        limit: Number(limit),
        includeOwnActivity
      });

      return res.json({
        success: true,
        data: {
          feeds: result.feeds,
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
      logger.error('获取用户动态流失败', error);
      return res.status(500).json({ 
        error: '获取动态流失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户的活动历史
  static async getUserActivity(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;

      if (!currentUserId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      // 如果查看别人的活动，需要检查隐私设置
      if (userId !== currentUserId) {
        // 这里可以添加隐私检查逻辑
        // 暂时允许所有用户查看公开的活动
      }

      const { 
        page = 1, 
        limit = 20, 
        action_type 
      } = req.query;

      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const result = await UserFeedModel.getUserActivity(userId, {
        page: Number(page),
        limit: Number(limit),
        actionType: action_type as string
      });

      return res.json({
        success: true,
        data: {
          feeds: result.feeds,
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
      logger.error('获取用户活动历史失败', error);
      return res.status(500).json({ 
        error: '获取活动历史失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 清理过期动态（管理员功能）
  static async cleanOldFeeds(req: AuthRequest, res: Response) {
    try {
      const currentUserId = req.user?.id;
      const currentUserRole = req.user?.role;

      if (!currentUserId || currentUserRole !== 'admin') {
        return res.status(403).json({ error: '没有权限执行此操作' });
      }

      const { days_to_keep = 90 } = req.query;

      const deletedCount = await UserFeedModel.cleanOldFeeds(Number(days_to_keep));

      return res.json({
        success: true,
        data: {
          deletedCount,
          message: `已清理 ${deletedCount} 条过期动态`
        }
      });
    } catch (error) {
      logger.error('清理过期动态失败', error);
      return res.status(500).json({ 
        error: '清理动态失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 删除用户的所有动态（管理员功能或用户注销时）
  static async deleteUserFeeds(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;
      const currentUserId = req.user?.id;
      const currentUserRole = req.user?.role;

      // 检查权限：只有管理员或用户本人可以删除动态
      if (currentUserRole !== 'admin' && currentUserId !== userId) {
        return res.status(403).json({ error: '没有权限执行此操作' });
      }

      if (!userId) {
        return res.status(400).json({ error: '用户ID不能为空' });
      }

      const deletedCount = await UserFeedModel.deleteUserFeeds(userId);

      return res.json({
        success: true,
        data: {
          deletedCount,
          message: `已删除 ${deletedCount} 条用户动态`
        }
      });
    } catch (error) {
      logger.error('删除用户动态失败', error);
      return res.status(500).json({ 
        error: '删除用户动态失败',
        message: '服务器内部错误' 
      });
    }
  }
}

export default FeedController;