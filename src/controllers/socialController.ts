import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import db from '../config/database';
import { emailService } from '../services/emailService';
import { sendRealtimeNotification } from '../services/websocketManager';
import { UserFeedModel } from '../models/UserFeed';

// 扩展Request接口以包含用户信息
interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

/**
 * 社交互动控制器
 * 处理用户关注、点赞、收藏、通知等社交功能
 */

// 关注用户
export const followUser = async (req: AuthRequest, res: Response) => {
  try {
    const { userId: followingId } = req.params;
    const followerId = req.user?.id;

    if (!followerId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    if (followerId === followingId) {
      return res.status(400).json({ error: '不能关注自己' });
    }

    // 检查是否已经关注
    const existingFollow = await db('user_follows')
      .where({ follower_id: followerId, following_id: followingId })
      .first();

    if (existingFollow) {
      return res.status(400).json({ error: '已经关注该用户' });
    }

    // 创建关注记录
    const followId = uuidv4();
    await db('user_follows').insert({
      id: followId,
      follower_id: followerId,
      following_id: followingId,
      created_at: new Date(),
    });

    // 创建通知
    if (followingId) {
      const followerInfo = await db('users').where('id', followerId).first();
      await createNotification({
        user_id: followingId,
        from_user_id: followerId,
        type: 'follow',
        title: '新的关注者',
        content: `${followerInfo.username} 关注了你`,
        related_id: followId,
        related_type: 'follow',
      });
    }

    // 创建动态记录
    try {
      if (followingId) {
        await UserFeedModel.createFollowFeed(followerId, followingId);
      }
    } catch (error) {
      console.error('创建关注动态失败:', error);
      // 不影响主流程
    }

    return res.json({ message: '关注成功', followId });
  } catch (error) {
    console.error('关注用户失败:', error);
    return res.status(500).json({ error: '关注失败' });
  }
};

// 取消关注用户
export const unfollowUser = async (req: AuthRequest, res: Response) => {
  try {
    const { userId: followingId } = req.params;
    const followerId = req.user?.id;

    if (!followerId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const deleted = await db('user_follows')
      .where({ follower_id: followerId, following_id: followingId })
      .del();

    if (deleted === 0) {
      return res.status(404).json({ error: '未找到关注记录' });
    }

    return res.json({ message: '取消关注成功' });
  } catch (error) {
    console.error('取消关注失败:', error);
    return res.status(500).json({ error: '取消关注失败' });
  }
};

// 获取关注列表
export const getFollowing = async (req: AuthRequest, res: Response) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    const following = await db('user_follows')
      .join('users', 'user_follows.following_id', 'users.id')
      .where('user_follows.follower_id', userId)
      .select(
        'users.id',
        'users.username',
        'users.avatar_url',
        'users.bio',
        'user_follows.created_at as followed_at',
      )
      .orderBy('user_follows.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const total = await db('user_follows')
      .where('follower_id', userId)
      .count('* as count')
      .first();

    return res.json({
      following,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number((total as any)?.['count']) || 0,
        totalPages: Math.ceil((Number((total as any)?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取关注列表失败:', error);
    return res.status(500).json({ error: '获取关注列表失败' });
  }
};

// 获取粉丝列表
export const getFollowers = async (req: AuthRequest, res: Response) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    const followers = await db('user_follows')
      .join('users', 'user_follows.follower_id', 'users.id')
      .where('user_follows.following_id', userId)
      .select(
        'users.id',
        'users.username',
        'users.avatar_url',
        'users.bio',
        'user_follows.created_at as followed_at',
      )
      .orderBy('user_follows.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const total = await db('user_follows')
      .where('following_id', userId)
      .count('* as count')
      .first();

    return res.json({
      followers,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number((total as any)?.['count']) || 0,
        totalPages: Math.ceil((Number((total as any)?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取粉丝列表失败:', error);
    return res.status(500).json({ error: '获取粉丝列表失败' });
  }
};

// 点赞标注
export const likeAnnotation = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 检查是否已经点赞
    const existingLike = await db('annotation_likes')
      .where({ annotation_id: annotationId, user_id: userId })
      .first();

    if (existingLike) {
      return res.status(400).json({ error: '已经点赞过该标注' });
    }

    // 创建点赞记录
    const likeId = uuidv4();
    await db('annotation_likes').insert({
      id: likeId,
      annotation_id: annotationId,
      user_id: userId,
      created_at: new Date(),
    });

    // 更新标注的点赞数
    await db('annotations')
      .where('id', annotationId)
      .increment('likes_count', 1);

    // 获取标注信息并创建通知
    const annotation = await db('annotations').where('id', annotationId).first();
    if (annotation && annotation.user_id !== userId) {
      const userInfo = await db('users').where('id', userId).first();
      if (annotationId) {
        await createNotification({
          user_id: annotation.user_id,
          from_user_id: userId,
          type: 'like',
          title: '标注获得点赞',
          content: `${userInfo.username} 点赞了你的标注`,
          related_id: annotationId,
          related_type: 'annotation',
        });
      }

      // 创建动态记录
      try {
        if (annotation.user_id && annotationId) {
          await UserFeedModel.createLikeFeed(userId, 'annotation', annotationId, annotation.user_id);
        }
      } catch (error) {
        console.error('创建点赞动态失败:', error);
      }
    }

    return res.json({ message: '点赞成功', likeId });
  } catch (error) {
    console.error('点赞标注失败:', error);
    return res.status(500).json({ error: '点赞失败' });
  }
};

// 取消点赞标注
export const unlikeAnnotation = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const deleted = await db('annotation_likes')
      .where({ annotation_id: annotationId, user_id: userId })
      .del();

    if (deleted === 0) {
      return res.status(404).json({ error: '未找到点赞记录' });
    }

    // 更新标注的点赞数
    await db('annotations')
      .where('id', annotationId)
      .decrement('likes_count', 1);

    return res.json({ message: '取消点赞成功' });
  } catch (error) {
    console.error('取消点赞失败:', error);
    return res.status(500).json({ error: '取消点赞失败' });
  }
};

// 收藏标注
export const favoriteAnnotation = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 检查是否已经收藏
    const existingFavorite = await db('user_favorites')
      .where({ user_id: userId, annotation_id: annotationId })
      .first();

    if (existingFavorite) {
      return res.status(400).json({ error: '已经收藏过该标注' });
    }

    // 创建收藏记录
    const favoriteId = uuidv4();
    await db('user_favorites').insert({
      id: favoriteId,
      user_id: userId,
      annotation_id: annotationId,
      created_at: new Date(),
    });

    // 创建动态记录
    try {
      const annotation = await db('annotations').where('id', annotationId).first();
      if (annotation && annotation.user_id && annotation.user_id !== userId && annotationId) {
        await UserFeedModel.createFavoriteFeed(userId, annotationId, annotation.user_id);
      }
    } catch (error) {
      console.error('创建收藏动态失败:', error);
    }

    return res.json({ message: '收藏成功', favoriteId });
  } catch (error) {
    console.error('收藏标注失败:', error);
    return res.status(500).json({ error: '收藏失败' });
  }
};

// 取消收藏标注
export const unfavoriteAnnotation = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const deleted = await db('user_favorites')
      .where({ user_id: userId, annotation_id: annotationId })
      .del();

    if (deleted === 0) {
      return res.status(404).json({ error: '未找到收藏记录' });
    }

    return res.json({ message: '取消收藏成功' });
  } catch (error) {
    console.error('取消收藏失败:', error);
    return res.status(500).json({ error: '取消收藏失败' });
  }
};

// 获取用户收藏列表
export const getUserFavorites = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const favorites = await db('user_favorites')
      .join('annotations', 'user_favorites.annotation_id', 'annotations.id')
      .join('users', 'annotations.user_id', 'users.id')
      .where('user_favorites.user_id', userId)
      .select(
        'annotations.*',
        'users.username',
        'users.avatar_url',
        'user_favorites.created_at as favorited_at',
      )
      .orderBy('user_favorites.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const total = await db('user_favorites')
      .where('user_id', userId)
      .count('* as count')
      .first();

    return res.json({
      favorites,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number((total as any)?.['count']) || 0,
        totalPages: Math.ceil((Number((total as any)?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取收藏列表失败:', error);
    return res.status(500).json({ error: '获取收藏列表失败' });
  }
};

// 创建通知的辅助函数
const createNotification = async (notificationData: {
  user_id: string;
  from_user_id?: string;
  type: string;
  title: string;
  content: string;
  related_id: string;
  related_type: string;
}): Promise<string | undefined> => {
  try {
    const notificationId = uuidv4();
    await db('notifications').insert({
      id: notificationId,
      ...notificationData,
      is_read: false,
      created_at: new Date(),
    });

    // 发送邮件通知和实时通知（异步，不阻塞主流程）
    setImmediate(async () => {
      try {
        // 获取接收通知用户的信息
        const user = await db('users')
          .select('email', 'username', 'email_notifications')
          .where('id', notificationData.user_id)
          .first();

        // 获取发送通知用户的信息（如果有）
        let fromUser = undefined;
        if (notificationData.from_user_id) {
          fromUser = await db('users')
            .select('id', 'username', 'avatar_url')
            .where('id', notificationData.from_user_id)
            .first();
        }

        // 生成操作链接
        const baseUrl = process.env['FRONTEND_URL'] || 'http://localhost:5176';
        let actionUrl = undefined;
        if (notificationData.related_type === 'annotation') {
          actionUrl = `${baseUrl}/map?annotation=${notificationData.related_id}`;
        } else if (notificationData.related_type === 'user' && notificationData.from_user_id) {
          actionUrl = `${baseUrl}/users/${notificationData.from_user_id}`;
        }

        // 发送邮件通知
        if (user && user.email && user.email_notifications) {
          await emailService.sendNotificationEmail(user.email, {
            type: notificationData.type,
            title: notificationData.title,
            content: notificationData.content,
            fromUsername: fromUser?.username,
            actionUrl,
          });
        }

        // 发送实时WebSocket通知
        await sendRealtimeNotification(notificationData.user_id, {
          type: notificationData.type,
          title: notificationData.title,
          message: notificationData.content,
          data: {
            sender: fromUser ? {
              id: fromUser.id,
              username: fromUser.username,
              avatar_url: fromUser.avatar_url,
            } : null,
            actionUrl,
            createdAt: new Date().toISOString(),
          },
        });
      } catch (error) {
        console.error('发送通知失败:', error);
      }
    });

    return notificationId;
  } catch (error) {
    console.error('创建通知失败:', error);
    return undefined;
  }
};

// 获取用户通知
export const getUserNotifications = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    const { page = 1, limit = 20, unread_only = false } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    let query = db('notifications')
      .leftJoin('users', 'notifications.from_user_id', 'users.id')
      .where('notifications.user_id', userId)
      .select(
        'notifications.*',
        'users.username as from_username',
        'users.avatar_url as from_avatar_url',
      );

    if (unread_only === 'true') {
      query = query.where('notifications.is_read', false);
    }

    const notifications = await query
      .orderBy('notifications.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const totalQuery = db('notifications').where('user_id', userId);
    if (unread_only === 'true') {
      totalQuery.where('is_read', false);
    }
    const total = await totalQuery.count('* as count').first();

    return res.json({
      notifications,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number((total as any)?.['count']) || 0,
        totalPages: Math.ceil((Number((total as any)?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取通知失败:', error);
    return res.status(500).json({ error: '获取通知失败' });
  }
};

// 标记通知为已读
export const markNotificationAsRead = async (req: AuthRequest, res: Response) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const updated = await db('notifications')
      .where({ id: notificationId, user_id: userId })
      .update({ is_read: true });

    if (updated === 0) {
      return res.status(404).json({ error: '未找到通知' });
    }

    return res.json({ message: '标记为已读成功' });
  } catch (error) {
    console.error('标记通知已读失败:', error);
    return res.status(500).json({ error: '标记已读失败' });
  }
};

// 标记所有通知为已读
export const markAllNotificationsAsRead = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    await db('notifications')
      .where({ user_id: userId, is_read: false })
      .update({ is_read: true });

    return res.json({ message: '所有通知已标记为已读' });
  } catch (error) {
    console.error('标记所有通知已读失败:', error);
    return res.status(500).json({ error: '标记已读失败' });
  }
};
