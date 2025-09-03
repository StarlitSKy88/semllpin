import { Request, Response } from 'express';
import db from '../config/database';

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
 * 用户关注系统控制器
 * 处理用户关注、取消关注、获取关注列表等功能
 */

// 关注用户
export const followUser = async (req: AuthRequest, res: Response) => {
  try {
    const { userId: targetUserId } = req.params;
    const followerId = req.user?.id;

    if (!followerId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    if (followerId === targetUserId) {
      return res.status(400).json({ error: '不能关注自己' });
    }

    // 验证目标用户是否存在
    const targetUser = await db('users').where('id', targetUserId).first();
    if (!targetUser) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 检查是否已经关注
    const existingFollow = await db('user_follows')
      .where({
        follower_id: followerId,
        following_id: targetUserId,
      })
      .first();

    if (existingFollow) {
      return res.status(400).json({ error: '已经关注该用户' });
    }

    // 创建关注关系
    await db('user_follows').insert({
      follower_id: followerId,
      following_id: targetUserId,
      created_at: new Date(),
    });

    // 更新用户关注数和粉丝数
    await db.transaction(async (trx) => {
      // 增加关注者的关注数
      await trx('users')
        .where('id', followerId)
        .increment('following_count', 1);

      // 增加被关注者的粉丝数
      await trx('users')
        .where('id', targetUserId)
        .increment('followers_count', 1);
    });

    // 创建关注通知
    const followerInfo = await db('users').where('id', followerId).first();
    if (followerInfo && targetUserId) {
      await createNotification({
        user_id: targetUserId,
        from_user_id: followerId,
        type: 'follow',
        title: '新粉丝',
        content: `${followerInfo.username} 关注了你`,
        related_id: followerId,
        related_type: 'user',
      });
    }

    return res.status(201).json({
      message: '关注成功',
      data: {
        follower_id: followerId,
        following_id: targetUserId,
      },
    });
  } catch (error) {
    console.error('关注用户失败:', error);
    return res.status(500).json({ error: '关注用户失败' });
  }
};

// 取消关注用户
export const unfollowUser = async (req: AuthRequest, res: Response) => {
  try {
    const { userId: targetUserId } = req.params;
    const followerId = req.user?.id;

    if (!followerId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 检查关注关系是否存在
    const existingFollow = await db('user_follows')
      .where({
        follower_id: followerId,
        following_id: targetUserId,
      })
      .first();

    if (!existingFollow) {
      return res.status(400).json({ error: '未关注该用户' });
    }

    // 删除关注关系
    await db('user_follows')
      .where({
        follower_id: followerId,
        following_id: targetUserId,
      })
      .del();

    // 更新用户关注数和粉丝数
    await db.transaction(async (trx) => {
      // 减少关注者的关注数
      await trx('users')
        .where('id', followerId)
        .decrement('following_count', 1);

      // 减少被关注者的粉丝数
      await trx('users')
        .where('id', targetUserId)
        .decrement('followers_count', 1);
    });

    return res.json({
      message: '取消关注成功',
    });
  } catch (error) {
    console.error('取消关注失败:', error);
    return res.status(500).json({ error: '取消关注失败' });
  }
};

// 获取用户的关注列表
export const getUserFollowing = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // 验证用户是否存在
    const user = await db('users').where('id', userId).first();
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 获取关注列表
    const following = await db('user_follows')
      .join('users', 'user_follows.following_id', 'users.id')
      .where('user_follows.follower_id', userId)
      .select(
        'users.id',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        'users.bio',
        'users.followers_count',
        'users.following_count',
        'user_follows.created_at as followed_at',
      )
      .orderBy('user_follows.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    // 获取总数
    const total = await db('user_follows')
      .where('follower_id', userId)
      .count('* as count')
      .first();

    return res.json({
      following,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total?.['count']) || 0,
        totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取关注列表失败:', error);
    return res.status(500).json({ error: '获取关注列表失败' });
  }
};

// 获取用户的粉丝列表
export const getUserFollowers = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // 验证用户是否存在
    const user = await db('users').where('id', userId).first();
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 获取粉丝列表
    const followers = await db('user_follows')
      .join('users', 'user_follows.follower_id', 'users.id')
      .where('user_follows.following_id', userId)
      .select(
        'users.id',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        'users.bio',
        'users.followers_count',
        'users.following_count',
        'user_follows.created_at as followed_at',
      )
      .orderBy('user_follows.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    // 获取总数
    const total = await db('user_follows')
      .where('following_id', userId)
      .count('* as count')
      .first();

    return res.json({
      followers,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total?.['count']) || 0,
        totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取粉丝列表失败:', error);
    return res.status(500).json({ error: '获取粉丝列表失败' });
  }
};

// 检查关注状态
export const checkFollowStatus = async (req: AuthRequest, res: Response) => {
  try {
    const { userId: targetUserId } = req.params;
    const currentUserId = req.user?.id;

    if (!currentUserId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 检查是否关注
    const isFollowing = await db('user_follows')
      .where({
        follower_id: currentUserId,
        following_id: targetUserId,
      })
      .first();

    // 检查是否被关注
    const isFollowedBy = await db('user_follows')
      .where({
        follower_id: targetUserId,
        following_id: currentUserId,
      })
      .first();

    return res.json({
      isFollowing: !!isFollowing,
      isFollowedBy: !!isFollowedBy,
      isMutual: !!isFollowing && !!isFollowedBy,
    });
  } catch (error) {
    console.error('检查关注状态失败:', error);
    return res.status(500).json({ error: '检查关注状态失败' });
  }
};

// 获取互相关注的用户列表
export const getMutualFollows = async (req: AuthRequest, res: Response) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user?.id;
    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    if (!currentUserId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 获取互相关注的用户
    const mutualFollows = await db('user_follows as f1')
      .join('user_follows as f2', function () {
        this.on('f1.following_id', '=', 'f2.follower_id')
          .andOn('f1.follower_id', '=', 'f2.following_id');
      })
      .join('users', 'f1.following_id', 'users.id')
      .where('f1.follower_id', userId)
      .select(
        'users.id',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        'users.bio',
        'users.followers_count',
        'users.following_count',
      )
      .limit(Number(limit))
      .offset(offset);

    // 获取总数
    const total = await db('user_follows as f1')
      .join('user_follows as f2', function () {
        this.on('f1.following_id', '=', 'f2.follower_id')
          .andOn('f1.follower_id', '=', 'f2.following_id');
      })
      .where('f1.follower_id', userId)
      .count('* as count')
      .first();

    return res.json({
      mutualFollows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total?.['count']) || 0,
        totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取互相关注列表失败:', error);
    return res.status(500).json({ error: '获取互相关注列表失败' });
  }
};

// 创建通知的辅助函数
const createNotification = async (notificationData: {
  user_id: string;
  from_user_id?: string;
  type: string;
  title: string;
  content: string;
  related_id?: string;
  related_type: string;
}): Promise<string | undefined> => {
  if (!notificationData.user_id) {
    console.error('user_id is required for creating notification');
    return undefined;
  }
  try {
    const notificationId = await db('notifications').insert({
      id: require('uuid').v4(),
      ...notificationData,
      is_read: false,
      created_at: new Date(),
    }).returning('id');

    return notificationId[0];
  } catch (error) {
    console.error('创建通知失败:', error);
    return undefined;
  }
};
