import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
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

interface NotificationSettings {
  email_notifications: boolean;
  push_notifications: boolean;
  follow_notifications: boolean;
  comment_notifications: boolean;
  like_notifications: boolean;
  share_notifications: boolean;
  system_notifications: boolean;
}

/**
 * 通知偏好设置控制器
 */

// 获取用户通知设置
export const getUserNotificationSettings = async (req: AuthRequest, res: Response): Promise<Response> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 从用户表获取通知设置
    const user = await db('users')
      .select(
        'email_notifications',
        'push_notifications',
        'follow_notifications',
        'comment_notifications',
        'like_notifications',
        'share_notifications',
        'system_notifications',
      )
      .where('id', userId)
      .first();

    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 设置默认值（如果字段为null）
    const settings: NotificationSettings = {
      email_notifications: user.email_notifications ?? true,
      push_notifications: user.push_notifications ?? true,
      follow_notifications: user.follow_notifications ?? true,
      comment_notifications: user.comment_notifications ?? true,
      like_notifications: user.like_notifications ?? true,
      share_notifications: user.share_notifications ?? true,
      system_notifications: user.system_notifications ?? true,
    };

    return res.json({
      success: true,
      data: settings,
    });
  } catch (error) {
    console.error('获取通知设置失败:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
};

// 更新用户通知设置
export const updateUserNotificationSettings = async (req: AuthRequest, res: Response): Promise<Response> => {
  try {
    const userId = req.user?.id;
    const settings = req.body as Partial<NotificationSettings>;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 验证设置字段
    const allowedFields = [
      'email_notifications',
      'push_notifications',
      'follow_notifications',
      'comment_notifications',
      'like_notifications',
      'share_notifications',
      'system_notifications',
    ];

    const updateData: Partial<NotificationSettings> = {};
    for (const field of allowedFields) {
      if (field in settings && typeof settings[field as keyof NotificationSettings] === 'boolean') {
        (updateData as any)[field] = settings[field as keyof NotificationSettings];
      }
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: '没有有效的设置字段' });
    }

    // 更新数据库
    await db('users')
      .where('id', userId)
      .update({
        ...updateData,
        updated_at: new Date(),
      });

    // 获取更新后的设置
    const updatedUser = await db('users')
      .select(
        'email_notifications',
        'push_notifications',
        'follow_notifications',
        'comment_notifications',
        'like_notifications',
        'share_notifications',
        'system_notifications',
      )
      .where('id', userId)
      .first();

    const updatedSettings: NotificationSettings = {
      email_notifications: updatedUser.email_notifications ?? true,
      push_notifications: updatedUser.push_notifications ?? true,
      follow_notifications: updatedUser.follow_notifications ?? true,
      comment_notifications: updatedUser.comment_notifications ?? true,
      like_notifications: updatedUser.like_notifications ?? true,
      share_notifications: updatedUser.share_notifications ?? true,
      system_notifications: updatedUser.system_notifications ?? true,
    };

    return res.json({
      success: true,
      message: '通知设置更新成功',
      data: updatedSettings,
    });
  } catch (error) {
    console.error('更新通知设置失败:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
};

// 测试通知发送
export const testNotification = async (req: AuthRequest, res: Response): Promise<Response> => {
  try {
    const userId = req.user?.id;
    const { type = 'system' } = req.body;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 创建测试通知
    const notificationId = uuidv4();
    await db('notifications').insert({
      id: notificationId,
      user_id: userId,
      type,
      title: '测试通知',
      content: '这是一条测试通知，用于验证通知系统是否正常工作。',
      related_id: userId,
      related_type: 'user',
      is_read: false,
      created_at: new Date(),
    });

    return res.json({
      success: true,
      message: '测试通知发送成功',
      data: {
        notificationId,
      },
    });
  } catch (error) {
    console.error('发送测试通知失败:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
};

// 获取通知统计
export const getNotificationStats = async (req: AuthRequest, res: Response): Promise<Response> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 获取通知统计
    const stats = await db('notifications')
      .select(
        db.raw('COUNT(*) as total'),
        db.raw('COUNT(CASE WHEN is_read = false THEN 1 END) as unread'),
        db.raw('COUNT(CASE WHEN type = "follow" THEN 1 END) as follow_count'),
        db.raw('COUNT(CASE WHEN type = "comment" THEN 1 END) as comment_count'),
        db.raw('COUNT(CASE WHEN type = "like" THEN 1 END) as like_count'),
        db.raw('COUNT(CASE WHEN type = "share" THEN 1 END) as share_count'),
        db.raw('COUNT(CASE WHEN type = "system" THEN 1 END) as system_count'),
      )
      .where('user_id', userId)
      .first();

    // 获取最近7天的通知数量
    const recentStats = await db('notifications')
      .select(
        db.raw('DATE(created_at) as date'),
        db.raw('COUNT(*) as count'),
      )
      .where('user_id', userId)
      .where('created_at', '>=', db.raw('DATE_SUB(NOW(), INTERVAL 7 DAY)'))
      .groupBy(db.raw('DATE(created_at)'))
      .orderBy('date', 'desc');

    return res.json({
      success: true,
      data: {
        total: parseInt((stats as any)['total']) || 0,
        unread: parseInt((stats as any)['unread']) || 0,
        byType: {
          follow: parseInt((stats as any)['follow_count']) || 0,
          comment: parseInt((stats as any)['comment_count']) || 0,
          like: parseInt((stats as any)['like_count']) || 0,
          share: parseInt((stats as any)['share_count']) || 0,
          system: parseInt((stats as any)['system_count']) || 0,
        },
        recent: recentStats.map((item: any) => ({
          date: item['date'],
          count: parseInt(item['count']) || 0,
        })),
      },
    });
  } catch (error) {
    console.error('获取通知统计失败:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
};

// 批量删除通知
export const deleteNotifications = async (req: AuthRequest, res: Response): Promise<Response> => {
  try {
    const userId = req.user?.id;
    const { notificationIds, deleteAll = false } = req.body;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    let deletedCount = 0;

    if (deleteAll) {
      // 删除所有通知
      deletedCount = await db('notifications')
        .where('user_id', userId)
        .del();
    } else if (notificationIds && Array.isArray(notificationIds)) {
      // 删除指定通知
      deletedCount = await db('notifications')
        .where('user_id', userId)
        .whereIn('id', notificationIds)
        .del();
    } else {
      return res.status(400).json({ error: '请提供要删除的通知ID或设置deleteAll为true' });
    }

    return res.json({
      success: true,
      message: `成功删除 ${deletedCount} 条通知`,
      data: {
        deletedCount,
      },
    });
  } catch (error) {
    console.error('删除通知失败:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
};
