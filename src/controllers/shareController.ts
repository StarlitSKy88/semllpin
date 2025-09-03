import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import db from '../config/database';
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
 * 分享功能控制器
 * 处理标注的社交媒体分享功能
 */

// 创建分享记录
export const createShareRecord = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const { platform, shareUrl, shareData } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    if (!platform) {
      return res.status(400).json({ error: '分享平台不能为空' });
    }

    // 验证标注是否存在
    const annotation = await db('annotations').where('id', annotationId).first();
    if (!annotation) {
      return res.status(404).json({ error: '标注不存在' });
    }

    // 验证平台类型
    const validPlatforms = ['twitter', 'instagram', 'tiktok', 'wechat', 'weibo', 'facebook', 'linkedin', 'other'];
    if (!validPlatforms.includes(platform)) {
      return res.status(400).json({ error: '不支持的分享平台' });
    }

    // 创建分享记录
    const shareId = uuidv4();
    await db('share_records').insert({
      id: shareId,
      user_id: userId,
      annotation_id: annotationId,
      platform,
      share_url: shareUrl || null,
      share_data: shareData ? JSON.stringify(shareData) : null,
      created_at: new Date(),
    });

    // 更新用户分享统计（如果有相关表）
    // 这里可以添加积分奖励逻辑

    // 创建分享成就通知
    const userInfo = await db('users').where('id', userId).first();
    if (annotation.user_id !== userId && annotationId) {
      await createNotification({
        user_id: annotation.user_id,
        from_user_id: userId,
        type: 'share',
        title: '标注被分享',
        content: `${userInfo.username} 分享了你的标注到 ${getPlatformName(platform)}`,
        related_id: annotationId,
        related_type: 'annotation',
      });
    }

    // 创建动态记录
    try {
      if (annotation.user_id && annotationId) {
        await UserFeedModel.createShareFeed(userId, annotationId, platform, annotation.user_id);
      }
    } catch (error) {
      console.error('创建分享动态失败:', error);
      // 不影响主流程
    }

    return res.status(201).json({
      message: '分享记录创建成功',
      shareId,
      platform,
      shareUrl: shareUrl || generateShareUrl(annotationId || '', platform),
    });
  } catch (error) {
    console.error('创建分享记录失败:', error);
    return res.status(500).json({ error: '创建分享记录失败' });
  }
};

// 获取标注的分享统计
export const getAnnotationShareStats = async (req: Request, res: Response) => {
  try {
    const { annotationId } = req.params;

    // 验证标注是否存在
    const annotation = await db('annotations').where('id', annotationId).first();
    if (!annotation) {
      return res.status(404).json({ error: '标注不存在' });
    }

    // 获取分享统计
    const shareStats = await db('share_records')
      .where('annotation_id', annotationId)
      .select('platform')
      .count('* as count')
      .groupBy('platform');

    const totalShares = await db('share_records')
      .where('annotation_id', annotationId)
      .count('* as total')
      .first();

    // 获取最近的分享记录
    const recentShares = await db('share_records')
      .join('users', 'share_records.user_id', 'users.id')
      .where('share_records.annotation_id', annotationId)
      .select(
        'share_records.platform',
        'share_records.created_at',
        'users.username',
        'users.avatar_url',
      )
      .orderBy('share_records.created_at', 'desc')
      .limit(10);

    // 格式化平台统计
    const platformStats = shareStats.reduce((acc: any, stat: any) => {
      acc[stat.platform] = Number(stat.count);
      return acc;
    }, {});

    return res.json({
      totalShares: Number(totalShares?.['total']) || 0,
      platformStats,
      recentShares: recentShares.map(share => ({
        platform: share.platform,
        platformName: getPlatformName(share.platform),
        createdAt: share.created_at,
        user: {
          username: share.username,
          avatarUrl: share.avatar_url,
        },
      })),
    });
  } catch (error) {
    console.error('获取分享统计失败:', error);
    return res.status(500).json({ error: '获取分享统计失败' });
  }
};

// 获取用户的分享历史
export const getUserShareHistory = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    const { page = 1, limit = 20, platform } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    let query = db('share_records')
      .join('annotations', 'share_records.annotation_id', 'annotations.id')
      .where('share_records.user_id', userId)
      .select(
        'share_records.*',
        'annotations.description',
        'annotations.smell_intensity',
        'annotations.latitude',
        'annotations.longitude',
      );

    if (platform) {
      query = query.where('share_records.platform', platform);
    }

    const shares = await query
      .orderBy('share_records.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const totalQuery = db('share_records').where('user_id', userId);
    if (platform) {
      totalQuery.where('platform', platform);
    }
    const total = await totalQuery.count('* as count').first();

    return res.json({
      shares: shares.map(share => ({
        id: share.id,
        platform: share.platform,
        platformName: getPlatformName(share.platform),
        shareUrl: share.share_url,
        createdAt: share.created_at,
        annotation: {
          id: share.annotation_id,
          description: share.description,
          smellIntensity: share.smell_intensity,
          latitude: share.latitude,
          longitude: share.longitude,
        },
      })),
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total?.['count']) || 0,
        totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取分享历史失败:', error);
    return res.status(500).json({ error: '获取分享历史失败' });
  }
};

// 获取热门分享内容
export const getPopularShares = async (req: Request, res: Response) => {
  try {
    const { timeRange = '7d', limit = 10 } = req.query;

    // 计算时间范围
    const startDate = new Date();
    switch (timeRange) {
      case '1d':
        startDate.setDate(startDate.getDate() - 1);
        break;
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      default:
        startDate.setDate(startDate.getDate() - 7);
    }

    // 获取热门分享的标注
    const popularShares = await db('share_records')
      .join('annotations', 'share_records.annotation_id', 'annotations.id')
      .join('users', 'annotations.user_id', 'users.id')
      .where('share_records.created_at', '>=', startDate)
      .select(
        'annotations.id',
        'annotations.description',
        'annotations.smell_intensity',
        'annotations.latitude',
        'annotations.longitude',
        'annotations.likes_count',
        'annotations.views_count',
        'users.username',
        'users.avatar_url',
      )
      .count('share_records.id as share_count')
      .groupBy('annotations.id')
      .orderBy('share_count', 'desc')
      .limit(Number(limit));

    return res.json({
      popularShares: popularShares.map(item => ({
        annotation: {
          id: item['id'],
          description: item['description'],
          smellIntensity: item['smell_intensity'],
          latitude: item['latitude'],
          longitude: item['longitude'],
          likesCount: item['likes_count'],
          viewsCount: item['views_count'],
          user: {
            username: item['username'],
            avatarUrl: item['avatar_url'],
          },
        },
        shareCount: Number(item['share_count']),
      })),
      timeRange,
      generatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error('获取热门分享失败:', error);
    return res.status(500).json({ error: '获取热门分享失败' });
  }
};

// 生成分享链接
export const generateShareLink = async (req: Request, res: Response) => {
  try {
    const { annotationId } = req.params;
    const { platform = 'general' } = req.query;

    // 验证标注是否存在
    const annotation = await db('annotations')
      .join('users', 'annotations.user_id', 'users.id')
      .where('annotations.id', annotationId)
      .select(
        'annotations.*',
        'users.username',
      )
      .first();

    if (!annotation) {
      return res.status(404).json({ error: '标注不存在' });
    }

    if (!annotationId) {
      return res.status(400).json({ error: '标注ID不能为空' });
    }
    const shareUrl = generateShareUrl(annotationId, platform as string);
    const shareText = generateShareText(annotation, platform as string);

    return res.json({
      shareUrl,
      shareText,
      platform,
      annotation: {
        id: annotation.id,
        description: annotation.description,
        smellIntensity: annotation.smell_intensity,
        username: annotation.username,
      },
    });
  } catch (error) {
    console.error('生成分享链接失败:', error);
    return res.status(500).json({ error: '生成分享链接失败' });
  }
};

// 辅助函数：获取平台中文名称
const getPlatformName = (platform: string): string => {
  const platformNames: { [key: string]: string } = {
    twitter: 'Twitter',
    instagram: 'Instagram',
    tiktok: 'TikTok',
    wechat: '微信',
    weibo: '微博',
    facebook: 'Facebook',
    linkedin: 'LinkedIn',
    other: '其他',
  };
  return platformNames[platform] || platform;
};

// 辅助函数：生成分享URL
const generateShareUrl = (annotationId: string, platform: string): string => {
  const baseUrl = process.env['FRONTEND_URL'] || 'https://smellpin.com';
  const annotationUrl = `${baseUrl}/annotation/${annotationId}`;

  switch (platform) {
    case 'twitter':
      return `https://twitter.com/intent/tweet?url=${encodeURIComponent(annotationUrl)}`;
    case 'facebook':
      return `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(annotationUrl)}`;
    case 'linkedin':
      return `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(annotationUrl)}`;
    case 'weibo':
      return `https://service.weibo.com/share/share.php?url=${encodeURIComponent(annotationUrl)}`;
    default:
      return annotationUrl;
  }
};

// 辅助函数：生成分享文本
const generateShareText = (annotation: any, platform: string): string => {
  const intensity = annotation.smell_intensity;
  const intensityText = intensity >= 8 ? '超强' : intensity >= 6 ? '强烈' : intensity >= 4 ? '中等' : '轻微';

  const baseText = `发现了一个${intensityText}的臭味点！${annotation.description ? ` - ${annotation.description}` : ''}`;

  switch (platform) {
    case 'twitter':
      return `${baseText} #臭味地图 #SmellPin`;
    case 'wechat':
    case 'weibo':
      return `${baseText} 快来看看这个有趣的发现！`;
    default:
      return baseText;
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
    return notificationId;
  } catch (error) {
    console.error('创建通知失败:', error);
    return undefined;
  }
};
