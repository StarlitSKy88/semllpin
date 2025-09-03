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
 * 评论系统控制器
 * 处理标注评论的增删改查和点赞功能
 */

// 创建评论
export const createComment = async (req: AuthRequest, res: Response) => {
  try {
    const { annotationId } = req.params;
    const { content, parentId } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: '评论内容不能为空' });
    }

    if (content.length > 500) {
      return res.status(400).json({ error: '评论内容不能超过500字符' });
    }

    // 验证标注是否存在
    const annotation = await db('annotations').where('id', annotationId).first();
    if (!annotation) {
      return res.status(404).json({ error: '标注不存在' });
    }

    // 如果是回复评论，验证父评论是否存在
    if (parentId) {
      const parentComment = await db('comments').where('id', parentId).first();
      if (!parentComment) {
        return res.status(404).json({ error: '父评论不存在' });
      }
      if (parentComment.annotation_id !== annotationId) {
        return res.status(400).json({ error: '父评论不属于该标注' });
      }
    }

    // 创建评论
    const commentId = uuidv4();
    await db('comments').insert({
      id: commentId,
      annotation_id: annotationId,
      user_id: userId,
      parent_id: parentId || null,
      content: content.trim(),
      likes_count: 0,
      created_at: new Date(),
      updated_at: new Date(),
    });

    // 获取完整的评论信息
    const comment = await db('comments')
      .join('users', 'comments.user_id', 'users.id')
      .where('comments.id', commentId)
      .select(
        'comments.*',
        'users.username',
        'users.avatar_url',
      )
      .first();

    // 创建通知（如果不是自己的标注）
    if (annotation.user_id !== userId && annotationId) {
      const userInfo = await db('users').where('id', userId).first();
      await createNotification({
        user_id: annotation.user_id,
        from_user_id: userId,
        type: 'comment',
        title: '新评论',
        content: `${userInfo.username} 评论了你的标注`,
        related_id: annotationId,
        related_type: 'annotation',
      });
    }

    // 如果是回复评论，通知被回复的用户
    if (parentId && commentId) {
      const parentComment = await db('comments').where('id', parentId).first();
      if (parentComment && parentComment.user_id !== userId) {
        const userInfo = await db('users').where('id', userId).first();
        await createNotification({
          user_id: parentComment.user_id,
          from_user_id: userId,
          type: 'reply',
          title: '新回复',
          content: `${userInfo.username} 回复了你的评论`,
          related_id: commentId,
          related_type: 'comment',
        });
      }
    }

    // 创建动态记录
    try {
      if (annotationId && annotation.user_id) {
        await UserFeedModel.createCommentFeed(
          userId, 
          commentId, 
          annotationId, 
          annotation.user_id, 
          { content: content.trim() }
        );
      }
    } catch (error) {
      console.error('创建评论动态失败:', error);
    }

    return res.status(201).json({
      message: '评论创建成功',
      comment: {
        id: comment.id,
        content: comment.content,
        likes_count: comment.likes_count,
        created_at: comment.created_at,
        updated_at: comment.updated_at,
        parent_id: comment.parent_id,
        user: {
          id: comment.user_id,
          username: comment.username,
          avatar_url: comment.avatar_url,
        },
      },
    });
  } catch (error) {
    console.error('创建评论失败:', error);
    return res.status(500).json({ error: '创建评论失败' });
  }
};

// 获取标注的评论列表
export const getAnnotationComments = async (req: Request, res: Response) => {
  try {
    const { annotationId } = req.params;
    const { page = 1, limit = 20, sort = 'newest' } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // 验证标注是否存在
    const annotation = await db('annotations').where('id', annotationId).first();
    if (!annotation) {
      return res.status(404).json({ error: '标注不存在' });
    }

    // 构建排序条件
    let orderBy: [string, string] = ['comments.created_at', 'desc'];
    if (sort === 'oldest') {
      orderBy = ['comments.created_at', 'asc'];
    } else if (sort === 'likes') {
      orderBy = ['comments.likes_count', 'desc'];
    }

    // 获取顶级评论（非回复）
    const comments = await db('comments')
      .join('users', 'comments.user_id', 'users.id')
      .where('comments.annotation_id', annotationId)
      .whereNull('comments.parent_id')
      .select(
        'comments.*',
        'users.username',
        'users.avatar_url',
      )
      .orderBy(orderBy[0], orderBy[1])
      .limit(Number(limit))
      .offset(offset);

    // 获取每个评论的回复
    const commentsWithReplies = await Promise.all(
      comments.map(async (comment) => {
        const replies = await db('comments')
          .join('users', 'comments.user_id', 'users.id')
          .where('comments.parent_id', comment.id)
          .select(
            'comments.*',
            'users.username',
            'users.avatar_url',
          )
          .orderBy('comments.created_at', 'asc')
          .limit(5); // 限制显示前5个回复

        const replyCount = await db('comments')
          .where('parent_id', comment.id)
          .count('* as count')
          .first();

        return {
          id: comment.id,
          content: comment.content,
          likes_count: comment.likes_count,
          created_at: comment.created_at,
          updated_at: comment.updated_at,
          user: {
            id: comment.user_id,
            username: comment.username,
            avatar_url: comment.avatar_url,
          },
          replies: replies.map(reply => ({
            id: reply.id,
            content: reply.content,
            likes_count: reply.likes_count,
            created_at: reply.created_at,
            user: {
              id: reply.user_id,
              username: reply.username,
              avatar_url: reply.avatar_url,
            },
          })),
          reply_count: Number(replyCount?.['count']) || 0,
        };
      }),
    );

    // 获取总评论数
    const total = await db('comments')
      .where('annotation_id', annotationId)
      .whereNull('parent_id')
      .count('* as count')
      .first();

    return res.json({
      comments: commentsWithReplies,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total?.['count']) || 0,
        totalPages: Math.ceil((Number(total?.['count']) || 0) / Number(limit)),
      },
    });
  } catch (error) {
    console.error('获取评论列表失败:', error);
    return res.status(500).json({ error: '获取评论列表失败' });
  }
};

// 获取评论的回复
export const getCommentReplies = async (req: Request, res: Response) => {
  try {
    const { commentId } = req.params;
    const { page = 1, limit = 10 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // 验证父评论是否存在
    const parentComment = await db('comments').where('id', commentId).first();
    if (!parentComment) {
      return res.status(404).json({ error: '评论不存在' });
    }

    const replies = await db('comments')
      .join('users', 'comments.user_id', 'users.id')
      .where('comments.parent_id', commentId)
      .select(
        'comments.*',
        'users.username',
        'users.avatar_url',
      )
      .orderBy('comments.created_at', 'asc')
      .limit(Number(limit))
      .offset(offset);

    const total = await db('comments')
      .where('parent_id', commentId)
      .count('* as count')
      .first();

    return res.json({
      replies: replies.map(reply => ({
        id: reply.id,
        content: reply.content,
        likes_count: reply.likes_count,
        created_at: reply.created_at,
        user: {
          id: reply.user_id,
          username: reply.username,
          avatar_url: reply.avatar_url,
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
    console.error('获取回复列表失败:', error);
    return res.status(500).json({ error: '获取回复列表失败' });
  }
};

// 更新评论
export const updateComment = async (req: AuthRequest, res: Response) => {
  try {
    const { commentId } = req.params;
    const { content } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: '评论内容不能为空' });
    }

    if (content.length > 500) {
      return res.status(400).json({ error: '评论内容不能超过500字符' });
    }

    // 验证评论是否存在且属于当前用户
    const comment = await db('comments').where('id', commentId).first();
    if (!comment) {
      return res.status(404).json({ error: '评论不存在' });
    }

    if (comment.user_id !== userId && req.user?.role !== 'admin') {
      return res.status(403).json({ error: '只能编辑自己的评论' });
    }

    // 更新评论
    await db('comments')
      .where('id', commentId)
      .update({
        content: content.trim(),
        updated_at: new Date(),
      });

    // 获取更新后的评论信息
    const updatedComment = await db('comments')
      .join('users', 'comments.user_id', 'users.id')
      .where('comments.id', commentId)
      .select(
        'comments.*',
        'users.username',
        'users.avatar_url',
      )
      .first();

    return res.json({
      message: '评论更新成功',
      comment: {
        id: updatedComment.id,
        content: updatedComment.content,
        likes_count: updatedComment.likes_count,
        created_at: updatedComment.created_at,
        updated_at: updatedComment.updated_at,
        user: {
          id: updatedComment.user_id,
          username: updatedComment.username,
          avatar_url: updatedComment.avatar_url,
        },
      },
    });
  } catch (error) {
    console.error('更新评论失败:', error);
    return res.status(500).json({ error: '更新评论失败' });
  }
};

// 删除评论
export const deleteComment = async (req: AuthRequest, res: Response) => {
  try {
    const { commentId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 验证评论是否存在且属于当前用户
    const comment = await db('comments').where('id', commentId).first();
    if (!comment) {
      return res.status(404).json({ error: '评论不存在' });
    }

    if (comment.user_id !== userId && req.user?.role !== 'admin') {
      return res.status(403).json({ error: '只能删除自己的评论' });
    }

    // 删除评论及其所有回复
    await db.transaction(async (trx) => {
      // 删除所有回复
      await trx('comments').where('parent_id', commentId).del();
      // 删除评论本身
      await trx('comments').where('id', commentId).del();
    });

    return res.json({ message: '评论删除成功' });
  } catch (error) {
    console.error('删除评论失败:', error);
    return res.status(500).json({ error: '删除评论失败' });
  }
};

// 点赞评论
export const likeComment = async (req: AuthRequest, res: Response) => {
  try {
    const { commentId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    // 验证评论是否存在
    const comment = await db('comments').where('id', commentId).first();
    if (!comment) {
      return res.status(404).json({ error: '评论不存在' });
    }

    // 检查是否已经点赞
    const existingLike = await db('comment_likes')
      .where({ comment_id: commentId, user_id: userId })
      .first();

    if (existingLike) {
      return res.status(400).json({ error: '已经点赞过该评论' });
    }

    // 创建点赞记录
    const likeId = uuidv4();
    await db('comment_likes').insert({
      id: likeId,
      comment_id: commentId,
      user_id: userId,
      created_at: new Date(),
    });

    // 更新评论的点赞数
    await db('comments')
      .where('id', commentId)
      .increment('likes_count', 1);

    // 创建通知（如果不是自己的评论）
    if (comment.user_id !== userId && commentId) {
      const userInfo = await db('users').where('id', userId).first();
      await createNotification({
        user_id: comment.user_id,
        from_user_id: userId,
        type: 'comment_like',
        title: '评论获得点赞',
        content: `${userInfo.username} 点赞了你的评论`,
        related_id: commentId,
        related_type: 'comment',
      });
    }

    return res.json({ message: '点赞成功', likeId });
  } catch (error) {
    console.error('点赞评论失败:', error);
    return res.status(500).json({ error: '点赞失败' });
  }
};

// 取消点赞评论
export const unlikeComment = async (req: AuthRequest, res: Response) => {
  try {
    const { commentId } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const deleted = await db('comment_likes')
      .where({ comment_id: commentId, user_id: userId })
      .del();

    if (deleted === 0) {
      return res.status(404).json({ error: '未找到点赞记录' });
    }

    // 更新评论的点赞数
    await db('comments')
      .where('id', commentId)
      .decrement('likes_count', 1);

    return res.json({ message: '取消点赞成功' });
  } catch (error) {
    console.error('取消点赞失败:', error);
    return res.status(500).json({ error: '取消点赞失败' });
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
