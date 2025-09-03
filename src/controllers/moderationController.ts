import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../config/database';
import { logger } from '../utils/logger';

interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

export interface ContentReport {
  id: string;
  content_type: 'annotation' | 'comment' | 'user_profile';
  content_id: string;
  reported_by?: string;
  moderator_id?: string;
  reason: 'spam' | 'inappropriate' | 'harassment' | 'fake_info' | 'other';
  description?: string;
  status: 'pending' | 'approved' | 'rejected' | 'needs_review';
  moderator_notes?: string;
  reported_at: Date;
  moderated_at?: Date;
}

/**
 * 内容审核控制器
 * 处理用户举报和内容审核功能
 */
export class ModerationController {
  // 举报内容
  static async reportContent(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const {
        content_type,
        content_id,
        reason,
        description
      } = req.body;

      // 验证必填字段
      if (!content_type || !content_id || !reason) {
        return res.status(400).json({ error: '内容类型、内容ID和举报理由不能为空' });
      }

      // 验证内容类型
      const validContentTypes = ['annotation', 'comment', 'user_profile'];
      if (!validContentTypes.includes(content_type)) {
        return res.status(400).json({ error: '无效的内容类型' });
      }

      // 验证举报理由
      const validReasons = ['spam', 'inappropriate', 'harassment', 'fake_info', 'other'];
      if (!validReasons.includes(reason)) {
        return res.status(400).json({ error: '无效的举报理由' });
      }

      // 验证内容是否存在
      const contentExists = await this.validateContentExists(content_type, content_id);
      if (!contentExists) {
        return res.status(404).json({ error: '要举报的内容不存在' });
      }

      // 检查是否已经举报过同样的内容
      const existingReport = await db('content_moderation')
        .where({
          content_type,
          content_id,
          reported_by: userId
        })
        .first();

      if (existingReport) {
        return res.status(400).json({ error: '您已经举报过此内容' });
      }

      // 创建举报记录
      const reportId = uuidv4();
      await db('content_moderation').insert({
        id: reportId,
        content_type,
        content_id,
        reported_by: userId,
        reason,
        description: description?.trim() || null,
        status: 'pending',
        reported_at: new Date()
      });

      // 记录日志
      logger.info('内容举报创建', {
        reportId,
        contentType: content_type,
        contentId: content_id,
        reportedBy: userId,
        reason
      });

      return res.status(201).json({
        success: true,
        data: {
          reportId,
          message: '举报已提交，我们会尽快处理'
        }
      });
    } catch (error) {
      logger.error('举报内容失败', error);
      return res.status(500).json({ 
        error: '举报提交失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取举报列表（管理员）
  static async getModerationQueue(req: AuthRequest, res: Response) {
    try {
      const currentUserRole = req.user?.role;
      if (!currentUserRole || !['admin', 'moderator'].includes(currentUserRole)) {
        return res.status(403).json({ error: '需要管理员或版主权限' });
      }

      const {
        page = 1,
        limit = 20,
        status = 'pending',
        content_type,
        reason
      } = req.query;

      let query = db('content_moderation')
        .select(
          'content_moderation.*',
          'reporters.username as reporter_username',
          'moderators.username as moderator_username'
        )
        .leftJoin('users as reporters', 'content_moderation.reported_by', 'reporters.id')
        .leftJoin('users as moderators', 'content_moderation.moderator_id', 'moderators.id');

      // 过滤条件
      if (status && status !== 'all') {
        query = query.where('content_moderation.status', status);
      }

      if (content_type) {
        query = query.where('content_type', content_type);
      }

      if (reason) {
        query = query.where('reason', reason);
      }

      // 获取总数
      const countQuery = query.clone();
      const totalResult = await countQuery.count('* as count');
      const total = parseInt((totalResult[0] as any).count, 10);

      // 分页查询
      const reports = await query
        .orderBy('reported_at', 'desc')
        .limit(Number(limit))
        .offset((Number(page) - 1) * Number(limit));

      // 为每个举报获取相关内容详情
      const reportsWithContent = await Promise.all(
        reports.map(async (report) => {
          const contentDetails = await this.getContentDetails(
            report.content_type,
            report.content_id
          );

          return {
            ...report,
            content_details: contentDetails
          };
        })
      );

      return res.json({
        success: true,
        data: {
          reports: reportsWithContent,
          pagination: {
            page: Number(page),
            limit: Number(limit),
            total,
            totalPages: Math.ceil(total / Number(limit)),
            hasNext: Number(page) * Number(limit) < total,
            hasPrev: Number(page) > 1
          }
        }
      });
    } catch (error) {
      logger.error('获取举报队列失败', error);
      return res.status(500).json({ 
        error: '获取举报列表失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 处理举报（审核）
  static async moderateContent(req: AuthRequest, res: Response) {
    try {
      const { reportId } = req.params;
      const currentUserId = req.user?.id;
      const currentUserRole = req.user?.role;

      if (!currentUserId || !currentUserRole || !['admin', 'moderator'].includes(currentUserRole)) {
        return res.status(403).json({ error: '需要管理员或版主权限' });
      }

      const {
        action, // 'approve', 'reject', 'needs_review'
        moderator_notes,
        content_action // 'delete', 'hide', 'warn_user', 'none'
      } = req.body;

      if (!action) {
        return res.status(400).json({ error: '审核动作不能为空' });
      }

      const validActions = ['approved', 'rejected', 'needs_review'];
      if (!validActions.includes(action)) {
        return res.status(400).json({ error: '无效的审核动作' });
      }

      // 获取举报信息
      const report = await db('content_moderation')
        .where('id', reportId)
        .first();

      if (!report) {
        return res.status(404).json({ error: '举报记录不存在' });
      }

      if (report.status !== 'pending' && report.status !== 'needs_review') {
        return res.status(400).json({ error: '该举报已处理完成' });
      }

      // 更新举报状态
      await db('content_moderation')
        .where('id', reportId)
        .update({
          status: action,
          moderator_id: currentUserId,
          moderator_notes: moderator_notes?.trim() || null,
          moderated_at: new Date()
        });

      // 如果审核通过且有内容动作，执行相应操作
      if (action === 'approved' && content_action) {
        await this.executeContentAction(
          report.content_type,
          report.content_id,
          content_action,
          currentUserId
        );
      }

      // 创建审核日志
      logger.info('内容审核完成', {
        reportId,
        contentType: report.content_type,
        contentId: report.content_id,
        moderatorId: currentUserId,
        action,
        contentAction: content_action
      });

      // 通知举报者（可选）
      if (report.reported_by) {
        await this.notifyReporter(
          report.reported_by,
          report.content_type,
          action,
          moderator_notes
        );
      }

      return res.json({
        success: true,
        data: {
          reportId,
          action,
          message: '审核处理完成'
        }
      });
    } catch (error) {
      logger.error('内容审核失败', error);
      return res.status(500).json({ 
        error: '内容审核失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 获取用户的举报历史
  static async getUserReports(req: AuthRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: '用户未认证' });
      }

      const { page = 1, limit = 20, status } = req.query;

      let query = db('content_moderation')
        .select(
          'content_moderation.*',
          'moderators.username as moderator_username'
        )
        .leftJoin('users as moderators', 'content_moderation.moderator_id', 'moderators.id')
        .where('reported_by', userId);

      if (status) {
        query = query.where('status', status);
      }

      // 获取总数
      const countQuery = query.clone();
      const totalResult = await countQuery.count('* as count');
      const total = parseInt((totalResult[0] as any).count, 10);

      // 分页查询
      const reports = await query
        .orderBy('reported_at', 'desc')
        .limit(Number(limit))
        .offset((Number(page) - 1) * Number(limit));

      return res.json({
        success: true,
        data: {
          reports,
          pagination: {
            page: Number(page),
            limit: Number(limit),
            total,
            totalPages: Math.ceil(total / Number(limit)),
            hasNext: Number(page) * Number(limit) < total,
            hasPrev: Number(page) > 1
          }
        }
      });
    } catch (error) {
      logger.error('获取用户举报历史失败', error);
      return res.status(500).json({ 
        error: '获取举报历史失败',
        message: '服务器内部错误' 
      });
    }
  }

  // 验证内容是否存在
  private static async validateContentExists(
    contentType: string,
    contentId: string
  ): Promise<boolean> {
    try {
      let table: string;
      let whereClause: any = { id: contentId };

      switch (contentType) {
        case 'annotation':
          table = 'annotations';
          whereClause.status = ['pending', 'approved']; // 不包括已删除的
          break;
        case 'comment':
          table = 'comments';
          whereClause.status = 'active';
          break;
        case 'user_profile':
          table = 'users';
          whereClause.status = 'active';
          break;
        default:
          return false;
      }

      const content = await db(table).where(whereClause).first();
      return !!content;
    } catch (error) {
      logger.error('验证内容存在性失败', { contentType, contentId, error });
      return false;
    }
  }

  // 获取内容详情
  private static async getContentDetails(
    contentType: string,
    contentId: string
  ): Promise<any> {
    try {
      let content: any = null;

      switch (contentType) {
        case 'annotation':
          content = await db('annotations')
            .select(
              'id',
              'user_id',
              'description',
              'latitude',
              'longitude',
              'smell_intensity',
              'status',
              'created_at'
            )
            .join('users', 'annotations.user_id', 'users.id')
            .where('annotations.id', contentId)
            .first();
          break;

        case 'comment':
          content = await db('comments')
            .select(
              'comments.id',
              'comments.annotation_id',
              'comments.user_id',
              'comments.content',
              'comments.status',
              'comments.created_at',
              'users.username'
            )
            .join('users', 'comments.user_id', 'users.id')
            .where('comments.id', contentId)
            .first();
          break;

        case 'user_profile':
          content = await db('users')
            .select(
              'id',
              'username',
              'display_name',
              'bio',
              'status',
              'created_at'
            )
            .where('id', contentId)
            .first();
          break;
      }

      return content;
    } catch (error) {
      logger.error('获取内容详情失败', { contentType, contentId, error });
      return null;
    }
  }

  // 执行内容动作
  private static async executeContentAction(
    contentType: string,
    contentId: string,
    action: string,
    moderatorId: string
  ): Promise<void> {
    try {
      switch (action) {
        case 'delete':
          await this.deleteContent(contentType, contentId, moderatorId);
          break;
        case 'hide':
          await this.hideContent(contentType, contentId, moderatorId);
          break;
        case 'warn_user':
          await this.warnContentOwner(contentType, contentId, moderatorId);
          break;
        // 'none' - 不执行任何动作
      }
    } catch (error) {
      logger.error('执行内容动作失败', { contentType, contentId, action, error });
      throw error;
    }
  }

  // 删除内容
  private static async deleteContent(
    contentType: string,
    contentId: string,
    moderatorId: string
  ): Promise<void> {
    switch (contentType) {
      case 'annotation':
        await db('annotations')
          .where('id', contentId)
          .update({
            status: 'rejected',
            moderated_by: moderatorId,
            moderated_at: new Date(),
            moderation_reason: '违反社区规则'
          });
        break;
      case 'comment':
        await db('comments')
          .where('id', contentId)
          .update({
            status: 'deleted',
            updated_at: new Date()
          });
        break;
      case 'user_profile':
        await db('users')
          .where('id', contentId)
          .update({
            status: 'suspended',
            updated_at: new Date()
          });
        break;
    }
  }

  // 隐藏内容
  private static async hideContent(
    contentType: string,
    contentId: string,
    moderatorId: string
  ): Promise<void> {
    // 类似删除，但可能有不同的状态
    switch (contentType) {
      case 'annotation':
        await db('annotations')
          .where('id', contentId)
          .update({
            status: 'hidden',
            moderated_by: moderatorId,
            moderated_at: new Date(),
            moderation_reason: '内容需要审核'
          });
        break;
      case 'comment':
        await db('comments')
          .where('id', contentId)
          .update({
            status: 'hidden',
            updated_at: new Date()
          });
        break;
    }
  }

  // 警告内容所有者
  private static async warnContentOwner(
    contentType: string,
    contentId: string,
    moderatorId: string
  ): Promise<void> {
    // 获取内容所有者
    let ownerId: string | null = null;

    switch (contentType) {
      case 'annotation':
        const annotation = await db('annotations').where('id', contentId).first();
        ownerId = annotation?.user_id;
        break;
      case 'comment':
        const comment = await db('comments').where('id', contentId).first();
        ownerId = comment?.user_id;
        break;
      case 'user_profile':
        ownerId = contentId;
        break;
    }

    if (ownerId) {
      // 创建警告通知
      await db('notifications').insert({
        id: uuidv4(),
        user_id: ownerId,
        from_user_id: moderatorId,
        type: 'warning',
        title: '内容警告',
        content: '您的内容违反了社区规则，请注意遵守平台规范',
        related_id: contentId,
        related_type: contentType,
        is_read: false,
        created_at: new Date()
      });
    }
  }

  // 通知举报者
  private static async notifyReporter(
    reporterId: string,
    contentType: string,
    action: string,
    moderatorNotes?: string
  ): Promise<void> {
    let title: string;
    let content: string;

    switch (action) {
      case 'approved':
        title = '举报处理完成';
        content = `您举报的${this.getContentTypeName(contentType)}违反了平台规则，我们已进行处理。感谢您的反馈！`;
        break;
      case 'rejected':
        title = '举报处理结果';
        content = `经过审核，您举报的${this.getContentTypeName(contentType)}未违反平台规则。`;
        break;
      default:
        return;
    }

    if (moderatorNotes) {
      content += `\n备注：${moderatorNotes}`;
    }

    await db('notifications').insert({
      id: uuidv4(),
      user_id: reporterId,
      type: 'moderation_result',
      title,
      content,
      is_read: false,
      created_at: new Date()
    });
  }

  // 获取内容类型中文名
  private static getContentTypeName(contentType: string): string {
    const typeNames: { [key: string]: string } = {
      annotation: '标注',
      comment: '评论',
      user_profile: '用户资料'
    };
    return typeNames[contentType] || '内容';
  }
}

export default ModerationController;