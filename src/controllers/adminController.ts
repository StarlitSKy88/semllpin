import { Request, Response } from 'express';
import { validationResult } from 'express-validator';
import { db } from '../config/database';
import { logger } from '../utils/logger';

// 扩展Request接口以包含用户信息
interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

// 管理员角色枚举
export const AdminRole = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
} as const;

export type AdminRoleType = typeof AdminRole[keyof typeof AdminRole];

// 用户状态枚举
export const UserStatus = {
  ACTIVE: 'active',
  SUSPENDED: 'suspended',
  BANNED: 'banned',
  PENDING: 'pending',
} as const;

export type UserStatusType = typeof UserStatus[keyof typeof UserStatus];

// 管理员统计接口
interface AdminStats {
  totalUsers: number;
  activeUsers: number;
  suspendedUsers: number;
  bannedUsers: number;
  totalAnnotations: number;
  pendingAnnotations: number;
  approvedAnnotations: number;
  rejectedAnnotations: number;
  totalRevenue: number;
  monthlyRevenue: number;
  totalTransactions: number;
  pendingReports: number;
}

// 用户管理接口
export interface UserManagement {
  id: string;
  username: string;
  email: string;
  status: UserStatusType;
  role: string;
  created_at: Date;
  last_login?: Date;
  total_annotations: number;
  total_spent: number;
  total_earned: number;
  reports_count: number;
}

// 内容审核接口
export interface ContentReview {
  id: string;
  type: 'annotation' | 'comment' | 'media';
  content_id: string;
  status: 'pending' | 'approved' | 'rejected';
  reported_by?: string;
  reason?: string;
  created_at: Date;
  reviewed_at?: Date;
  reviewed_by?: string;
  content_preview: string;
}

/**
 * 获取管理员仪表板统计数据
 */
export const getAdminStats = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    // 获取用户统计
    const userStats = await db('users')
      .select(
        db.raw('COUNT(*) as total_users'),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as active_users', [UserStatus.ACTIVE]),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as suspended_users', [UserStatus.SUSPENDED]),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as banned_users', [UserStatus.BANNED]),
      )
      .first();

    // 获取标注统计
    const annotationStats = await db('annotations')
      .select(
        db.raw('COUNT(*) as total_annotations'),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as pending_annotations', ['pending']),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as approved_annotations', ['approved']),
        db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as rejected_annotations', ['rejected']),
      )
      .first();

    // 获取收入统计
    const revenueStats = await db('payments')
      .select(
        db.raw('SUM(amount) as total_revenue'),
        db.raw('COUNT(*) as total_transactions'),
      )
      .where('status', 'completed')
      .first();

    // 获取本月收入
    const monthlyRevenue = await db('payments')
      .sum('amount as monthly_revenue')
      .where('status', 'completed')
      .where(db.raw('DATE_TRUNC(\'month\', created_at) = DATE_TRUNC(\'month\', CURRENT_DATE)'))
      .first();

    // 获取待处理举报数量
    const pendingReports = await db('content_reports')
      .count('* as pending_reports')
      .where('status', 'pending')
      .first();

    const stats: AdminStats = {
      totalUsers: parseInt(userStats?.total_users || '0'),
      activeUsers: parseInt(userStats?.active_users || '0'),
      suspendedUsers: parseInt(userStats?.suspended_users || '0'),
      bannedUsers: parseInt(userStats?.banned_users || '0'),
      totalAnnotations: parseInt(annotationStats?.total_annotations || '0'),
      pendingAnnotations: parseInt(annotationStats?.pending_annotations || '0'),
      approvedAnnotations: parseInt(annotationStats?.approved_annotations || '0'),
      rejectedAnnotations: parseInt(annotationStats?.rejected_annotations || '0'),
      totalRevenue: parseFloat(revenueStats?.total_revenue || '0'),
      monthlyRevenue: parseFloat(monthlyRevenue?.['monthly_revenue'] || '0'),
      totalTransactions: parseInt(revenueStats?.total_transactions || '0'),
      pendingReports: parseInt(String(pendingReports?.['pending_reports'] || '0')),
    };

    logger.info(`Admin ${req.user.username} accessed dashboard stats`);

    res.json({
      success: true,
      data: stats,
      message: '管理员统计数据获取成功',
    });
  } catch (error) {
    logger.error('获取管理员统计数据失败:', error);
    res.status(500).json({
      success: false,
      message: '获取统计数据失败',
    });
  }
};

/**
 * 获取用户管理列表
 */
export const getUserManagement = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { page = 1, limit = 20, status, search, sortBy = 'created_at', sortOrder = 'desc' } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let query = db('users')
      .select(
        'users.id',
        'users.username',
        'users.email',
        'users.status',
        'users.role',
        'users.created_at',
        'users.last_login',
        db.raw('COUNT(DISTINCT annotations.id) as total_annotations'),
        db.raw('COALESCE(SUM(DISTINCT payments.amount), 0) as total_spent'),
        db.raw('COALESCE(SUM(DISTINCT wallet_transactions.amount), 0) as total_earned'),
        db.raw('COUNT(DISTINCT content_reports.id) as reports_count'),
      )
      .leftJoin('annotations', 'users.id', 'annotations.user_id')
      .leftJoin('payments', 'users.id', 'payments.user_id')
      .leftJoin('wallet_transactions', function () {
        this.on('users.id', '=', 'wallet_transactions.user_id')
          .andOn('wallet_transactions.type', '=', db.raw('?', ['credit']));
      })
      .leftJoin('content_reports', 'users.id', 'content_reports.reported_user_id')
      .groupBy('users.id', 'users.username', 'users.email', 'users.status', 'users.role', 'users.created_at', 'users.last_login');

    // 状态筛选
    if (status) {
      query = query.where('users.status', status as string);
    }

    // 搜索功能
    if (search) {
      query = query.where(function () {
        this.where('users.username', 'ilike', `%${search}%`)
          .orWhere('users.email', 'ilike', `%${search}%`);
      });
    }

    // 排序
    const validSortFields = ['created_at', 'username', 'email', 'total_annotations', 'total_spent', 'reports_count'];
    if (validSortFields.includes(sortBy as string)) {
      query = query.orderBy(sortBy as string, sortOrder as 'asc' | 'desc');
    }

    // 分页
    const users = await query.limit(Number(limit)).offset(offset);

    // 获取总数
    const totalQuery = db('users').count('* as total');
    if (status) {
      totalQuery.where('status', status as string);
    }
    if (search) {
      totalQuery.where(function () {
        this.where('username', 'ilike', `%${search}%`)
          .orWhere('email', 'ilike', `%${search}%`);
      });
    }
    const totalResult = await totalQuery.first();
    const total = parseInt(String(totalResult?.['total'] || '0'));

    logger.info(`Admin ${req.user.username} accessed user management list`);

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          totalPages: Math.ceil(total / Number(limit)),
        },
      },
      message: '用户管理列表获取成功',
    });
  } catch (error) {
    logger.error('获取用户管理列表失败:', error);
    res.status(500).json({
      success: false,
      message: '获取用户列表失败',
    });
  }
};

/**
 * 更新用户状态
 */
export const updateUserStatus = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        success: false,
        message: '参数验证失败',
        errors: errors.array(),
      });
      return;
    }

    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { userId } = req.params;
    const { status, reason } = req.body;

    // 验证状态值
    if (!Object.values(UserStatus).includes(status)) {
      res.status(400).json({
        success: false,
        message: '无效的用户状态',
      });
      return;
    }

    // 检查用户是否存在
    const user = await db('users').where('id', userId).first();
    if (!user) {
      res.status(404).json({
        success: false,
        message: '用户不存在',
      });
      return;
    }

    // 防止修改超级管理员状态
    if (user.role === AdminRole.SUPER_ADMIN && req.user.role !== AdminRole.SUPER_ADMIN) {
      res.status(403).json({
        success: false,
        message: '无法修改超级管理员状态',
      });
      return;
    }

    // 更新用户状态
    await db('users')
      .where('id', userId)
      .update({
        status,
        updated_at: new Date(),
      });

    // 记录管理操作日志
    await db('admin_logs').insert({
      admin_id: req.user.id,
      action: 'update_user_status',
      target_type: 'user',
      target_id: userId,
      details: JSON.stringify({
        old_status: user.status,
        new_status: status,
        reason,
      }),
      created_at: new Date(),
    });

    logger.info(`Admin ${req.user.username} updated user ${user.username} status to ${status}`);

    res.json({
      success: true,
      message: '用户状态更新成功',
    });
  } catch (error) {
    logger.error('更新用户状态失败:', error);
    res.status(500).json({
      success: false,
      message: '更新用户状态失败',
    });
  }
};

/**
 * 获取内容审核列表
 */
export const getContentReviews = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { page = 1, limit = 20, status = 'pending', type } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let query = db('content_reports')
      .select(
        'content_reports.*',
        'reporter.username as reporter_username',
        'reported_user.username as reported_username',
      )
      .leftJoin('users as reporter', 'content_reports.reporter_id', 'reporter.id')
      .leftJoin('users as reported_user', 'content_reports.reported_user_id', 'reported_user.id');

    // 状态筛选
    if (status) {
      query = query.where('content_reports.status', status as string);
    }

    // 类型筛选
    if (type) {
      query = query.where('content_reports.content_type', type as string);
    }

    // 排序和分页
    const reviews = await query
      .orderBy('content_reports.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    // 获取总数
    const totalQuery = db('content_reports').count('* as total');
    if (status) {
      totalQuery.where('status', status as string);
    }
    if (type) {
      totalQuery.where('content_type', type as string);
    }
    const totalResult = await totalQuery.first();
    const total = parseInt(String(totalResult?.['total'] || '0'));

    logger.info(`Admin ${req.user.username} accessed content reviews`);

    res.json({
      success: true,
      data: {
        reviews,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          totalPages: Math.ceil(total / Number(limit)),
        },
      },
      message: '内容审核列表获取成功',
    });
  } catch (error) {
    logger.error('获取内容审核列表失败:', error);
    res.status(500).json({
      success: false,
      message: '获取审核列表失败',
    });
  }
};

/**
 * 处理内容审核
 */
export const handleContentReview = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        success: false,
        message: '参数验证失败',
        errors: errors.array(),
      });
      return;
    }

    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { reviewId } = req.params;
    const { action, reason } = req.body; // action: 'approve' | 'reject'

    // 检查审核记录是否存在
    const review = await db('content_reports').where('id', reviewId).first();
    if (!review) {
      res.status(404).json({
        success: false,
        message: '审核记录不存在',
      });
      return;
    }

    if (review.status !== 'pending') {
      res.status(400).json({
        success: false,
        message: '该内容已经被审核过了',
      });
      return;
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    // 开始事务
    await db.transaction(async (trx) => {
      // 更新审核状态
      await trx('content_reports')
        .where('id', reviewId)
        .update({
          status: newStatus,
          reviewed_by: req.user!.id,
          reviewed_at: new Date(),
          review_reason: reason,
        });

      // 如果是拒绝，需要处理相关内容
      if (action === 'reject') {
        if (review.content_type === 'annotation') {
          await trx('annotations')
            .where('id', review.content_id)
            .update({ status: 'rejected' });
        } else if (review.content_type === 'comment') {
          await trx('comments')
            .where('id', review.content_id)
            .update({ status: 'hidden' });
        }
      }

      // 记录管理操作日志
      await trx('admin_logs').insert({
        admin_id: req.user!.id,
        action: 'content_review',
        target_type: 'content_report',
        target_id: reviewId,
        details: JSON.stringify({
          action,
          content_type: review.content_type,
          content_id: review.content_id,
          reason,
        }),
        created_at: new Date(),
      });
    });

    logger.info(`Admin ${req.user.username} ${action}ed content review ${reviewId}`);

    res.json({
      success: true,
      message: `内容审核${action === 'approve' ? '通过' : '拒绝'}成功`,
    });
  } catch (error) {
    logger.error('处理内容审核失败:', error);
    res.status(500).json({
      success: false,
      message: '处理审核失败',
    });
  }
};

/**
 * 批量操作用户
 */
export const batchUserOperation = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        success: false,
        message: '参数验证失败',
        errors: errors.array(),
      });
      return;
    }

    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { userIds, operation, reason } = req.body;
    // operation: 'suspend' | 'activate' | 'ban' | 'delete'

    if (!Array.isArray(userIds) || userIds.length === 0) {
      res.status(400).json({
        success: false,
        message: '用户ID列表不能为空',
      });
      return;
    }

    // 检查用户是否存在且不包含超级管理员
    const users = await db('users').whereIn('id', userIds);
    const superAdmins = users.filter(user => user.role === AdminRole.SUPER_ADMIN);

    if (superAdmins.length > 0 && req.user.role !== AdminRole.SUPER_ADMIN) {
      res.status(403).json({
        success: false,
        message: '无法对超级管理员执行批量操作',
      });
      return;
    }

    const updateData: any = { updated_at: new Date() };
    let actionName = '';

    switch (operation) {
      case 'suspend':
        updateData.status = UserStatus.SUSPENDED;
        actionName = '暂停';
        break;
      case 'activate':
        updateData.status = UserStatus.ACTIVE;
        actionName = '激活';
        break;
      case 'ban':
        updateData.status = UserStatus.BANNED;
        actionName = '封禁';
        break;
      case 'delete':
        // 软删除
        updateData.deleted_at = new Date();
        actionName = '删除';
        break;
      default:
        res.status(400).json({
          success: false,
          message: '无效的操作类型',
        });
        return;
    }

    // 执行批量操作
    await db.transaction(async (trx) => {
      await trx('users')
        .whereIn('id', userIds)
        .update(updateData);

      // 记录管理操作日志
      const logEntries = userIds.map(userId => ({
        admin_id: req.user!.id,
        action: `batch_${operation}`,
        target_type: 'user',
        target_id: userId,
        details: JSON.stringify({ reason }),
        created_at: new Date(),
      }));

      await trx('admin_logs').insert(logEntries);
    });

    logger.info(`Admin ${req.user.username} performed batch ${operation} on ${userIds.length} users`);

    res.json({
      success: true,
      message: `批量${actionName}操作成功，共处理${userIds.length}个用户`,
    });
  } catch (error) {
    logger.error('批量用户操作失败:', error);
    res.status(500).json({
      success: false,
      message: '批量操作失败',
    });
  }
};

/**
 * 获取管理操作日志
 */
export const getAdminLogs = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // 检查管理员权限
    if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: '权限不足，需要管理员权限',
      });
      return;
    }

    const { page = 1, limit = 50, action, adminId, startDate, endDate } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let query = db('admin_logs')
      .select(
        'admin_logs.*',
        'users.username as admin_username',
      )
      .leftJoin('users', 'admin_logs.admin_id', 'users.id');

    // 筛选条件
    if (action) {
      query = query.where('admin_logs.action', action as string);
    }
    if (adminId) {
      query = query.where('admin_logs.admin_id', adminId as string);
    }
    if (startDate) {
      query = query.where('admin_logs.created_at', '>=', startDate as string);
    }
    if (endDate) {
      query = query.where('admin_logs.created_at', '<=', endDate as string);
    }

    // 排序和分页
    const logs = await query
      .orderBy('admin_logs.created_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    // 获取总数
    const totalQuery = db('admin_logs').count('* as total');
    if (action) {
      totalQuery.where('action', action as string);
    }
    if (adminId) {
      totalQuery.where('admin_id', adminId as string);
    }
    if (startDate) {
      totalQuery.where('created_at', '>=', startDate as string);
    }
    if (endDate) {
      totalQuery.where('created_at', '<=', endDate as string);
    }

    const totalResult = await totalQuery.first();
    const total = parseInt(String(totalResult?.['total'] || '0'));

    res.json({
      success: true,
      data: {
        logs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          totalPages: Math.ceil(total / Number(limit)),
        },
      },
      message: '管理日志获取成功',
    });
  } catch (error) {
    logger.error('获取管理日志失败:', error);
    res.status(500).json({
      success: false,
      message: '获取管理日志失败',
    });
  }
};
