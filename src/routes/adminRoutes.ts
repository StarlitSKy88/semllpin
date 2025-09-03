import { Router } from 'express';
import { body, param, query } from 'express-validator';
import {
  getAdminStats,
  getUserManagement,
  updateUserStatus,
  getContentReviews,
  handleContentReview,
  batchUserOperation,
  getAdminLogs,
} from '../controllers/adminController';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有管理员路由都需要认证
router.use(authMiddleware);

/**
 * @route GET /api/v1/admin/stats
 * @desc 获取管理员仪表板统计数据
 * @access Admin, Super Admin, Moderator
 */
router.get('/stats', getAdminStats);

/**
 * @route GET /api/v1/admin/users
 * @desc 获取用户管理列表
 * @access Admin, Super Admin, Moderator
 * @query page - 页码 (默认: 1)
 * @query limit - 每页数量 (默认: 20)
 * @query status - 用户状态筛选 (active, suspended, banned, pending)
 * @query search - 搜索关键词 (用户名或邮箱)
 * @query sortBy - 排序字段 (created_at, username, email, total_annotations, total_spent, reports_count)
 * @query sortOrder - 排序方向 (asc, desc)
 */
router.get('/users', [
  query('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
  query('status').optional().isIn(['active', 'suspended', 'banned', 'pending']).withMessage('无效的用户状态'),
  query('search').optional().isLength({ max: 100 }).withMessage('搜索关键词不能超过100字符'),
  query('sortBy').optional().isIn(['created_at', 'username', 'email', 'total_annotations', 'total_spent', 'reports_count']).withMessage('无效的排序字段'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('排序方向必须是asc或desc'),
], getUserManagement);

/**
 * @route PUT /api/v1/admin/users/:userId/status
 * @desc 更新用户状态
 * @access Admin, Super Admin
 * @param userId - 用户ID
 * @body status - 新状态 (active, suspended, banned, pending)
 * @body reason - 操作原因
 */
router.put('/users/:userId/status', [
  param('userId').isUUID().withMessage('用户ID格式无效'),
  body('status').isIn(['active', 'suspended', 'banned', 'pending']).withMessage('无效的用户状态'),
  body('reason').optional().isLength({ max: 500 }).withMessage('操作原因不能超过500字符'),
], updateUserStatus);

/**
 * @route GET /api/v1/admin/content-reviews
 * @desc 获取内容审核列表
 * @access Admin, Super Admin, Moderator
 * @query page - 页码 (默认: 1)
 * @query limit - 每页数量 (默认: 20)
 * @query status - 审核状态 (pending, approved, rejected)
 * @query type - 内容类型 (annotation, comment, media)
 */
router.get('/content-reviews', [
  query('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
  query('status').optional().isIn(['pending', 'approved', 'rejected']).withMessage('无效的审核状态'),
  query('type').optional().isIn(['annotation', 'comment', 'media']).withMessage('无效的内容类型'),
], getContentReviews);

/**
 * @route PUT /api/v1/admin/content-reviews/:reviewId
 * @desc 处理内容审核
 * @access Admin, Super Admin, Moderator
 * @param reviewId - 审核记录ID
 * @body action - 审核动作 (approve, reject)
 * @body reason - 审核原因
 */
router.put('/content-reviews/:reviewId', [
  param('reviewId').isUUID().withMessage('审核记录ID格式无效'),
  body('action').isIn(['approve', 'reject']).withMessage('审核动作必须是approve或reject'),
  body('reason').optional().isLength({ max: 500 }).withMessage('审核原因不能超过500字符'),
], handleContentReview);

/**
 * @route POST /api/v1/admin/users/batch
 * @desc 批量操作用户
 * @access Admin, Super Admin
 * @body userIds - 用户ID数组
 * @body operation - 操作类型 (suspend, activate, ban, delete)
 * @body reason - 操作原因
 */
router.post('/users/batch', [
  body('userIds').isArray({ min: 1 }).withMessage('用户ID列表不能为空'),
  body('userIds.*').isUUID().withMessage('用户ID格式无效'),
  body('operation').isIn(['suspend', 'activate', 'ban', 'delete']).withMessage('无效的操作类型'),
  body('reason').optional().isLength({ max: 500 }).withMessage('操作原因不能超过500字符'),
], batchUserOperation);

/**
 * @route GET /api/v1/admin/logs
 * @desc 获取管理操作日志
 * @access Admin, Super Admin
 * @query page - 页码 (默认: 1)
 * @query limit - 每页数量 (默认: 50)
 * @query action - 操作类型筛选
 * @query adminId - 管理员ID筛选
 * @query startDate - 开始日期
 * @query endDate - 结束日期
 */
router.get('/logs', [
  query('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('每页数量必须在1-200之间'),
  query('action').optional().isLength({ max: 50 }).withMessage('操作类型不能超过50字符'),
  query('adminId').optional().isUUID().withMessage('管理员ID格式无效'),
  query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
  query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
], getAdminLogs);

export default router;
