"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const adminController_1 = require("../controllers/adminController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.use(auth_1.authMiddleware);
router.get('/stats', adminController_1.getAdminStats);
router.get('/users', [
    (0, express_validator_1.query)('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
    (0, express_validator_1.query)('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
    (0, express_validator_1.query)('status').optional().isIn(['active', 'suspended', 'banned', 'pending']).withMessage('无效的用户状态'),
    (0, express_validator_1.query)('search').optional().isLength({ max: 100 }).withMessage('搜索关键词不能超过100字符'),
    (0, express_validator_1.query)('sortBy').optional().isIn(['created_at', 'username', 'email', 'total_annotations', 'total_spent', 'reports_count']).withMessage('无效的排序字段'),
    (0, express_validator_1.query)('sortOrder').optional().isIn(['asc', 'desc']).withMessage('排序方向必须是asc或desc'),
], adminController_1.getUserManagement);
router.put('/users/:userId/status', [
    (0, express_validator_1.param)('userId').isUUID().withMessage('用户ID格式无效'),
    (0, express_validator_1.body)('status').isIn(['active', 'suspended', 'banned', 'pending']).withMessage('无效的用户状态'),
    (0, express_validator_1.body)('reason').optional().isLength({ max: 500 }).withMessage('操作原因不能超过500字符'),
], adminController_1.updateUserStatus);
router.get('/content-reviews', [
    (0, express_validator_1.query)('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
    (0, express_validator_1.query)('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
    (0, express_validator_1.query)('status').optional().isIn(['pending', 'approved', 'rejected']).withMessage('无效的审核状态'),
    (0, express_validator_1.query)('type').optional().isIn(['annotation', 'comment', 'media']).withMessage('无效的内容类型'),
], adminController_1.getContentReviews);
router.put('/content-reviews/:reviewId', [
    (0, express_validator_1.param)('reviewId').isUUID().withMessage('审核记录ID格式无效'),
    (0, express_validator_1.body)('action').isIn(['approve', 'reject']).withMessage('审核动作必须是approve或reject'),
    (0, express_validator_1.body)('reason').optional().isLength({ max: 500 }).withMessage('审核原因不能超过500字符'),
], adminController_1.handleContentReview);
router.post('/users/batch', [
    (0, express_validator_1.body)('userIds').isArray({ min: 1 }).withMessage('用户ID列表不能为空'),
    (0, express_validator_1.body)('userIds.*').isUUID().withMessage('用户ID格式无效'),
    (0, express_validator_1.body)('operation').isIn(['suspend', 'activate', 'ban', 'delete']).withMessage('无效的操作类型'),
    (0, express_validator_1.body)('reason').optional().isLength({ max: 500 }).withMessage('操作原因不能超过500字符'),
], adminController_1.batchUserOperation);
router.get('/logs', [
    (0, express_validator_1.query)('page').optional().isInt({ min: 1 }).withMessage('页码必须是正整数'),
    (0, express_validator_1.query)('limit').optional().isInt({ min: 1, max: 200 }).withMessage('每页数量必须在1-200之间'),
    (0, express_validator_1.query)('action').optional().isLength({ max: 50 }).withMessage('操作类型不能超过50字符'),
    (0, express_validator_1.query)('adminId').optional().isUUID().withMessage('管理员ID格式无效'),
    (0, express_validator_1.query)('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    (0, express_validator_1.query)('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
], adminController_1.getAdminLogs);
exports.default = router;
//# sourceMappingURL=adminRoutes.js.map