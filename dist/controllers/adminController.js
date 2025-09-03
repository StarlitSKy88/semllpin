"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAdminLogs = exports.batchUserOperation = exports.handleContentReview = exports.getContentReviews = exports.updateUserStatus = exports.getUserManagement = exports.getAdminStats = exports.UserStatus = exports.AdminRole = void 0;
const express_validator_1 = require("express-validator");
const database_1 = require("../config/database");
const logger_1 = require("../utils/logger");
exports.AdminRole = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    MODERATOR: 'moderator',
};
exports.UserStatus = {
    ACTIVE: 'active',
    SUSPENDED: 'suspended',
    BANNED: 'banned',
    PENDING: 'pending',
};
const getAdminStats = async (req, res) => {
    try {
        if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const userStats = await (0, database_1.db)('users')
            .select(database_1.db.raw('COUNT(*) as total_users'), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as active_users', [exports.UserStatus.ACTIVE]), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as suspended_users', [exports.UserStatus.SUSPENDED]), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as banned_users', [exports.UserStatus.BANNED]))
            .first();
        const annotationStats = await (0, database_1.db)('annotations')
            .select(database_1.db.raw('COUNT(*) as total_annotations'), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as pending_annotations', ['pending']), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as approved_annotations', ['approved']), database_1.db.raw('COUNT(CASE WHEN status = ? THEN 1 END) as rejected_annotations', ['rejected']))
            .first();
        const revenueStats = await (0, database_1.db)('payments')
            .select(database_1.db.raw('SUM(amount) as total_revenue'), database_1.db.raw('COUNT(*) as total_transactions'))
            .where('status', 'completed')
            .first();
        const monthlyRevenue = await (0, database_1.db)('payments')
            .sum('amount as monthly_revenue')
            .where('status', 'completed')
            .where(database_1.db.raw('DATE_TRUNC(\'month\', created_at) = DATE_TRUNC(\'month\', CURRENT_DATE)'))
            .first();
        const pendingReports = await (0, database_1.db)('content_reports')
            .count('* as pending_reports')
            .where('status', 'pending')
            .first();
        const stats = {
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
        logger_1.logger.info(`Admin ${req.user.username} accessed dashboard stats`);
        res.json({
            success: true,
            data: stats,
            message: '管理员统计数据获取成功',
        });
    }
    catch (error) {
        logger_1.logger.error('获取管理员统计数据失败:', error);
        res.status(500).json({
            success: false,
            message: '获取统计数据失败',
        });
    }
};
exports.getAdminStats = getAdminStats;
const getUserManagement = async (req, res) => {
    try {
        if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { page = 1, limit = 20, status, search, sortBy = 'created_at', sortOrder = 'desc' } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        let query = (0, database_1.db)('users')
            .select('users.id', 'users.username', 'users.email', 'users.status', 'users.role', 'users.created_at', 'users.last_login', database_1.db.raw('COUNT(DISTINCT annotations.id) as total_annotations'), database_1.db.raw('COALESCE(SUM(DISTINCT payments.amount), 0) as total_spent'), database_1.db.raw('COALESCE(SUM(DISTINCT wallet_transactions.amount), 0) as total_earned'), database_1.db.raw('COUNT(DISTINCT content_reports.id) as reports_count'))
            .leftJoin('annotations', 'users.id', 'annotations.user_id')
            .leftJoin('payments', 'users.id', 'payments.user_id')
            .leftJoin('wallet_transactions', function () {
            this.on('users.id', '=', 'wallet_transactions.user_id')
                .andOn('wallet_transactions.type', '=', database_1.db.raw('?', ['credit']));
        })
            .leftJoin('content_reports', 'users.id', 'content_reports.reported_user_id')
            .groupBy('users.id', 'users.username', 'users.email', 'users.status', 'users.role', 'users.created_at', 'users.last_login');
        if (status) {
            query = query.where('users.status', status);
        }
        if (search) {
            query = query.where(function () {
                this.where('users.username', 'ilike', `%${search}%`)
                    .orWhere('users.email', 'ilike', `%${search}%`);
            });
        }
        const validSortFields = ['created_at', 'username', 'email', 'total_annotations', 'total_spent', 'reports_count'];
        if (validSortFields.includes(sortBy)) {
            query = query.orderBy(sortBy, sortOrder);
        }
        const users = await query.limit(Number(limit)).offset(offset);
        const totalQuery = (0, database_1.db)('users').count('* as total');
        if (status) {
            totalQuery.where('status', status);
        }
        if (search) {
            totalQuery.where(function () {
                this.where('username', 'ilike', `%${search}%`)
                    .orWhere('email', 'ilike', `%${search}%`);
            });
        }
        const totalResult = await totalQuery.first();
        const total = parseInt(String(totalResult?.['total'] || '0'));
        logger_1.logger.info(`Admin ${req.user.username} accessed user management list`);
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
    }
    catch (error) {
        logger_1.logger.error('获取用户管理列表失败:', error);
        res.status(500).json({
            success: false,
            message: '获取用户列表失败',
        });
    }
};
exports.getUserManagement = getUserManagement;
const updateUserStatus = async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            res.status(400).json({
                success: false,
                message: '参数验证失败',
                errors: errors.array(),
            });
            return;
        }
        if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { userId } = req.params;
        const { status, reason } = req.body;
        if (!Object.values(exports.UserStatus).includes(status)) {
            res.status(400).json({
                success: false,
                message: '无效的用户状态',
            });
            return;
        }
        const user = await (0, database_1.db)('users').where('id', userId).first();
        if (!user) {
            res.status(404).json({
                success: false,
                message: '用户不存在',
            });
            return;
        }
        if (user.role === exports.AdminRole.SUPER_ADMIN && req.user.role !== exports.AdminRole.SUPER_ADMIN) {
            res.status(403).json({
                success: false,
                message: '无法修改超级管理员状态',
            });
            return;
        }
        await (0, database_1.db)('users')
            .where('id', userId)
            .update({
            status,
            updated_at: new Date(),
        });
        await (0, database_1.db)('admin_logs').insert({
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
        logger_1.logger.info(`Admin ${req.user.username} updated user ${user.username} status to ${status}`);
        res.json({
            success: true,
            message: '用户状态更新成功',
        });
    }
    catch (error) {
        logger_1.logger.error('更新用户状态失败:', error);
        res.status(500).json({
            success: false,
            message: '更新用户状态失败',
        });
    }
};
exports.updateUserStatus = updateUserStatus;
const getContentReviews = async (req, res) => {
    try {
        if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { page = 1, limit = 20, status = 'pending', type } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        let query = (0, database_1.db)('content_reports')
            .select('content_reports.*', 'reporter.username as reporter_username', 'reported_user.username as reported_username')
            .leftJoin('users as reporter', 'content_reports.reporter_id', 'reporter.id')
            .leftJoin('users as reported_user', 'content_reports.reported_user_id', 'reported_user.id');
        if (status) {
            query = query.where('content_reports.status', status);
        }
        if (type) {
            query = query.where('content_reports.content_type', type);
        }
        const reviews = await query
            .orderBy('content_reports.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const totalQuery = (0, database_1.db)('content_reports').count('* as total');
        if (status) {
            totalQuery.where('status', status);
        }
        if (type) {
            totalQuery.where('content_type', type);
        }
        const totalResult = await totalQuery.first();
        const total = parseInt(String(totalResult?.['total'] || '0'));
        logger_1.logger.info(`Admin ${req.user.username} accessed content reviews`);
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
    }
    catch (error) {
        logger_1.logger.error('获取内容审核列表失败:', error);
        res.status(500).json({
            success: false,
            message: '获取审核列表失败',
        });
    }
};
exports.getContentReviews = getContentReviews;
const handleContentReview = async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            res.status(400).json({
                success: false,
                message: '参数验证失败',
                errors: errors.array(),
            });
            return;
        }
        if (!req.user || !['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { reviewId } = req.params;
        const { action, reason } = req.body;
        const review = await (0, database_1.db)('content_reports').where('id', reviewId).first();
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
        await database_1.db.transaction(async (trx) => {
            await trx('content_reports')
                .where('id', reviewId)
                .update({
                status: newStatus,
                reviewed_by: req.user.id,
                reviewed_at: new Date(),
                review_reason: reason,
            });
            if (action === 'reject') {
                if (review.content_type === 'annotation') {
                    await trx('annotations')
                        .where('id', review.content_id)
                        .update({ status: 'rejected' });
                }
                else if (review.content_type === 'comment') {
                    await trx('comments')
                        .where('id', review.content_id)
                        .update({ status: 'hidden' });
                }
            }
            await trx('admin_logs').insert({
                admin_id: req.user.id,
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
        logger_1.logger.info(`Admin ${req.user.username} ${action}ed content review ${reviewId}`);
        res.json({
            success: true,
            message: `内容审核${action === 'approve' ? '通过' : '拒绝'}成功`,
        });
    }
    catch (error) {
        logger_1.logger.error('处理内容审核失败:', error);
        res.status(500).json({
            success: false,
            message: '处理审核失败',
        });
    }
};
exports.handleContentReview = handleContentReview;
const batchUserOperation = async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            res.status(400).json({
                success: false,
                message: '参数验证失败',
                errors: errors.array(),
            });
            return;
        }
        if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { userIds, operation, reason } = req.body;
        if (!Array.isArray(userIds) || userIds.length === 0) {
            res.status(400).json({
                success: false,
                message: '用户ID列表不能为空',
            });
            return;
        }
        const users = await (0, database_1.db)('users').whereIn('id', userIds);
        const superAdmins = users.filter(user => user.role === exports.AdminRole.SUPER_ADMIN);
        if (superAdmins.length > 0 && req.user.role !== exports.AdminRole.SUPER_ADMIN) {
            res.status(403).json({
                success: false,
                message: '无法对超级管理员执行批量操作',
            });
            return;
        }
        const updateData = { updated_at: new Date() };
        let actionName = '';
        switch (operation) {
            case 'suspend':
                updateData.status = exports.UserStatus.SUSPENDED;
                actionName = '暂停';
                break;
            case 'activate':
                updateData.status = exports.UserStatus.ACTIVE;
                actionName = '激活';
                break;
            case 'ban':
                updateData.status = exports.UserStatus.BANNED;
                actionName = '封禁';
                break;
            case 'delete':
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
        await database_1.db.transaction(async (trx) => {
            await trx('users')
                .whereIn('id', userIds)
                .update(updateData);
            const logEntries = userIds.map(userId => ({
                admin_id: req.user.id,
                action: `batch_${operation}`,
                target_type: 'user',
                target_id: userId,
                details: JSON.stringify({ reason }),
                created_at: new Date(),
            }));
            await trx('admin_logs').insert(logEntries);
        });
        logger_1.logger.info(`Admin ${req.user.username} performed batch ${operation} on ${userIds.length} users`);
        res.json({
            success: true,
            message: `批量${actionName}操作成功，共处理${userIds.length}个用户`,
        });
    }
    catch (error) {
        logger_1.logger.error('批量用户操作失败:', error);
        res.status(500).json({
            success: false,
            message: '批量操作失败',
        });
    }
};
exports.batchUserOperation = batchUserOperation;
const getAdminLogs = async (req, res) => {
    try {
        if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
            res.status(403).json({
                success: false,
                message: '权限不足，需要管理员权限',
            });
            return;
        }
        const { page = 1, limit = 50, action, adminId, startDate, endDate } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        let query = (0, database_1.db)('admin_logs')
            .select('admin_logs.*', 'users.username as admin_username')
            .leftJoin('users', 'admin_logs.admin_id', 'users.id');
        if (action) {
            query = query.where('admin_logs.action', action);
        }
        if (adminId) {
            query = query.where('admin_logs.admin_id', adminId);
        }
        if (startDate) {
            query = query.where('admin_logs.created_at', '>=', startDate);
        }
        if (endDate) {
            query = query.where('admin_logs.created_at', '<=', endDate);
        }
        const logs = await query
            .orderBy('admin_logs.created_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const totalQuery = (0, database_1.db)('admin_logs').count('* as total');
        if (action) {
            totalQuery.where('action', action);
        }
        if (adminId) {
            totalQuery.where('admin_id', adminId);
        }
        if (startDate) {
            totalQuery.where('created_at', '>=', startDate);
        }
        if (endDate) {
            totalQuery.where('created_at', '<=', endDate);
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
    }
    catch (error) {
        logger_1.logger.error('获取管理日志失败:', error);
        res.status(500).json({
            success: false,
            message: '获取管理日志失败',
        });
    }
};
exports.getAdminLogs = getAdminLogs;
//# sourceMappingURL=adminController.js.map