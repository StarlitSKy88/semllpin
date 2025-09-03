/**
 * 管理后台财务数据API路由
 * 提供交易统计、收入分析、提现管理、手续费统计等接口
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const {
    authenticateAdmin,
    requirePermission,
    requireRole,
    logAdminAction,
    PERMISSIONS,
    ADMIN_ROLES
} = require('../../middleware/adminAuth');

// 应用管理员身份验证中间件
router.use(authenticateAdmin);

/**
 * @route GET /api/admin/finance/overview
 * @desc 获取财务概览数据
 * @access Admin (Finance Read Permission)
 */
router.get('/overview', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    logAdminAction('view_finance_overview', 'finance')
], async (req, res) => {
    try {
        const today = new Date();
        const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
        const lastWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
        const lastMonth = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
        
        // 并行查询各项财务数据
        const [totalRevenueResult, todayRevenueResult, pendingWithdrawalsResult, 
               totalUsersResult, activeUsersResult, transactionStatsResult] = await Promise.all([
            // 总收入
            req.db.query(`
                SELECT 
                    COALESCE(SUM(amount), 0) as total_revenue,
                    COALESCE(SUM(platform_fee), 0) as total_platform_fee
                FROM transactions 
                WHERE status = 'completed' AND type IN ('annotation_payment', 'reward_claim')
            `),
            
            // 今日收入
            req.db.query(`
                SELECT 
                    COALESCE(SUM(amount), 0) as today_revenue,
                    COALESCE(SUM(platform_fee), 0) as today_platform_fee,
                    COUNT(*) as today_transactions
                FROM transactions 
                WHERE status = 'completed' 
                    AND type IN ('annotation_payment', 'reward_claim')
                    AND created_at >= $1
            `, [today.toISOString().split('T')[0]]),
            
            // 待处理提现
            req.db.query(`
                SELECT 
                    COUNT(*) as pending_count,
                    COALESCE(SUM(amount), 0) as pending_amount
                FROM withdrawals 
                WHERE status = 'pending'
            `),
            
            // 用户统计
            req.db.query(`
                SELECT COUNT(*) as total_users
                FROM users 
                WHERE created_at IS NOT NULL
            `),
            
            // 活跃用户（最近7天有交易）
            req.db.query(`
                SELECT COUNT(DISTINCT user_id) as active_users
                FROM transactions 
                WHERE created_at >= $1
            `, [lastWeek.toISOString()]),
            
            // 交易统计
            req.db.query(`
                SELECT 
                    type,
                    COUNT(*) as count,
                    COALESCE(SUM(amount), 0) as total_amount
                FROM transactions 
                WHERE status = 'completed' AND created_at >= $1
                GROUP BY type
            `, [lastMonth.toISOString()])
        ]);
        
        // 计算增长率（与昨天对比）
        const yesterdayRevenueResult = await req.db.query(`
            SELECT 
                COALESCE(SUM(amount), 0) as yesterday_revenue,
                COALESCE(SUM(platform_fee), 0) as yesterday_platform_fee
            FROM transactions 
            WHERE status = 'completed' 
                AND type IN ('annotation_payment', 'reward_claim')
                AND created_at >= $1 AND created_at < $2
        `, [yesterday.toISOString().split('T')[0], today.toISOString().split('T')[0]]);
        
        const todayRevenue = parseFloat(todayRevenueResult.rows[0].today_revenue);
        const yesterdayRevenue = parseFloat(yesterdayRevenueResult.rows[0].yesterday_revenue);
        const revenueGrowthRate = yesterdayRevenue > 0 
            ? ((todayRevenue - yesterdayRevenue) / yesterdayRevenue * 100).toFixed(2)
            : todayRevenue > 0 ? 100 : 0;
        
        const overview = {
            totalRevenue: {
                amount: parseFloat(totalRevenueResult.rows[0].total_revenue),
                platformFee: parseFloat(totalRevenueResult.rows[0].total_platform_fee)
            },
            todayRevenue: {
                amount: todayRevenue,
                platformFee: parseFloat(todayRevenueResult.rows[0].today_platform_fee),
                transactions: parseInt(todayRevenueResult.rows[0].today_transactions),
                growthRate: parseFloat(revenueGrowthRate)
            },
            pendingWithdrawals: {
                count: parseInt(pendingWithdrawalsResult.rows[0].pending_count),
                amount: parseFloat(pendingWithdrawalsResult.rows[0].pending_amount)
            },
            userStats: {
                totalUsers: parseInt(totalUsersResult.rows[0].total_users),
                activeUsers: parseInt(activeUsersResult.rows[0].active_users)
            },
            transactionStats: transactionStatsResult.rows.map(row => ({
                type: row.type,
                count: parseInt(row.count),
                totalAmount: parseFloat(row.total_amount)
            }))
        };
        
        res.json({
            success: true,
            data: overview
        });
        
    } catch (error) {
        console.error('Finance overview error:', error);
        res.status(500).json({
            success: false,
            message: '获取财务概览失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/finance/transactions
 * @desc 获取交易记录列表
 * @access Admin (Finance Read Permission)
 */
router.get('/transactions', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
    query('type').optional().isIn(['annotation_payment', 'reward_claim', 'withdrawal', 'refund', 'deposit']).withMessage('无效的交易类型'),
    query('status').optional().isIn(['pending', 'completed', 'failed', 'cancelled']).withMessage('无效的交易状态'),
    query('userId').optional().isInt({ min: 1 }).withMessage('用户ID必须为正整数'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    query('minAmount').optional().isFloat({ min: 0 }).withMessage('最小金额必须为非负数'),
    query('maxAmount').optional().isFloat({ min: 0 }).withMessage('最大金额必须为非负数'),
    logAdminAction('view_transactions', 'finance')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const {
            page = 1,
            limit = 20,
            type,
            status,
            userId,
            startDate,
            endDate,
            minAmount,
            maxAmount
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (type) {
            whereClause += ` AND t.type = $${paramIndex}`;
            queryParams.push(type);
            paramIndex++;
        }
        
        if (status) {
            whereClause += ` AND t.status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        if (userId) {
            whereClause += ` AND t.user_id = $${paramIndex}`;
            queryParams.push(userId);
            paramIndex++;
        }
        
        if (startDate) {
            whereClause += ` AND t.created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND t.created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        if (minAmount) {
            whereClause += ` AND t.amount >= $${paramIndex}`;
            queryParams.push(minAmount);
            paramIndex++;
        }
        
        if (maxAmount) {
            whereClause += ` AND t.amount <= $${paramIndex}`;
            queryParams.push(maxAmount);
            paramIndex++;
        }
        
        // 查询交易记录
        const transactionsQuery = `
            SELECT 
                t.id,
                t.user_id,
                u.username,
                u.email,
                t.type,
                t.amount,
                t.platform_fee,
                t.status,
                t.payment_method,
                t.transaction_id,
                t.metadata,
                t.created_at,
                t.updated_at,
                t.completed_at
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            ${whereClause}
            ORDER BY t.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM transactions t
            ${whereClause}
        `;
        
        const [transactionsResult, countResult] = await Promise.all([
            req.db.query(transactionsQuery, queryParams),
            req.db.query(countQuery, queryParams.slice(0, -2))
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        res.json({
            success: true,
            data: {
                transactions: transactionsResult.rows.map(row => ({
                    id: row.id,
                    user: {
                        id: row.user_id,
                        username: row.username,
                        email: row.email
                    },
                    type: row.type,
                    amount: parseFloat(row.amount),
                    platformFee: parseFloat(row.platform_fee || 0),
                    status: row.status,
                    paymentMethod: row.payment_method,
                    transactionId: row.transaction_id,
                    metadata: row.metadata,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    completedAt: row.completed_at
                })),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
        
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({
            success: false,
            message: '获取交易记录失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/finance/withdrawals
 * @desc 获取提现申请列表
 * @access Admin (Finance Read Permission)
 */
router.get('/withdrawals', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
    query('status').optional().isIn(['pending', 'approved', 'rejected', 'completed', 'failed']).withMessage('无效的提现状态'),
    query('userId').optional().isInt({ min: 1 }).withMessage('用户ID必须为正整数'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    logAdminAction('view_withdrawals', 'finance')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const {
            page = 1,
            limit = 20,
            status,
            userId,
            startDate,
            endDate
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (status) {
            whereClause += ` AND w.status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        if (userId) {
            whereClause += ` AND w.user_id = $${paramIndex}`;
            queryParams.push(userId);
            paramIndex++;
        }
        
        if (startDate) {
            whereClause += ` AND w.created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND w.created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        // 查询提现记录
        const withdrawalsQuery = `
            SELECT 
                w.id,
                w.user_id,
                u.username,
                u.email,
                u.phone,
                w.amount,
                w.fee,
                w.actual_amount,
                w.payment_method,
                w.payment_account,
                w.status,
                w.admin_note,
                w.processed_by,
                w.processed_at,
                w.created_at,
                w.updated_at,
                admin_user.username as processed_by_username
            FROM withdrawals w
            LEFT JOIN users u ON w.user_id = u.id
            LEFT JOIN users admin_user ON w.processed_by = admin_user.id
            ${whereClause}
            ORDER BY w.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM withdrawals w
            ${whereClause}
        `;
        
        const [withdrawalsResult, countResult] = await Promise.all([
            req.db.query(withdrawalsQuery, queryParams),
            req.db.query(countQuery, queryParams.slice(0, -2))
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        res.json({
            success: true,
            data: {
                withdrawals: withdrawalsResult.rows.map(row => ({
                    id: row.id,
                    user: {
                        id: row.user_id,
                        username: row.username,
                        email: row.email,
                        phone: row.phone
                    },
                    amount: parseFloat(row.amount),
                    fee: parseFloat(row.fee || 0),
                    actualAmount: parseFloat(row.actual_amount),
                    paymentMethod: row.payment_method,
                    paymentAccount: row.payment_account,
                    status: row.status,
                    adminNote: row.admin_note,
                    processedBy: row.processed_by ? {
                        id: row.processed_by,
                        username: row.processed_by_username
                    } : null,
                    processedAt: row.processed_at,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at
                })),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
        
    } catch (error) {
        console.error('Get withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: '获取提现记录失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route PUT /api/admin/finance/withdrawals/:id/approve
 * @desc 批准提现申请
 * @access Admin (Finance Write Permission)
 */
router.put('/withdrawals/:id/approve', [
    requirePermission(PERMISSIONS.FINANCE_WITHDRAW),
    body('adminNote').optional().isString().isLength({ max: 500 }).withMessage('管理员备注不能超过500字符'),
    logAdminAction('approve_withdrawal', 'finance')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { id } = req.params;
        const { adminNote } = req.body;
        const adminId = req.admin.id;
        
        // 检查提现申请是否存在且状态为pending
        const withdrawalResult = await req.db.query(
            'SELECT * FROM withdrawals WHERE id = $1 AND status = $2',
            [id, 'pending']
        );
        
        if (withdrawalResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '提现申请不存在或状态不允许操作'
            });
        }
        
        const withdrawal = withdrawalResult.rows[0];
        
        // 更新提现状态
        await req.db.query(`
            UPDATE withdrawals 
            SET status = 'approved', 
                admin_note = $1, 
                processed_by = $2, 
                processed_at = NOW(),
                updated_at = NOW()
            WHERE id = $3
        `, [adminNote, adminId, id]);
        
        // 记录财务操作日志
        await req.db.query(`
            INSERT INTO financial_logs 
            (user_id, type, amount, description, admin_id, reference_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
        `, [
            withdrawal.user_id,
            'withdrawal_approved',
            withdrawal.actual_amount,
            `提现申请已批准 - ${adminNote || '无备注'}`,
            adminId,
            id
        ]);
        
        res.json({
            success: true,
            message: '提现申请已批准'
        });
        
    } catch (error) {
        console.error('Approve withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: '批准提现申请失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route PUT /api/admin/finance/withdrawals/:id/reject
 * @desc 拒绝提现申请
 * @access Admin (Finance Write Permission)
 */
router.put('/withdrawals/:id/reject', [
    requirePermission(PERMISSIONS.FINANCE_WITHDRAW),
    body('adminNote').isString().isLength({ min: 1, max: 500 }).withMessage('拒绝原因必填且不能超过500字符'),
    logAdminAction('reject_withdrawal', 'finance')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { id } = req.params;
        const { adminNote } = req.body;
        const adminId = req.admin.id;
        
        // 检查提现申请是否存在且状态为pending
        const withdrawalResult = await req.db.query(
            'SELECT * FROM withdrawals WHERE id = $1 AND status = $2',
            [id, 'pending']
        );
        
        if (withdrawalResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '提现申请不存在或状态不允许操作'
            });
        }
        
        const withdrawal = withdrawalResult.rows[0];
        
        // 开始事务
        await req.db.query('BEGIN');
        
        try {
            // 更新提现状态
            await req.db.query(`
                UPDATE withdrawals 
                SET status = 'rejected', 
                    admin_note = $1, 
                    processed_by = $2, 
                    processed_at = NOW(),
                    updated_at = NOW()
                WHERE id = $3
            `, [adminNote, adminId, id]);
            
            // 退还用户余额
            await req.db.query(`
                UPDATE user_wallets 
                SET balance = balance + $1,
                    updated_at = NOW()
                WHERE user_id = $2
            `, [withdrawal.amount, withdrawal.user_id]);
            
            // 记录财务操作日志
            await req.db.query(`
                INSERT INTO financial_logs 
                (user_id, type, amount, description, admin_id, reference_id, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
            `, [
                withdrawal.user_id,
                'withdrawal_rejected',
                withdrawal.amount,
                `提现申请已拒绝，余额已退还 - ${adminNote}`,
                adminId,
                id
            ]);
            
            await req.db.query('COMMIT');
            
            res.json({
                success: true,
                message: '提现申请已拒绝，用户余额已退还'
            });
            
        } catch (error) {
            await req.db.query('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.error('Reject withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: '拒绝提现申请失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/finance/revenue-stats
 * @desc 获取收入统计数据
 * @access Admin (Finance Read Permission)
 */
router.get('/revenue-stats', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    query('period').optional().isIn(['day', 'week', 'month', 'year']).withMessage('无效的统计周期'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    logAdminAction('view_revenue_stats', 'finance')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { period = 'day', startDate, endDate } = req.query;
        
        // 设置默认时间范围
        let defaultStartDate, defaultEndDate;
        const now = new Date();
        
        switch (period) {
            case 'day':
                defaultStartDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // 最近30天
                break;
            case 'week':
                defaultStartDate = new Date(now.getTime() - 12 * 7 * 24 * 60 * 60 * 1000); // 最近12周
                break;
            case 'month':
                defaultStartDate = new Date(now.getTime() - 12 * 30 * 24 * 60 * 60 * 1000); // 最近12个月
                break;
            case 'year':
                defaultStartDate = new Date(now.getTime() - 5 * 365 * 24 * 60 * 60 * 1000); // 最近5年
                break;
        }
        
        defaultEndDate = now;
        
        const queryStartDate = startDate || defaultStartDate.toISOString();
        const queryEndDate = endDate || defaultEndDate.toISOString();
        
        // 根据周期确定日期格式
        let dateFormat;
        switch (period) {
            case 'day':
                dateFormat = 'YYYY-MM-DD';
                break;
            case 'week':
                dateFormat = 'YYYY-"W"WW';
                break;
            case 'month':
                dateFormat = 'YYYY-MM';
                break;
            case 'year':
                dateFormat = 'YYYY';
                break;
        }
        
        // 查询收入统计
        const revenueStatsQuery = `
            SELECT 
                TO_CHAR(created_at, '${dateFormat}') as period,
                COUNT(*) as transaction_count,
                COALESCE(SUM(CASE WHEN type = 'annotation_payment' THEN amount ELSE 0 END), 0) as annotation_revenue,
                COALESCE(SUM(CASE WHEN type = 'reward_claim' THEN amount ELSE 0 END), 0) as reward_payout,
                COALESCE(SUM(platform_fee), 0) as platform_fee,
                COALESCE(SUM(amount), 0) as total_amount
            FROM transactions 
            WHERE status = 'completed' 
                AND type IN ('annotation_payment', 'reward_claim')
                AND created_at >= $1 
                AND created_at <= $2
            GROUP BY TO_CHAR(created_at, '${dateFormat}')
            ORDER BY period
        `;
        
        const revenueStatsResult = await req.db.query(revenueStatsQuery, [queryStartDate, queryEndDate]);
        
        // 查询总体统计
        const totalStatsResult = await req.db.query(`
            SELECT 
                COUNT(*) as total_transactions,
                COALESCE(SUM(CASE WHEN type = 'annotation_payment' THEN amount ELSE 0 END), 0) as total_annotation_revenue,
                COALESCE(SUM(CASE WHEN type = 'reward_claim' THEN amount ELSE 0 END), 0) as total_reward_payout,
                COALESCE(SUM(platform_fee), 0) as total_platform_fee,
                COALESCE(SUM(amount), 0) as total_amount
            FROM transactions 
            WHERE status = 'completed' 
                AND type IN ('annotation_payment', 'reward_claim')
                AND created_at >= $1 
                AND created_at <= $2
        `, [queryStartDate, queryEndDate]);
        
        const stats = {
            period,
            dateRange: {
                startDate: queryStartDate,
                endDate: queryEndDate
            },
            summary: {
                totalTransactions: parseInt(totalStatsResult.rows[0].total_transactions),
                totalAnnotationRevenue: parseFloat(totalStatsResult.rows[0].total_annotation_revenue),
                totalRewardPayout: parseFloat(totalStatsResult.rows[0].total_reward_payout),
                totalPlatformFee: parseFloat(totalStatsResult.rows[0].total_platform_fee),
                netRevenue: parseFloat(totalStatsResult.rows[0].total_platform_fee)
            },
            data: revenueStatsResult.rows.map(row => ({
                period: row.period,
                transactionCount: parseInt(row.transaction_count),
                annotationRevenue: parseFloat(row.annotation_revenue),
                rewardPayout: parseFloat(row.reward_payout),
                platformFee: parseFloat(row.platform_fee),
                netRevenue: parseFloat(row.platform_fee)
            }))
        };
        
        res.json({
            success: true,
            data: stats
        });
        
    } catch (error) {
        console.error('Get revenue stats error:', error);
        res.status(500).json({
            success: false,
            message: '获取收入统计失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

module.exports = router;