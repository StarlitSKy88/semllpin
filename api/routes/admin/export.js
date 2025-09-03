/**
 * 管理后台数据导出API路由
 * 提供CSV、Excel格式的数据导出功能
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

const express = require('express');
const router = express.Router();
const { query, validationResult } = require('express-validator');
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
 * CSV格式化工具函数
 */
function formatCSV(data, headers) {
    if (!data || data.length === 0) {
        return headers.join(',') + '\n';
    }
    
    const csvRows = [];
    
    // 添加表头
    csvRows.push(headers.join(','));
    
    // 添加数据行
    data.forEach(row => {
        const values = headers.map(header => {
            const value = row[header] || '';
            // 处理包含逗号、引号或换行符的值
            if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))) {
                return `"${value.replace(/"/g, '""')}"`;
            }
            return value;
        });
        csvRows.push(values.join(','));
    });
    
    return csvRows.join('\n');
}

/**
 * Excel格式化工具函数（简化版，生成CSV格式但设置正确的MIME类型）
 */
function formatExcel(data, headers) {
    // 简化实现：生成CSV格式但使用Excel MIME类型
    // 在生产环境中，建议使用专门的Excel库如 xlsx
    return formatCSV(data, headers);
}

/**
 * @route GET /api/admin/export/users
 * @desc 导出用户数据
 * @access Admin (User Read Permission)
 */
router.get('/users', [
    requirePermission(PERMISSIONS.USER_READ),
    query('format').isIn(['csv', 'excel']).withMessage('导出格式必须为csv或excel'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    query('status').optional().isIn(['active', 'inactive', 'banned']).withMessage('无效的用户状态'),
    logAdminAction('export_users', 'user')
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
        
        const { format, startDate, endDate, status } = req.query;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (startDate) {
            whereClause += ` AND created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        if (status) {
            whereClause += ` AND status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        const result = await req.db.query(`
            SELECT 
                id,
                username,
                email,
                phone,
                status,
                level,
                total_earnings,
                total_spent,
                created_at,
                last_login_at,
                is_verified
            FROM users 
            ${whereClause}
            ORDER BY created_at DESC
        `, queryParams);
        
        const headers = [
            'id', 'username', 'email', 'phone', 'status', 'level',
            'total_earnings', 'total_spent', 'created_at', 'last_login_at', 'is_verified'
        ];
        
        const data = result.rows.map(row => ({
            id: row.id,
            username: row.username || '',
            email: row.email || '',
            phone: row.phone || '',
            status: row.status,
            level: row.level,
            total_earnings: row.total_earnings || 0,
            total_spent: row.total_spent || 0,
            created_at: row.created_at ? row.created_at.toISOString() : '',
            last_login_at: row.last_login_at ? row.last_login_at.toISOString() : '',
            is_verified: row.is_verified ? 'Yes' : 'No'
        }));
        
        let fileContent, mimeType, fileName;
        
        if (format === 'excel') {
            fileContent = formatExcel(data, headers);
            mimeType = 'application/vnd.ms-excel';
            fileName = `users_export_${new Date().toISOString().split('T')[0]}.xls`;
        } else {
            fileContent = formatCSV(data, headers);
            mimeType = 'text/csv';
            fileName = `users_export_${new Date().toISOString().split('T')[0]}.csv`;
        }
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(fileContent);
        
    } catch (error) {
        console.error('Export users error:', error);
        res.status(500).json({
            success: false,
            message: '导出用户数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/export/transactions
 * @desc 导出交易数据
 * @access Admin (Finance Read Permission)
 */
router.get('/transactions', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    query('format').isIn(['csv', 'excel']).withMessage('导出格式必须为csv或excel'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    query('type').optional().isIn(['payment', 'reward', 'withdrawal', 'refund']).withMessage('无效的交易类型'),
    query('status').optional().isIn(['pending', 'completed', 'failed', 'cancelled']).withMessage('无效的交易状态'),
    logAdminAction('export_transactions', 'finance')
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
        
        const { format, startDate, endDate, type, status } = req.query;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
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
        
        if (type) {
            whereClause += ` AND t.transaction_type = $${paramIndex}`;
            queryParams.push(type);
            paramIndex++;
        }
        
        if (status) {
            whereClause += ` AND t.status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        const result = await req.db.query(`
            SELECT 
                t.id,
                t.user_id,
                u.username,
                t.transaction_type,
                t.amount,
                t.fee,
                t.net_amount,
                t.status,
                t.payment_method,
                t.reference_id,
                t.description,
                t.created_at,
                t.completed_at
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            ${whereClause}
            ORDER BY t.created_at DESC
        `, queryParams);
        
        const headers = [
            'id', 'user_id', 'username', 'transaction_type', 'amount', 'fee',
            'net_amount', 'status', 'payment_method', 'reference_id', 'description',
            'created_at', 'completed_at'
        ];
        
        const data = result.rows.map(row => ({
            id: row.id,
            user_id: row.user_id,
            username: row.username || '',
            transaction_type: row.transaction_type,
            amount: row.amount || 0,
            fee: row.fee || 0,
            net_amount: row.net_amount || 0,
            status: row.status,
            payment_method: row.payment_method || '',
            reference_id: row.reference_id || '',
            description: row.description || '',
            created_at: row.created_at ? row.created_at.toISOString() : '',
            completed_at: row.completed_at ? row.completed_at.toISOString() : ''
        }));
        
        let fileContent, mimeType, fileName;
        
        if (format === 'excel') {
            fileContent = formatExcel(data, headers);
            mimeType = 'application/vnd.ms-excel';
            fileName = `transactions_export_${new Date().toISOString().split('T')[0]}.xls`;
        } else {
            fileContent = formatCSV(data, headers);
            mimeType = 'text/csv';
            fileName = `transactions_export_${new Date().toISOString().split('T')[0]}.csv`;
        }
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(fileContent);
        
    } catch (error) {
        console.error('Export transactions error:', error);
        res.status(500).json({
            success: false,
            message: '导出交易数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/export/annotations
 * @desc 导出标注数据
 * @access Admin (Content Read Permission)
 */
router.get('/annotations', [
    requirePermission(PERMISSIONS.CONTENT_READ),
    query('format').isIn(['csv', 'excel']).withMessage('导出格式必须为csv或excel'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    query('status').optional().isIn(['active', 'expired', 'reported', 'removed']).withMessage('无效的标注状态'),
    logAdminAction('export_annotations', 'content')
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
        
        const { format, startDate, endDate, status } = req.query;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (startDate) {
            whereClause += ` AND a.created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND a.created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        if (status) {
            whereClause += ` AND a.status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        const result = await req.db.query(`
            SELECT 
                a.id,
                a.user_id,
                u.username,
                a.title,
                a.content,
                a.latitude,
                a.longitude,
                a.address,
                a.price,
                a.status,
                a.view_count,
                a.report_count,
                a.created_at,
                a.expires_at
            FROM annotations a
            LEFT JOIN users u ON a.user_id = u.id
            ${whereClause}
            ORDER BY a.created_at DESC
        `, queryParams);
        
        const headers = [
            'id', 'user_id', 'username', 'title', 'content', 'latitude',
            'longitude', 'address', 'price', 'status', 'view_count',
            'report_count', 'created_at', 'expires_at'
        ];
        
        const data = result.rows.map(row => ({
            id: row.id,
            user_id: row.user_id,
            username: row.username || '',
            title: row.title || '',
            content: row.content || '',
            latitude: row.latitude || 0,
            longitude: row.longitude || 0,
            address: row.address || '',
            price: row.price || 0,
            status: row.status,
            view_count: row.view_count || 0,
            report_count: row.report_count || 0,
            created_at: row.created_at ? row.created_at.toISOString() : '',
            expires_at: row.expires_at ? row.expires_at.toISOString() : ''
        }));
        
        let fileContent, mimeType, fileName;
        
        if (format === 'excel') {
            fileContent = formatExcel(data, headers);
            mimeType = 'application/vnd.ms-excel';
            fileName = `annotations_export_${new Date().toISOString().split('T')[0]}.xls`;
        } else {
            fileContent = formatCSV(data, headers);
            mimeType = 'text/csv';
            fileName = `annotations_export_${new Date().toISOString().split('T')[0]}.csv`;
        }
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(fileContent);
        
    } catch (error) {
        console.error('Export annotations error:', error);
        res.status(500).json({
            success: false,
            message: '导出标注数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/export/rewards
 * @desc 导出奖励数据
 * @access Admin (Finance Read Permission)
 */
router.get('/rewards', [
    requirePermission(PERMISSIONS.FINANCE_READ),
    query('format').isIn(['csv', 'excel']).withMessage('导出格式必须为csv或excel'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    query('status').optional().isIn(['pending', 'claimed', 'expired']).withMessage('无效的奖励状态'),
    logAdminAction('export_rewards', 'finance')
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
        
        const { format, startDate, endDate, status } = req.query;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (startDate) {
            whereClause += ` AND r.created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND r.created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        if (status) {
            whereClause += ` AND r.status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        const result = await req.db.query(`
            SELECT 
                r.id,
                r.user_id,
                u.username,
                r.annotation_id,
                a.title as annotation_title,
                r.reward_type,
                r.amount,
                r.multiplier,
                r.status,
                r.claimed_at,
                r.expires_at,
                r.created_at
            FROM rewards r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN annotations a ON r.annotation_id = a.id
            ${whereClause}
            ORDER BY r.created_at DESC
        `, queryParams);
        
        const headers = [
            'id', 'user_id', 'username', 'annotation_id', 'annotation_title',
            'reward_type', 'amount', 'multiplier', 'status', 'claimed_at',
            'expires_at', 'created_at'
        ];
        
        const data = result.rows.map(row => ({
            id: row.id,
            user_id: row.user_id,
            username: row.username || '',
            annotation_id: row.annotation_id,
            annotation_title: row.annotation_title || '',
            reward_type: row.reward_type,
            amount: row.amount || 0,
            multiplier: row.multiplier || 1,
            status: row.status,
            claimed_at: row.claimed_at ? row.claimed_at.toISOString() : '',
            expires_at: row.expires_at ? row.expires_at.toISOString() : '',
            created_at: row.created_at ? row.created_at.toISOString() : ''
        }));
        
        let fileContent, mimeType, fileName;
        
        if (format === 'excel') {
            fileContent = formatExcel(data, headers);
            mimeType = 'application/vnd.ms-excel';
            fileName = `rewards_export_${new Date().toISOString().split('T')[0]}.xls`;
        } else {
            fileContent = formatCSV(data, headers);
            mimeType = 'text/csv';
            fileName = `rewards_export_${new Date().toISOString().split('T')[0]}.csv`;
        }
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(fileContent);
        
    } catch (error) {
        console.error('Export rewards error:', error);
        res.status(500).json({
            success: false,
            message: '导出奖励数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/export/analytics
 * @desc 导出分析数据
 * @access Admin (Analytics Read Permission)
 */
router.get('/analytics', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    query('format').isIn(['csv', 'excel']).withMessage('导出格式必须为csv或excel'),
    query('type').isIn(['daily', 'weekly', 'monthly']).withMessage('分析类型必须为daily、weekly或monthly'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    logAdminAction('export_analytics', 'analytics')
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
        
        const { format, type, startDate, endDate } = req.query;
        
        // 根据类型确定日期格式
        let dateFormat, groupBy;
        switch (type) {
            case 'daily':
                dateFormat = 'YYYY-MM-DD';
                groupBy = 'DATE(created_at)';
                break;
            case 'weekly':
                dateFormat = 'YYYY-"W"WW';
                groupBy = 'DATE_TRUNC(\'week\', created_at)';
                break;
            case 'monthly':
                dateFormat = 'YYYY-MM';
                groupBy = 'DATE_TRUNC(\'month\', created_at)';
                break;
            default:
                dateFormat = 'YYYY-MM-DD';
                groupBy = 'DATE(created_at)';
        }
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (startDate) {
            whereClause += ` AND created_at >= $${paramIndex}`;
            queryParams.push(startDate);
            paramIndex++;
        }
        
        if (endDate) {
            whereClause += ` AND created_at <= $${paramIndex}`;
            queryParams.push(endDate);
            paramIndex++;
        }
        
        // 查询用户注册统计
        const userStatsQuery = `
            SELECT 
                TO_CHAR(${groupBy}, '${dateFormat}') as period,
                COUNT(*) as new_users,
                COUNT(CASE WHEN is_verified = true THEN 1 END) as verified_users
            FROM users 
            ${whereClause}
            GROUP BY ${groupBy}
            ORDER BY ${groupBy}
        `;
        
        // 查询交易统计
        const transactionStatsQuery = `
            SELECT 
                TO_CHAR(${groupBy}, '${dateFormat}') as period,
                COUNT(*) as total_transactions,
                SUM(amount) as total_amount,
                SUM(fee) as total_fees,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_transactions
            FROM transactions 
            ${whereClause}
            GROUP BY ${groupBy}
            ORDER BY ${groupBy}
        `;
        
        // 查询标注统计
        const annotationStatsQuery = `
            SELECT 
                TO_CHAR(${groupBy}, '${dateFormat}') as period,
                COUNT(*) as new_annotations,
                SUM(price) as total_annotation_value,
                AVG(price) as avg_annotation_price
            FROM annotations 
            ${whereClause}
            GROUP BY ${groupBy}
            ORDER BY ${groupBy}
        `;
        
        const [userStats, transactionStats, annotationStats] = await Promise.all([
            req.db.query(userStatsQuery, queryParams),
            req.db.query(transactionStatsQuery, queryParams),
            req.db.query(annotationStatsQuery, queryParams)
        ]);
        
        // 合并数据
        const periodMap = new Map();
        
        // 处理用户数据
        userStats.rows.forEach(row => {
            periodMap.set(row.period, {
                period: row.period,
                new_users: parseInt(row.new_users) || 0,
                verified_users: parseInt(row.verified_users) || 0,
                total_transactions: 0,
                total_amount: 0,
                total_fees: 0,
                completed_transactions: 0,
                new_annotations: 0,
                total_annotation_value: 0,
                avg_annotation_price: 0
            });
        });
        
        // 处理交易数据
        transactionStats.rows.forEach(row => {
            const existing = periodMap.get(row.period) || {
                period: row.period,
                new_users: 0,
                verified_users: 0,
                new_annotations: 0,
                total_annotation_value: 0,
                avg_annotation_price: 0
            };
            
            existing.total_transactions = parseInt(row.total_transactions) || 0;
            existing.total_amount = parseFloat(row.total_amount) || 0;
            existing.total_fees = parseFloat(row.total_fees) || 0;
            existing.completed_transactions = parseInt(row.completed_transactions) || 0;
            
            periodMap.set(row.period, existing);
        });
        
        // 处理标注数据
        annotationStats.rows.forEach(row => {
            const existing = periodMap.get(row.period) || {
                period: row.period,
                new_users: 0,
                verified_users: 0,
                total_transactions: 0,
                total_amount: 0,
                total_fees: 0,
                completed_transactions: 0
            };
            
            existing.new_annotations = parseInt(row.new_annotations) || 0;
            existing.total_annotation_value = parseFloat(row.total_annotation_value) || 0;
            existing.avg_annotation_price = parseFloat(row.avg_annotation_price) || 0;
            
            periodMap.set(row.period, existing);
        });
        
        const data = Array.from(periodMap.values()).sort((a, b) => a.period.localeCompare(b.period));
        
        const headers = [
            'period', 'new_users', 'verified_users', 'total_transactions',
            'total_amount', 'total_fees', 'completed_transactions',
            'new_annotations', 'total_annotation_value', 'avg_annotation_price'
        ];
        
        let fileContent, mimeType, fileName;
        
        if (format === 'excel') {
            fileContent = formatExcel(data, headers);
            mimeType = 'application/vnd.ms-excel';
            fileName = `analytics_${type}_export_${new Date().toISOString().split('T')[0]}.xls`;
        } else {
            fileContent = formatCSV(data, headers);
            mimeType = 'text/csv';
            fileName = `analytics_${type}_export_${new Date().toISOString().split('T')[0]}.csv`;
        }
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(fileContent);
        
    } catch (error) {
        console.error('Export analytics error:', error);
        res.status(500).json({
            success: false,
            message: '导出分析数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

module.exports = router;