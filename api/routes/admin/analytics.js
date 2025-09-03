/**
 * 管理后台分析数据API路由
 * 提供用户行为分析、地理热力图数据、实时监控等接口
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
 * @route GET /api/admin/analytics/overview
 * @desc 获取分析数据概览
 * @access Admin (Analytics Read Permission)
 */
router.get('/overview', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    logAdminAction('view_analytics_overview', 'analytics')
], async (req, res) => {
    try {
        const today = new Date();
        const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
        const lastWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
        const lastMonth = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
        
        // 并行查询各项分析数据
        const [userStatsResult, annotationStatsResult, rewardStatsResult, 
               geoStatsResult, deviceStatsResult, activityStatsResult] = await Promise.all([
            // 用户统计
            req.db.query(`
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(CASE WHEN created_at >= $1 THEN 1 END) as new_users_today,
                    COUNT(CASE WHEN created_at >= $2 THEN 1 END) as new_users_week,
                    COUNT(CASE WHEN last_login >= $2 THEN 1 END) as active_users_week,
                    COUNT(CASE WHEN last_login >= $3 THEN 1 END) as active_users_month
                FROM users
            `, [today.toISOString().split('T')[0], lastWeek.toISOString(), lastMonth.toISOString()]),
            
            // 标注统计
            req.db.query(`
                SELECT 
                    COUNT(*) as total_annotations,
                    COUNT(CASE WHEN created_at >= $1 THEN 1 END) as annotations_today,
                    COUNT(CASE WHEN created_at >= $2 THEN 1 END) as annotations_week,
                    AVG(amount) as avg_annotation_amount,
                    SUM(amount) as total_annotation_value
                FROM annotations 
                WHERE status = 'active'
            `, [today.toISOString().split('T')[0], lastWeek.toISOString()]),
            
            // 奖励统计
            req.db.query(`
                SELECT 
                    COUNT(*) as total_rewards,
                    COUNT(CASE WHEN created_at >= $1 THEN 1 END) as rewards_today,
                    COUNT(CASE WHEN created_at >= $2 THEN 1 END) as rewards_week,
                    SUM(amount) as total_reward_amount,
                    COUNT(DISTINCT user_id) as unique_reward_users
                FROM user_rewards 
                WHERE status = 'claimed'
            `, [today.toISOString().split('T')[0], lastWeek.toISOString()]),
            
            // 地理统计
            req.db.query(`
                SELECT 
                    COUNT(DISTINCT ST_SnapToGrid(location, 0.01)) as unique_locations,
                    COUNT(*) as total_location_reports,
                    COUNT(CASE WHEN created_at >= $1 THEN 1 END) as location_reports_today
                FROM user_locations 
                WHERE created_at >= $2
            `, [today.toISOString().split('T')[0], lastMonth.toISOString()]),
            
            // 设备统计
            req.db.query(`
                SELECT 
                    device_type,
                    COUNT(*) as count
                FROM user_sessions 
                WHERE created_at >= $1
                GROUP BY device_type
            `, [lastMonth.toISOString()]),
            
            // 活跃度统计
            req.db.query(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(DISTINCT user_id) as daily_active_users
                FROM user_sessions 
                WHERE created_at >= $1
                GROUP BY DATE(created_at)
                ORDER BY date DESC
                LIMIT 7
            `, [lastWeek.toISOString()])
        ]);
        
        const overview = {
            userStats: {
                totalUsers: parseInt(userStatsResult.rows[0].total_users),
                newUsersToday: parseInt(userStatsResult.rows[0].new_users_today),
                newUsersWeek: parseInt(userStatsResult.rows[0].new_users_week),
                activeUsersWeek: parseInt(userStatsResult.rows[0].active_users_week),
                activeUsersMonth: parseInt(userStatsResult.rows[0].active_users_month)
            },
            annotationStats: {
                totalAnnotations: parseInt(annotationStatsResult.rows[0].total_annotations),
                annotationsToday: parseInt(annotationStatsResult.rows[0].annotations_today),
                annotationsWeek: parseInt(annotationStatsResult.rows[0].annotations_week),
                avgAnnotationAmount: parseFloat(annotationStatsResult.rows[0].avg_annotation_amount || 0),
                totalAnnotationValue: parseFloat(annotationStatsResult.rows[0].total_annotation_value || 0)
            },
            rewardStats: {
                totalRewards: parseInt(rewardStatsResult.rows[0].total_rewards),
                rewardsToday: parseInt(rewardStatsResult.rows[0].rewards_today),
                rewardsWeek: parseInt(rewardStatsResult.rows[0].rewards_week),
                totalRewardAmount: parseFloat(rewardStatsResult.rows[0].total_reward_amount || 0),
                uniqueRewardUsers: parseInt(rewardStatsResult.rows[0].unique_reward_users)
            },
            geoStats: {
                uniqueLocations: parseInt(geoStatsResult.rows[0].unique_locations),
                totalLocationReports: parseInt(geoStatsResult.rows[0].total_location_reports),
                locationReportsToday: parseInt(geoStatsResult.rows[0].location_reports_today)
            },
            deviceStats: deviceStatsResult.rows.map(row => ({
                deviceType: row.device_type,
                count: parseInt(row.count)
            })),
            activityTrend: activityStatsResult.rows.map(row => ({
                date: row.date,
                dailyActiveUsers: parseInt(row.daily_active_users)
            }))
        };
        
        res.json({
            success: true,
            data: overview
        });
        
    } catch (error) {
        console.error('Analytics overview error:', error);
        res.status(500).json({
            success: false,
            message: '获取分析概览失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/analytics/user-behavior
 * @desc 获取用户行为分析数据
 * @access Admin (Analytics Read Permission)
 */
router.get('/user-behavior', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    query('period').optional().isIn(['day', 'week', 'month']).withMessage('无效的统计周期'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    logAdminAction('view_user_behavior', 'analytics')
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
        }
        
        // 并行查询用户行为数据
        const [userActivityResult, sessionStatsResult, featureUsageResult, 
               retentionResult, conversionResult] = await Promise.all([
            // 用户活跃度趋势
            req.db.query(`
                SELECT 
                    TO_CHAR(created_at, '${dateFormat}') as period,
                    COUNT(DISTINCT user_id) as active_users,
                    COUNT(*) as total_sessions,
                    AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/60) as avg_session_duration
                FROM user_sessions 
                WHERE created_at >= $1 AND created_at <= $2
                GROUP BY TO_CHAR(created_at, '${dateFormat}')
                ORDER BY period
            `, [queryStartDate, queryEndDate]),
            
            // 会话统计
            req.db.query(`
                SELECT 
                    device_type,
                    COUNT(*) as session_count,
                    AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/60) as avg_duration,
                    COUNT(DISTINCT user_id) as unique_users
                FROM user_sessions 
                WHERE created_at >= $1 AND created_at <= $2
                GROUP BY device_type
            `, [queryStartDate, queryEndDate]),
            
            // 功能使用统计
            req.db.query(`
                SELECT 
                    action_type,
                    COUNT(*) as usage_count,
                    COUNT(DISTINCT user_id) as unique_users
                FROM user_actions 
                WHERE created_at >= $1 AND created_at <= $2
                GROUP BY action_type
                ORDER BY usage_count DESC
            `, [queryStartDate, queryEndDate]),
            
            // 用户留存分析（简化版）
            req.db.query(`
                WITH user_cohorts AS (
                    SELECT 
                        user_id,
                        DATE_TRUNC('week', created_at) as cohort_week
                    FROM users 
                    WHERE created_at >= $1
                ),
                user_activity AS (
                    SELECT 
                        user_id,
                        DATE_TRUNC('week', created_at) as activity_week
                    FROM user_sessions 
                    WHERE created_at >= $1
                    GROUP BY user_id, DATE_TRUNC('week', created_at)
                )
                SELECT 
                    uc.cohort_week,
                    COUNT(DISTINCT uc.user_id) as cohort_size,
                    COUNT(DISTINCT CASE WHEN ua.activity_week = uc.cohort_week + INTERVAL '1 week' THEN uc.user_id END) as week_1_retention,
                    COUNT(DISTINCT CASE WHEN ua.activity_week = uc.cohort_week + INTERVAL '2 week' THEN uc.user_id END) as week_2_retention,
                    COUNT(DISTINCT CASE WHEN ua.activity_week = uc.cohort_week + INTERVAL '4 week' THEN uc.user_id END) as week_4_retention
                FROM user_cohorts uc
                LEFT JOIN user_activity ua ON uc.user_id = ua.user_id
                GROUP BY uc.cohort_week
                ORDER BY uc.cohort_week DESC
                LIMIT 10
            `, [queryStartDate]),
            
            // 转化漏斗分析
            req.db.query(`
                WITH funnel_data AS (
                    SELECT 
                        user_id,
                        MAX(CASE WHEN action_type = 'app_open' THEN 1 ELSE 0 END) as opened_app,
                        MAX(CASE WHEN action_type = 'view_map' THEN 1 ELSE 0 END) as viewed_map,
                        MAX(CASE WHEN action_type = 'create_annotation' THEN 1 ELSE 0 END) as created_annotation,
                        MAX(CASE WHEN action_type = 'claim_reward' THEN 1 ELSE 0 END) as claimed_reward
                    FROM user_actions 
                    WHERE created_at >= $1 AND created_at <= $2
                    GROUP BY user_id
                )
                SELECT 
                    SUM(opened_app) as step_1_users,
                    SUM(viewed_map) as step_2_users,
                    SUM(created_annotation) as step_3_users,
                    SUM(claimed_reward) as step_4_users
                FROM funnel_data
            `, [queryStartDate, queryEndDate])
        ]);
        
        const behaviorData = {
            period,
            dateRange: {
                startDate: queryStartDate,
                endDate: queryEndDate
            },
            userActivity: userActivityResult.rows.map(row => ({
                period: row.period,
                activeUsers: parseInt(row.active_users),
                totalSessions: parseInt(row.total_sessions),
                avgSessionDuration: parseFloat(row.avg_session_duration || 0)
            })),
            sessionStats: sessionStatsResult.rows.map(row => ({
                deviceType: row.device_type,
                sessionCount: parseInt(row.session_count),
                avgDuration: parseFloat(row.avg_duration || 0),
                uniqueUsers: parseInt(row.unique_users)
            })),
            featureUsage: featureUsageResult.rows.map(row => ({
                actionType: row.action_type,
                usageCount: parseInt(row.usage_count),
                uniqueUsers: parseInt(row.unique_users)
            })),
            retention: retentionResult.rows.map(row => ({
                cohortWeek: row.cohort_week,
                cohortSize: parseInt(row.cohort_size),
                week1Retention: parseFloat((parseInt(row.week_1_retention) / parseInt(row.cohort_size) * 100).toFixed(2)),
                week2Retention: parseFloat((parseInt(row.week_2_retention) / parseInt(row.cohort_size) * 100).toFixed(2)),
                week4Retention: parseFloat((parseInt(row.week_4_retention) / parseInt(row.cohort_size) * 100).toFixed(2))
            })),
            conversionFunnel: conversionResult.rows.length > 0 ? {
                step1: parseInt(conversionResult.rows[0].step_1_users),
                step2: parseInt(conversionResult.rows[0].step_2_users),
                step3: parseInt(conversionResult.rows[0].step_3_users),
                step4: parseInt(conversionResult.rows[0].step_4_users)
            } : { step1: 0, step2: 0, step3: 0, step4: 0 }
        };
        
        res.json({
            success: true,
            data: behaviorData
        });
        
    } catch (error) {
        console.error('User behavior analytics error:', error);
        res.status(500).json({
            success: false,
            message: '获取用户行为分析失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/analytics/heatmap
 * @desc 获取地理热力图数据
 * @access Admin (Analytics Read Permission)
 */
router.get('/heatmap', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    query('type').optional().isIn(['annotations', 'rewards', 'users']).withMessage('无效的热力图类型'),
    query('bounds').optional().matches(/^-?\d+\.\d+,-?\d+\.\d+,-?\d+\.\d+,-?\d+\.\d+$/).withMessage('边界坐标格式无效'),
    query('zoom').optional().isInt({ min: 1, max: 18 }).withMessage('缩放级别必须在1-18之间'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效'),
    logAdminAction('view_heatmap', 'analytics')
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
            type = 'annotations', 
            bounds, 
            zoom = 10, 
            startDate, 
            endDate 
        } = req.query;
        
        // 设置默认时间范围（最近30天）
        const defaultEndDate = new Date();
        const defaultStartDate = new Date(defaultEndDate.getTime() - 30 * 24 * 60 * 60 * 1000);
        
        const queryStartDate = startDate || defaultStartDate.toISOString();
        const queryEndDate = endDate || defaultEndDate.toISOString();
        
        // 根据缩放级别确定网格精度
        const gridSize = Math.max(0.001, 0.1 / Math.pow(2, zoom - 8));
        
        let query, queryParams;
        
        // 构建边界条件
        let boundsCondition = '';
        if (bounds) {
            const [minLng, minLat, maxLng, maxLat] = bounds.split(',').map(parseFloat);
            boundsCondition = `AND ST_Within(location, ST_MakeEnvelope($${queryParams ? queryParams.length + 1 : 3}, $${queryParams ? queryParams.length + 2 : 4}, $${queryParams ? queryParams.length + 3 : 5}, $${queryParams ? queryParams.length + 4 : 6}, 4326))`;
            queryParams = queryParams || [queryStartDate, queryEndDate];
            queryParams.push(minLng, minLat, maxLng, maxLat);
        }
        
        switch (type) {
            case 'annotations':
                query = `
                    SELECT 
                        ST_X(ST_SnapToGrid(location, $3)) as lng,
                        ST_Y(ST_SnapToGrid(location, $3)) as lat,
                        COUNT(*) as count,
                        SUM(amount) as total_amount,
                        AVG(amount) as avg_amount
                    FROM annotations 
                    WHERE created_at >= $1 AND created_at <= $2 
                        AND status = 'active'
                        ${boundsCondition}
                    GROUP BY ST_SnapToGrid(location, $3)
                    HAVING COUNT(*) > 0
                    ORDER BY count DESC
                    LIMIT 1000
                `;
                queryParams = queryParams || [queryStartDate, queryEndDate, gridSize];
                if (!queryParams.includes(gridSize)) queryParams.splice(2, 0, gridSize);
                break;
                
            case 'rewards':
                query = `
                    SELECT 
                        ST_X(ST_SnapToGrid(ul.location, $3)) as lng,
                        ST_Y(ST_SnapToGrid(ul.location, $3)) as lat,
                        COUNT(*) as count,
                        SUM(ur.amount) as total_amount,
                        AVG(ur.amount) as avg_amount
                    FROM user_rewards ur
                    JOIN user_locations ul ON ur.user_id = ul.user_id 
                        AND ABS(EXTRACT(EPOCH FROM (ur.created_at - ul.created_at))) < 300
                    WHERE ur.created_at >= $1 AND ur.created_at <= $2 
                        AND ur.status = 'claimed'
                        ${boundsCondition.replace('location', 'ul.location')}
                    GROUP BY ST_SnapToGrid(ul.location, $3)
                    HAVING COUNT(*) > 0
                    ORDER BY count DESC
                    LIMIT 1000
                `;
                queryParams = queryParams || [queryStartDate, queryEndDate, gridSize];
                if (!queryParams.includes(gridSize)) queryParams.splice(2, 0, gridSize);
                break;
                
            case 'users':
                query = `
                    SELECT 
                        ST_X(ST_SnapToGrid(location, $3)) as lng,
                        ST_Y(ST_SnapToGrid(location, $3)) as lat,
                        COUNT(DISTINCT user_id) as count,
                        COUNT(*) as total_reports
                    FROM user_locations 
                    WHERE created_at >= $1 AND created_at <= $2
                        ${boundsCondition}
                    GROUP BY ST_SnapToGrid(location, $3)
                    HAVING COUNT(DISTINCT user_id) > 0
                    ORDER BY count DESC
                    LIMIT 1000
                `;
                queryParams = queryParams || [queryStartDate, queryEndDate, gridSize];
                if (!queryParams.includes(gridSize)) queryParams.splice(2, 0, gridSize);
                break;
        }
        
        const result = await req.db.query(query, queryParams);
        
        const heatmapData = {
            type,
            gridSize,
            dateRange: {
                startDate: queryStartDate,
                endDate: queryEndDate
            },
            bounds: bounds ? {
                minLng: parseFloat(bounds.split(',')[0]),
                minLat: parseFloat(bounds.split(',')[1]),
                maxLng: parseFloat(bounds.split(',')[2]),
                maxLat: parseFloat(bounds.split(',')[3])
            } : null,
            points: result.rows.map(row => ({
                lng: parseFloat(row.lng),
                lat: parseFloat(row.lat),
                count: parseInt(row.count),
                totalAmount: parseFloat(row.total_amount || 0),
                avgAmount: parseFloat(row.avg_amount || 0),
                totalReports: parseInt(row.total_reports || 0)
            }))
        };
        
        res.json({
            success: true,
            data: heatmapData
        });
        
    } catch (error) {
        console.error('Heatmap analytics error:', error);
        res.status(500).json({
            success: false,
            message: '获取热力图数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/analytics/realtime
 * @desc 获取实时监控数据
 * @access Admin (Analytics Read Permission)
 */
router.get('/realtime', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    logAdminAction('view_realtime_analytics', 'analytics')
], async (req, res) => {
    try {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        // 并行查询实时数据
        const [currentOnlineResult, recentActivityResult, systemStatsResult, 
               alertsResult, performanceResult] = await Promise.all([
            // 当前在线用户（最近5分钟有活动）
            req.db.query(`
                SELECT COUNT(DISTINCT user_id) as online_users
                FROM user_sessions 
                WHERE updated_at >= $1
            `, [new Date(now.getTime() - 5 * 60 * 1000).toISOString()]),
            
            // 最近活动（最近1小时）
            req.db.query(`
                SELECT 
                    DATE_TRUNC('minute', created_at) as minute,
                    COUNT(*) as activity_count,
                    COUNT(DISTINCT user_id) as unique_users
                FROM user_actions 
                WHERE created_at >= $1
                GROUP BY DATE_TRUNC('minute', created_at)
                ORDER BY minute DESC
                LIMIT 60
            `, [oneHourAgo.toISOString()]),
            
            // 系统统计（最近24小时）
            req.db.query(`
                SELECT 
                    'annotations' as type,
                    COUNT(*) as count
                FROM annotations 
                WHERE created_at >= $1
                UNION ALL
                SELECT 
                    'rewards' as type,
                    COUNT(*) as count
                FROM user_rewards 
                WHERE created_at >= $1
                UNION ALL
                SELECT 
                    'transactions' as type,
                    COUNT(*) as count
                FROM transactions 
                WHERE created_at >= $1
                UNION ALL
                SELECT 
                    'new_users' as type,
                    COUNT(*) as count
                FROM users 
                WHERE created_at >= $1
            `, [oneDayAgo.toISOString()]),
            
            // 系统警报（检查异常情况）
            req.db.query(`
                SELECT 
                    'high_error_rate' as alert_type,
                    COUNT(*) as count,
                    'API错误率过高' as message
                FROM api_logs 
                WHERE created_at >= $1 AND status_code >= 500
                HAVING COUNT(*) > 100
                UNION ALL
                SELECT 
                    'suspicious_activity' as alert_type,
                    COUNT(*) as count,
                    '可疑用户活动' as message
                FROM user_actions 
                WHERE created_at >= $1 
                GROUP BY user_id
                HAVING COUNT(*) > 1000
                LIMIT 1
            `, [oneHourAgo.toISOString()]),
            
            // 性能指标（最近1小时平均响应时间）
            req.db.query(`
                SELECT 
                    endpoint,
                    AVG(response_time) as avg_response_time,
                    COUNT(*) as request_count,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                FROM api_logs 
                WHERE created_at >= $1
                GROUP BY endpoint
                ORDER BY request_count DESC
                LIMIT 10
            `, [oneHourAgo.toISOString()])
        ]);
        
        const realtimeData = {
            timestamp: now.toISOString(),
            onlineUsers: parseInt(currentOnlineResult.rows[0]?.online_users || 0),
            recentActivity: recentActivityResult.rows.map(row => ({
                minute: row.minute,
                activityCount: parseInt(row.activity_count),
                uniqueUsers: parseInt(row.unique_users)
            })),
            systemStats: systemStatsResult.rows.reduce((acc, row) => {
                acc[row.type] = parseInt(row.count);
                return acc;
            }, {}),
            alerts: alertsResult.rows.map(row => ({
                type: row.alert_type,
                count: parseInt(row.count),
                message: row.message,
                severity: parseInt(row.count) > 500 ? 'high' : 'medium'
            })),
            performance: performanceResult.rows.map(row => ({
                endpoint: row.endpoint,
                avgResponseTime: parseFloat(row.avg_response_time || 0),
                requestCount: parseInt(row.request_count),
                errorCount: parseInt(row.error_count),
                errorRate: parseFloat((parseInt(row.error_count) / parseInt(row.request_count) * 100).toFixed(2))
            }))
        };
        
        res.json({
            success: true,
            data: realtimeData
        });
        
    } catch (error) {
        console.error('Realtime analytics error:', error);
        res.status(500).json({
            success: false,
            message: '获取实时监控数据失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/analytics/reports
 * @desc 获取分析报告列表
 * @access Admin (Analytics Read Permission)
 */
router.get('/reports', [
    requirePermission(PERMISSIONS.ANALYTICS_READ),
    query('type').optional().isIn(['daily', 'weekly', 'monthly']).withMessage('无效的报告类型'),
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('每页数量必须在1-50之间'),
    logAdminAction('view_analytics_reports', 'analytics')
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
        
        const { type, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (type) {
            whereClause += ` AND report_type = $${paramIndex}`;
            queryParams.push(type);
            paramIndex++;
        }
        
        // 查询报告列表
        const reportsQuery = `
            SELECT 
                id,
                report_type,
                title,
                description,
                report_data,
                generated_by,
                generated_at,
                file_path,
                file_size,
                status
            FROM analytics_reports 
            ${whereClause}
            ORDER BY generated_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM analytics_reports 
            ${whereClause}
        `;
        
        const [reportsResult, countResult] = await Promise.all([
            req.db.query(reportsQuery, queryParams),
            req.db.query(countQuery, queryParams.slice(0, -2))
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        res.json({
            success: true,
            data: {
                reports: reportsResult.rows.map(row => ({
                    id: row.id,
                    reportType: row.report_type,
                    title: row.title,
                    description: row.description,
                    generatedBy: row.generated_by,
                    generatedAt: row.generated_at,
                    filePath: row.file_path,
                    fileSize: row.file_size,
                    status: row.status
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
        console.error('Get analytics reports error:', error);
        res.status(500).json({
            success: false,
            message: '获取分析报告失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

module.exports = router;