/**
 * LBS奖励系统API路由
 * 提供位置上报、奖励查询、地理围栏管理等接口
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

const express = require('express');
const router = express.Router();
const GeofencingService = require('../services/geofencingService');
const RewardCalculationEngine = require('../services/rewardCalculationEngine');
const LocationVerificationService = require('../services/locationVerificationService');
const AntiFraudService = require('../services/antiFraudService');
const NotificationService = require('../services/notificationService');
const { getWebSocketService } = require('../services/websocketManager');
const { authenticateToken, validateRequest } = require('../middleware/auth');
const { body, query, validationResult } = require('express-validator');

// 初始化服务
let geofencingService, rewardEngine, locationVerifier, antiFraudService, notificationService;

// 初始化服务实例
function initializeServices(database) {
    geofencingService = new GeofencingService(database);
    rewardEngine = new RewardCalculationEngine(database);
    locationVerifier = new LocationVerificationService(database);
    antiFraudService = new AntiFraudService();
    notificationService = new NotificationService();
}

/**
 * @route POST /api/lbs/location/report
 * @desc 上报用户位置并检测奖励
 * @access Private
 */
router.post('/location/report', [
    authenticateToken,
    body('longitude').isFloat({ min: -180, max: 180 }).withMessage('经度必须在-180到180之间'),
    body('latitude').isFloat({ min: -90, max: 90 }).withMessage('纬度必须在-90到90之间'),
    body('accuracy').optional().isFloat({ min: 0 }).withMessage('精度必须为正数'),
    body('timestamp').optional().isISO8601().withMessage('时间戳格式无效'),
    body('speed').optional().isFloat({ min: 0 }).withMessage('速度必须为正数'),
    body('heading').optional().isFloat({ min: 0, max: 360 }).withMessage('方向必须在0到360之间'),
    body('altitude').optional().isFloat().withMessage('海拔必须为数字'),
    body('provider').optional().isIn(['gps', 'network', 'passive', 'fused']).withMessage('无效的位置提供者'),
    body('deviceInfo').optional().isObject().withMessage('设备信息必须为对象')
], async (req, res) => {
    try {
        // 验证请求参数
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }

        const userId = req.user.id;
        const {
            longitude,
            latitude,
            accuracy = null,
            timestamp = new Date().toISOString(),
            speed = null,
            heading = null,
            altitude = null,
            provider = 'gps',
            deviceInfo = {}
        } = req.body;

        // 1. 位置验证
        const locationData = {
            userId,
            longitude,
            latitude,
            accuracy,
            timestamp,
            speed,
            heading,
            altitude,
            provider,
            deviceInfo
        };

        const verification = await locationVerifier.verifyLocation(locationData);
        
        if (!verification.isValid) {
            return res.status(400).json({
                success: false,
                message: '位置数据验证失败',
                reason: verification.checks,
                recommendations: verification.recommendations
            });
        }

        // 2. 记录位置上报
        const locationReport = await recordLocationReport(req.db, locationData);

        // 3. 检测地理围栏
        const geofenceDetection = await geofencingService.detectGeofenceEntry(
            latitude, longitude
        );

        let rewardResult = null;
        
        // 4. 如果检测到地理围栏，进行防作弊检测和计算奖励
        if (geofenceDetection && geofenceDetection.length > 0) {
            const geofence = geofenceDetection[0]; // 取第一个匹配的地理围栏
            
            // 4.1 防作弊检测
            const fraudDetection = await antiFraudService.detectFraud({
                userId,
                latitude,
                longitude,
                accuracy,
                geofenceId: geofence.id,
                deviceInfo
            });
            
            // 如果防作弊检测未通过，拒绝奖励但记录日志
            if (!fraudDetection.isValid) {
                return res.status(400).json({
                    success: false,
                    message: '检测到可疑行为，奖励被拒绝',
                    data: {
                        locationReport: {
                            id: (await recordLocationReport(req.db, locationData)).id,
                            timestamp: new Date().toISOString()
                        },
                        verification: {
                            confidence: verification.confidence,
                            riskLevel: verification.riskLevel
                        },
                        geofenceDetection: {
                            detected: true,
                            count: 1,
                            geofences: [{
                                id: geofence.id,
                                name: geofence.name,
                                type: geofence.reward_type
                            }]
                        },
                        fraudDetection: {
                            riskScore: fraudDetection.riskScore,
                            riskLevel: fraudDetection.riskLevel,
                            violations: fraudDetection.violations,
                            reason: '检测到异常行为模式'
                        },
                        reward: {
                            earned: false,
                            amount: 0,
                            reason: '防作弊检测未通过'
                        }
                    }
                });
            }
            
            // 4.2 计算奖励
            const rewardParams = {
                userId,
                geofenceId: geofence.id,
                rewardType: geofence.reward_type || 'checkin',
                baseAmount: geofence.base_reward || 1.0,
                longitude,
                latitude,
                metadata: {
                    geofenceName: geofence.name,
                    detectionAccuracy: accuracy,
                    verificationConfidence: verification.confidence,
                    fraudRiskScore: fraudDetection.riskScore,
                    fraudRiskLevel: fraudDetection.riskLevel
                }
            };

            rewardResult = await rewardEngine.calculateReward(rewardParams);
            
            // 5. 如果奖励计算成功，记录奖励
            if (rewardResult.success) {
                await recordReward(req.db, {
                    userId,
                    geofenceId: geofence.id,
                    rewardType: rewardParams.rewardType,
                    amount: rewardResult.rewardAmount,
                    longitude,
                    latitude,
                    metadata: {
                        ...rewardResult.breakdown,
                        locationReportId: locationReport.id
                    }
                });
                
                // 发送实时奖励通知
                try {
                    await notificationService.sendRewardNotification(userId, {
                        type: 'reward_earned',
                        rewardType: rewardParams.rewardType,
                        amount: rewardResult.rewardAmount,
                        geofenceName: geofence.name,
                        breakdown: rewardResult.breakdown,
                        timestamp: new Date().toISOString()
                    });
                    
                    // 发送地理围栏进入通知
                    await notificationService.sendGeofenceNotification(userId, {
                        type: 'geofence_entered',
                        geofenceName: geofence.name,
                        geofenceType: geofence.reward_type,
                        coordinates: { lat: latitude, lng: longitude },
                        timestamp: new Date().toISOString()
                    });
                } catch (notificationError) {
                    console.error('发送通知失败:', notificationError);
                    // 通知失败不影响主流程
                }
            }
        }

        // 6. 返回结果
        const responseData = {
            locationReport: {
                id: locationReport.id,
                timestamp: locationReport.created_at
            },
            verification: {
                confidence: verification.confidence,
                riskLevel: verification.riskLevel
            },
            geofenceDetection: {
                detected: geofenceDetection && geofenceDetection.length > 0,
                count: geofenceDetection?.length || 0,
                geofences: geofenceDetection?.map(g => ({
                    id: g.id,
                    name: g.name,
                    type: g.reward_type
                })) || []
            },
            reward: rewardResult ? {
                earned: rewardResult.success,
                amount: rewardResult.rewardAmount || 0,
                reason: rewardResult.reason || null,
                breakdown: rewardResult.breakdown || null
            } : null
        };

        // 如果进行了防作弊检测，添加检测结果
        if (geofenceDetection && geofenceDetection.length > 0) {
            // 重新获取防作弊检测结果（因为之前可能已经通过检测）
            const geofence = geofenceDetection[0];
            const fraudDetection = await antiFraudService.detectFraud({
                userId,
                latitude,
                longitude,
                accuracy,
                geofenceId: geofence.id,
                deviceInfo
            });
            
            responseData.fraudDetection = {
                riskScore: fraudDetection.riskScore,
                riskLevel: fraudDetection.riskLevel,
                violations: fraudDetection.violations,
                passed: fraudDetection.isValid
            };
        }

        res.json({
            success: true,
            message: '位置上报成功',
            data: responseData
        });

    } catch (error) {
        console.error('Location report error:', error);
        res.status(500).json({
            success: false,
            message: '位置上报失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/lbs/rewards/history
 * @desc 获取用户奖励历史
 * @access Private
 */
router.get('/rewards/history', [
    authenticateToken,
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量必须在1-100之间'),
    query('type').optional().isIn(['discovery', 'checkin', 'duration', 'social']).withMessage('无效的奖励类型'),
    query('startDate').optional().isISO8601().withMessage('开始日期格式无效'),
    query('endDate').optional().isISO8601().withMessage('结束日期格式无效')
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

        const userId = req.user.id;
        const {
            page = 1,
            limit = 20,
            type = null,
            startDate = null,
            endDate = null
        } = req.query;

        const offset = (page - 1) * limit;
        
        // 构建查询条件
        let whereClause = 'WHERE r.user_id = $1';
        let queryParams = [userId];
        let paramIndex = 2;
        
        if (type) {
            whereClause += ` AND r.reward_type = $${paramIndex}`;
            queryParams.push(type);
            paramIndex++;
        }
        
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

        // 查询奖励历史
        const historyQuery = `
            SELECT 
                r.id,
                r.reward_type,
                r.reward_amount as amount,
                r.created_at,
                r.metadata,
                r.longitude,
                r.latitude,
                g.name as geofence_name,
                g.metadata->>'description' as geofence_description
            FROM lbs_rewards r
            LEFT JOIN geofence_configs g ON r.geofence_id = g.id
            ${whereClause}
            ORDER BY r.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM lbs_rewards r
            ${whereClause}
        `;
        
        const [historyResult, countResult] = await Promise.all([
            req.db.query(historyQuery, queryParams),
            req.db.query(countQuery, queryParams.slice(0, -2)) // 移除limit和offset参数
        ]);

        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);

        res.json({
            success: true,
            data: {
                rewards: historyResult.rows.map(row => ({
                    id: row.id,
                    type: row.reward_type,
                    amount: parseFloat(row.amount),
                    earnedAt: row.created_at,
                    location: {
                        longitude: row.longitude,
                        latitude: row.latitude
                    },
                    geofence: {
                        name: row.geofence_name,
                        description: row.geofence_description
                    },
                    metadata: row.metadata
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
        console.error('Reward history error:', error);
        res.status(500).json({
            success: false,
            message: '获取奖励历史失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/lbs/rewards/stats
 * @desc 获取用户奖励统计
 * @access Private
 */
router.get('/rewards/stats', [
    authenticateToken,
    query('period').optional().isIn(['today', 'week', 'month', 'year', 'all']).withMessage('无效的统计周期')
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

        const userId = req.user.id;
        const { period = 'all' } = req.query;
        
        // 构建时间条件
        let timeCondition = '';
        switch (period) {
            case 'today':
                timeCondition = "AND DATE(created_at) = CURRENT_DATE";
                break;
            case 'week':
                timeCondition = "AND created_at >= CURRENT_DATE - INTERVAL '7 days'";
                break;
            case 'month':
                timeCondition = "AND created_at >= CURRENT_DATE - INTERVAL '30 days'";
                break;
            case 'year':
                timeCondition = "AND created_at >= CURRENT_DATE - INTERVAL '365 days'";
                break;
            default:
                timeCondition = '';
        }

        // 查询统计数据
        const statsQuery = `
            SELECT 
                COUNT(*) as total_rewards,
                SUM(reward_amount) as total_amount,
                AVG(reward_amount) as avg_amount,
                reward_type,
                COUNT(*) as type_count,
                SUM(reward_amount) as type_amount
            FROM lbs_rewards
            WHERE user_id = $1 ${timeCondition}
            GROUP BY ROLLUP(reward_type)
            ORDER BY reward_type NULLS LAST
        `;

        const result = await req.db.query(statsQuery, [userId]);
        
        // 处理统计结果
        const stats = {
            overall: {
                totalRewards: 0,
                totalAmount: 0,
                averageAmount: 0
            },
            byType: {}
        };
        
        result.rows.forEach(row => {
            if (row.reward_type === null) {
                // 总计行
                stats.overall = {
                    totalRewards: parseInt(row.total_rewards),
                    totalAmount: parseFloat(row.total_amount) || 0,
                    averageAmount: parseFloat(row.avg_amount) || 0
                };
            } else {
                // 按类型统计
                stats.byType[row.reward_type] = {
                    count: parseInt(row.type_count),
                    amount: parseFloat(row.type_amount) || 0
                };
            }
        });

        // 查询排名信息
        const rankQuery = `
            WITH user_totals AS (
                SELECT 
                    user_id,
                    SUM(reward_amount) as total_amount,
                    RANK() OVER (ORDER BY SUM(reward_amount) DESC) as rank
                FROM lbs_rewards
                WHERE 1=1 ${timeCondition}
                GROUP BY user_id
            )
            SELECT rank, total_amount
            FROM user_totals
            WHERE user_id = $1
        `;
        
        const rankResult = await req.db.query(rankQuery, [userId]);
        const userRank = rankResult.rows[0] || { rank: null, total_amount: 0 };

        res.json({
            success: true,
            data: {
                period,
                stats,
                ranking: {
                    rank: userRank.rank,
                    totalAmount: parseFloat(userRank.total_amount) || 0
                },
                generatedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Reward stats error:', error);
        res.status(500).json({
            success: false,
            message: '获取奖励统计失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/lbs/geofences/nearby
 * @desc 获取附近的地理围栏
 * @access Private
 */
router.get('/geofences/nearby', [
    authenticateToken,
    query('longitude').isFloat({ min: -180, max: 180 }).withMessage('经度必须在-180到180之间'),
    query('latitude').isFloat({ min: -90, max: 90 }).withMessage('纬度必须在-90到90之间'),
    query('radius').optional().isInt({ min: 100, max: 5000 }).withMessage('半径必须在100-5000米之间')
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

        const { longitude, latitude, radius = 1000 } = req.query;
        
        const nearbyGeofences = await geofenceService.getNearbyGeofences(
            parseFloat(longitude),
            parseFloat(latitude),
            parseInt(radius)
        );

        res.json({
            success: true,
            data: {
                geofences: nearbyGeofences.map(geofence => ({
                    id: geofence.id,
                    name: geofence.name,
                    description: geofence.description,
                    rewardType: geofence.reward_type,
                    baseReward: parseFloat(geofence.base_reward),
                    radius: geofence.radius,
                    location: {
                        longitude: geofence.longitude,
                        latitude: geofence.latitude
                    },
                    distance: geofence.distance,
                    isActive: geofence.is_active,
                    metadata: geofence.metadata
                })),
                searchRadius: parseInt(radius),
                searchCenter: {
                    longitude: parseFloat(longitude),
                    latitude: parseFloat(latitude)
                },
                count: nearbyGeofences.length
            }
        });

    } catch (error) {
        console.error('Nearby geofences error:', error);
        res.status(500).json({
            success: false,
            message: '获取附近地理围栏失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route POST /api/lbs/geofences
 * @desc 创建新的地理围栏（管理员功能）
 * @access Private (Admin)
 */
router.post('/geofences', [
    authenticateToken,
    // validateAdminRole, // 需要实现管理员权限验证
    body('name').isLength({ min: 1, max: 100 }).withMessage('名称长度必须在1-100字符之间'),
    body('description').optional().isLength({ max: 500 }).withMessage('描述长度不能超过500字符'),
    body('longitude').isFloat({ min: -180, max: 180 }).withMessage('经度必须在-180到180之间'),
    body('latitude').isFloat({ min: -90, max: 90 }).withMessage('纬度必须在-90到90之间'),
    body('radius').isInt({ min: 10, max: 1000 }).withMessage('半径必须在10-1000米之间'),
    body('rewardType').isIn(['discovery', 'checkin', 'duration', 'social']).withMessage('无效的奖励类型'),
    body('baseReward').isFloat({ min: 0.01, max: 100 }).withMessage('基础奖励必须在0.01-100之间')
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
            name,
            description = '',
            longitude,
            latitude,
            radius,
            rewardType,
            baseReward,
            metadata = {}
        } = req.body;

        const geofence = await geofenceService.createGeofence({
            name,
            description,
            longitude,
            latitude,
            radius,
            rewardType,
            baseReward,
            metadata,
            createdBy: req.user.id
        });

        res.status(201).json({
            success: true,
            message: '地理围栏创建成功',
            data: {
                geofence: {
                    id: geofence.id,
                    name: geofence.name,
                    description: geofence.description,
                    location: {
                        longitude: geofence.longitude,
                        latitude: geofence.latitude
                    },
                    radius: geofence.radius,
                    rewardType: geofence.reward_type,
                    baseReward: parseFloat(geofence.base_reward),
                    isActive: geofence.is_active,
                    createdAt: geofence.created_at
                }
            }
        });

    } catch (error) {
        console.error('Create geofence error:', error);
        res.status(500).json({
            success: false,
            message: '创建地理围栏失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

// 辅助函数

/**
 * 记录位置上报
 * @param {Object} db - 数据库连接
 * @param {Object} locationData - 位置数据
 * @returns {Promise<Object>} 位置记录
 */
async function recordLocationReport(db, locationData) {
    const {
        userId,
        longitude,
        latitude,
        accuracy,
        timestamp,
        speed,
        heading,
        altitude,
        provider
    } = locationData;

    const query = `
        INSERT INTO location_reports (
            user_id, longitude, latitude, accuracy, speed, heading, 
            altitude, provider, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9
        ) RETURNING id, created_at
    `;

    const result = await db.query(query, [
        userId, longitude, latitude, accuracy, speed, heading, 
        altitude, provider, timestamp
    ]);

    return result.rows[0];
}

/**
 * 记录奖励
 * @param {Object} db - 数据库连接
 * @param {Object} rewardData - 奖励数据
 * @returns {Promise<Object>} 奖励记录
 */
async function recordReward(db, rewardData) {
    const {
        userId,
        geofenceId,
        rewardType,
        amount,
        longitude,
        latitude,
        metadata
    } = rewardData;

    const query = `
        INSERT INTO lbs_rewards (
            user_id, geofence_id, reward_type, reward_amount, 
            longitude, latitude, metadata
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7
        ) RETURNING id, created_at
    `;

    const result = await db.query(query, [
        userId, geofenceId, rewardType, amount, longitude, latitude, JSON.stringify(metadata)
    ]);

    return result.rows[0];
}

// 导出路由和初始化函数
module.exports = {
    router,
    initializeServices
};