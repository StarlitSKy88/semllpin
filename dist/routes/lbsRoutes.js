"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const geofenceService_1 = require("../services/geofenceService");
const rewardCalculationService_1 = require("../services/rewardCalculationService");
const antiFraudService_1 = require("../services/antiFraudService");
const auth_1 = require("../middleware/auth");
const database_1 = require("../config/database");
const router = (0, express_1.Router)();
router.use(auth_1.authMiddleware);
const geofenceService = new geofenceService_1.GeofenceService();
const rewardCalculationService = new rewardCalculationService_1.RewardCalculationService();
const antiFraudService = new antiFraudService_1.AntiFraudService();
router.post('/report-location', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未登录',
                data: null,
            });
            return;
        }
        const locationData = req.body;
        const validation = validateLocationRequest(locationData);
        if (!validation.valid) {
            res.status(400).json({
                code: 400,
                message: validation.message,
                data: null,
            });
            return;
        }
        const locationReport = {
            id: '',
            userId,
            latitude: locationData.latitude,
            longitude: locationData.longitude,
            accuracy: locationData.accuracy,
            timestamp: new Date(),
            reportType: 'manual',
            ...(locationData.deviceInfo && { deviceInfo: locationData.deviceInfo }),
        };
        const fraudResult = await antiFraudService.detectFraud(userId, locationReport, '');
        if (fraudResult.isFraudulent) {
            res.status(403).json({
                code: 403,
                message: '检测到可疑行为',
                data: {
                    fraudScore: fraudResult.fraudScore,
                    reasons: fraudResult.reasons,
                },
            });
            return;
        }
        const savedLocation = await saveLocationReport(locationReport);
        const geofenceTriggers = await geofenceService.checkGeofenceTriggers(locationData.latitude, locationData.longitude, userId);
        const rewards = [];
        for (const trigger of geofenceTriggers) {
            if (!trigger.triggered) {
                continue;
            }
            const specificFraudResult = await antiFraudService.detectFraud(userId, locationReport, trigger.annotationId);
            if (specificFraudResult.isFraudulent) {
                console.log(`用户${userId}在标注${trigger.annotationId}处检测到作弊行为`);
                continue;
            }
            const rewardAmount = await rewardCalculationService.calculateRewardWithDB(trigger.annotationId, userId, 'discovery');
            if (rewardAmount > 0) {
                const reward = await createRewardRecord({
                    userId,
                    annotationId: trigger.annotationId,
                    amount: rewardAmount,
                    rewardType: 'discovery',
                    locationReportId: savedLocation.id,
                });
                rewards.push({
                    annotationId: trigger.annotationId,
                    amount: rewardAmount,
                    rewardId: reward.id,
                    distance: trigger.distance,
                });
            }
        }
        res.json({
            code: 200,
            message: '位置上报成功',
            data: {
                locationId: savedLocation.id,
                triggeredGeofences: geofenceTriggers.length,
                rewards,
                totalRewardAmount: rewards.reduce((sum, r) => sum + r.amount, 0),
            },
        });
    }
    catch (error) {
        console.error('位置上报失败:', error);
        res.status(500).json({
            code: 500,
            message: '位置上报失败',
            data: null,
        });
    }
});
router.get('/rewards', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const { page = 1, limit = 20 } = req.query;
        const offset = (Number(page) - 1) * Number(limit);
        const rewards = await (0, database_1.db)('lbs_rewards as r')
            .leftJoin('annotations as a', 'r.annotation_id', 'a.id')
            .where('r.user_id', userId)
            .select('r.*', 'a.description as annotation_description')
            .orderBy('r.discovered_at', 'desc')
            .limit(Number(limit))
            .offset(offset);
        const formattedRewards = rewards.map((reward) => ({
            id: reward.id,
            amount: parseFloat(reward.reward_amount),
            rewardType: reward.reward_type,
            status: reward.status,
            discoveredAt: reward.discovered_at,
            annotation: {
                id: reward.annotation_id,
                description: reward.annotation_description,
            },
        }));
        return res.json({
            rewards: formattedRewards,
            pagination: {
                page: Number(page),
                limit: Number(limit),
                total: formattedRewards.length,
            },
        });
    }
    catch (error) {
        console.error('获取奖励记录失败:', error);
        return res.status(500).json({ error: '获取奖励记录失败' });
    }
});
router.post('/claim-reward', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({
                code: 401,
                message: '用户未登录',
                data: null,
            });
            return;
        }
        const { rewardIds } = req.body;
        if (!rewardIds || !Array.isArray(rewardIds) || rewardIds.length === 0) {
            res.status(400).json({
                code: 400,
                message: '请选择要领取的奖励',
                data: null,
            });
            return;
        }
        const rewards = await (0, database_1.db)('lbs_rewards')
            .whereIn('id', rewardIds)
            .where('user_id', userId)
            .where('status', 'verified')
            .select('*');
        const rewardList = Array.isArray(rewards) ? rewards : [];
        if (rewardList.length === 0) {
            res.status(404).json({
                code: 404,
                message: '未找到可领取的奖励',
                data: null,
            });
            return;
        }
        if (rewardList.length !== rewardIds.length) {
            res.status(400).json({
                code: 400,
                message: '部分奖励无法领取',
                data: null,
            });
            return;
        }
        const totalAmount = rewardList.reduce((sum, r) => sum + parseFloat(r['amount']), 0);
        await (0, database_1.db)('lbs_rewards')
            .whereIn('id', rewardIds)
            .where('user_id', userId)
            .update({
            status: 'claimed',
            claimed_at: database_1.db.fn.now(),
            updated_at: database_1.db.fn.now(),
        });
        await (0, database_1.db)('users')
            .where('id', userId)
            .increment('wallet_balance', totalAmount)
            .update('updated_at', database_1.db.fn.now());
        await (0, database_1.db)('wallet_transactions').insert({
            user_id: userId,
            type: 'reward_claim',
            amount: totalAmount,
            description: '领取LBS奖励',
            reference_type: 'lbs_rewards',
            reference_ids: JSON.stringify(rewardIds),
            status: 'completed',
        });
        const response = {
            success: true,
            amount: totalAmount,
            claimedRewards: rewardList.map(r => formatRewardRecord(r)),
            newWalletBalance: await getUserWalletBalance(userId),
        };
        res.json({
            code: 200,
            message: '奖励领取成功',
            data: response,
        });
    }
    catch (error) {
        console.error('领取奖励失败:', error);
        res.status(500).json({
            code: 500,
            message: '领取奖励失败',
            data: null,
        });
    }
});
router.get('/stats', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ error: '用户未认证' });
        }
        const stats = await (0, database_1.db)('lbs_rewards')
            .where({ user_id: userId, status: 'verified' })
            .select(database_1.db.raw('COUNT(*) as total_rewards'), database_1.db.raw('COALESCE(SUM(amount), 0) as total_amount'), database_1.db.raw('COUNT(CASE WHEN created_at >= NOW() - INTERVAL \'30 days\' THEN 1 END) as monthly_rewards'), database_1.db.raw('COALESCE(SUM(CASE WHEN created_at >= NOW() - INTERVAL \'30 days\' THEN amount ELSE 0 END), 0) as monthly_amount'))
            .first();
        return res.json({
            totalRewards: parseInt(stats?.total_rewards || '0'),
            totalAmount: parseFloat(stats?.total_amount || '0'),
            monthlyRewards: parseInt(stats?.monthly_rewards || '0'),
            monthlyAmount: parseFloat(stats?.monthly_amount || '0'),
        });
    }
    catch (error) {
        console.error('获取LBS统计失败:', error);
        return res.status(500).json({ error: '获取统计失败' });
    }
});
function validateLocationRequest(data) {
    if (!data.latitude || !data.longitude) {
        return { valid: false, message: '缺少位置坐标' };
    }
    if (data.latitude < -90 || data.latitude > 90) {
        return { valid: false, message: '纬度范围无效' };
    }
    if (data.longitude < -180 || data.longitude > 180) {
        return { valid: false, message: '经度范围无效' };
    }
    if (data.accuracy && data.accuracy > 1000) {
        return { valid: false, message: 'GPS精度过低' };
    }
    return { valid: true };
}
async function saveLocationReport(locationReport) {
    const result = await (0, database_1.db)('location_reports')
        .insert({
        user_id: locationReport.userId,
        latitude: locationReport.latitude,
        longitude: locationReport.longitude,
        accuracy: locationReport.accuracy,
        timestamp: locationReport.timestamp,
        device_info: JSON.stringify(locationReport.deviceInfo || {}),
        report_type: locationReport.reportType,
    })
        .returning('id');
    return {
        ...locationReport,
        id: result[0].id,
    };
}
async function createRewardRecord(data) {
    const result = await (0, database_1.db)('lbs_rewards')
        .insert({
        user_id: data.userId,
        annotation_id: data.annotationId,
        amount: data.amount,
        reward_type: data.rewardType,
        location_report_id: data.locationReportId,
        status: 'verified',
    })
        .returning('*');
    return formatRewardRecord(result[0]);
}
function formatRewardRecord(row) {
    const reward = {
        id: row['id'],
        userId: row['user_id'],
        annotationId: row['annotation_id'],
        amount: parseFloat(row['amount']),
        rewardType: row['reward_type'],
        status: row['status'],
        locationReportId: row['location_report_id'],
        createdAt: new Date(row['created_at']),
        updatedAt: new Date(row['updated_at']),
    };
    if (row['claimed_at']) {
        reward.claimedAt = new Date(row['claimed_at']);
    }
    return reward;
}
async function getUserWalletBalance(userId) {
    const result = await (0, database_1.db)('users')
        .where('id', userId)
        .select('wallet_balance')
        .first();
    return result ? parseFloat(result.wallet_balance) : 0;
}
exports.default = router;
//# sourceMappingURL=lbsRoutes.js.map