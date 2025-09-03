"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getLocationHotspots = exports.getUserStats = exports.claimReward = exports.getUserRewards = exports.findNearbyUsers = exports.checkinUser = exports.updateUserLocation = void 0;
const database_1 = require("@/config/database");
const errorHandler_1 = require("@/middleware/errorHandler");
const errorHandler_2 = require("@/middleware/errorHandler");
const logger_1 = require("@/utils/logger");
const redis_1 = require("@/config/redis");
const uuid_1 = require("uuid");
exports.updateUserLocation = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { latitude, longitude, accuracy, altitude, speed, heading, locationName, address } = req.body;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    if (!latitude || !longitude) {
        throw (0, errorHandler_1.createValidationError)('location', '经纬度不能为空');
    }
    if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
        throw (0, errorHandler_1.createValidationError)('coordinates', '经纬度格式不正确');
    }
    try {
        await (0, database_1.db)('user_locations')
            .where({ user_id: userId })
            .update({ is_current: false });
        const [location] = await (0, database_1.db)('user_locations')
            .insert({
            id: (0, uuid_1.v4)(),
            user_id: userId,
            latitude,
            longitude,
            location_name: locationName,
            address,
            accuracy,
            altitude,
            speed,
            heading,
            location_type: 'manual',
            is_current: true,
        })
            .returning('*');
        await (0, database_1.db)('user_stats')
            .insert({
            id: (0, uuid_1.v4)(),
            user_id: userId,
            last_location_update: new Date(),
        })
            .onConflict('user_id')
            .merge({
            last_location_update: new Date(),
            updated_at: new Date(),
        });
        await redis_1.cacheService.set(`user_location:${userId}`, JSON.stringify({ latitude, longitude, locationName, address }), 3600);
        logger_1.logger.info('用户位置更新成功', { userId, latitude, longitude });
        res.json({
            success: true,
            message: '位置更新成功',
            data: {
                location,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('位置更新失败', { userId, error });
        throw error;
    }
});
exports.checkinUser = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { latitude, longitude, locationName, address, checkinType = 'manual', notes } = req.body;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    if (!latitude || !longitude) {
        throw (0, errorHandler_1.createValidationError)('location', '经纬度不能为空');
    }
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const existingCheckin = await (0, database_1.db)('checkin_records')
            .where('user_id', userId)
            .where('created_at', '>=', today)
            .whereRaw('ABS(latitude - ?) < 0.001 AND ABS(longitude - ?) < 0.001', [latitude, longitude])
            .first();
        if (existingCheckin) {
            throw (0, errorHandler_1.createConflictError)('今天已在此位置签到过了');
        }
        const userStats = await (0, database_1.db)('user_stats')
            .where('user_id', userId)
            .first();
        let consecutiveDays = 1;
        let bonusMultiplier = 1.0;
        if (userStats?.last_checkin_at) {
            const lastCheckin = new Date(userStats.last_checkin_at);
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            if (lastCheckin >= yesterday) {
                consecutiveDays = (userStats.consecutive_checkins || 0) + 1;
                bonusMultiplier = Math.min(1 + (consecutiveDays - 1) * 0.1, 3.0);
            }
        }
        const isFirstTime = !(await (0, database_1.db)('checkin_records')
            .where('user_id', userId)
            .whereRaw('ABS(latitude - ?) < 0.005 AND ABS(longitude - ?) < 0.005', [latitude, longitude])
            .first());
        if (isFirstTime) {
            bonusMultiplier *= 1.5;
        }
        const hotspot = await (0, database_1.db)('location_hotspots')
            .where('is_active', true)
            .whereRaw('ABS(latitude - ?) < 0.01 AND ABS(longitude - ?) < 0.01', [latitude, longitude])
            .first();
        if (hotspot) {
            bonusMultiplier *= hotspot.reward_multiplier;
        }
        const basePoints = 10;
        const pointsEarned = Math.floor(basePoints * bonusMultiplier);
        const [checkin] = await (0, database_1.db)('checkin_records')
            .insert({
            id: (0, uuid_1.v4)(),
            user_id: userId,
            latitude,
            longitude,
            location_name: locationName,
            address,
            checkin_type: checkinType,
            points_earned: pointsEarned,
            bonus_multiplier: bonusMultiplier,
            consecutive_days: consecutiveDays,
            is_first_time: isFirstTime,
            notes,
        })
            .returning('*');
        await createRewardRecord({
            userId,
            rewardType: 'checkin',
            rewardCategory: 'daily_checkin',
            points: pointsEarned,
            description: `签到奖励${isFirstTime ? '(首次到访)' : ''}${hotspot ? `(${hotspot.name})` : ''}`,
            sourceId: checkin.id,
            sourceType: 'checkin',
            latitude,
            longitude,
            multiplier: bonusMultiplier,
        });
        await (0, database_1.db)('user_stats')
            .insert({
            id: (0, uuid_1.v4)(),
            user_id: userId,
            total_points: pointsEarned,
            available_points: pointsEarned,
            total_checkins: 1,
            consecutive_checkins: consecutiveDays,
            max_consecutive_checkins: consecutiveDays,
            last_checkin_at: new Date(),
        })
            .onConflict('user_id')
            .merge({
            total_points: database_1.db.raw('user_stats.total_points + ?', [pointsEarned]),
            available_points: database_1.db.raw('user_stats.available_points + ?', [pointsEarned]),
            total_checkins: database_1.db.raw('user_stats.total_checkins + 1'),
            consecutive_checkins: consecutiveDays,
            max_consecutive_checkins: database_1.db.raw('GREATEST(user_stats.max_consecutive_checkins, ?)', [consecutiveDays]),
            last_checkin_at: new Date(),
            updated_at: new Date(),
        });
        if (hotspot) {
            await (0, database_1.db)('location_hotspots')
                .where('id', hotspot.id)
                .increment('checkin_count', 1)
                .increment('popularity_score', Math.floor(pointsEarned / 2));
        }
        logger_1.logger.info('用户签到成功', { userId, checkinId: checkin.id, pointsEarned, consecutiveDays });
        res.json({
            success: true,
            message: '签到成功',
            data: {
                checkin,
                pointsEarned,
                consecutiveDays,
                bonusMultiplier,
                isFirstTime,
                hotspot: hotspot ? { name: hotspot.name, category: hotspot.category } : null,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('签到失败', { userId, error });
        throw error;
    }
});
exports.findNearbyUsers = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { latitude, longitude, radius = 1000 } = req.query;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    if (!latitude || !longitude) {
        throw (0, errorHandler_1.createValidationError)('location', '经纬度不能为空');
    }
    try {
        const radiusInDegrees = parseInt(radius) / 111000;
        const nearbyUsers = await (0, database_1.db)('user_locations')
            .join('users', 'user_locations.user_id', 'users.id')
            .leftJoin('user_stats', 'users.id', 'user_stats.user_id')
            .select('users.id', 'users.username', 'users.display_name', 'users.avatar_url', 'user_locations.latitude', 'user_locations.longitude', 'user_stats.level_id', 'user_stats.total_points')
            .where('users.status', 'active')
            .where('user_locations.is_current', true)
            .whereNot('users.id', userId)
            .whereRaw('ABS(user_locations.latitude - ?) < ? AND ABS(user_locations.longitude - ?) < ?', [
            parseFloat(latitude), radiusInDegrees,
            parseFloat(longitude), radiusInDegrees,
        ])
            .limit(50);
        for (const nearbyUser of nearbyUsers) {
            const distance = Math.sqrt(Math.pow((nearbyUser.latitude - parseFloat(latitude)) * 111000, 2) +
                Math.pow((nearbyUser.longitude - parseFloat(longitude)) * 111000, 2));
            const existingRecord = await (0, database_1.db)('nearby_users')
                .where({ user_id: userId, nearby_user_id: nearbyUser.id })
                .first();
            if (existingRecord) {
                await (0, database_1.db)('nearby_users')
                    .where({ user_id: userId, nearby_user_id: nearbyUser.id })
                    .update({
                    distance,
                    latitude: parseFloat(latitude),
                    longitude: parseFloat(longitude),
                    nearby_latitude: nearbyUser.latitude,
                    nearby_longitude: nearbyUser.longitude,
                    last_seen_at: new Date(),
                });
            }
            else {
                await (0, database_1.db)('nearby_users')
                    .insert({
                    id: (0, uuid_1.v4)(),
                    user_id: userId,
                    nearby_user_id: nearbyUser.id,
                    distance,
                    latitude: parseFloat(latitude),
                    longitude: parseFloat(longitude),
                    nearby_latitude: nearbyUser.latitude,
                    nearby_longitude: nearbyUser.longitude,
                    last_seen_at: new Date(),
                });
            }
            nearbyUser.distance = distance;
        }
        logger_1.logger.info('附近用户查找成功', { userId, count: nearbyUsers.length });
        res.json({
            success: true,
            message: '附近用户查找成功',
            data: {
                users: nearbyUsers,
                total: nearbyUsers.length,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('附近用户查找失败', { userId, error });
        throw error;
    }
});
exports.getUserRewards = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { page = 1, limit = 20, status, rewardType } = req.query;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    try {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        let query = (0, database_1.db)('reward_records')
            .where('user_id', userId);
        if (status) {
            query = query.where('status', status);
        }
        if (rewardType) {
            query = query.where('reward_type', rewardType);
        }
        const [rewards, totalCount] = await Promise.all([
            query
                .clone()
                .orderBy('created_at', 'desc')
                .limit(parseInt(limit))
                .offset(offset),
            query.clone().count('* as count').first(),
        ]);
        res.json({
            success: true,
            message: '奖励记录获取成功',
            data: {
                rewards,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: parseInt(totalCount?.['count'] || '0'),
                    totalPages: Math.ceil(parseInt(totalCount?.['count'] || '0') / parseInt(limit)),
                },
            },
        });
    }
    catch (error) {
        logger_1.logger.error('奖励记录获取失败', { userId, error });
        throw error;
    }
});
exports.claimReward = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { rewardId } = req.params;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    try {
        const reward = await (0, database_1.db)('reward_records')
            .where({ id: rewardId, user_id: userId, status: 'pending' })
            .first();
        if (!reward) {
            throw (0, errorHandler_1.createNotFoundError)('奖励不存在或已领取');
        }
        if (reward.expires_at && new Date(reward.expires_at) < new Date()) {
            await (0, database_1.db)('reward_records')
                .where('id', rewardId)
                .update({ status: 'expired' });
            throw (0, errorHandler_1.createValidationError)('reward', '奖励已过期');
        }
        await (0, database_1.db)('reward_records')
            .where('id', rewardId)
            .update({
            status: 'claimed',
            claimed_at: new Date(),
        });
        await (0, database_1.db)('user_stats')
            .where('user_id', userId)
            .increment('available_points', reward.points)
            .increment('available_coins', reward.coins || 0);
        logger_1.logger.info('奖励领取成功', { userId, rewardId, points: reward.points });
        res.json({
            success: true,
            message: '奖励领取成功',
            data: {
                reward,
                pointsEarned: reward.points,
                coinsEarned: reward.coins || 0,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('奖励领取失败', { userId, rewardId, error });
        throw error;
    }
});
exports.getUserStats = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    if (!userId) {
        throw (0, errorHandler_1.createValidationError)('auth', '用户未认证');
    }
    try {
        const stats = await (0, database_1.db)('user_stats')
            .where('user_id', userId)
            .first();
        if (!stats) {
            const [newStats] = await (0, database_1.db)('user_stats')
                .insert({
                id: (0, uuid_1.v4)(),
                user_id: userId,
            })
                .returning('*');
            res.json({
                success: true,
                message: '用户统计获取成功',
                data: { stats: newStats },
            });
            return;
        }
        const recentCheckins = await (0, database_1.db)('checkin_records')
            .where('user_id', userId)
            .orderBy('created_at', 'desc')
            .limit(5);
        const pendingRewardsCount = await (0, database_1.db)('reward_records')
            .where({ user_id: userId, status: 'pending' })
            .count('* as count')
            .first();
        res.json({
            success: true,
            message: '用户统计获取成功',
            data: {
                stats,
                recentCheckins,
                pendingRewardsCount: parseInt(pendingRewardsCount?.['count'] || '0'),
            },
        });
    }
    catch (error) {
        logger_1.logger.error('用户统计获取失败', { userId, error });
        throw error;
    }
});
exports.getLocationHotspots = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { latitude, longitude, radius = 5000, category } = req.query;
    try {
        let query = (0, database_1.db)('location_hotspots')
            .where('is_active', true);
        if (latitude && longitude) {
            const radiusInDegrees = parseInt(radius) / 111000;
            query = query
                .whereRaw('ABS(latitude - ?) < ? AND ABS(longitude - ?) < ?', [
                parseFloat(latitude), radiusInDegrees,
                parseFloat(longitude), radiusInDegrees,
            ]);
        }
        if (category) {
            query = query.where('category', category);
        }
        const hotspots = await query.limit(50);
        res.json({
            success: true,
            message: '热点位置获取成功',
            data: {
                hotspots,
                total: hotspots.length,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('热点位置获取失败', { error });
        throw error;
    }
});
async function createRewardRecord(rewardData) {
    await (0, database_1.db)('reward_records')
        .insert({
        id: (0, uuid_1.v4)(),
        user_id: rewardData.userId,
        reward_type: rewardData.rewardType,
        reward_category: rewardData.rewardCategory,
        points: rewardData.points,
        coins: rewardData.coins || 0,
        cash_value: rewardData.cashValue || 0,
        description: rewardData.description,
        source_id: rewardData.sourceId,
        source_type: rewardData.sourceType,
        location_id: rewardData.locationId,
        latitude: rewardData.latitude,
        longitude: rewardData.longitude,
        multiplier: rewardData.multiplier || 1.0,
        status: 'pending',
    });
}
exports.default = {
    updateUserLocation: exports.updateUserLocation,
    checkinUser: exports.checkinUser,
    findNearbyUsers: exports.findNearbyUsers,
    getUserRewards: exports.getUserRewards,
    claimReward: exports.claimReward,
    getUserStats: exports.getUserStats,
    getLocationHotspots: exports.getLocationHotspots,
};
//# sourceMappingURL=lbsController.js.map