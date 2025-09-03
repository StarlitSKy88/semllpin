"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RewardCalculationService = void 0;
const database_1 = require("../config/database");
class RewardCalculationService {
    constructor() {
    }
    async calculateReward(params) {
        try {
            const [annotation, geofenceConfig] = await Promise.all([
                this.getAnnotation(params.annotationId),
                this.getGeofenceConfig(params.annotationId),
            ]);
            if (!annotation) {
                return this.createIneligibleResult('标注不存在');
            }
            const existingReward = await this.checkExistingReward(params.annotationId, params.userId);
            if (existingReward) {
                return this.createIneligibleResult('用户已获得该标注奖励');
            }
            const minAccuracy = geofenceConfig?.minAccuracyMeters || 20;
            if (params.locationData.accuracy > minAccuracy) {
                return this.createIneligibleResult(`GPS精度不足，要求${minAccuracy}米以内`);
            }
            const minStayDuration = geofenceConfig?.minStayDuration || 30;
            if (params.locationData.stayDuration < minStayDuration) {
                return this.createIneligibleResult(`停留时间不足，要求${minStayDuration}秒以上`);
            }
            const basePercentage = geofenceConfig?.rewardBasePercentage || 50.0;
            const baseAmount = annotation.amount * (basePercentage / 100.0);
            let timeDecayFactor = 1.0;
            if (geofenceConfig?.timeDecayEnabled !== false) {
                timeDecayFactor = await this.calculateTimeDecayFactor(annotation.createdAt);
            }
            let firstFinderBonus = 0;
            if (params.rewardType === 'first_finder') {
                const isFirstFinder = await this.isFirstFinder(params.annotationId, params.userId);
                if (isFirstFinder && geofenceConfig?.firstFinderBonus) {
                    firstFinderBonus = geofenceConfig.firstFinderBonus / 100.0;
                }
            }
            let comboBonus = 0;
            if (params.rewardType === 'combo' && geofenceConfig?.comboBonusEnabled) {
                const comboStreak = await this.getUserComboStreak(params.userId);
                comboBonus = this.calculateComboBonus(comboStreak);
            }
            const finalAmount = Math.max(baseAmount * timeDecayFactor * (1 + firstFinderBonus + comboBonus), 0.01);
            return {
                finalAmount: Math.round(finalAmount * 100) / 100,
                breakdown: {
                    baseAmount: Math.round(baseAmount * 100) / 100,
                    timeDecayFactor,
                    firstFinderBonus: Math.round(firstFinderBonus * 100 * 100) / 100,
                    comboBonus: Math.round(comboBonus * 100 * 100) / 100,
                    finalAmount: Math.round(finalAmount * 100) / 100,
                },
                eligibility: {
                    eligible: true,
                    reasons: ['满足所有奖励条件'],
                },
            };
        }
        catch (error) {
            console.error('奖励计算失败:', error);
            return this.createIneligibleResult('奖励计算失败');
        }
    }
    async calculateRewardWithDB(annotationId, userId, rewardType) {
        try {
            const result = await database_1.db.raw(`
        SELECT calculate_lbs_reward_amount(
          ?::uuid,
          ?::uuid,
          ?
        ) as reward_amount
      `, [annotationId, userId, rewardType]);
            const resultArray = result;
            return parseFloat(resultArray[0]?.['reward_amount'] || '0');
        }
        catch (error) {
            console.error('数据库奖励计算失败:', error);
            throw new Error('数据库奖励计算失败');
        }
    }
    async calculateTimeDecayFactor(createdAt) {
        try {
            const result = await database_1.db.raw(`
        SELECT calculate_time_decay_factor(?::timestamp with time zone) as decay_factor
      `, [createdAt.toISOString()]);
            const resultArray = result;
            return parseFloat(resultArray[0]?.['decay_factor'] || '1');
        }
        catch (error) {
            console.error('时间衰减计算失败:', error);
            return this.calculateTimeDecayFactorLocal(createdAt);
        }
    }
    calculateTimeDecayFactorLocal(createdAt) {
        const now = new Date();
        const hoursDiff = (now.getTime() - createdAt.getTime()) / (1000 * 60 * 60);
        if (hoursDiff <= 24) {
            return 0.70;
        }
        if (hoursDiff <= 168) {
            return 0.50;
        }
        if (hoursDiff <= 720) {
            return 0.30;
        }
        return 0.10;
    }
    async isFirstFinder(annotationId, userId) {
        try {
            const result = await database_1.db.raw(`
        SELECT is_first_finder(
          ?::uuid,
          ?::uuid
        ) as is_first
      `, [annotationId, userId]);
            const rows = Array.isArray(result) ? result : [];
            return rows.length > 0 ? rows[0]['is_first'] : false;
        }
        catch (error) {
            console.error('首次发现者检查失败:', error);
            return false;
        }
    }
    async getUserComboStreak(userId) {
        try {
            const result = await (0, database_1.db)('lbs_reward_stats')
                .select('current_combo_streak')
                .where('user_id', userId);
            const stats = Array.isArray(result) ? result : [];
            return stats.length > 0 ? stats[0]['current_combo_streak'] : 0;
        }
        catch (error) {
            console.error('获取连击数失败:', error);
            return 0;
        }
    }
    calculateComboBonus(comboStreak) {
        if (comboStreak < 2) {
            return 0;
        }
        if (comboStreak < 5) {
            return 0.05;
        }
        if (comboStreak < 10) {
            return 0.10;
        }
        if (comboStreak < 20) {
            return 0.15;
        }
        return 0.20;
    }
    async getAnnotation(annotationId) {
        try {
            const result = await (0, database_1.db)('annotations')
                .select('id', 'amount', 'created_at', 'status')
                .where('id', annotationId)
                .where('status', 'active');
            const annotations = Array.isArray(result) ? result : [];
            return annotations.length > 0 ? {
                id: annotations[0]['id'],
                amount: parseFloat(annotations[0]['amount']),
                createdAt: new Date(annotations[0]['created_at']),
                status: annotations[0]['status'],
            } : null;
        }
        catch (error) {
            console.error('获取标注信息失败:', error);
            return null;
        }
    }
    async getGeofenceConfig(annotationId) {
        try {
            const result = await (0, database_1.db)('geofence_configs')
                .select('*')
                .where('annotation_id', annotationId)
                .where('is_active', true)
                .orderBy('created_at', 'desc')
                .limit(1);
            const configs = Array.isArray(result) ? result : [];
            if (configs.length === 0) {
                return null;
            }
            const row = configs[0];
            return {
                id: row['id'],
                annotationId: row['annotation_id'],
                radiusMeters: row['radius_meters'],
                detectionFrequency: row['detection_frequency'],
                minAccuracyMeters: row['min_accuracy_meters'],
                minStayDuration: row['min_stay_duration'],
                maxSpeedKmh: parseFloat(row['max_speed_kmh']),
                isActive: row['is_active'],
                rewardBasePercentage: parseFloat(row['reward_base_percentage']),
                timeDecayEnabled: row['time_decay_enabled'],
                firstFinderBonus: parseFloat(row['first_finder_bonus']),
                comboBonusEnabled: row['combo_bonus_enabled'],
                createdAt: new Date(row['created_at']),
                updatedAt: new Date(row['updated_at']),
            };
        }
        catch (error) {
            console.error('获取地理围栏配置失败:', error);
            return null;
        }
    }
    async checkExistingReward(annotationId, userId) {
        try {
            const result = await (0, database_1.db)('lbs_rewards')
                .count('* as count')
                .where('annotation_id', annotationId)
                .where('user_id', userId)
                .whereIn('status', ['verified', 'claimed'])
                .where('created_at', '>', database_1.db.raw('NOW() - INTERVAL \'24 hours\''));
            const rows = Array.isArray(result) ? result : [];
            return rows.length > 0 ? parseInt(rows[0]['count']) > 0 : false;
        }
        catch (error) {
            console.error('检查现有奖励失败:', error);
            return false;
        }
    }
    createIneligibleResult(reason) {
        return {
            finalAmount: 0,
            breakdown: {
                baseAmount: 0,
                timeDecayFactor: 0,
                firstFinderBonus: 0,
                comboBonus: 0,
                finalAmount: 0,
            },
            eligibility: {
                eligible: false,
                reasons: [reason],
            },
        };
    }
}
exports.RewardCalculationService = RewardCalculationService;
//# sourceMappingURL=rewardCalculationService.js.map