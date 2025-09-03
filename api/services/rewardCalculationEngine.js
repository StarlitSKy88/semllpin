/**
 * LBS奖励计算引擎
 * 实现时间衰减机制、奖励类型计算和防作弊检测
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

class RewardCalculationEngine {
    constructor(database) {
        this.db = database;
        
        // 奖励类型配置
        this.rewardTypes = {
            discovery: {
                baseMultiplier: 1.0,
                firstDiscovererBonus: 0.5, // 50%首发奖励
                maxDailyRewards: 5
            },
            checkin: {
                baseMultiplier: 0.8,
                firstDiscovererBonus: 0.3,
                maxDailyRewards: 10
            },
            duration: {
                baseMultiplier: 1.2,
                hourlyBonus: 0.1, // 每小时额外0.1元
                maxDailyRewards: 3
            },
            social: {
                baseMultiplier: 0.9,
                interactionBonus: 0.2,
                maxDailyRewards: 8
            }
        };

        // 时间衰减配置
        this.timeDecayConfig = {
            maxDecayHours: 168, // 7天
            maxDecayRate: 0.5,  // 最大衰减50%
            minDecayFactor: 0.5 // 最小衰减因子
        };
    }

    /**
     * 计算LBS奖励
     * @param {Object} params - 计算参数
     * @returns {Promise<Object>} 奖励计算结果
     */
    async calculateReward(params) {
        try {
            const {
                userId,
                geofenceId,
                rewardType,
                baseAmount,
                longitude,
                latitude,
                durationMinutes = 0,
                metadata = {}
            } = params;

            // 验证输入参数
            this.validateCalculationParams(params);

            // 检查今日奖励限制
            const todayRewardCount = await this.getTodayRewardCount(userId, geofenceId, rewardType);
            const maxDailyRewards = this.rewardTypes[rewardType]?.maxDailyRewards || 5;
            
            if (todayRewardCount >= maxDailyRewards) {
                return {
                    success: false,
                    reason: 'daily_limit_exceeded',
                    message: `今日${rewardType}奖励已达上限 (${maxDailyRewards}次)`,
                    rewardAmount: 0
                };
            }

            // 计算时间衰减因子
            const timeDecayFactor = await this.calculateTimeDecayFactor(userId, longitude, latitude);

            // 检查是否为首次发现者
            const isFirstDiscoverer = await this.checkFirstDiscoverer(userId, longitude, latitude);

            // 计算最终奖励金额
            const rewardCalculation = this.computeFinalReward({
                rewardType,
                baseAmount,
                timeDecayFactor,
                isFirstDiscoverer,
                durationMinutes,
                metadata
            });

            // 防作弊检测
            const fraudCheck = await this.performFraudDetection(userId, longitude, latitude, rewardCalculation.finalAmount);
            
            if (!fraudCheck.isValid) {
                return {
                    success: false,
                    reason: 'fraud_detected',
                    message: fraudCheck.reason,
                    rewardAmount: 0,
                    fraudDetails: fraudCheck.details
                };
            }

            return {
                success: true,
                rewardAmount: rewardCalculation.finalAmount,
                breakdown: {
                    baseAmount: baseAmount,
                    timeDecayFactor: timeDecayFactor,
                    isFirstDiscoverer: isFirstDiscoverer,
                    discoveryBonus: rewardCalculation.discoveryBonus,
                    durationBonus: rewardCalculation.durationBonus,
                    typeMultiplier: rewardCalculation.typeMultiplier
                },
                metadata: {
                    calculatedAt: new Date().toISOString(),
                    todayRewardCount: todayRewardCount + 1,
                    maxDailyRewards: maxDailyRewards
                }
            };

        } catch (error) {
            console.error('Reward calculation error:', error);
            throw new Error(`Reward calculation failed: ${error.message}`);
        }
    }

    /**
     * 计算时间衰减因子
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {Promise<number>} 时间衰减因子
     */
    async calculateTimeDecayFactor(userId, longitude, latitude) {
        try {
            // 获取用户在附近区域的历史奖励记录
            const query = `
                SELECT 
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MAX(created_at))) / 3600 as hours_since_last,
                    longitude, latitude
                FROM lbs_rewards
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
            `;

            const result = await this.db.query(query, [userId]);
            
            // 过滤出100米范围内的记录
             let hoursSinceLast = this.timeDecayConfig.maxDecayHours;
             if (result.rows.length > 0) {
                 for (const row of result.rows) {
                     const distance = this.calculateDistance(
                         parseFloat(row.latitude),
                         parseFloat(row.longitude),
                         latitude,
                         longitude
                     ) * 1000; // 转换为米
                     
                     if (distance <= 100 && row.hours_since_last !== null) {
                         hoursSinceLast = Math.min(hoursSinceLast, row.hours_since_last);
                     }
                 }
             }
            
            // 计算衰减因子：factor = 1 - (hours / maxHours) * maxDecayRate
            const decayFactor = Math.max(
                this.timeDecayConfig.minDecayFactor,
                1.0 - (hoursSinceLast / this.timeDecayConfig.maxDecayHours) * this.timeDecayConfig.maxDecayRate
            );

            return Math.min(1.0, decayFactor);

        } catch (error) {
            console.error('Error calculating time decay factor:', error);
            return 1.0; // 默认无衰减
        }
    }

    /**
     * 检查是否为首次发现者
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} radius - 检查半径（米）
     * @returns {Promise<boolean>} 是否为首次发现者
     */
    async checkFirstDiscoverer(userId, longitude, latitude, radius = 50) {
        try {
            // 获取30天内其他用户的奖励记录
            const query = `
                SELECT longitude, latitude
                FROM lbs_rewards
                WHERE user_id != $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
            `;

            const result = await this.db.query(query, [userId]);
            
            // 计算指定半径内的记录数量
             let existingCount = 0;
             for (const row of result.rows) {
                 const distance = this.calculateDistance(
                     parseFloat(row.latitude),
                     parseFloat(row.longitude),
                     latitude,
                     longitude
                 ) * 1000; // 转换为米
                 
                 if (distance <= radius) {
                     existingCount++;
                 }
             }
            return existingCount === 0;

        } catch (error) {
            console.error('Error checking first discoverer:', error);
            return false;
        }
    }

    /**
     * 计算最终奖励金额
     * @param {Object} params - 计算参数
     * @returns {Object} 奖励计算详情
     */
    computeFinalReward(params) {
        const {
            rewardType,
            baseAmount,
            timeDecayFactor,
            isFirstDiscoverer,
            durationMinutes,
            metadata
        } = params;

        const typeConfig = this.rewardTypes[rewardType] || this.rewardTypes.checkin;
        
        // 基础金额 * 类型倍数 * 时间衰减
        let finalAmount = baseAmount * typeConfig.baseMultiplier * timeDecayFactor;
        
        // 首次发现者奖励
        let discoveryBonus = 0;
        if (isFirstDiscoverer) {
            discoveryBonus = baseAmount * typeConfig.firstDiscovererBonus;
            finalAmount += discoveryBonus;
        }

        // 持续时间奖励（仅适用于duration类型）
        let durationBonus = 0;
        if (rewardType === 'duration' && durationMinutes > 0) {
            durationBonus = (durationMinutes / 60) * typeConfig.hourlyBonus;
            finalAmount += durationBonus;
        }

        // 社交互动奖励（仅适用于social类型）
        let socialBonus = 0;
        if (rewardType === 'social' && metadata.interactionCount) {
            socialBonus = metadata.interactionCount * typeConfig.interactionBonus;
            finalAmount += socialBonus;
        }

        return {
            finalAmount: Math.round(finalAmount * 100) / 100, // 保留两位小数
            discoveryBonus,
            durationBonus,
            socialBonus,
            typeMultiplier: typeConfig.baseMultiplier
        };
    }

    /**
     * 获取今日奖励次数
     * @param {number} userId - 用户ID
     * @param {number} geofenceId - 地理围栏ID
     * @param {string} rewardType - 奖励类型
     * @returns {Promise<number>} 今日奖励次数
     */
    async getTodayRewardCount(userId, geofenceId, rewardType) {
        try {
            const query = `
                SELECT COUNT(*) as reward_count
                FROM lbs_rewards
                WHERE user_id = $1
                  AND geofence_id = $2
                  AND reward_type = $3
                  AND DATE(created_at) = CURRENT_DATE
            `;

            const result = await this.db.query(query, [userId, geofenceId, rewardType]);
            return parseInt(result.rows[0].reward_count) || 0;

        } catch (error) {
            console.error('Error getting today reward count:', error);
            return 0;
        }
    }

    /**
     * 防作弊检测
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} rewardAmount - 奖励金额
     * @returns {Promise<Object>} 检测结果
     */
    async performFraudDetection(userId, longitude, latitude, rewardAmount) {
        try {
            const checks = [];

            // 1. 检查异常移动速度
            const speedCheck = await this.checkAbnormalSpeed(userId, longitude, latitude);
            checks.push(speedCheck);

            // 2. 检查频繁触发
            const frequencyCheck = await this.checkFrequentTriggers(userId);
            checks.push(frequencyCheck);

            // 3. 检查位置精度
            const accuracyCheck = await this.checkLocationAccuracy(userId, longitude, latitude);
            checks.push(accuracyCheck);

            // 4. 检查奖励金额异常
            const amountCheck = this.checkAbnormalAmount(rewardAmount);
            checks.push(amountCheck);

            // 综合评估风险等级
            const riskLevel = this.calculateRiskLevel(checks);
            const isValid = riskLevel !== 'critical';

            // 记录检测日志
            if (!isValid || riskLevel === 'high') {
                await this.logFraudDetection(userId, longitude, latitude, riskLevel, checks);
            }

            return {
                isValid,
                riskLevel,
                reason: isValid ? null : '检测到可疑行为',
                details: checks.filter(check => !check.passed)
            };

        } catch (error) {
            console.error('Fraud detection error:', error);
            return {
                isValid: true, // 检测失败时默认通过
                riskLevel: 'low',
                reason: null,
                details: []
            };
        }
    }

    /**
     * 检查异常移动速度
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {Promise<Object>} 检查结果
     */
    async checkAbnormalSpeed(userId, longitude, latitude) {
        try {
            const query = `
                SELECT 
                    longitude as last_lon,
                    latitude as last_lat,
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - created_at)) as seconds_ago
                FROM lbs_rewards
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                ORDER BY created_at DESC
                LIMIT 1
            `;

            const result = await this.db.query(query, [userId]);
            
            if (result.rows.length === 0) {
                return { type: 'speed', passed: true, message: 'No recent location data' };
            }

            const lastLocation = result.rows[0];
            const distance = this.calculateDistance(
                lastLocation.last_lon, lastLocation.last_lat,
                longitude, latitude
            );
            const timeSeconds = lastLocation.seconds_ago;
            const speedMps = distance / timeSeconds; // 米/秒
            const speedKmh = speedMps * 3.6; // 公里/小时

            // 超过120km/h认为异常
            const isAbnormal = speedKmh > 120;

            return {
                type: 'speed',
                passed: !isAbnormal,
                message: isAbnormal ? `移动速度异常: ${speedKmh.toFixed(1)} km/h` : 'Speed normal',
                data: { speedKmh, distance, timeSeconds }
            };

        } catch (error) {
            console.error('Speed check error:', error);
            return { type: 'speed', passed: true, message: 'Speed check failed' };
        }
    }

    /**
     * 检查频繁触发
     * @param {number} userId - 用户ID
     * @returns {Promise<Object>} 检查结果
     */
    async checkFrequentTriggers(userId) {
        try {
            const query = `
                SELECT COUNT(*) as recent_count
                FROM lbs_rewards
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
            `;

            const result = await this.db.query(query, [userId]);
            const recentCount = parseInt(result.rows[0].recent_count) || 0;
            
            // 1小时内超过20次认为异常
            const isFrequent = recentCount > 20;

            return {
                type: 'frequency',
                passed: !isFrequent,
                message: isFrequent ? `1小时内触发${recentCount}次，疑似刷奖励` : 'Frequency normal',
                data: { recentCount }
            };

        } catch (error) {
            console.error('Frequency check error:', error);
            return { type: 'frequency', passed: true, message: 'Frequency check failed' };
        }
    }

    /**
     * 检查位置精度
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {Promise<Object>} 检查结果
     */
    async checkLocationAccuracy(userId, longitude, latitude) {
        // 检查坐标是否过于精确（可能是模拟器）
        const lonStr = longitude.toString();
        const latStr = latitude.toString();
        
        const lonDecimals = lonStr.includes('.') ? lonStr.split('.')[1].length : 0;
        const latDecimals = latStr.includes('.') ? latStr.split('.')[1].length : 0;
        
        // 超过8位小数可能是模拟器
        const isSuspicious = lonDecimals > 8 || latDecimals > 8;
        
        return {
            type: 'accuracy',
            passed: !isSuspicious,
            message: isSuspicious ? '位置精度异常，疑似模拟器' : 'Location accuracy normal',
            data: { lonDecimals, latDecimals }
        };
    }

    /**
     * 检查奖励金额异常
     * @param {number} rewardAmount - 奖励金额
     * @returns {Object} 检查结果
     */
    checkAbnormalAmount(rewardAmount) {
        // 单次奖励超过100元认为异常
        const isAbnormal = rewardAmount > 100;
        
        return {
            type: 'amount',
            passed: !isAbnormal,
            message: isAbnormal ? `奖励金额异常: ${rewardAmount}元` : 'Reward amount normal',
            data: { rewardAmount }
        };
    }

    /**
     * 计算风险等级
     * @param {Array} checks - 检查结果数组
     * @returns {string} 风险等级
     */
    calculateRiskLevel(checks) {
        const failedChecks = checks.filter(check => !check.passed);
        
        if (failedChecks.length === 0) return 'low';
        if (failedChecks.length === 1) return 'medium';
        if (failedChecks.length >= 2) return 'high';
        
        // 特殊情况：速度异常直接判定为critical
        const speedCheck = checks.find(check => check.type === 'speed');
        if (speedCheck && !speedCheck.passed && speedCheck.data?.speedKmh > 200) {
            return 'critical';
        }
        
        return 'high';
    }

    /**
     * 记录防作弊检测日志
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {string} riskLevel - 风险等级
     * @param {Array} checks - 检查结果
     */
    async logFraudDetection(userId, longitude, latitude, riskLevel, checks) {
        try {
            const query = `
                INSERT INTO anti_fraud_logs (
                    user_id, detection_type, risk_level, longitude, latitude,
                    suspicious_data, action_taken, is_blocked
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8
                )
            `;

            const suspiciousData = {
                checks: checks.filter(check => !check.passed),
                timestamp: new Date().toISOString()
            };
            
            const actionTaken = riskLevel === 'critical' ? 'reward_blocked' : 'logged_only';
            const isBlocked = riskLevel === 'critical';

            await this.db.query(query, [
                userId, 'reward_calculation', riskLevel, longitude, latitude,
                JSON.stringify(suspiciousData), actionTaken, isBlocked
            ]);

        } catch (error) {
            console.error('Error logging fraud detection:', error);
        }
    }

    /**
     * 验证计算参数
     * @param {Object} params - 参数对象
     */
    validateCalculationParams(params) {
        const { userId, geofenceId, rewardType, baseAmount, longitude, latitude } = params;
        
        if (!userId || !geofenceId || !rewardType || !baseAmount) {
            throw new Error('Missing required parameters');
        }
        
        if (!this.rewardTypes[rewardType]) {
            throw new Error(`Invalid reward type: ${rewardType}`);
        }
        
        if (baseAmount <= 0 || baseAmount > 1000) {
            throw new Error('Invalid base amount');
        }
        
        if (!this.isValidCoordinate(longitude, latitude)) {
            throw new Error('Invalid coordinates');
        }
    }

    /**
     * 验证坐标有效性
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {boolean} 坐标是否有效
     */
    isValidCoordinate(longitude, latitude) {
        return (
            typeof longitude === 'number' &&
            typeof latitude === 'number' &&
            longitude >= -180 && longitude <= 180 &&
            latitude >= -90 && latitude <= 90 &&
            !isNaN(longitude) && !isNaN(latitude)
        );
    }

    /**
     * 计算两点之间的距离（米）
     * @param {number} lon1 - 点1经度
     * @param {number} lat1 - 点1纬度
     * @param {number} lon2 - 点2经度
     * @param {number} lat2 - 点2纬度
     * @returns {number} 距离（米）
     */
    calculateDistance(lon1, lat1, lon2, lat2) {
        const R = 6371000; // 地球半径（米）
        const φ1 = lat1 * Math.PI / 180;
        const φ2 = lat2 * Math.PI / 180;
        const Δφ = (lat2 - lat1) * Math.PI / 180;
        const Δλ = (lon2 - lon1) * Math.PI / 180;

        const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
                Math.cos(φ1) * Math.cos(φ2) *
                Math.sin(Δλ/2) * Math.sin(Δλ/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

        return R * c;
    }
}

module.exports = RewardCalculationEngine;