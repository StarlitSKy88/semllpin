/**
 * 位置验证服务
 * 实现GPS坐标精度验证、防作弊检测和位置数据质量评估
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

class LocationVerificationService {
    constructor(database) {
        this.db = database;
        
        // 验证配置
        this.config = {
            // 坐标精度配置
            accuracy: {
                minAccuracy: 100,        // 最小精度要求（米）
                maxAccuracy: 5,          // 最高精度阈值（米）
                suspiciousAccuracy: 1,   // 可疑精度阈值（米）
                decimalPlaces: {
                    normal: 6,           // 正常小数位数
                    suspicious: 8        // 可疑小数位数
                }
            },
            
            // 移动速度配置
            speed: {
                maxWalkingSpeed: 8,      // 最大步行速度 (km/h)
                maxCyclingSpeed: 30,     // 最大骑行速度 (km/h)
                maxDrivingSpeed: 120,    // 最大驾驶速度 (km/h)
                impossibleSpeed: 300     // 不可能的速度 (km/h)
            },
            
            // 时间间隔配置
            timing: {
                minInterval: 5,          // 最小上报间隔（秒）
                maxInterval: 3600,       // 最大上报间隔（秒）
                suspiciousInterval: 1    // 可疑上报间隔（秒）
            },
            
            // 地理围栏配置
            geofence: {
                minStayDuration: 30,     // 最小停留时间（秒）
                maxDetectionRadius: 500, // 最大检测半径（米）
                bounceThreshold: 3       // 反复进出阈值
            }
        };
    }

    /**
     * 验证位置数据
     * @param {Object} locationData - 位置数据
     * @returns {Promise<Object>} 验证结果
     */
    async verifyLocation(locationData) {
        try {
            const {
                userId,
                longitude,
                latitude,
                accuracy,
                timestamp,
                speed = null,
                heading = null,
                altitude = null,
                provider = 'gps'
            } = locationData;

            // 基础数据验证
            const basicValidation = this.validateBasicData(locationData);
            if (!basicValidation.isValid) {
                return basicValidation;
            }

            // 坐标精度验证
            const accuracyCheck = this.validateAccuracy(longitude, latitude, accuracy);
            
            // 移动速度验证
            const speedCheck = await this.validateMovementSpeed(userId, longitude, latitude, timestamp);
            
            // 时间间隔验证
            const timingCheck = await this.validateTiming(userId, timestamp);
            
            // 位置合理性验证
            const reasonabilityCheck = this.validateLocationReasonability(longitude, latitude, altitude);
            
            // 设备指纹验证
            const deviceCheck = await this.validateDeviceFingerprint(userId, provider, accuracy);
            
            // 地理围栏行为验证
            const behaviorCheck = await this.validateGeofenceBehavior(userId, longitude, latitude, timestamp);

            // 高级轨迹分析
            const trajectoryCheck = await this.analyzeMovementTrajectory(userId, longitude, latitude, timestamp);

            // 综合评估
            const overallAssessment = this.assessOverallValidity([
                accuracyCheck,
                speedCheck,
                timingCheck,
                reasonabilityCheck,
                deviceCheck,
                behaviorCheck,
                trajectoryCheck
            ]);

            // 记录验证日志
            await this.logVerificationResult(userId, locationData, overallAssessment);

            return {
                isValid: overallAssessment.isValid,
                confidence: overallAssessment.confidence,
                riskLevel: overallAssessment.riskLevel,
                checks: {
                    accuracy: accuracyCheck,
                    speed: speedCheck,
                    timing: timingCheck,
                    reasonability: reasonabilityCheck,
                    device: deviceCheck,
                    behavior: behaviorCheck,
                    trajectory: trajectoryCheck
                },
                recommendations: overallAssessment.recommendations,
                metadata: {
                    verifiedAt: new Date().toISOString(),
                    verificationVersion: '1.0'
                }
            };

        } catch (error) {
            console.error('Location verification error:', error);
            return {
                isValid: false,
                confidence: 0,
                riskLevel: 'critical',
                error: error.message,
                checks: {},
                recommendations: ['重新获取位置数据'],
                metadata: {
                    verifiedAt: new Date().toISOString(),
                    error: true
                }
            };
        }
    }

    /**
     * 验证基础数据
     * @param {Object} locationData - 位置数据
     * @returns {Object} 验证结果
     */
    validateBasicData(locationData) {
        const { userId, longitude, latitude, timestamp } = locationData;
        
        const errors = [];
        
        if (!userId) errors.push('用户ID缺失');
        if (typeof longitude !== 'number' || isNaN(longitude)) errors.push('经度数据无效');
        if (typeof latitude !== 'number' || isNaN(latitude)) errors.push('纬度数据无效');
        if (!timestamp) errors.push('时间戳缺失');
        
        if (longitude < -180 || longitude > 180) errors.push('经度超出有效范围');
        if (latitude < -90 || latitude > 90) errors.push('纬度超出有效范围');
        
        const timestampDate = new Date(timestamp);
        if (isNaN(timestampDate.getTime())) errors.push('时间戳格式无效');
        
        const now = new Date();
        const timeDiff = Math.abs(now - timestampDate) / 1000; // 秒
        if (timeDiff > 300) errors.push('时间戳与当前时间差异过大'); // 5分钟
        
        return {
            isValid: errors.length === 0,
            errors,
            type: 'basic_validation'
        };
    }

    /**
     * 验证坐标精度
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} accuracy - 精度（米）
     * @returns {Object} 验证结果
     */
    validateAccuracy(longitude, latitude, accuracy) {
        const issues = [];
        let riskLevel = 'low';
        
        // 检查精度值
        if (accuracy && accuracy < this.config.accuracy.suspiciousAccuracy) {
            issues.push(`精度过高，疑似模拟器: ${accuracy}米`);
            riskLevel = 'high';
        }
        
        if (accuracy && accuracy > this.config.accuracy.minAccuracy) {
            issues.push(`精度过低: ${accuracy}米`);
            riskLevel = riskLevel === 'high' ? 'high' : 'medium';
        }
        
        // 检查小数位数
        const lonDecimals = this.getDecimalPlaces(longitude);
        const latDecimals = this.getDecimalPlaces(latitude);
        
        if (lonDecimals > this.config.accuracy.decimalPlaces.suspicious || 
            latDecimals > this.config.accuracy.decimalPlaces.suspicious) {
            issues.push(`坐标小数位数异常: 经度${lonDecimals}位, 纬度${latDecimals}位`);
            riskLevel = 'high';
        }
        
        // 检查坐标是否为整数或过于规整
        if (lonDecimals === 0 || latDecimals === 0) {
            issues.push('坐标为整数，疑似手动输入');
            riskLevel = 'medium';
        }
        
        // 检查坐标是否重复（连续多个相同坐标）
        const lonStr = longitude.toString();
        const latStr = latitude.toString();
        if (this.hasRepeatingPattern(lonStr) || this.hasRepeatingPattern(latStr)) {
            issues.push('坐标存在重复模式，疑似生成');
            riskLevel = 'high';
        }
        
        return {
            passed: issues.length === 0,
            riskLevel,
            issues,
            data: {
                accuracy,
                lonDecimals,
                latDecimals
            },
            type: 'accuracy_check'
        };
    }

    /**
     * 验证移动速度
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {string} timestamp - 时间戳
     * @returns {Promise<Object>} 验证结果
     */
    async validateMovementSpeed(userId, longitude, latitude, timestamp) {
        try {
            const query = `
                SELECT 
                    longitude as last_lon,
                    latitude as last_lat,
                    created_at
                FROM location_reports
                WHERE user_id = $1
                  AND created_at < $2
                ORDER BY created_at DESC
                LIMIT 1
            `;

            const result = await this.db.query(query, [userId, timestamp]);
            
            if (result.rows.length === 0) {
                return {
                    passed: true,
                    riskLevel: 'low',
                    issues: [],
                    data: { message: '无历史位置数据' },
                    type: 'speed_check'
                };
            }

            const lastLocation = result.rows[0];
            const distance = this.calculateDistance(
                lastLocation.last_lon, lastLocation.last_lat,
                longitude, latitude
            );
            
            const timeDiff = (new Date(timestamp) - new Date(lastLocation.created_at)) / 1000; // 秒
            const speedMps = distance / timeDiff; // 米/秒
            const speedKmh = speedMps * 3.6; // 公里/小时

            const issues = [];
            let riskLevel = 'low';
            
            if (speedKmh > this.config.speed.impossibleSpeed) {
                issues.push(`移动速度不可能: ${speedKmh.toFixed(1)} km/h`);
                riskLevel = 'critical';
            } else if (speedKmh > this.config.speed.maxDrivingSpeed) {
                issues.push(`移动速度过快: ${speedKmh.toFixed(1)} km/h`);
                riskLevel = 'high';
            } else if (speedKmh > this.config.speed.maxCyclingSpeed) {
                issues.push(`移动速度较快: ${speedKmh.toFixed(1)} km/h`);
                riskLevel = 'medium';
            }
            
            // 检查瞬移（极短时间内移动很远距离）
            if (timeDiff < 5 && distance > 100) {
                issues.push(`疑似瞬移: ${timeDiff}秒内移动${distance.toFixed(1)}米`);
                riskLevel = 'high';
            }

            return {
                passed: issues.length === 0,
                riskLevel,
                issues,
                data: {
                    speedKmh: speedKmh.toFixed(1),
                    distance: distance.toFixed(1),
                    timeDiff
                },
                type: 'speed_check'
            };

        } catch (error) {
            console.error('Speed validation error:', error);
            return {
                passed: true,
                riskLevel: 'low',
                issues: [],
                data: { error: 'Speed check failed' },
                type: 'speed_check'
            };
        }
    }

    /**
     * 验证时间间隔
     * @param {number} userId - 用户ID
     * @param {string} timestamp - 时间戳
     * @returns {Promise<Object>} 验证结果
     */
    async validateTiming(userId, timestamp) {
        try {
            const query = `
                SELECT 
                    created_at,
                    EXTRACT(EPOCH FROM ($2::timestamp - created_at)) as interval_seconds
                FROM location_reports
                WHERE user_id = $1
                  AND created_at < $2
                ORDER BY created_at DESC
                LIMIT 5
            `;

            const result = await this.db.query(query, [userId, timestamp]);
            
            if (result.rows.length === 0) {
                return {
                    passed: true,
                    riskLevel: 'low',
                    issues: [],
                    data: { message: '首次位置上报' },
                    type: 'timing_check'
                };
            }

            const intervals = result.rows.map(row => row.interval_seconds);
            const lastInterval = intervals[0];
            
            const issues = [];
            let riskLevel = 'low';
            
            // 检查上报间隔过短
            if (lastInterval < this.config.timing.suspiciousInterval) {
                issues.push(`上报间隔过短: ${lastInterval}秒`);
                riskLevel = 'high';
            } else if (lastInterval < this.config.timing.minInterval) {
                issues.push(`上报间隔较短: ${lastInterval}秒`);
                riskLevel = 'medium';
            }
            
            // 检查规律性上报（可能是脚本）
            if (intervals.length >= 3) {
                const isRegular = this.checkRegularPattern(intervals);
                if (isRegular) {
                    issues.push('上报时间过于规律，疑似自动化脚本');
                    riskLevel = 'high';
                }
            }
            
            // 检查频繁上报
            const recentCount = intervals.filter(interval => interval < 60).length;
            if (recentCount >= 3) {
                issues.push(`1分钟内频繁上报${recentCount}次`);
                riskLevel = 'high';
            }

            return {
                passed: issues.length === 0,
                riskLevel,
                issues,
                data: {
                    lastInterval,
                    recentIntervals: intervals.slice(0, 3),
                    recentCount
                },
                type: 'timing_check'
            };

        } catch (error) {
            console.error('Timing validation error:', error);
            return {
                passed: true,
                riskLevel: 'low',
                issues: [],
                data: { error: 'Timing check failed' },
                type: 'timing_check'
            };
        }
    }

    /**
     * 验证位置合理性
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} altitude - 海拔
     * @returns {Object} 验证结果
     */
    validateLocationReasonability(longitude, latitude, altitude) {
        const issues = [];
        let riskLevel = 'low';
        
        // 检查是否在海洋中（简单检查）
        if (this.isInOcean(longitude, latitude)) {
            issues.push('位置在海洋中，可能不合理');
            riskLevel = 'medium';
        }
        
        // 检查海拔异常
        if (altitude !== null && altitude !== undefined) {
            if (altitude < -500 || altitude > 9000) {
                issues.push(`海拔异常: ${altitude}米`);
                riskLevel = 'medium';
            }
        }
        
        // 检查是否在已知的测试坐标
        if (this.isTestCoordinate(longitude, latitude)) {
            issues.push('疑似测试坐标');
            riskLevel = 'high';
        }
        
        return {
            passed: issues.length === 0,
            riskLevel,
            issues,
            data: {
                longitude,
                latitude,
                altitude
            },
            type: 'reasonability_check'
        };
    }

    /**
     * 验证设备指纹
     * @param {number} userId - 用户ID
     * @param {string} provider - 位置提供者
     * @param {number} accuracy - 精度
     * @returns {Promise<Object>} 验证结果
     */
    async validateDeviceFingerprint(userId, provider, accuracy) {
        try {
            const query = `
                SELECT 
                    provider,
                    accuracy,
                    COUNT(*) as count
                FROM location_reports
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
                GROUP BY provider, accuracy
                ORDER BY count DESC
            `;

            const result = await this.db.query(query, [userId]);
            
            const issues = [];
            let riskLevel = 'low';
            
            // 检查提供者异常
            if (provider && !['gps', 'network', 'passive', 'fused'].includes(provider)) {
                issues.push(`未知的位置提供者: ${provider}`);
                riskLevel = 'medium';
            }
            
            // 检查精度值过于一致
            if (result.rows.length > 0) {
                const sameAccuracyCount = result.rows.find(row => 
                    row.accuracy === accuracy && row.count > 10
                );
                
                if (sameAccuracyCount) {
                    issues.push(`精度值过于一致: ${accuracy}米出现${sameAccuracyCount.count}次`);
                    riskLevel = 'medium';
                }
            }
            
            return {
                passed: issues.length === 0,
                riskLevel,
                issues,
                data: {
                    provider,
                    accuracy,
                    recentPatterns: result.rows.slice(0, 3)
                },
                type: 'device_check'
            };

        } catch (error) {
            console.error('Device fingerprint validation error:', error);
            return {
                passed: true,
                riskLevel: 'low',
                issues: [],
                data: { error: 'Device check failed' },
                type: 'device_check'
            };
        }
    }

    /**
     * 验证地理围栏行为
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {string} timestamp - 时间戳
     * @returns {Promise<Object>} 验证结果
     */
    async validateGeofenceBehavior(userId, longitude, latitude, timestamp) {
        try {
            // 检查反复进出地理围栏的行为
            const query = `
                SELECT 
                    geofence_id,
                    longitude,
                    latitude,
                    created_at
                FROM lbs_rewards
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
            `;

            const allRewards = await this.db.query(query, [userId]);
            
            // 手动过滤100米范围内的记录
            const nearbyRewards = allRewards.rows.filter(reward => {
                const distance = this.calculateDistance(
                    longitude, latitude,
                    reward.longitude, reward.latitude
                );
                return distance <= 100;
            });
            
            // 按地理围栏分组计算
            const geofenceGroups = {};
            nearbyRewards.forEach(reward => {
                if (!geofenceGroups[reward.geofence_id]) {
                    geofenceGroups[reward.geofence_id] = {
                        entry_count: 0,
                        last_entry: null
                    };
                }
                geofenceGroups[reward.geofence_id].entry_count++;
                if (!geofenceGroups[reward.geofence_id].last_entry || 
                    new Date(reward.created_at) > new Date(geofenceGroups[reward.geofence_id].last_entry)) {
                    geofenceGroups[reward.geofence_id].last_entry = reward.created_at;
                }
            });
            
            // 找出超过阈值的地理围栏
            const result = { rows: [] };
            Object.entries(geofenceGroups).forEach(([geofenceId, data]) => {
                if (data.entry_count > this.config.geofence.bounceThreshold) {
                    result.rows.push({
                        geofence_id: geofenceId,
                        entry_count: data.entry_count,
                        last_entry: data.last_entry
                    });
                }
            });
            
            const issues = [];
            let riskLevel = 'low';
            
            if (result.rows.length > 0) {
                const bounceData = result.rows[0];
                issues.push(`1小时内在同一区域反复触发${bounceData.entry_count}次`);
                riskLevel = 'high';
            }
            
            return {
                passed: issues.length === 0,
                riskLevel,
                issues,
                data: {
                    bounceDetected: result.rows.length > 0,
                    bounceCount: result.rows.length > 0 ? result.rows[0].entry_count : 0
                },
                type: 'behavior_check'
            };

        } catch (error) {
            console.error('Geofence behavior validation error:', error);
            return {
                passed: true,
                riskLevel: 'low',
                issues: [],
                data: { error: 'Behavior check failed' },
                type: 'behavior_check'
            };
        }
    }

    /**
     * 综合评估有效性
     * @param {Array} checks - 检查结果数组
     * @returns {Object} 综合评估结果
     */
    assessOverallValidity(checks) {
        const failedChecks = checks.filter(check => !check.passed);
        const riskLevels = checks.map(check => check.riskLevel);
        
        // 计算置信度
        let confidence = 100;
        failedChecks.forEach(check => {
            switch (check.riskLevel) {
                case 'critical': confidence -= 50; break;
                case 'high': confidence -= 30; break;
                case 'medium': confidence -= 15; break;
                case 'low': confidence -= 5; break;
            }
        });
        confidence = Math.max(0, confidence);
        
        // 确定整体风险等级
        let overallRiskLevel = 'low';
        if (riskLevels.includes('critical')) {
            overallRiskLevel = 'critical';
        } else if (riskLevels.includes('high')) {
            overallRiskLevel = 'high';
        } else if (riskLevels.includes('medium')) {
            overallRiskLevel = 'medium';
        }
        
        // 确定是否有效
        const isValid = overallRiskLevel !== 'critical' && confidence >= 60;
        
        // 生成建议
        const recommendations = this.generateRecommendations(failedChecks);
        
        return {
            isValid,
            confidence,
            riskLevel: overallRiskLevel,
            failedChecksCount: failedChecks.length,
            recommendations
        };
    }

    /**
     * 生成建议
     * @param {Array} failedChecks - 失败的检查
     * @returns {Array} 建议列表
     */
    generateRecommendations(failedChecks) {
        const recommendations = [];
        
        failedChecks.forEach(check => {
            switch (check.type) {
                case 'accuracy_check':
                    recommendations.push('检查GPS设置，确保位置服务正常工作');
                    break;
                case 'speed_check':
                    recommendations.push('确认移动方式，避免异常快速移动');
                    break;
                case 'timing_check':
                    recommendations.push('调整位置上报频率，避免过于频繁');
                    break;
                case 'device_check':
                    recommendations.push('检查设备设置，确保使用真实设备');
                    break;
                case 'behavior_check':
                    recommendations.push('避免在短时间内反复进出同一区域');
                    break;
            }
        });
        
        return [...new Set(recommendations)]; // 去重
    }

    /**
     * 记录验证结果
     * @param {number} userId - 用户ID
     * @param {Object} locationData - 位置数据
     * @param {Object} assessment - 评估结果
     */
    async logVerificationResult(userId, locationData, assessment) {
        try {
            if (!assessment.isValid || assessment.riskLevel === 'high') {
                const query = `
                    INSERT INTO anti_fraud_logs (
                        user_id, detection_type, risk_level, longitude, latitude,
                        suspicious_data, action_taken, is_blocked
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8
                    )
                `;

                const suspiciousData = {
                    confidence: assessment.confidence,
                    failedChecksCount: assessment.failedChecksCount,
                    timestamp: new Date().toISOString()
                };
                
                await this.db.query(query, [
                    userId,
                    'location_verification',
                    assessment.riskLevel,
                    locationData.longitude,
                    locationData.latitude,
                    JSON.stringify(suspiciousData),
                    assessment.isValid ? 'logged_only' : 'location_rejected',
                    !assessment.isValid
                ]);
            }
        } catch (error) {
            console.error('Error logging verification result:', error);
        }
    }

    // 辅助方法
    
    /**
     * 获取小数位数
     * @param {number} num - 数字
     * @returns {number} 小数位数
     */
    getDecimalPlaces(num) {
        const str = num.toString();
        if (str.indexOf('.') === -1) return 0;
        return str.split('.')[1].length;
    }

    /**
     * 检查重复模式
     * @param {string} str - 字符串
     * @returns {boolean} 是否有重复模式
     */
    hasRepeatingPattern(str) {
        const patterns = ['000', '111', '222', '333', '444', '555', '666', '777', '888', '999'];
        return patterns.some(pattern => str.includes(pattern));
    }

    /**
     * 检查规律模式
     * @param {Array} intervals - 时间间隔数组
     * @returns {boolean} 是否有规律模式
     */
    checkRegularPattern(intervals) {
        if (intervals.length < 3) return false;
        
        const tolerance = 2; // 2秒容差
        const firstInterval = intervals[0];
        
        return intervals.slice(1).every(interval => 
            Math.abs(interval - firstInterval) <= tolerance
        );
    }

    /**
     * 检查是否在海洋中
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {boolean} 是否在海洋中
     */
    isInOcean(longitude, latitude) {
        // 简单的海洋检查（实际应用中应使用更精确的地理数据）
        const oceanAreas = [
            { minLon: -180, maxLon: -120, minLat: 20, maxLat: 60 }, // 北太平洋
            { minLon: 120, maxLon: 180, minLat: -60, maxLat: 20 },   // 西太平洋
            { minLon: -60, maxLon: 20, minLat: -60, maxLat: 20 }     // 大西洋
        ];
        
        return oceanAreas.some(area => 
            longitude >= area.minLon && longitude <= area.maxLon &&
            latitude >= area.minLat && latitude <= area.maxLat
        );
    }

    /**
     * 检查是否为测试坐标
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @returns {boolean} 是否为测试坐标
     */
    isTestCoordinate(longitude, latitude) {
        const testCoordinates = [
            { lon: 0, lat: 0 },           // 原点
            { lon: 116.397128, lat: 39.916527 }, // 天安门
            { lon: 121.473701, lat: 31.230416 }  // 上海外滩
        ];
        
        const tolerance = 0.001; // 约100米
        
        return testCoordinates.some(coord => 
            Math.abs(longitude - coord.lon) < tolerance &&
            Math.abs(latitude - coord.lat) < tolerance
        );
    }

    /**
     * 高级移动轨迹分析
     * @param {number} userId - 用户ID
     * @param {number} longitude - 当前经度
     * @param {number} latitude - 当前纬度
     * @param {string} timestamp - 时间戳
     * @returns {Promise<Object>} 轨迹分析结果
     */
    async analyzeMovementTrajectory(userId, longitude, latitude, timestamp) {
        try {
            // 获取最近的位置记录
            const query = `
                SELECT longitude, latitude, created_at
                FROM location_reports
                WHERE user_id = $1
                  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '2 hours'
                ORDER BY created_at DESC
                LIMIT 20
            `;
            
            const result = await this.db.query(query, [userId]);
            const locations = result.rows;
            
            if (locations.length < 3) {
                return {
                    passed: true,
                    riskLevel: 'low',
                    issues: [],
                    data: { message: '轨迹数据不足' },
                    type: 'trajectory_analysis'
                };
            }
            
            // 添加当前位置
            locations.unshift({
                longitude,
                latitude,
                created_at: timestamp
            });
            
            const issues = [];
            let riskLevel = 'low';
            
            // 1. 轨迹平滑度分析
            const smoothnessResult = this.analyzeTrajectorySmoothing(locations);
            if (!smoothnessResult.passed) {
                issues.push(...smoothnessResult.issues);
                riskLevel = this.getHigherRiskLevel(riskLevel, smoothnessResult.riskLevel);
            }
            
            // 2. 异常跳跃检测
            const jumpResult = this.detectAbnormalJumps(locations);
            if (!jumpResult.passed) {
                issues.push(...jumpResult.issues);
                riskLevel = this.getHigherRiskLevel(riskLevel, jumpResult.riskLevel);
            }
            
            // 3. 停留点分析
            const stayPointResult = this.analyzeStayPoints(locations);
            if (!stayPointResult.passed) {
                issues.push(...stayPointResult.issues);
                riskLevel = this.getHigherRiskLevel(riskLevel, stayPointResult.riskLevel);
            }
            
            // 4. 移动模式分析
            const patternResult = this.analyzeMovementPattern(locations);
            if (!patternResult.passed) {
                issues.push(...patternResult.issues);
                riskLevel = this.getHigherRiskLevel(riskLevel, patternResult.riskLevel);
            }
            
            return {
                passed: issues.length === 0,
                riskLevel,
                issues,
                data: {
                    smoothness: smoothnessResult.data,
                    jumps: jumpResult.data,
                    stayPoints: stayPointResult.data,
                    pattern: patternResult.data
                },
                type: 'trajectory_analysis'
            };
            
        } catch (error) {
            console.error('Trajectory analysis error:', error);
            return {
                passed: true,
                riskLevel: 'low',
                issues: [],
                data: { error: 'Trajectory analysis failed' },
                type: 'trajectory_analysis'
            };
        }
    }
    
    /**
     * 分析轨迹平滑度
     * @param {Array} locations - 位置数组
     * @returns {Object} 平滑度分析结果
     */
    analyzeTrajectorySmoothing(locations) {
        const issues = [];
        let riskLevel = 'low';
        
        if (locations.length < 3) {
            return { passed: true, issues, riskLevel, data: {} };
        }
        
        const directions = [];
        const speeds = [];
        
        for (let i = 1; i < locations.length; i++) {
            const prev = locations[i];
            const curr = locations[i - 1];
            
            const distance = this.calculateDistance(
                prev.longitude, prev.latitude,
                curr.longitude, curr.latitude
            );
            
            const timeDiff = (new Date(curr.created_at) - new Date(prev.created_at)) / 1000;
            const speed = timeDiff > 0 ? (distance / timeDiff) * 3.6 : 0; // km/h
            
            const direction = this.calculateBearing(
                prev.longitude, prev.latitude,
                curr.longitude, curr.latitude
            );
            
            directions.push(direction);
            speeds.push(speed);
        }
        
        // 检查方向变化的剧烈程度
        let sharpTurns = 0;
        for (let i = 1; i < directions.length; i++) {
            const angleDiff = Math.abs(directions[i] - directions[i - 1]);
            const normalizedDiff = Math.min(angleDiff, 360 - angleDiff);
            
            if (normalizedDiff > 120) { // 超过120度的急转弯
                sharpTurns++;
            }
        }
        
        if (sharpTurns > directions.length * 0.3) {
            issues.push(`轨迹存在过多急转弯: ${sharpTurns}次`);
            riskLevel = 'medium';
        }
        
        // 检查速度变化的剧烈程度
        const speedVariance = this.calculateVariance(speeds);
        if (speedVariance > 100) { // 速度变化过大
            issues.push(`移动速度变化过于剧烈: 方差${speedVariance.toFixed(1)}`);
            riskLevel = this.getHigherRiskLevel(riskLevel, 'medium');
        }
        
        return {
            passed: issues.length === 0,
            issues,
            riskLevel,
            data: {
                sharpTurns,
                speedVariance: speedVariance.toFixed(1),
                avgSpeed: (speeds.reduce((a, b) => a + b, 0) / speeds.length).toFixed(1)
            }
        };
    }
    
    /**
     * 检测异常跳跃
     * @param {Array} locations - 位置数组
     * @returns {Object} 跳跃检测结果
     */
    detectAbnormalJumps(locations) {
        const issues = [];
        let riskLevel = 'low';
        
        if (locations.length < 2) {
            return { passed: true, issues, riskLevel, data: {} };
        }
        
        let jumpCount = 0;
        let maxJumpDistance = 0;
        
        for (let i = 1; i < locations.length; i++) {
            const prev = locations[i];
            const curr = locations[i - 1];
            
            const distance = this.calculateDistance(
                prev.longitude, prev.latitude,
                curr.longitude, curr.latitude
            );
            
            const timeDiff = (new Date(curr.created_at) - new Date(prev.created_at)) / 1000;
            
            // 检测瞬移（短时间内移动很远距离）
            if (timeDiff < 10 && distance > 500) {
                jumpCount++;
                maxJumpDistance = Math.max(maxJumpDistance, distance);
            }
        }
        
        if (jumpCount > 0) {
            issues.push(`检测到${jumpCount}次异常跳跃，最大距离${maxJumpDistance.toFixed(1)}米`);
            riskLevel = jumpCount > 2 ? 'high' : 'medium';
        }
        
        return {
            passed: issues.length === 0,
            issues,
            riskLevel,
            data: {
                jumpCount,
                maxJumpDistance: maxJumpDistance.toFixed(1)
            }
        };
    }
    
    /**
     * 分析停留点
     * @param {Array} locations - 位置数组
     * @returns {Object} 停留点分析结果
     */
    analyzeStayPoints(locations) {
        const issues = [];
        let riskLevel = 'low';
        
        if (locations.length < 3) {
            return { passed: true, issues, riskLevel, data: {} };
        }
        
        const stayPoints = [];
        let currentStayPoint = null;
        
        for (let i = 0; i < locations.length; i++) {
            const location = locations[i];
            
            if (!currentStayPoint) {
                currentStayPoint = {
                    longitude: location.longitude,
                    latitude: location.latitude,
                    startTime: location.created_at,
                    endTime: location.created_at,
                    count: 1
                };
            } else {
                const distance = this.calculateDistance(
                    currentStayPoint.longitude, currentStayPoint.latitude,
                    location.longitude, location.latitude
                );
                
                if (distance <= 50) { // 50米范围内认为是同一停留点
                    currentStayPoint.endTime = location.created_at;
                    currentStayPoint.count++;
                } else {
                    // 结束当前停留点
                    const duration = (new Date(currentStayPoint.endTime) - new Date(currentStayPoint.startTime)) / 1000;
                    if (duration >= this.config.geofence.minStayDuration) {
                        stayPoints.push({
                            ...currentStayPoint,
                            duration
                        });
                    }
                    
                    // 开始新的停留点
                    currentStayPoint = {
                        longitude: location.longitude,
                        latitude: location.latitude,
                        startTime: location.created_at,
                        endTime: location.created_at,
                        count: 1
                    };
                }
            }
        }
        
        // 处理最后一个停留点
        if (currentStayPoint) {
            const duration = (new Date(currentStayPoint.endTime) - new Date(currentStayPoint.startTime)) / 1000;
            if (duration >= this.config.geofence.minStayDuration) {
                stayPoints.push({
                    ...currentStayPoint,
                    duration
                });
            }
        }
        
        // 检查停留点的合理性
        const shortStays = stayPoints.filter(point => point.duration < 60); // 少于1分钟的停留
        if (shortStays.length > stayPoints.length * 0.5) {
            issues.push(`过多短时间停留点: ${shortStays.length}个`);
            riskLevel = 'medium';
        }
        
        return {
            passed: issues.length === 0,
            issues,
            riskLevel,
            data: {
                stayPointCount: stayPoints.length,
                shortStayCount: shortStays.length,
                avgStayDuration: stayPoints.length > 0 ? 
                    (stayPoints.reduce((sum, point) => sum + point.duration, 0) / stayPoints.length).toFixed(1) : 0
            }
        };
    }
    
    /**
     * 分析移动模式
     * @param {Array} locations - 位置数组
     * @returns {Object} 移动模式分析结果
     */
    analyzeMovementPattern(locations) {
        const issues = [];
        let riskLevel = 'low';
        
        if (locations.length < 5) {
            return { passed: true, issues, riskLevel, data: {} };
        }
        
        const distances = [];
        const timeIntervals = [];
        
        for (let i = 1; i < locations.length; i++) {
            const prev = locations[i];
            const curr = locations[i - 1];
            
            const distance = this.calculateDistance(
                prev.longitude, prev.latitude,
                curr.longitude, curr.latitude
            );
            
            const timeDiff = (new Date(curr.created_at) - new Date(prev.created_at)) / 1000;
            
            distances.push(distance);
            timeIntervals.push(timeDiff);
        }
        
        // 检查距离的规律性
        const distanceVariance = this.calculateVariance(distances);
        const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
        
        if (distanceVariance < avgDistance * 0.1 && avgDistance > 10) {
            issues.push(`移动距离过于规律，疑似脚本: 平均${avgDistance.toFixed(1)}米`);
            riskLevel = 'high';
        }
        
        // 检查时间间隔的规律性
        const timeVariance = this.calculateVariance(timeIntervals);
        const avgTime = timeIntervals.reduce((a, b) => a + b, 0) / timeIntervals.length;
        
        if (timeVariance < avgTime * 0.1 && avgTime > 5) {
            issues.push(`时间间隔过于规律，疑似自动化: 平均${avgTime.toFixed(1)}秒`);
            riskLevel = this.getHigherRiskLevel(riskLevel, 'high');
        }
        
        return {
            passed: issues.length === 0,
            issues,
            riskLevel,
            data: {
                avgDistance: avgDistance.toFixed(1),
                distanceVariance: distanceVariance.toFixed(1),
                avgTimeInterval: avgTime.toFixed(1),
                timeVariance: timeVariance.toFixed(1)
            }
        };
    }
    
    /**
     * 计算方位角
     * @param {number} lon1 - 起点经度
     * @param {number} lat1 - 起点纬度
     * @param {number} lon2 - 终点经度
     * @param {number} lat2 - 终点纬度
     * @returns {number} 方位角（度）
     */
    calculateBearing(lon1, lat1, lon2, lat2) {
        const φ1 = lat1 * Math.PI / 180;
        const φ2 = lat2 * Math.PI / 180;
        const Δλ = (lon2 - lon1) * Math.PI / 180;
        
        const y = Math.sin(Δλ) * Math.cos(φ2);
        const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(Δλ);
        
        const θ = Math.atan2(y, x);
        
        return (θ * 180 / Math.PI + 360) % 360;
    }
    
    /**
     * 计算方差
     * @param {Array} values - 数值数组
     * @returns {number} 方差
     */
    calculateVariance(values) {
        if (values.length === 0) return 0;
        
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(value => Math.pow(value - mean, 2));
        
        return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    }
    
    /**
     * 获取更高的风险等级
     * @param {string} current - 当前风险等级
     * @param {string} new_level - 新风险等级
     * @returns {string} 更高的风险等级
     */
    getHigherRiskLevel(current, new_level) {
        const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        return levels[new_level] > levels[current] ? new_level : current;
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

module.exports = LocationVerificationService;