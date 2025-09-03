const { query } = require('../config/database');

/**
 * 防作弊检测服务
 * 检测异常移动模式、频繁触发、虚拟定位等作弊行为
 */
class AntiFraudService {
  constructor() {
    // 配置参数
    this.config = {
      // 最大移动速度 (km/h) - 超过此速度认为异常
      maxMovementSpeed: 120,
      // 最小停留时间 (秒) - 获得奖励需要停留的最短时间
      minStayDuration: 30,
      // 同一地理围栏24小时内最大触发次数
      maxTriggersPerDay: 3,
      // GPS精度要求 (米) - 精度超过此值不给奖励
      maxGpsAccuracy: 20,
      // 异常移动检测时间窗口 (分钟)
      movementTimeWindow: 10,
      // 风险评分阈值
      riskThresholds: {
        low: 30,
        medium: 60,
        high: 80
      }
    };
  }

  /**
   * 综合防作弊检测
   * @param {Object} params 检测参数
   * @param {string} params.userId 用户ID
   * @param {number} params.latitude 纬度
   * @param {number} params.longitude 经度
   * @param {number} params.accuracy GPS精度
   * @param {string} params.geofenceId 地理围栏ID
   * @param {Object} params.deviceInfo 设备信息
   * @returns {Object} 检测结果
   */
  async detectFraud(params) {
    const {
      userId,
      latitude,
      longitude,
      accuracy,
      geofenceId,
      deviceInfo = {}
    } = params;

    try {
      const detectionResults = {
        isValid: true,
        riskScore: 0,
        riskLevel: 'low',
        violations: [],
        details: {}
      };

      // 1. GPS精度检测
      const accuracyCheck = await this.checkGpsAccuracy(accuracy);
      if (!accuracyCheck.isValid) {
        detectionResults.violations.push('gps_accuracy');
        detectionResults.riskScore += 20;
      }
      detectionResults.details.accuracyCheck = accuracyCheck;

      // 2. 移动速度检测
      const speedCheck = await this.checkMovementSpeed(userId, latitude, longitude);
      if (!speedCheck.isValid) {
        detectionResults.violations.push('abnormal_speed');
        detectionResults.riskScore += 30;
      }
      detectionResults.details.speedCheck = speedCheck;

      // 3. 频繁触发检测
      const frequencyCheck = await this.checkTriggerFrequency(userId, geofenceId);
      if (!frequencyCheck.isValid) {
        detectionResults.violations.push('frequent_triggers');
        detectionResults.riskScore += 25;
      }
      detectionResults.details.frequencyCheck = frequencyCheck;

      // 4. 停留时间检测
      const stayCheck = await this.checkStayDuration(userId, latitude, longitude);
      if (!stayCheck.isValid) {
        detectionResults.violations.push('insufficient_stay');
        detectionResults.riskScore += 15;
      }
      detectionResults.details.stayCheck = stayCheck;

      // 5. 设备指纹检测
      const deviceCheck = await this.checkDeviceFingerprint(userId, deviceInfo);
      if (!deviceCheck.isValid) {
        detectionResults.violations.push('device_anomaly');
        detectionResults.riskScore += 20;
      }
      detectionResults.details.deviceCheck = deviceCheck;

      // 6. 位置模式检测
      const patternCheck = await this.checkLocationPattern(userId, latitude, longitude);
      if (!patternCheck.isValid) {
        detectionResults.violations.push('suspicious_pattern');
        detectionResults.riskScore += 25;
      }
      detectionResults.details.patternCheck = patternCheck;

      // 计算最终风险等级
      detectionResults.riskLevel = this.calculateRiskLevel(detectionResults.riskScore);
      detectionResults.isValid = detectionResults.riskScore < this.config.riskThresholds.high;

      // 记录检测日志
      await this.logDetectionResult(userId, geofenceId, detectionResults);

      return detectionResults;
    } catch (error) {
      console.error('防作弊检测失败:', error);
      // 检测失败时采用保守策略，拒绝奖励
      return {
        isValid: false,
        riskScore: 100,
        riskLevel: 'high',
        violations: ['detection_error'],
        details: { error: error.message }
      };
    }
  }

  /**
   * GPS精度检测
   */
  async checkGpsAccuracy(accuracy) {
    const isValid = accuracy <= this.config.maxGpsAccuracy;
    return {
      isValid,
      accuracy,
      threshold: this.config.maxGpsAccuracy,
      message: isValid ? 'GPS精度正常' : `GPS精度过低: ${accuracy}m > ${this.config.maxGpsAccuracy}m`
    };
  }

  /**
   * 移动速度检测
   */
  async checkMovementSpeed(userId, latitude, longitude) {
    try {
      // 获取用户最近的位置记录
      const recentLocations = await query(`
        SELECT latitude, longitude, created_at
        FROM location_reports
        WHERE user_id = $1
          AND created_at > NOW() - INTERVAL '${this.config.movementTimeWindow} minutes'
        ORDER BY created_at DESC
        LIMIT 5
      `, [userId]);

      if (recentLocations.rows.length < 2) {
        return {
          isValid: true,
          speed: 0,
          message: '位置记录不足，无法计算速度'
        };
      }

      let maxSpeed = 0;
      const locations = recentLocations.rows;

      for (let i = 0; i < locations.length - 1; i++) {
        const loc1 = locations[i];
        const loc2 = locations[i + 1];

        const distance = this.calculateDistance(
          parseFloat(loc1.latitude),
          parseFloat(loc1.longitude),
          parseFloat(loc2.latitude),
          parseFloat(loc2.longitude)
        );

        const timeDiff = (new Date(loc1.created_at) - new Date(loc2.created_at)) / 1000 / 3600; // 小时
        const speed = distance / timeDiff; // km/h

        if (speed > maxSpeed) {
          maxSpeed = speed;
        }
      }

      const isValid = maxSpeed <= this.config.maxMovementSpeed;
      return {
        isValid,
        speed: Math.round(maxSpeed * 100) / 100,
        threshold: this.config.maxMovementSpeed,
        message: isValid ? '移动速度正常' : `移动速度异常: ${Math.round(maxSpeed)}km/h > ${this.config.maxMovementSpeed}km/h`
      };
    } catch (error) {
      console.error('移动速度检测失败:', error);
      return {
        isValid: false,
        speed: 0,
        message: '移动速度检测失败'
      };
    }
  }

  /**
   * 频繁触发检测
   */
  async checkTriggerFrequency(userId, geofenceId) {
    try {
      const result = await query(`
        SELECT COUNT(*) as trigger_count
        FROM lbs_rewards
        WHERE user_id = $1
          AND geofence_id = $2
          AND created_at > NOW() - INTERVAL '24 hours'
      `, [userId, geofenceId]);

      const triggerCount = parseInt(result.rows[0].trigger_count);
      const isValid = triggerCount < this.config.maxTriggersPerDay;

      return {
        isValid,
        triggerCount,
        threshold: this.config.maxTriggersPerDay,
        message: isValid ? '触发频率正常' : `触发过于频繁: ${triggerCount}次 >= ${this.config.maxTriggersPerDay}次/天`
      };
    } catch (error) {
      console.error('频繁触发检测失败:', error);
      return {
        isValid: false,
        triggerCount: 0,
        message: '频繁触发检测失败'
      };
    }
  }

  /**
   * 停留时间检测
   */
  async checkStayDuration(userId, latitude, longitude) {
    try {
      // 检查用户在当前位置附近的停留时间（使用简单距离计算）
      const nearbyLocations = await query(`
        SELECT created_at, latitude, longitude
        FROM location_reports
        WHERE user_id = $1
          AND created_at > NOW() - INTERVAL '1 hour'
        ORDER BY created_at ASC
      `, [userId]);

      // 过滤出50米范围内的位置记录
      const filteredLocations = nearbyLocations.rows.filter(row => {
        const distance = this.calculateDistance(
          parseFloat(row.latitude),
          parseFloat(row.longitude),
          latitude,
          longitude
        ) * 1000; // 转换为米
        return distance <= 50;
      });

      if (filteredLocations.length < 2) {
        return {
          isValid: false,
          stayDuration: 0,
          threshold: this.config.minStayDuration,
          message: '停留时间不足，需要更多位置记录'
        };
      }

      const firstTime = new Date(filteredLocations[0].created_at);
      const lastTime = new Date(filteredLocations[filteredLocations.length - 1].created_at);
      const stayDuration = (lastTime - firstTime) / 1000; // 秒

      const isValid = stayDuration >= this.config.minStayDuration;

      return {
        isValid,
        stayDuration: Math.round(stayDuration),
        threshold: this.config.minStayDuration,
        message: isValid ? '停留时间充足' : `停留时间不足: ${Math.round(stayDuration)}秒 < ${this.config.minStayDuration}秒`
      };
    } catch (error) {
      console.error('停留时间检测失败:', error);
      return {
        isValid: false,
        stayDuration: 0,
        message: '停留时间检测失败'
      };
    }
  }

  /**
   * 设备指纹检测
   */
  async checkDeviceFingerprint(userId, deviceInfo) {
    try {
      const {
        userAgent,
        screenResolution,
        timezone,
        language,
        platform
      } = deviceInfo;

      // 检查设备信息变化频率
      const deviceHistory = await query(`
        SELECT device_info, created_at
        FROM location_reports
        WHERE user_id = $1
          AND device_info IS NOT NULL
          AND created_at > NOW() - INTERVAL '7 days'
        ORDER BY created_at DESC
        LIMIT 10
      `, [userId]);

      if (deviceHistory.rows.length === 0) {
        return {
          isValid: true,
          message: '首次设备记录'
        };
      }

      // 检查设备信息一致性
      let inconsistencyCount = 0;
      const recentDevices = deviceHistory.rows.slice(0, 5);

      for (const record of recentDevices) {
        const historicalDevice = record.device_info;
        if (historicalDevice.userAgent !== userAgent ||
            historicalDevice.platform !== platform) {
          inconsistencyCount++;
        }
      }

      const inconsistencyRate = inconsistencyCount / recentDevices.length;
      const isValid = inconsistencyRate < 0.5; // 50%以下的不一致率认为正常

      return {
        isValid,
        inconsistencyRate: Math.round(inconsistencyRate * 100),
        message: isValid ? '设备指纹正常' : `设备信息变化频繁: ${Math.round(inconsistencyRate * 100)}%不一致率`
      };
    } catch (error) {
      console.error('设备指纹检测失败:', error);
      return {
        isValid: true, // 设备检测失败时不阻止奖励
        message: '设备指纹检测失败'
      };
    }
  }

  /**
   * 位置模式检测
   */
  async checkLocationPattern(userId, latitude, longitude) {
    try {
      // 检查是否存在规律性的位置模式（如网格状移动）
      const recentLocations = await query(`
        SELECT latitude, longitude, created_at
        FROM location_reports
        WHERE user_id = $1
          AND created_at > NOW() - INTERVAL '2 hours'
        ORDER BY created_at DESC
        LIMIT 20
      `, [userId]);

      if (recentLocations.rows.length < 10) {
        return {
          isValid: true,
          message: '位置记录不足，无法分析模式'
        };
      }

      const locations = recentLocations.rows.map(row => ({
        lat: parseFloat(row.latitude),
        lng: parseFloat(row.longitude),
        time: new Date(row.created_at)
      }));

      // 检查是否存在完美的网格模式
      let gridPatternScore = 0;
      const distances = [];

      for (let i = 0; i < locations.length - 1; i++) {
        const distance = this.calculateDistance(
          locations[i].lat,
          locations[i].lng,
          locations[i + 1].lat,
          locations[i + 1].lng
        );
        distances.push(distance);
      }

      // 计算距离的标准差，标准差过小可能表示人工模式
      const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
      const variance = distances.reduce((sum, d) => sum + Math.pow(d - avgDistance, 2), 0) / distances.length;
      const stdDev = Math.sqrt(variance);

      // 如果标准差很小且平均距离很小，可能是虚拟定位
      if (stdDev < 0.01 && avgDistance < 0.1) {
        gridPatternScore += 30;
      }

      // 检查时间间隔的规律性
      const timeIntervals = [];
      for (let i = 0; i < locations.length - 1; i++) {
        const interval = (locations[i].time - locations[i + 1].time) / 1000; // 秒
        timeIntervals.push(interval);
      }

      const avgInterval = timeIntervals.reduce((a, b) => a + b, 0) / timeIntervals.length;
      const intervalVariance = timeIntervals.reduce((sum, t) => sum + Math.pow(t - avgInterval, 2), 0) / timeIntervals.length;
      const intervalStdDev = Math.sqrt(intervalVariance);

      // 时间间隔过于规律也可能是自动化
      if (intervalStdDev < 5 && avgInterval < 60) {
        gridPatternScore += 20;
      }

      const isValid = gridPatternScore < 30;

      return {
        isValid,
        patternScore: gridPatternScore,
        avgDistance: Math.round(avgDistance * 1000) / 1000,
        avgInterval: Math.round(avgInterval),
        message: isValid ? '位置模式正常' : `检测到可疑位置模式，评分: ${gridPatternScore}`
      };
    } catch (error) {
      console.error('位置模式检测失败:', error);
      return {
        isValid: true,
        message: '位置模式检测失败'
      };
    }
  }

  /**
   * 计算风险等级
   */
  calculateRiskLevel(riskScore) {
    if (riskScore < this.config.riskThresholds.low) {
      return 'low';
    } else if (riskScore < this.config.riskThresholds.medium) {
      return 'medium';
    } else if (riskScore < this.config.riskThresholds.high) {
      return 'high';
    } else {
      return 'critical';
    }
  }

  /**
   * 记录检测结果
   */
  async logDetectionResult(userId, geofenceId, detectionResult) {
    try {
      await query(`
        INSERT INTO anti_fraud_logs (
          user_id,
          geofence_id,
          risk_score,
          risk_level,
          violations,
          detection_details,
          is_valid
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        userId,
        geofenceId,
        detectionResult.riskScore,
        detectionResult.riskLevel,
        JSON.stringify(detectionResult.violations),
        JSON.stringify(detectionResult.details),
        detectionResult.isValid
      ]);
    } catch (error) {
      console.error('记录防作弊日志失败:', error);
    }
  }

  /**
   * 计算两点间距离（公里）
   */
  calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // 地球半径（公里）
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  /**
   * 角度转弧度
   */
  toRadians(degrees) {
    return degrees * (Math.PI / 180);
  }

  /**
   * 获取用户风险统计
   */
  async getUserRiskStats(userId, days = 7) {
    try {
      const result = await query(`
        SELECT 
          COUNT(*) as total_detections,
          COUNT(CASE WHEN is_valid = false THEN 1 END) as blocked_attempts,
          AVG(risk_score) as avg_risk_score,
          array_agg(DISTINCT unnest(violations)) as common_violations
        FROM anti_fraud_logs
        WHERE user_id = $1
          AND created_at > NOW() - INTERVAL '${days} days'
      `, [userId]);

      const stats = result.rows[0];
      return {
        totalDetections: parseInt(stats.total_detections) || 0,
        blockedAttempts: parseInt(stats.blocked_attempts) || 0,
        avgRiskScore: parseFloat(stats.avg_risk_score) || 0,
        commonViolations: stats.common_violations || [],
        blockRate: stats.total_detections > 0 ? 
          (stats.blocked_attempts / stats.total_detections * 100).toFixed(2) : 0
      };
    } catch (error) {
      console.error('获取用户风险统计失败:', error);
      return {
        totalDetections: 0,
        blockedAttempts: 0,
        avgRiskScore: 0,
        commonViolations: [],
        blockRate: 0
      };
    }
  }
}

module.exports = AntiFraudService;