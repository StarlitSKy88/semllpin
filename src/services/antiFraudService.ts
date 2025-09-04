import { db } from '../config/database';
import {
  LocationReport,
  AntiFraudResult,
  AntiFraudLog,
} from '../types/lbs';

// 防作弊检测服务
export class AntiFraudService {
  public db?: { query: (sql: string, params?: any[]) => Promise<{ rows: any[] }> };
  constructor() {
    // 使用全局数据库连接
  }

  /**
   * 综合防作弊检测
   * @param userId 用户ID
   * @param locationData 位置数据
   * @param annotationId 标注ID
   */
  async detectFraud(
    userId: string,
    locationData: LocationReport,
    annotationId: string,
  ): Promise<AntiFraudResult> {
    try {
      const checks = await Promise.all([
        this.validateGPSAccuracyInternal(locationData),
        this.detectAbnormalMovement(userId, locationData),
        this.checkLocationHistory(userId, locationData),
        this.detectSuspiciousPatterns(userId),
        this.validateDeviceConsistency(userId, locationData.deviceInfo),
      ]);

      const fraudScore = this.calculateFraudScore(checks);
      const isFraudulent = fraudScore > 0.7; // 阈值70%

      // 记录检测结果
      await this.logAntiFraudResult({
        userId,
        annotationId,
        locationData,
        fraudScore,
        isFraudulent,
        checkResults: checks,
      });

      return {
        isFraudulent,
        fraudScore,
        reasons: checks.filter(check => !check.passed).map(check => check.reason),
        checkResults: checks,
      };
    } catch (error) {
      console.error('防作弊检测失败:', error);
      return {
        isFraudulent: true,
        fraudScore: 1.0,
        reasons: ['防作弊检测系统错误'],
        checkResults: [],
      };
    }
  }

  /**
   * GPS精度验证（供 detectFraud 内部使用）
   * @param locationData 位置数据
   */
  private async validateGPSAccuracyInternal(locationData: LocationReport): Promise<{
    passed: boolean;
    reason: string;
    score: number;
  }> {
    const maxAccuracy = 50; // 最大允许精度50米
    const accuracy = locationData.accuracy;

    if (accuracy > maxAccuracy) {
      return {
        passed: false,
        reason: `GPS精度不足: ${accuracy}米 > ${maxAccuracy}米`,
        score: 0.8,
      };
    }

    // 精度越好，可疑度越低
    const score = Math.min(accuracy / maxAccuracy * 0.3, 0.3);

    return {
      passed: true,
      reason: `GPS精度正常: ${accuracy}米`,
      score,
    };
  }

  /**
   * 检测异常移动模式
   * @param userId 用户ID
   * @param currentLocation 当前位置
   */
  private async detectAbnormalMovement(
    userId: string,
    currentLocation: LocationReport,
  ): Promise<{
    passed: boolean;
    reason: string;
    score: number;
  }> {
    try {
      // 获取用户最近的位置记录
      const recentLocations = await db('location_reports')
        .where('user_id', userId)
        .where('timestamp', '>', db.raw('NOW() - INTERVAL \'1 hour\''))
        .orderBy('timestamp', 'desc')
        .limit(10)
        .select('latitude', 'longitude', 'timestamp', 'accuracy');

      const locations = Array.isArray(recentLocations) ? recentLocations : [];
      if (locations.length < 2) {
        return {
          passed: true,
          reason: '位置记录不足，无法检测移动模式',
          score: 0.1,
        };
      }

      const lastLocation = locations[0] as Record<string, any>;
      const timeDiff = (new Date(currentLocation.timestamp).getTime() -
                       new Date(lastLocation['timestamp']).getTime()) / 1000; // 秒

      if (timeDiff < 10) {
        return {
          passed: false,
          reason: '位置上报频率过高',
          score: 0.9,
        };
      }

      // 计算移动距离和速度
      const distance = this.calculateDistance(
        lastLocation['latitude'],
        lastLocation['longitude'],
        currentLocation.latitude,
        currentLocation.longitude,
      );

      const speedKmh = (distance / 1000) / (timeDiff / 3600);
      const maxReasonableSpeed = 120; // 最大合理速度120km/h

      if (speedKmh > maxReasonableSpeed) {
        return {
          passed: false,
          reason: `移动速度异常: ${speedKmh.toFixed(1)}km/h > ${maxReasonableSpeed}km/h`,
          score: 0.95,
        };
      }

      // 检测瞬移模式（短时间内大距离移动）
      if (timeDiff < 60 && distance > 1000) {
        return {
          passed: false,
          reason: `疑似瞬移: ${timeDiff}秒内移动${distance.toFixed(0)}米`,
          score: 0.9,
        };
      }

      // 速度越高，可疑度越高
      const speedScore = Math.min(speedKmh / maxReasonableSpeed * 0.4, 0.4);

      return {
        passed: true,
        reason: `移动模式正常: 速度${speedKmh.toFixed(1)}km/h`,
        score: speedScore,
      };
    } catch (error) {
      console.error('移动模式检测失败:', error);
      return {
        passed: false,
        reason: '移动模式检测失败',
        score: 0.5,
      };
    }
  }

  /**
   * 检查位置历史记录
   * @param userId 用户ID
   * @param currentLocation 当前位置
   */
  private async checkLocationHistory(
    userId: string,
    currentLocation: LocationReport,
  ): Promise<{
    passed: boolean;
    reason: string;
    score: number;
  }> {
    try {
      // 检查是否在同一位置重复上报
      const duplicateCount = await db('location_reports')
        .where('user_id', userId)
        .whereRaw(
          'ST_DWithin(location_point, ST_GeomFromText(?, 4326), 10)',
          [`POINT(${currentLocation.longitude} ${currentLocation.latitude})`],
        )
        .where('timestamp', '>', db.raw('NOW() - INTERVAL \'1 hour\''))
        .count('* as count')
        .first();

      const duplicates = parseInt(String(duplicateCount?.['count'] || '0'));
      if (duplicates > 5) {
        return {
          passed: false,
          reason: `同一位置重复上报${duplicates}次`,
          score: 0.8,
        };
      }

      // 检查24小时内的位置分布
      const locationSpread = await db('location_reports')
        .where('user_id', userId)
        .where('timestamp', '>', db.raw('NOW() - INTERVAL \'24 hours\''))
        .select(
          db.raw('COUNT(*) as total_reports'),
          db.raw('COUNT(DISTINCT ST_SnapToGrid(ST_Point(longitude, latitude), 0.001)) as unique_locations'),
        )
        .first();

      const totalReports = parseInt((locationSpread as any)?.total_reports || '0');
      const uniqueLocations = parseInt((locationSpread as any)?.unique_locations || '0');

      if (totalReports > 10 && uniqueLocations < 3) {
        return {
          passed: false,
          reason: `位置分布异常: ${totalReports}次上报仅${uniqueLocations}个不同位置`,
          score: 0.7,
        };
      }

      return {
        passed: true,
        reason: '位置历史记录正常',
        score: Math.min(duplicates * 0.1, 0.3),
      };
    } catch (error) {
      console.error('位置历史检查失败:', error);
      return {
        passed: false,
        reason: '位置历史检查失败',
        score: 0.5,
      };
    }
  }

  /**
   * 检测可疑行为模式
   * @param userId 用户ID
   */
  private async detectSuspiciousPatterns(userId: string): Promise<{
    passed: boolean;
    reason: string;
    score: number;
  }> {
    try {
      // 检查奖励获取频率
      const recentRewards = await db('lbs_rewards')
        .count('* as count')
        .where('user_id', userId)
        .where('created_at', '>', db.raw('NOW() - INTERVAL \'24 hours\''))
        .whereIn('status', ['verified', 'claimed']);

      const rewardCount = parseInt((recentRewards[0] as any)?.count || '0');
      const maxDailyRewards = 20; // 每日最大奖励次数

      if (rewardCount > maxDailyRewards) {
        return {
          passed: false,
          reason: `24小时内获得奖励${rewardCount}次，超过限制${maxDailyRewards}次`,
          score: 0.9,
        };
      }

      // 检查账号创建时间
      const accountAge = await db('users')
        .select(db.raw('EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400 as age_days'))
        .where('id', userId);

      const ageDays = parseFloat((accountAge[0] as any)?.age_days || '0');
      if (ageDays < 1 && rewardCount > 5) {
        return {
          passed: false,
          reason: `新账号异常活跃: 创建${ageDays.toFixed(1)}天，已获得${rewardCount}次奖励`,
          score: 0.8,
        };
      }

      return {
        passed: true,
        reason: '行为模式正常',
        score: Math.min(rewardCount / maxDailyRewards * 0.3, 0.3),
      };
    } catch (error) {
      console.error('可疑模式检测失败:', error);
      return {
        passed: false,
        reason: '可疑模式检测失败',
        score: 0.5,
      };
    }
  }

  /**
   * 验证设备一致性
   * @param userId 用户ID
   * @param deviceInfo 设备信息
   */
  private async validateDeviceConsistency(
    userId: string,
    deviceInfo?: Record<string, any>,
  ): Promise<{
    passed: boolean;
    reason: string;
    score: number;
  }> {
    if (!deviceInfo) {
      return {
        passed: false,
        reason: '缺少设备信息',
        score: 0.6,
      };
    }

    try {
      // 检查设备指纹变化
      const recentDevices = await db('location_reports')
        .distinct('device_info')
        .where('user_id', userId)
        .where('timestamp', '>', db.raw('NOW() - INTERVAL \'7 days\''))
        .whereNotNull('device_info')
        .orderBy('timestamp', 'desc')
        .limit(5);

      const devices = Array.isArray(recentDevices) ? recentDevices : [];
      if (devices.length > 3) {
        return {
          passed: false,
          reason: `7天内使用${devices.length}个不同设备`,
          score: 0.7,
        };
      }

      return {
        passed: true,
        reason: '设备信息一致',
        score: 0.1,
      };
    } catch (error) {
      console.error('设备一致性检查失败:', error);
      return {
        passed: false,
        reason: '设备一致性检查失败',
        score: 0.5,
      };
    }
  }

  /**
   * 计算综合作弊分数
   * @param checks 检查结果数组
   */
  private calculateFraudScore(checks: Array<{ passed: boolean; score: number }>): number {
    if (checks.length === 0) {
      return 0;
    }

    const totalScore = checks.reduce((sum, check) => sum + check.score, 0);
    const maxScore = checks.length;

    return Math.min(totalScore / maxScore, 1.0);
  }

  /**
   * 记录防作弊检测结果
   * @param data 检测数据
   */
  private async logAntiFraudResult(data: {
    userId: string;
    annotationId: string;
    locationData: LocationReport;
    fraudScore: number;
    isFraudulent: boolean;
    checkResults: any[];
  }): Promise<void> {
    try {
      await db('anti_fraud_logs').insert({
        user_id: data.userId,
        annotation_id: data.annotationId,
        location_data: JSON.stringify(data.locationData),
        fraud_score: data.fraudScore,
        is_fraudulent: data.isFraudulent,
        check_results: JSON.stringify(data.checkResults),
        detection_timestamp: db.fn.now(),
      });
    } catch (error) {
      console.error('记录防作弊日志失败:', error);
    }
  }

  /**
   * 计算两点间距离（米）
   * @param lat1 纬度1
   * @param lon1 经度1
   * @param lat2 纬度2
   * @param lon2 经度2
   */
  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371000; // 地球半径（米）
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  /**
   * 角度转弧度
   * @param degrees 角度
   */
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }

  // ====== Public APIs for unit tests ======

  // 同步 GPS 校验，用于单元测试期望的 API 形态
  public validateGPSAccuracy(gps: { latitude: number; longitude: number; accuracy: number; timestamp: number | Date }): { isValid: boolean; confidence?: number; reason?: string } {
    const { latitude, longitude, accuracy, timestamp } = gps || ({} as any);
    // 坐标合法性
    if (
      typeof latitude !== 'number' ||
      typeof longitude !== 'number' ||
      latitude < -90 || latitude > 90 ||
      longitude < -180 || longitude > 180
    ) {
      return { isValid: false, reason: 'Invalid coordinates' };
    }
    // 精度阈值（米）
    if (typeof accuracy !== 'number' || accuracy > 100) {
      return { isValid: false, reason: 'GPS accuracy too low' };
    }
    // 采样时间新鲜度（5分钟内）
    const ts = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp);
    if (!ts || Date.now() - ts > 5 * 60 * 1000) {
      return { isValid: false, reason: 'GPS reading too old' };
    }
    // 置信度（精度越高置信度越高）
    const confidence = Math.max(0, Math.min(1, 1 - accuracy / 50));
    return { isValid: true, confidence };
  }

  // 分析移动模式
  public async analyzeMovementPattern(
    userId: string,
    currentLocation: { latitude: number; longitude: number }
  ): Promise<{ isNormal: boolean; suspiciousActivity: boolean; reason?: string }> {
    try {
      if (!this.db?.query) {
        return { isNormal: true, suspiciousActivity: false };
      }
      const res = await this.db.query(
        'SELECT latitude, longitude, timestamp FROM location_reports WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 10',
        [userId]
      );
      const rows = (res?.rows || []) as Array<{ latitude: number; longitude: number; timestamp: string | Date }>;

      // 检测长期静止（坐标重复）
      const allSame = rows.length >= 5 && rows.every(r =>
        Math.abs(r.latitude - rows[0].latitude) < 1e-6 &&
        Math.abs(r.longitude - rows[0].longitude) < 1e-6
      );
      if (allSame) {
        return { isNormal: false, suspiciousActivity: true, reason: 'Stationary for extended period' };
      }

      if (rows.length > 0) {
        const last = rows[0];
        const lastTs = new Date(last.timestamp).getTime();
        const nowTs = Date.now();
        const dtSec = Math.max(1, (nowTs - lastTs) / 1000);
        const distM = this.calculateDistance(last.latitude, last.longitude, currentLocation.latitude, currentLocation.longitude);
        const speedKmh = (distM / 1000) / (dtSec / 3600);
        if (speedKmh > 1000) {
          return { isNormal: false, suspiciousActivity: true, reason: 'Impossible movement speed detected' };
        }
      }
      return { isNormal: true, suspiciousActivity: false };
    } catch {
      return { isNormal: true, suspiciousActivity: false };
    }
  }

  // 设备指纹
  public detectDeviceFingerprinting(deviceInfo: Record<string, any>): string {
    const ua = String(deviceInfo?.['userAgent'] || '');
    const sr = String(deviceInfo?.['screenResolution'] || '');
    const tz = String(deviceInfo?.['timezone'] || '');
    const lang = String(deviceInfo?.['language'] || '');
    const pf = String(deviceInfo?.['platform'] || '');
    const raw = `${ua}|${sr}|${tz}|${lang}|${pf}`;
    // 简单 hash
    let h1 = 2166136261;
    for (let i = 0; i < raw.length; i++) {
      h1 ^= raw.charCodeAt(i);
      h1 += (h1 << 1) + (h1 << 4) + (h1 << 7) + (h1 << 8) + (h1 << 24);
    }
    return Math.abs(h1 >>> 0).toString(16) + Math.abs(h1).toString(36);
  }

  // 检查同一设备多个账号
  public async checkDeviceMultipleAccounts(deviceFingerprint: string): Promise<{ multipleAccounts: boolean; accountCount: number }> {
    if (!this.db?.query) return { multipleAccounts: false, accountCount: 0 };
    const res = await this.db.query('SELECT user_id FROM users WHERE device_fingerprint = $1', [deviceFingerprint]);
    const count = (res?.rows || []).length;
    return { multipleAccounts: count > 1, accountCount: count };
  }

  // 分析奖励领取模式
  public async analyzeRewardClaimingPattern(userId: string): Promise<{ isNormal: boolean; riskScore: number; suspiciousPatterns: string[] }> {
    if (!this.db?.query) return { isNormal: true, riskScore: 0.2, suspiciousPatterns: [] };
    const res = await this.db.query(
      'SELECT annotation_id, claimed_at, reward_amount FROM lbs_rewards WHERE user_id = $1 ORDER BY claimed_at DESC LIMIT 100',
      [userId]
    );
    const rows = (res?.rows || []) as Array<{ annotation_id: string; claimed_at: Date | string; reward_amount: number }>;

    let risk = 0.2;
    const patterns: string[] = [];

    // 快速连续领取
    let rapid = false;
    for (let i = 0; i < rows.length - 1; i++) {
      const t1 = new Date(rows[i].claimed_at).getTime();
      const t2 = new Date(rows[i + 1].claimed_at).getTime();
      if (Math.abs(t1 - t2) < 60 * 1000) { // 少于60秒
        rapid = true; break;
      }
    }
    if (rapid) { risk += 0.7; patterns.push('Rapid successive claims'); }

    // 异常金额
    const unusual = rows.some(r => Number(r.reward_amount) > 500);
    if (unusual) { risk += 0.3; patterns.push('Unusual reward amounts'); }

    risk = Math.max(0, Math.min(1, risk));
    return { isNormal: patterns.length === 0, riskScore: risk, suspiciousPatterns: patterns };
  }

  // 地理围栏篡改检查
  public async checkGeofenceManipulation(
    userId: string,
    geofenceId: string,
    userLocation: { latitude: number; longitude: number }
  ): Promise<{ isValid: boolean; manipulationDetected: boolean; reason?: string }> {
    if (!this.db?.query) return { isValid: true, manipulationDetected: false };
    const res = await this.db.query(
      'SELECT center_lat, center_lng, radius FROM geofences WHERE id = $1',
      [geofenceId]
    );
    const geo = (res?.rows || [])[0] as { center_lat: number; center_lng: number; radius: number } | undefined;
    if (!geo) return { isValid: false, manipulationDetected: true, reason: 'Geofence not found' };
    const dist = this.calculateDistance(geo.center_lat, geo.center_lng, userLocation.latitude, userLocation.longitude);
    if (dist > Number(geo.radius || 0)) {
      return { isValid: false, manipulationDetected: true, reason: 'User location outside geofence' };
    }
    return { isValid: true, manipulationDetected: false };
  }

  // 计算风险分数
  public async calculateRiskScore(
    userId: string,
    context: { deviceInfo?: Record<string, any>; location?: { latitude: number; longitude: number }; recentActivity?: string }
  ): Promise<number> {
    if (!this.db?.query) return 0.3;

    const violationsRes = await this.db.query(
      'SELECT violation_type FROM anti_fraud_logs WHERE user_id = $1 AND detection_timestamp > NOW() - INTERVAL \'7 days\'',
      [userId]
    );
    const deviceFp = this.detectDeviceFingerprinting(context?.deviceInfo || {});
    const accountsRes = await this.db.query(
      'SELECT user_id FROM users WHERE device_fingerprint = $1',
      [deviceFp]
    );
    const claimsRes = await this.db.query(
      'SELECT claimed_at FROM lbs_rewards WHERE user_id = $1 AND claimed_at > NOW() - INTERVAL \'24 hours\'',
      [userId]
    );

    let score = 0;
    if ((violationsRes?.rows || []).length > 0) score += 0.4;
    if ((accountsRes?.rows || []).length > 1) score += 0.3;
    if ((claimsRes?.rows || []).length > 30) score += 0.4;
    if ((context?.recentActivity || '').toLowerCase().includes('suspicious')) score += 0.2;

    return Math.max(0, Math.min(1, score));
  }

  // 记录可疑行为
  public async recordSuspiciousActivity(activityData: { userId: string; activityType: string; description?: string; riskScore?: number; metadata?: any }): Promise<any> {
    if (!this.db?.query) return { id: 'mock', ...activityData };
    const sql = 'INSERT INTO suspicious_activities (user_id, activity_type, description, risk_score, metadata, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id';
    const params = [
      activityData.userId,
      activityData.activityType,
      activityData.description || null,
      activityData.riskScore ?? null,
      activityData.metadata ? JSON.stringify(activityData.metadata) : null,
    ];
    const res = await this.db.query(sql, params);
    return (res?.rows || [])[0] || { id: undefined };
  }

  /**
   * 获取用户的作弊历史记录
   * @param userId 用户ID
   * @param days 查询天数
   */
  async getUserFraudHistory(userId: string, days: number = 30): Promise<AntiFraudLog[]> {
    try {
      const result = await db('anti_fraud_logs')
        .select('*')
        .where('user_id', userId)
        .where('detection_timestamp', '>', db.raw(`NOW() - INTERVAL '${days} days'`))
        .orderBy('detection_timestamp', 'desc')
        .limit(100);

      const logs = Array.isArray(result) ? result : [];
      return logs.map((row: Record<string, any>) => ({
        id: row['id'],
        userId: row['user_id'],
        detectionType: 'location_fraud',
        riskScore: parseFloat(row['fraud_score'] || '0'),
        details: {
          annotationId: row['annotation_id'],
          locationData: row['location_data'],
          fraudScore: parseFloat(row['fraud_score'] || '0'),
          isFraudulent: row['is_fraudulent'],
          checkResults: row['check_results'],
        },
        locationReportId: row['location_report_id'],
        lbsRewardId: row['lbs_reward_id'],
        createdAt: new Date(row['detection_timestamp'] || row['created_at']),
      }));
    } catch (error) {
      console.error('获取作弊历史失败:', error);
      return [];
    }
  }

  /**
   * 判断是否应该阻止用户
   * @param userId 用户ID
   * @param riskScore 风险分数
   */
  async shouldBlockUser(userId: string, riskScore: number): Promise<{
    shouldBlock: boolean;
    reason?: string;
  }> {
    try {
      // 高风险分数直接阻止
      if (riskScore >= 0.9) {
        return {
          shouldBlock: true,
          reason: 'High risk score detected',
        };
      }

      let violationCount = 0;
      if (this.db?.query) {
        const res = await this.db.query(
          'SELECT violation_type FROM anti_fraud_logs WHERE user_id = $1 AND is_fraudulent = true AND detection_timestamp > NOW() - INTERVAL \'24 hours\'',
          [userId]
        );
        violationCount = (res?.rows || []).length;
      } else {
        // 回退到全局数据库
        const recentViolations = await db('anti_fraud_logs')
          .count('* as violation_count')
          .where('user_id', userId)
          .where('is_fraudulent', true)
          .where('detection_timestamp', '>', db.raw('NOW() - INTERVAL \'24 hours\''))
          .first();
        violationCount = parseInt((recentViolations as any)?.violation_count || '0');
      }

      // 24小时内多次违规
      if (violationCount >= 3) {
        return {
          shouldBlock: true,
          reason: 'Multiple violations detected in 24 hours',
        };
      }

      // 中等风险分数且有违规记录
      if (riskScore >= 0.6 && violationCount >= 1) {
        return {
          shouldBlock: true,
          reason: 'Multiple violations with elevated risk score',
        };
      }

      return {
        shouldBlock: false,
      };
    } catch (error) {
      console.error('用户阻止检查失败:', error);
      // 出错时保守处理，不阻止用户
      return {
        shouldBlock: false,
        reason: 'Error in block check, allowing user',
      };
    }
  }
}
