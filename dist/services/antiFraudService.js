"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AntiFraudService = void 0;
const database_1 = require("../config/database");
class AntiFraudService {
    constructor() {
    }
    async detectFraud(userId, locationData, annotationId) {
        try {
            const checks = await Promise.all([
                this.validateGPSAccuracyInternal(locationData),
                this.detectAbnormalMovement(userId, locationData),
                this.checkLocationHistory(userId, locationData),
                this.detectSuspiciousPatterns(userId),
                this.validateDeviceConsistency(userId, locationData.deviceInfo),
            ]);
            const fraudScore = this.calculateFraudScore(checks);
            const isFraudulent = fraudScore > 0.7;
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
        }
        catch (error) {
            console.error('防作弊检测失败:', error);
            return {
                isFraudulent: true,
                fraudScore: 1.0,
                reasons: ['防作弊检测系统错误'],
                checkResults: [],
            };
        }
    }
    async validateGPSAccuracyInternal(locationData) {
        const maxAccuracy = 50;
        const accuracy = locationData.accuracy;
        if (accuracy > maxAccuracy) {
            return {
                passed: false,
                reason: `GPS精度不足: ${accuracy}米 > ${maxAccuracy}米`,
                score: 0.8,
            };
        }
        const score = Math.min(accuracy / maxAccuracy * 0.3, 0.3);
        return {
            passed: true,
            reason: `GPS精度正常: ${accuracy}米`,
            score,
        };
    }
    async detectAbnormalMovement(userId, currentLocation) {
        try {
            const recentLocations = await (0, database_1.db)('location_reports')
                .where('user_id', userId)
                .where('timestamp', '>', database_1.db.raw('NOW() - INTERVAL \'1 hour\''))
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
            const lastLocation = locations[0];
            const timeDiff = (new Date(currentLocation.timestamp).getTime() -
                new Date(lastLocation['timestamp']).getTime()) / 1000;
            if (timeDiff < 10) {
                return {
                    passed: false,
                    reason: '位置上报频率过高',
                    score: 0.9,
                };
            }
            const distance = this.calculateDistance(lastLocation['latitude'], lastLocation['longitude'], currentLocation.latitude, currentLocation.longitude);
            const speedKmh = (distance / 1000) / (timeDiff / 3600);
            const maxReasonableSpeed = 120;
            if (speedKmh > maxReasonableSpeed) {
                return {
                    passed: false,
                    reason: `移动速度异常: ${speedKmh.toFixed(1)}km/h > ${maxReasonableSpeed}km/h`,
                    score: 0.95,
                };
            }
            if (timeDiff < 60 && distance > 1000) {
                return {
                    passed: false,
                    reason: `疑似瞬移: ${timeDiff}秒内移动${distance.toFixed(0)}米`,
                    score: 0.9,
                };
            }
            const speedScore = Math.min(speedKmh / maxReasonableSpeed * 0.4, 0.4);
            return {
                passed: true,
                reason: `移动模式正常: 速度${speedKmh.toFixed(1)}km/h`,
                score: speedScore,
            };
        }
        catch (error) {
            console.error('移动模式检测失败:', error);
            return {
                passed: false,
                reason: '移动模式检测失败',
                score: 0.5,
            };
        }
    }
    async checkLocationHistory(userId, currentLocation) {
        try {
            const duplicateCount = await (0, database_1.db)('location_reports')
                .where('user_id', userId)
                .whereRaw('ST_DWithin(location_point, ST_GeomFromText(?, 4326), 10)', [`POINT(${currentLocation.longitude} ${currentLocation.latitude})`])
                .where('timestamp', '>', database_1.db.raw('NOW() - INTERVAL \'1 hour\''))
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
            const locationSpread = await (0, database_1.db)('location_reports')
                .where('user_id', userId)
                .where('timestamp', '>', database_1.db.raw('NOW() - INTERVAL \'24 hours\''))
                .select(database_1.db.raw('COUNT(*) as total_reports'), database_1.db.raw('COUNT(DISTINCT ST_SnapToGrid(ST_Point(longitude, latitude), 0.001)) as unique_locations'))
                .first();
            const totalReports = parseInt(locationSpread?.total_reports || '0');
            const uniqueLocations = parseInt(locationSpread?.unique_locations || '0');
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
        }
        catch (error) {
            console.error('位置历史检查失败:', error);
            return {
                passed: false,
                reason: '位置历史检查失败',
                score: 0.5,
            };
        }
    }
    async detectSuspiciousPatterns(userId) {
        try {
            const recentRewards = await (0, database_1.db)('lbs_rewards')
                .count('* as count')
                .where('user_id', userId)
                .where('created_at', '>', database_1.db.raw('NOW() - INTERVAL \'24 hours\''))
                .whereIn('status', ['verified', 'claimed']);
            const rewardCount = parseInt(recentRewards[0]?.count || '0');
            const maxDailyRewards = 20;
            if (rewardCount > maxDailyRewards) {
                return {
                    passed: false,
                    reason: `24小时内获得奖励${rewardCount}次，超过限制${maxDailyRewards}次`,
                    score: 0.9,
                };
            }
            const accountAge = await (0, database_1.db)('users')
                .select(database_1.db.raw('EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400 as age_days'))
                .where('id', userId);
            const ageDays = parseFloat(accountAge[0]?.age_days || '0');
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
        }
        catch (error) {
            console.error('可疑模式检测失败:', error);
            return {
                passed: false,
                reason: '可疑模式检测失败',
                score: 0.5,
            };
        }
    }
    async validateDeviceConsistency(userId, deviceInfo) {
        if (!deviceInfo) {
            return {
                passed: false,
                reason: '缺少设备信息',
                score: 0.6,
            };
        }
        try {
            const recentDevices = await (0, database_1.db)('location_reports')
                .distinct('device_info')
                .where('user_id', userId)
                .where('timestamp', '>', database_1.db.raw('NOW() - INTERVAL \'7 days\''))
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
        }
        catch (error) {
            console.error('设备一致性检查失败:', error);
            return {
                passed: false,
                reason: '设备一致性检查失败',
                score: 0.5,
            };
        }
    }
    calculateFraudScore(checks) {
        if (checks.length === 0) {
            return 0;
        }
        const totalScore = checks.reduce((sum, check) => sum + check.score, 0);
        const maxScore = checks.length;
        return Math.min(totalScore / maxScore, 1.0);
    }
    async logAntiFraudResult(data) {
        try {
            await (0, database_1.db)('anti_fraud_logs').insert({
                user_id: data.userId,
                annotation_id: data.annotationId,
                location_data: JSON.stringify(data.locationData),
                fraud_score: data.fraudScore,
                is_fraudulent: data.isFraudulent,
                check_results: JSON.stringify(data.checkResults),
                detection_timestamp: database_1.db.fn.now(),
            });
        }
        catch (error) {
            console.error('记录防作弊日志失败:', error);
        }
    }
    calculateDistance(lat1, lon1, lat2, lon2) {
        const R = 6371000;
        const dLat = this.toRadians(lat2 - lat1);
        const dLon = this.toRadians(lon2 - lon1);
        const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
                Math.sin(dLon / 2) * Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
    toRadians(degrees) {
        return degrees * (Math.PI / 180);
    }
    validateGPSAccuracy(gps) {
        const { latitude, longitude, accuracy, timestamp } = gps || {};
        if (typeof latitude !== 'number' ||
            typeof longitude !== 'number' ||
            latitude < -90 || latitude > 90 ||
            longitude < -180 || longitude > 180) {
            return { isValid: false, reason: 'Invalid coordinates' };
        }
        if (typeof accuracy !== 'number' || accuracy > 100) {
            return { isValid: false, reason: 'GPS accuracy too low' };
        }
        const ts = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp);
        if (!ts || Date.now() - ts > 5 * 60 * 1000) {
            return { isValid: false, reason: 'GPS reading too old' };
        }
        const confidence = Math.max(0, Math.min(1, 1 - accuracy / 50));
        return { isValid: true, confidence };
    }
    async analyzeMovementPattern(userId, currentLocation) {
        try {
            if (!this.db?.query) {
                return { isNormal: true, suspiciousActivity: false };
            }
            const res = await this.db.query('SELECT latitude, longitude, timestamp FROM location_reports WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 10', [userId]);
            const rows = (res?.rows || []);
            const allSame = rows.length >= 5 && rows.every(r => Math.abs(r.latitude - rows[0].latitude) < 1e-6 &&
                Math.abs(r.longitude - rows[0].longitude) < 1e-6);
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
        }
        catch {
            return { isNormal: true, suspiciousActivity: false };
        }
    }
    detectDeviceFingerprinting(deviceInfo) {
        const ua = String(deviceInfo?.['userAgent'] || '');
        const sr = String(deviceInfo?.['screenResolution'] || '');
        const tz = String(deviceInfo?.['timezone'] || '');
        const lang = String(deviceInfo?.['language'] || '');
        const pf = String(deviceInfo?.['platform'] || '');
        const raw = `${ua}|${sr}|${tz}|${lang}|${pf}`;
        let h1 = 2166136261;
        for (let i = 0; i < raw.length; i++) {
            h1 ^= raw.charCodeAt(i);
            h1 += (h1 << 1) + (h1 << 4) + (h1 << 7) + (h1 << 8) + (h1 << 24);
        }
        return Math.abs(h1 >>> 0).toString(16) + Math.abs(h1).toString(36);
    }
    async checkDeviceMultipleAccounts(deviceFingerprint) {
        if (!this.db?.query)
            return { multipleAccounts: false, accountCount: 0 };
        const res = await this.db.query('SELECT user_id FROM users WHERE device_fingerprint = $1', [deviceFingerprint]);
        const count = (res?.rows || []).length;
        return { multipleAccounts: count > 1, accountCount: count };
    }
    async analyzeRewardClaimingPattern(userId) {
        if (!this.db?.query)
            return { isNormal: true, riskScore: 0.2, suspiciousPatterns: [] };
        const res = await this.db.query('SELECT annotation_id, claimed_at, reward_amount FROM lbs_rewards WHERE user_id = $1 ORDER BY claimed_at DESC LIMIT 100', [userId]);
        const rows = (res?.rows || []);
        let risk = 0.2;
        const patterns = [];
        let rapid = false;
        for (let i = 0; i < rows.length - 1; i++) {
            const t1 = new Date(rows[i].claimed_at).getTime();
            const t2 = new Date(rows[i + 1].claimed_at).getTime();
            if (Math.abs(t1 - t2) < 60 * 1000) {
                rapid = true;
                break;
            }
        }
        if (rapid) {
            risk += 0.7;
            patterns.push('Rapid successive claims');
        }
        const unusual = rows.some(r => Number(r.reward_amount) > 500);
        if (unusual) {
            risk += 0.3;
            patterns.push('Unusual reward amounts');
        }
        risk = Math.max(0, Math.min(1, risk));
        return { isNormal: patterns.length === 0, riskScore: risk, suspiciousPatterns: patterns };
    }
    async checkGeofenceManipulation(userId, geofenceId, userLocation) {
        if (!this.db?.query)
            return { isValid: true, manipulationDetected: false };
        const res = await this.db.query('SELECT center_lat, center_lng, radius FROM geofences WHERE id = $1', [geofenceId]);
        const geo = (res?.rows || [])[0];
        if (!geo)
            return { isValid: false, manipulationDetected: true, reason: 'Geofence not found' };
        const dist = this.calculateDistance(geo.center_lat, geo.center_lng, userLocation.latitude, userLocation.longitude);
        if (dist > Number(geo.radius || 0)) {
            return { isValid: false, manipulationDetected: true, reason: 'User location outside geofence' };
        }
        return { isValid: true, manipulationDetected: false };
    }
    async calculateRiskScore(userId, context) {
        if (!this.db?.query)
            return 0.3;
        const violationsRes = await this.db.query('SELECT violation_type FROM anti_fraud_logs WHERE user_id = $1 AND detection_timestamp > NOW() - INTERVAL \'7 days\'', [userId]);
        const deviceFp = this.detectDeviceFingerprinting(context?.deviceInfo || {});
        const accountsRes = await this.db.query('SELECT user_id FROM users WHERE device_fingerprint = $1', [deviceFp]);
        const claimsRes = await this.db.query('SELECT claimed_at FROM lbs_rewards WHERE user_id = $1 AND claimed_at > NOW() - INTERVAL \'24 hours\'', [userId]);
        let score = 0;
        if ((violationsRes?.rows || []).length > 0)
            score += 0.4;
        if ((accountsRes?.rows || []).length > 1)
            score += 0.3;
        if ((claimsRes?.rows || []).length > 30)
            score += 0.4;
        if ((context?.recentActivity || '').toLowerCase().includes('suspicious'))
            score += 0.2;
        return Math.max(0, Math.min(1, score));
    }
    async recordSuspiciousActivity(activityData) {
        if (!this.db?.query)
            return { id: 'mock', ...activityData };
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
    async getUserFraudHistory(userId, days = 30) {
        try {
            const result = await (0, database_1.db)('anti_fraud_logs')
                .select('*')
                .where('user_id', userId)
                .where('detection_timestamp', '>', database_1.db.raw(`NOW() - INTERVAL '${days} days'`))
                .orderBy('detection_timestamp', 'desc')
                .limit(100);
            const logs = Array.isArray(result) ? result : [];
            return logs.map((row) => ({
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
        }
        catch (error) {
            console.error('获取作弊历史失败:', error);
            return [];
        }
    }
    async shouldBlockUser(userId, riskScore) {
        try {
            if (riskScore >= 0.9) {
                return {
                    shouldBlock: true,
                    reason: 'High risk score detected',
                };
            }
            let violationCount = 0;
            if (this.db?.query) {
                const res = await this.db.query('SELECT violation_type FROM anti_fraud_logs WHERE user_id = $1 AND is_fraudulent = true AND detection_timestamp > NOW() - INTERVAL \'24 hours\'', [userId]);
                violationCount = (res?.rows || []).length;
            }
            else {
                const recentViolations = await (0, database_1.db)('anti_fraud_logs')
                    .count('* as violation_count')
                    .where('user_id', userId)
                    .where('is_fraudulent', true)
                    .where('detection_timestamp', '>', database_1.db.raw('NOW() - INTERVAL \'24 hours\''))
                    .first();
                violationCount = parseInt(recentViolations?.violation_count || '0');
            }
            if (violationCount >= 3) {
                return {
                    shouldBlock: true,
                    reason: 'Multiple violations detected in 24 hours',
                };
            }
            if (riskScore >= 0.6 && violationCount >= 1) {
                return {
                    shouldBlock: true,
                    reason: 'Multiple violations with elevated risk score',
                };
            }
            return {
                shouldBlock: false,
            };
        }
        catch (error) {
            console.error('用户阻止检查失败:', error);
            return {
                shouldBlock: false,
                reason: 'Error in block check, allowing user',
            };
        }
    }
}
exports.AntiFraudService = AntiFraudService;
//# sourceMappingURL=antiFraudService.js.map