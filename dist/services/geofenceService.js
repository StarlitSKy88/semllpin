"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GeofenceService = void 0;
const database_1 = require("../config/database");
class GeofenceService {
    constructor() {
    }
    async checkGeofenceTriggers(latitude, longitude, _userId) {
        try {
            const result = await database_1.db.raw(`
        SELECT 
          a.id as annotation_id,
          ST_Distance(
            ST_GeogFromText('POINT(' || ? || ' ' || ? || ')'),
            a.location
          ) as distance
        FROM annotations a
        INNER JOIN geofence_configs gc ON a.id = gc.annotation_id
        WHERE gc.is_active = true
          AND ST_DWithin(
            ST_GeogFromText('POINT(' || ? || ' ' || ? || ')'),
            a.location,
            gc.radius_meters
          )
      `, [longitude, latitude, longitude, latitude]);
            const geofences = Array.isArray(result) ? result : [];
            return geofences.map((row) => ({
                annotationId: row['annotation_id'],
                distance: parseFloat(row['distance']),
                triggered: true,
            }));
        }
        catch (error) {
            console.error('地理围栏检测失败:', error);
            throw new Error('地理围栏检测失败');
        }
    }
    async createGeofenceConfig(config) {
        try {
            const result = await (0, database_1.db)('geofence_configs')
                .insert({
                annotation_id: config.annotationId,
                radius_meters: config.radiusMeters,
                detection_frequency: config.detectionFrequency,
                min_accuracy_meters: config.minAccuracyMeters,
                min_stay_duration: config.minStayDuration,
                max_speed_kmh: config.maxSpeedKmh,
                is_active: config.isActive,
                reward_base_percentage: config.rewardBasePercentage,
                time_decay_enabled: config.timeDecayEnabled,
                first_finder_bonus: config.firstFinderBonus,
                combo_bonus_enabled: config.comboBonusEnabled,
            })
                .returning('*');
            const resultArray = result;
            return this.mapGeofenceConfig(resultArray[0] || {});
        }
        catch (error) {
            console.error('创建地理围栏配置失败:', error);
            throw new Error('创建地理围栏配置失败');
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
            return configs.length > 0 ? this.mapGeofenceConfig(configs[0]) : null;
        }
        catch (error) {
            console.error('获取地理围栏配置失败:', error);
            throw new Error('获取地理围栏配置失败');
        }
    }
    async updateGeofenceConfig(id, updates) {
        try {
            const result = await (0, database_1.db)('geofence_configs')
                .where('id', id)
                .update({
                ...updates,
                updated_at: database_1.db.fn.now(),
            })
                .returning('*');
            const configs = Array.isArray(result) ? result : [];
            if (configs.length === 0) {
                throw new Error('地理围栏配置不存在');
            }
            return this.mapGeofenceConfig(configs[0]);
        }
        catch (error) {
            console.error('更新地理围栏配置失败:', error);
            throw new Error('更新地理围栏配置失败');
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
    validateGPSAccuracy(accuracy, requiredAccuracy = 20) {
        return accuracy <= requiredAccuracy;
    }
    validateMovementSpeed(previousLocation, currentLocation, maxSpeedKmh = 50) {
        const distance = this.calculateDistance(previousLocation.latitude, previousLocation.longitude, currentLocation.latitude, currentLocation.longitude);
        const timeDiff = (currentLocation.timestamp.getTime() - previousLocation.timestamp.getTime()) / 1000;
        const speedKmh = (distance / 1000) / (timeDiff / 3600);
        return speedKmh <= maxSpeedKmh;
    }
    toRadians(degrees) {
        return degrees * (Math.PI / 180);
    }
    mapGeofenceConfig(row) {
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
}
exports.GeofenceService = GeofenceService;
//# sourceMappingURL=geofenceService.js.map