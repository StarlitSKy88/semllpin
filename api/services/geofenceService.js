/**
 * 地理围栏检测服务
 * 使用PostGIS进行高效的地理位置计算
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

class GeofenceService {
    constructor(database) {
        this.db = database;
    }

    /**
     * 检测用户位置是否进入任何地理围栏
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} accuracy - GPS精度（米）
     * @returns {Promise<Array>} 匹配的地理围栏列表
     */
    async detectGeofenceEntry(userId, longitude, latitude, accuracy = 10) {
        try {
            // 验证坐标有效性
            if (!this.isValidCoordinate(longitude, latitude)) {
                throw new Error('Invalid coordinates provided');
            }

            // 构建用户位置点
            const userLocation = `POINT(${longitude} ${latitude})`;

            // 查询匹配的地理围栏
            const query = `
                SELECT 
                    gc.id as geofence_id,
                    gc.name as geofence_name,
                    gc.reward_type,
                    gc.base_reward_amount,
                    gc.max_daily_rewards,
                    gc.min_stay_duration,
                    gc.priority_level,
                    gc.metadata,
                    ST_Distance(gc.center_point, ST_GeomFromText($1, 4326)) as distance_meters,
                    gc.radius_meters
                FROM geofence_configs gc
                WHERE gc.is_active = TRUE
                  AND ST_DWithin(
                      gc.center_point, 
                      ST_GeomFromText($1, 4326), 
                      gc.radius_meters + $2
                  )
                ORDER BY 
                    gc.priority_level DESC,
                    ST_Distance(gc.center_point, ST_GeomFromText($1, 4326)) ASC
            `;

            const result = await this.db.query(query, [userLocation, accuracy]);
            
            // 处理检测结果
            const detectedGeofences = result.rows.map(row => ({
                geofenceId: row.geofence_id,
                name: row.geofence_name,
                rewardType: row.reward_type,
                baseRewardAmount: parseFloat(row.base_reward_amount),
                maxDailyRewards: row.max_daily_rewards,
                minStayDuration: row.min_stay_duration,
                priorityLevel: row.priority_level,
                distanceMeters: parseFloat(row.distance_meters),
                radiusMeters: row.radius_meters,
                metadata: row.metadata || {}
            }));

            // 记录检测日志
            await this.logGeofenceDetection(userId, longitude, latitude, detectedGeofences);

            return detectedGeofences;

        } catch (error) {
            console.error('Geofence detection error:', error);
            throw new Error(`Geofence detection failed: ${error.message}`);
        }
    }

    /**
     * 检查用户今日在指定地理围栏的奖励次数
     * @param {number} userId - 用户ID
     * @param {number} geofenceId - 地理围栏ID
     * @returns {Promise<number>} 今日奖励次数
     */
    async getTodayRewardCount(userId, geofenceId) {
        try {
            const query = `
                SELECT COUNT(*) as reward_count
                FROM lbs_rewards
                WHERE user_id = $1
                  AND geofence_id = $2
                  AND DATE(created_at) = CURRENT_DATE
            `;

            const result = await this.db.query(query, [userId, geofenceId]);
            return parseInt(result.rows[0].reward_count) || 0;

        } catch (error) {
            console.error('Error getting today reward count:', error);
            return 0;
        }
    }

    /**
     * 检查用户是否满足最小停留时间要求
     * @param {number} userId - 用户ID
     * @param {number} geofenceId - 地理围栏ID
     * @param {number} minStayDuration - 最小停留时间（秒）
     * @returns {Promise<boolean>} 是否满足停留时间
     */
    async checkMinStayDuration(userId, geofenceId, minStayDuration) {
        try {
            // 获取用户在该地理围栏的最近位置记录
            const query = `
                SELECT 
                    lr.timestamp_server,
                    gc.center_point,
                    gc.radius_meters
                FROM location_reports lr
                CROSS JOIN geofence_configs gc
                WHERE lr.user_id = $1
                  AND gc.id = $2
                  AND lr.timestamp_server >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
                  AND ST_DWithin(gc.center_point, lr.location_point, gc.radius_meters)
                ORDER BY lr.timestamp_server ASC
            `;

            const result = await this.db.query(query, [userId, geofenceId]);
            
            if (result.rows.length === 0) {
                return false;
            }

            // 计算连续停留时间
            const firstEntry = new Date(result.rows[0].timestamp_server);
            const lastEntry = new Date(result.rows[result.rows.length - 1].timestamp_server);
            const stayDuration = (lastEntry - firstEntry) / 1000; // 转换为秒

            return stayDuration >= minStayDuration;

        } catch (error) {
            console.error('Error checking min stay duration:', error);
            return false;
        }
    }

    /**
     * 获取附近的地理围栏（不考虑是否进入）
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {number} searchRadius - 搜索半径（米）
     * @returns {Promise<Array>} 附近的地理围栏列表
     */
    async getNearbyGeofences(longitude, latitude, searchRadius = 1000) {
        try {
            if (!this.isValidCoordinate(longitude, latitude)) {
                throw new Error('Invalid coordinates provided');
            }

            const userLocation = `POINT(${longitude} ${latitude})`;

            const query = `
                SELECT 
                    gc.id,
                    gc.name,
                    gc.reward_type,
                    gc.base_reward_amount,
                    gc.radius_meters,
                    gc.priority_level,
                    ST_Distance(gc.center_point, ST_GeomFromText($1, 4326)) as distance_meters,
                    ST_X(gc.center_point) as longitude,
                    ST_Y(gc.center_point) as latitude
                FROM geofence_configs gc
                WHERE gc.is_active = TRUE
                  AND ST_DWithin(
                      gc.center_point, 
                      ST_GeomFromText($1, 4326), 
                      $2
                  )
                ORDER BY ST_Distance(gc.center_point, ST_GeomFromText($1, 4326)) ASC
                LIMIT 20
            `;

            const result = await this.db.query(query, [userLocation, searchRadius]);
            
            return result.rows.map(row => ({
                id: row.id,
                name: row.name,
                rewardType: row.reward_type,
                baseRewardAmount: parseFloat(row.base_reward_amount),
                radiusMeters: row.radius_meters,
                priorityLevel: row.priority_level,
                distanceMeters: parseFloat(row.distance_meters),
                center: {
                    longitude: parseFloat(row.longitude),
                    latitude: parseFloat(row.latitude)
                }
            }));

        } catch (error) {
            console.error('Error getting nearby geofences:', error);
            throw new Error(`Failed to get nearby geofences: ${error.message}`);
        }
    }

    /**
     * 创建新的地理围栏
     * @param {Object} geofenceData - 地理围栏数据
     * @returns {Promise<Object>} 创建的地理围栏信息
     */
    async createGeofence(geofenceData) {
        try {
            const {
                name,
                longitude,
                latitude,
                radiusMeters,
                rewardType,
                baseRewardAmount,
                maxDailyRewards = 10,
                minStayDuration = 300,
                priorityLevel = 1,
                metadata = {}
            } = geofenceData;

            if (!this.isValidCoordinate(longitude, latitude)) {
                throw new Error('Invalid coordinates provided');
            }

            const centerPoint = `POINT(${longitude} ${latitude})`;

            const query = `
                INSERT INTO geofence_configs (
                    name, center_point, radius_meters, reward_type, 
                    base_reward_amount, max_daily_rewards, min_stay_duration, 
                    priority_level, metadata
                ) VALUES (
                    $1, ST_GeomFromText($2, 4326), $3, $4, $5, $6, $7, $8, $9
                )
                RETURNING id, name, reward_type, base_reward_amount, created_at
            `;

            const result = await this.db.query(query, [
                name, centerPoint, radiusMeters, rewardType,
                baseRewardAmount, maxDailyRewards, minStayDuration,
                priorityLevel, JSON.stringify(metadata)
            ]);

            return result.rows[0];

        } catch (error) {
            console.error('Error creating geofence:', error);
            throw new Error(`Failed to create geofence: ${error.message}`);
        }
    }

    /**
     * 记录地理围栏检测日志
     * @param {number} userId - 用户ID
     * @param {number} longitude - 经度
     * @param {number} latitude - 纬度
     * @param {Array} detectedGeofences - 检测到的地理围栏
     */
    async logGeofenceDetection(userId, longitude, latitude, detectedGeofences) {
        try {
            // 这里可以添加详细的检测日志记录
            // 用于后续分析和调试
            console.log(`Geofence detection for user ${userId}:`, {
                location: { longitude, latitude },
                detectedCount: detectedGeofences.length,
                geofences: detectedGeofences.map(g => g.name)
            });
        } catch (error) {
            console.error('Error logging geofence detection:', error);
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

module.exports = GeofenceService;