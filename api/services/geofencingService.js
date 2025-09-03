/**
 * 地理围栏检测服务
 * 使用简单的距离计算替代PostGIS
 */

class GeofencingService {
  constructor(db) {
    this.db = db;
  }

  /**
   * 计算两点之间的距离（米）
   * 使用Haversine公式
   */
  calculateDistance(lat1, lon1, lat2, lon2) {
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
   */
  toRadians(degrees) {
    return degrees * (Math.PI / 180);
  }

  /**
   * 检测用户位置是否在地理围栏内
   * @param {number} userLat - 用户纬度
   * @param {number} userLon - 用户经度
   * @param {number} geofenceLat - 地理围栏中心纬度
   * @param {number} geofenceLon - 地理围栏中心经度
   * @param {number} radius - 地理围栏半径（米）
   * @returns {boolean} 是否在围栏内
   */
  isInsideGeofence(userLat, userLon, geofenceLat, geofenceLon, radius) {
    const distance = this.calculateDistance(userLat, userLon, geofenceLat, geofenceLon);
    return distance <= radius;
  }

  /**
   * 获取用户当前位置附近的活跃地理围栏
   * @param {number} latitude - 用户纬度
   * @param {number} longitude - 用户经度
   * @param {number} searchRadius - 搜索半径（米），默认1000米
   * @returns {Array} 附近的地理围栏列表
   */
  async getNearbyGeofences(latitude, longitude, searchRadius = 1000) {
    try {
      // 获取所有活跃的地理围栏
      const geofences = await this.db('geofence_configs')
        .where('is_active', true)
        .select('*');

      // 过滤出在搜索范围内的地理围栏
      const nearbyGeofences = geofences.filter(geofence => {
        const distance = this.calculateDistance(
          latitude, longitude,
          parseFloat(geofence.center_latitude),
          parseFloat(geofence.center_longitude)
        );
        return distance <= (searchRadius + geofence.radius_meters);
      });

      // 添加距离信息并排序
      return nearbyGeofences.map(geofence => {
        const distance = this.calculateDistance(
          latitude, longitude,
          parseFloat(geofence.center_latitude),
          parseFloat(geofence.center_longitude)
        );
        return {
          ...geofence,
          distance_meters: Math.round(distance),
          is_inside: this.isInsideGeofence(
            latitude, longitude,
            parseFloat(geofence.center_latitude),
            parseFloat(geofence.center_longitude),
            geofence.radius_meters
          )
        };
      }).sort((a, b) => a.distance_meters - b.distance_meters);
    } catch (error) {
      console.error('获取附近地理围栏失败:', error);
      throw error;
    }
  }

  /**
   * 检测用户是否进入了任何地理围栏
   * @param {number} latitude - 用户纬度
   * @param {number} longitude - 用户经度
   * @returns {Array} 用户当前所在的地理围栏列表
   */
  async detectGeofenceEntry(latitude, longitude) {
    try {
      const nearbyGeofences = await this.getNearbyGeofences(latitude, longitude);
      return nearbyGeofences.filter(geofence => geofence.is_inside);
    } catch (error) {
      console.error('检测地理围栏进入失败:', error);
      throw error;
    }
  }

  /**
   * 获取地理围栏详情
   * @param {number} geofenceId - 地理围栏ID
   * @returns {Object} 地理围栏详情
   */
  async getGeofenceById(geofenceId) {
    try {
      const geofence = await this.db('geofence_configs')
        .where('id', geofenceId)
        .first();
      
      if (!geofence) {
        throw new Error(`地理围栏 ${geofenceId} 不存在`);
      }
      
      return geofence;
    } catch (error) {
      console.error('获取地理围栏详情失败:', error);
      throw error;
    }
  }

  /**
   * 创建新的地理围栏
   * @param {Object} geofenceData - 地理围栏数据
   * @returns {Object} 创建的地理围栏
   */
  async createGeofence(geofenceData) {
    try {
      const [geofence] = await this.db('geofence_configs')
        .insert({
          name: geofenceData.name,
          center_latitude: geofenceData.center_latitude,
          center_longitude: geofenceData.center_longitude,
          radius_meters: geofenceData.radius_meters || 100,
          reward_type: geofenceData.reward_type,
          base_reward_amount: geofenceData.base_reward_amount || 1.00,
          max_daily_rewards: geofenceData.max_daily_rewards || 10,
          min_stay_duration: geofenceData.min_stay_duration || 300,
          is_active: geofenceData.is_active !== false,
          priority_level: geofenceData.priority_level || 1,
          metadata: geofenceData.metadata || {}
        })
        .returning('*');
      
      return geofence;
    } catch (error) {
      console.error('创建地理围栏失败:', error);
      throw error;
    }
  }

  /**
   * 更新地理围栏
   * @param {number} geofenceId - 地理围栏ID
   * @param {Object} updateData - 更新数据
   * @returns {Object} 更新后的地理围栏
   */
  async updateGeofence(geofenceId, updateData) {
    try {
      const [geofence] = await this.db('geofence_configs')
        .where('id', geofenceId)
        .update({
          ...updateData,
          updated_at: new Date()
        })
        .returning('*');
      
      if (!geofence) {
        throw new Error(`地理围栏 ${geofenceId} 不存在`);
      }
      
      return geofence;
    } catch (error) {
      console.error('更新地理围栏失败:', error);
      throw error;
    }
  }

  /**
   * 删除地理围栏
   * @param {number} geofenceId - 地理围栏ID
   * @returns {boolean} 是否删除成功
   */
  async deleteGeofence(geofenceId) {
    try {
      const deletedCount = await this.db('geofence_configs')
        .where('id', geofenceId)
        .del();
      
      return deletedCount > 0;
    } catch (error) {
      console.error('删除地理围栏失败:', error);
      throw error;
    }
  }

  /**
   * 获取地理围栏统计信息
   * @param {number} geofenceId - 地理围栏ID
   * @param {string} startDate - 开始日期
   * @param {string} endDate - 结束日期
   * @returns {Object} 统计信息
   */
  async getGeofenceStats(geofenceId, startDate, endDate) {
    try {
      const stats = await this.db('lbs_rewards')
        .where('geofence_id', geofenceId)
        .whereBetween('created_at', [startDate, endDate])
        .select(
          this.db.raw('COUNT(*) as total_rewards'),
          this.db.raw('SUM(reward_amount) as total_amount'),
          this.db.raw('COUNT(DISTINCT user_id) as unique_users'),
          this.db.raw('AVG(reward_amount) as avg_reward')
        )
        .first();
      
      return {
        total_rewards: parseInt(stats.total_rewards) || 0,
        total_amount: parseFloat(stats.total_amount) || 0,
        unique_users: parseInt(stats.unique_users) || 0,
        avg_reward: parseFloat(stats.avg_reward) || 0
      };
    } catch (error) {
      console.error('获取地理围栏统计失败:', error);
      throw error;
    }
  }
}

module.exports = GeofencingService;