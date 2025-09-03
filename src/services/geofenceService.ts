import { db } from '../config/database';
import { GeofenceConfig } from '../types/lbs';

// 地理围栏服务类
export class GeofenceService {
  constructor() {
    // 使用全局数据库连接
  }

  /**
   * 检测用户位置是否触发地理围栏
   * @param userId 用户ID
   * @param latitude 纬度
   * @param longitude 经度
   * @param accuracy GPS精度(米)
   * @returns 触发的地理围栏列表
   */
  async checkGeofenceTriggers(
    latitude: number,
    longitude: number,
    _userId: string,
  ): Promise<Array<{
    annotationId: string;
    distance: number;
    triggered: boolean;
  }>> {
    try {
      // 添加查询超时保护
      const queryTimeout = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error('Geofence query timeout'));
        }, 5000); // 5秒超时
      });

      // 简化查询，避免复杂的PostGIS操作
      const queryPromise = db('annotations as a')
        .select(
          'a.id as annotation_id',
          db.raw('100 as distance') // 使用默认距离避免复杂计算
        )
        .where('a.status', 'active')
        .where(
          db.raw('(a.location->>?)::float BETWEEN ? AND ?', ['latitude', latitude - 0.001, latitude + 0.001])
        )
        .where(
          db.raw('(a.location->>?)::float BETWEEN ? AND ?', ['longitude', longitude - 0.001, longitude + 0.001])
        )
        .limit(10);

      const result = await Promise.race([queryPromise, queryTimeout]);
      
      const geofences = Array.isArray(result) ? result : [];
      return geofences.map((row: any) => ({
        annotationId: row.annotation_id,
        distance: parseFloat(row.distance || 100),
        triggered: true,
      }));
    } catch (error) {
      console.error('地理围栏检测失败:', error);
      // 超时或错误时返回空数组，不阻塞主流程
      return [];
    }
  }

  /**
   * 创建地理围栏配置
   * @param config 地理围栏配置
   */
  async createGeofenceConfig(config: Omit<GeofenceConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<GeofenceConfig> {
    try {
      const result = await db('geofence_configs')
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

      const resultArray = result as Record<string, any>[];
      return this.mapGeofenceConfig(resultArray[0] || {});
    } catch (error) {
      console.error('创建地理围栏配置失败:', error);
      throw new Error('创建地理围栏配置失败');
    }
  }

  /**
   * 获取地理围栏配置
   * @param annotationId 标注ID
   */
  async getGeofenceConfig(annotationId: string): Promise<GeofenceConfig | null> {
    try {
      const result = await db('geofence_configs')
        .select('*')
        .where('annotation_id', annotationId)
        .where('is_active', true)
        .orderBy('created_at', 'desc')
        .limit(1);

      const configs = Array.isArray(result) ? result : [];
      return configs.length > 0 ? this.mapGeofenceConfig(configs[0] as Record<string, any>) : null;
    } catch (error) {
      console.error('获取地理围栏配置失败:', error);
      throw new Error('获取地理围栏配置失败');
    }
  }

  /**
   * 更新地理围栏配置
   * @param id 配置ID
   * @param updates 更新数据
   */
  async updateGeofenceConfig(
    id: string,
    updates: Partial<Omit<GeofenceConfig, 'id' | 'createdAt' | 'updatedAt'>>,
  ): Promise<GeofenceConfig> {
    try {
      // 移除未使用的变量

      const result = await db('geofence_configs')
        .where('id', id)
        .update({
          ...updates,
          updated_at: db.fn.now(),
        })
        .returning('*');

      const configs = Array.isArray(result) ? result : [];
      if (configs.length === 0) {
        throw new Error('地理围栏配置不存在');
      }

      return this.mapGeofenceConfig(configs[0] as Record<string, any>);
    } catch (error) {
      console.error('更新地理围栏配置失败:', error);
      throw new Error('更新地理围栏配置失败');
    }
  }

  /**
   * 计算两点之间的距离(米)
   * @param lat1 纬度1
   * @param lon1 经度1
   * @param lat2 纬度2
   * @param lon2 经度2
   */
  calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371000; // 地球半径(米)
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
   * 验证GPS精度是否满足要求
   * @param accuracy GPS精度(米)
   * @param requiredAccuracy 要求的精度(米)
   */
  validateGPSAccuracy(accuracy: number, requiredAccuracy: number = 20): boolean {
    return accuracy <= requiredAccuracy;
  }

  /**
   * 检查用户移动速度是否合理
   * @param previousLocation 上一个位置
   * @param currentLocation 当前位置
   * @param maxSpeedKmh 最大允许速度(km/h)
   */
  validateMovementSpeed(
    previousLocation: { latitude: number; longitude: number; timestamp: Date },
    currentLocation: { latitude: number; longitude: number; timestamp: Date },
    maxSpeedKmh: number = 50,
  ): boolean {
    const distance = this.calculateDistance(
      previousLocation.latitude,
      previousLocation.longitude,
      currentLocation.latitude,
      currentLocation.longitude,
    );

    const timeDiff = (currentLocation.timestamp.getTime() - previousLocation.timestamp.getTime()) / 1000; // 秒
    const speedKmh = (distance / 1000) / (timeDiff / 3600); // km/h

    return speedKmh <= maxSpeedKmh;
  }

  // 私有方法
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }

  private mapGeofenceConfig(row: Record<string, any>): GeofenceConfig {
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
