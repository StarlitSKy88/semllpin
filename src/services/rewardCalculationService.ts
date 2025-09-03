import { db } from '../config/database';
import {
  RewardCalculationParams,
  RewardCalculationResult,
  LBSReward,
  GeofenceConfig,
} from '../types/lbs';

// 奖励计算引擎服务
export class RewardCalculationService {
  constructor() {
    // 使用全局数据库连接
  }

  /**
   * 计算LBS奖励金额
   * @param params 奖励计算参数
   * @returns 奖励计算结果
   */
  async calculateReward(params: RewardCalculationParams): Promise<RewardCalculationResult> {
    try {
      // 1. 获取标注信息和地理围栏配置
      const [annotation, geofenceConfig] = await Promise.all([
        this.getAnnotation(params.annotationId),
        this.getGeofenceConfig(params.annotationId),
      ]);

      if (!annotation) {
        return this.createIneligibleResult('标注不存在');
      }

      // 2. 检查用户是否已经获得过该标注的奖励
      const existingReward = await this.checkExistingReward(params.annotationId, params.userId);
      if (existingReward) {
        return this.createIneligibleResult('用户已获得该标注奖励');
      }

      // 3. 验证位置精度
      const minAccuracy = geofenceConfig?.minAccuracyMeters || 20;
      if (params.locationData.accuracy > minAccuracy) {
        return this.createIneligibleResult(`GPS精度不足，要求${minAccuracy}米以内`);
      }

      // 4. 验证停留时间
      const minStayDuration = geofenceConfig?.minStayDuration || 30;
      if (params.locationData.stayDuration < minStayDuration) {
        return this.createIneligibleResult(`停留时间不足，要求${minStayDuration}秒以上`);
      }

      // 5. 计算基础奖励
      const basePercentage = geofenceConfig?.rewardBasePercentage || 50.0;
      const baseAmount = annotation.amount * (basePercentage / 100.0);

      // 6. 计算时间衰减因子
      let timeDecayFactor = 1.0;
      if (geofenceConfig?.timeDecayEnabled !== false) {
        timeDecayFactor = await this.calculateTimeDecayFactor(annotation.createdAt);
      }

      // 7. 检查是否为首次发现者
      let firstFinderBonus = 0;
      if (params.rewardType === 'first_finder') {
        const isFirstFinder = await this.isFirstFinder(params.annotationId, params.userId);
        if (isFirstFinder && geofenceConfig?.firstFinderBonus) {
          firstFinderBonus = geofenceConfig.firstFinderBonus / 100.0;
        }
      }

      // 8. 计算连击奖励
      let comboBonus = 0;
      if (params.rewardType === 'combo' && geofenceConfig?.comboBonusEnabled) {
        const comboStreak = await this.getUserComboStreak(params.userId);
        comboBonus = this.calculateComboBonus(comboStreak);
      }

      // 9. 计算最终金额
      const finalAmount = Math.max(
        baseAmount * timeDecayFactor * (1 + firstFinderBonus + comboBonus),
        0.01, // 最小0.01元
      );

      return {
        finalAmount: Math.round(finalAmount * 100) / 100, // 保留2位小数
        breakdown: {
          baseAmount: Math.round(baseAmount * 100) / 100,
          timeDecayFactor,
          firstFinderBonus: Math.round(firstFinderBonus * 100 * 100) / 100, // 转换为百分比
          comboBonus: Math.round(comboBonus * 100 * 100) / 100, // 转换为百分比
          finalAmount: Math.round(finalAmount * 100) / 100,
        },
        eligibility: {
          eligible: true,
          reasons: ['满足所有奖励条件'],
        },
      };
    } catch (error) {
      console.error('奖励计算失败:', error);
      return this.createIneligibleResult('奖励计算失败');
    }
  }

  /**
   * 使用数据库函数计算奖励金额
   * @param annotationId 标注ID
   * @param userId 用户ID
   * @param rewardType 奖励类型
   */
  async calculateRewardWithDB(
    annotationId: string,
    userId: string,
    rewardType: LBSReward['rewardType'],
  ): Promise<number> {
    try {
      const result = await db.raw(`
        SELECT calculate_lbs_reward_amount(
          ?::uuid,
          ?::uuid,
          ?
        ) as reward_amount
      `, [annotationId, userId, rewardType]);

      const resultArray = result as Record<string, any>[];
      return parseFloat(resultArray[0]?.['reward_amount'] || '0');
    } catch (error) {
      console.error('数据库奖励计算失败:', error);
      throw new Error('数据库奖励计算失败');
    }
  }

  /**
   * 计算时间衰减因子
   * @param createdAt 标注创建时间
   */
  private async calculateTimeDecayFactor(createdAt: Date): Promise<number> {
    try {
      const result = await db.raw(`
        SELECT calculate_time_decay_factor(?::timestamp with time zone) as decay_factor
      `, [createdAt.toISOString()]);

      const resultArray = result as Record<string, any>[];
      return parseFloat(resultArray[0]?.['decay_factor'] || '1');
    } catch (error) {
      console.error('时间衰减计算失败:', error);
      // 使用本地计算作为备选
      return this.calculateTimeDecayFactorLocal(createdAt);
    }
  }

  /**
   * 本地计算时间衰减因子
   * @param createdAt 标注创建时间
   */
  private calculateTimeDecayFactorLocal(createdAt: Date): number {
    const now = new Date();
    const hoursDiff = (now.getTime() - createdAt.getTime()) / (1000 * 60 * 60);

    if (hoursDiff <= 24) {
      return 0.70;
    } // 24小时内：70%
    if (hoursDiff <= 168) {
      return 0.50;
    } // 1-7天：50%
    if (hoursDiff <= 720) {
      return 0.30;
    } // 7-30天：30%
    return 0.10; // 30天后：10%
  }

  /**
   * 检查是否为首次发现者
   * @param annotationId 标注ID
   * @param userId 用户ID
   */
  private async isFirstFinder(annotationId: string, userId: string): Promise<boolean> {
    try {
      const result = await db.raw(`
        SELECT is_first_finder(
          ?::uuid,
          ?::uuid
        ) as is_first
      `, [annotationId, userId]);

      const rows = Array.isArray(result) ? result : [];
      return rows.length > 0 ? (rows[0] as Record<string, any>)['is_first'] : false;
    } catch (error) {
      console.error('首次发现者检查失败:', error);
      return false;
    }
  }

  /**
   * 获取用户当前连击数
   * @param userId 用户ID
   */
  private async getUserComboStreak(userId: string): Promise<number> {
    try {
      const result = await db('lbs_reward_stats')
        .select('current_combo_streak')
        .where('user_id', userId);

      const stats = Array.isArray(result) ? result : [];
      return stats.length > 0 ? (stats[0] as Record<string, any>)['current_combo_streak'] : 0;
    } catch (error) {
      console.error('获取连击数失败:', error);
      return 0;
    }
  }

  /**
   * 计算连击奖励倍数
   * @param comboStreak 连击数
   */
  private calculateComboBonus(comboStreak: number): number {
    if (comboStreak < 2) {
      return 0;
    }
    if (comboStreak < 5) {
      return 0.05;
    } // 5%
    if (comboStreak < 10) {
      return 0.10;
    } // 10%
    if (comboStreak < 20) {
      return 0.15;
    } // 15%
    return 0.20; // 20% (最大)
  }

  /**
   * 获取标注信息
   * @param annotationId 标注ID
   */
  private async getAnnotation(annotationId: string): Promise<{
    id: string;
    amount: number;
    createdAt: Date;
    status: string;
  } | null> {
    try {
      const result = await db('annotations')
        .select('id', 'amount', 'created_at', 'status')
        .where('id', annotationId)
        .where('status', 'active');

      const annotations = Array.isArray(result) ? result : [];
      return annotations.length > 0 ? {
        id: (annotations[0] as Record<string, any>)['id'],
        amount: parseFloat((annotations[0] as Record<string, any>)['amount']),
        createdAt: new Date((annotations[0] as Record<string, any>)['created_at']),
        status: (annotations[0] as Record<string, any>)['status'],
      } : null;
    } catch (error) {
      console.error('获取标注信息失败:', error);
      return null;
    }
  }

  /**
   * 获取地理围栏配置
   * @param annotationId 标注ID
   */
  private async getGeofenceConfig(annotationId: string): Promise<GeofenceConfig | null> {
    try {
      const result = await db('geofence_configs')
        .select('*')
        .where('annotation_id', annotationId)
        .where('is_active', true)
        .orderBy('created_at', 'desc')
        .limit(1);

      const configs = Array.isArray(result) ? result : [];
      if (configs.length === 0) {
        return null;
      }

      const row = configs[0] as Record<string, any>;
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
    } catch (error) {
      console.error('获取地理围栏配置失败:', error);
      return null;
    }
  }

  /**
   * 检查用户是否已获得该标注奖励
   * @param annotationId 标注ID
   * @param userId 用户ID
   */
  private async checkExistingReward(annotationId: string, userId: string): Promise<boolean> {
    try {
      const result = await db('lbs_rewards')
        .count('* as count')
        .where('annotation_id', annotationId)
        .where('user_id', userId)
        .whereIn('status', ['verified', 'claimed'])
        .where('created_at', '>', db.raw('NOW() - INTERVAL \'24 hours\''));

      const rows = Array.isArray(result) ? result : [];
      return rows.length > 0 ? parseInt((rows[0] as Record<string, any>)['count']) > 0 : false;
    } catch (error) {
      console.error('检查现有奖励失败:', error);
      return false;
    }
  }

  /**
   * 创建不符合条件的结果
   * @param reason 原因
   */
  private createIneligibleResult(reason: string): RewardCalculationResult {
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
