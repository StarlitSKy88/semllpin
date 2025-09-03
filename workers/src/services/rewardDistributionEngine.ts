import { NeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { GeofencingService, GeofenceResult } from './geofencing';
import { AntiFraudService } from './antiFraudService';
import { z } from 'zod';

// 验证模式
const distributionRequestSchema = z.object({
  user_id: z.string().uuid(),
  annotation_id: z.string().uuid(),
  user_location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180)
  }),
  trigger_timestamp: z.string().datetime().optional()
});

const rewardConfigSchema = z.object({
  annotation_id: z.string().uuid(),
  base_fee: z.number().min(0),
  time_decay_factor: z.number().min(0).max(1),
  user_level_multiplier: z.number().min(0.1).max(5),
  max_rewards_per_day: z.number().min(1).max(100),
  min_reward_amount: z.number().min(0.01)
});

// 奖励分发结果接口
export interface RewardDistributionResult {
  success: boolean;
  reward_id?: string;
  user_id: string;
  annotation_id: string;
  calculated_reward: number;
  actual_reward: number;
  distribution_reason: string;
  geofence_verification: GeofenceResult;
  fraud_check_result: {
    is_suspicious: boolean;
    risk_score: number;
    flags: string[];
  };
  timestamp: string;
  metadata: {
    user_level: number;
    time_decay_applied: number;
    pool_balance_before: number;
    pool_balance_after: number;
    daily_reward_count: number;
  };
}

// 奖励配置接口
export interface RewardConfiguration {
  annotation_id: string;
  base_fee: number;
  time_decay_factor: number;
  user_level_multiplier: number;
  max_rewards_per_day: number;
  min_reward_amount: number;
  created_at: string;
  updated_at: string;
}

// 奖励历史记录接口
export interface RewardHistoryRecord {
  id: string;
  user_id: string;
  annotation_id: string;
  reward_amount: number;
  distribution_method: string;
  geofence_distance: number;
  fraud_risk_score: number;
  user_level_at_distribution: number;
  created_at: string;
  metadata: any;
}

// 奖励统计接口
export interface RewardStatistics {
  total_distributed: number;
  total_recipients: number;
  average_reward: number;
  distribution_by_day: Array<{
    date: string;
    count: number;
    total_amount: number;
  }>;
  top_earners: Array<{
    user_id: string;
    username?: string;
    total_earned: number;
    reward_count: number;
  }>;
  annotation_performance: Array<{
    annotation_id: string;
    total_distributed: number;
    unique_recipients: number;
    current_pool_balance: number;
  }>;
}

// 默认奖励配置
const DEFAULT_REWARD_CONFIG = {
  base_fee: 1.0,
  time_decay_factor: 0.95, // 每天衰减5%
  user_level_multiplier: 1.0,
  max_rewards_per_day: 10,
  min_reward_amount: 0.10
};

// 用户等级配置
const USER_LEVEL_MULTIPLIERS = {
  1: 1.0,   // 新手
  2: 1.1,   // 普通
  3: 1.25,  // 活跃
  4: 1.5,   // 专家
  5: 2.0    // 大师
};

/**
 * 实时奖励分发引擎
 * 负责处理标注奖励的动态计算和实时分发
 */
export class RewardDistributionEngine {
  private db: NeonDatabase;
  private env: Env;
  private geofencingService: GeofencingService;
  private antiFraudService: AntiFraudService;
  
  // 分发缓存，防止重复分发
  private distributionCache = new Map<string, {
    timestamp: number;
    reward_amount: number;
  }>();
  
  private readonly CACHE_TTL = 30 * 60 * 1000; // 30分钟缓存时间

  constructor(env: Env) {
    this.env = env;
    this.db = new NeonDatabase(env.DATABASE_URL);
    this.geofencingService = new GeofencingService(env);
    this.antiFraudService = new AntiFraudService(env);
  }

  /**
   * 主要的奖励分发方法
   * 在用户触发地理围栏时立即调用
   */
  async distributeReward(params: {
    user_id: string;
    annotation_id: string;
    user_location: { latitude: number; longitude: number };
    trigger_timestamp?: string;
  }): Promise<RewardDistributionResult> {
    try {
      // 验证输入参数
      const validatedParams = distributionRequestSchema.parse(params);
      const { user_id, annotation_id, user_location } = validatedParams;

      // 检查缓存，防止重复分发
      const cacheKey = `${user_id}:${annotation_id}`;
      const cached = this.distributionCache.get(cacheKey);
      if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
        throw new Error('Reward already distributed recently for this user and annotation');
      }

      // 1. 地理围栏验证
      const geofenceResult = await this.geofencingService.checkGeofence({
        user_location,
        annotation_id
      });

      if (!geofenceResult.is_within_geofence) {
        return {
          success: false,
          user_id,
          annotation_id,
          calculated_reward: 0,
          actual_reward: 0,
          distribution_reason: 'User not within geofence',
          geofence_verification: geofenceResult,
          fraud_check_result: {
            is_suspicious: false,
            risk_score: 0,
            flags: []
          },
          timestamp: new Date().toISOString(),
          metadata: {
            user_level: 1,
            time_decay_applied: 0,
            pool_balance_before: 0,
            pool_balance_after: 0,
            daily_reward_count: 0
          }
        };
      }

      // 2. 防作弊检查
      const fraudCheckResult = await this.antiFraudService.analyzeUserBehavior(user_id, {
        location: user_location,
        action_type: 'reward_claim',
        annotation_id,
        timestamp: new Date().toISOString()
      });

      if (fraudCheckResult.is_suspicious && fraudCheckResult.risk_score > 0.7) {
        return {
          success: false,
          user_id,
          annotation_id,
          calculated_reward: 0,
          actual_reward: 0,
          distribution_reason: 'High fraud risk detected',
          geofence_verification: geofenceResult,
          fraud_check_result: fraudCheckResult,
          timestamp: new Date().toISOString(),
          metadata: {
            user_level: 1,
            time_decay_applied: 0,
            pool_balance_before: 0,
            pool_balance_after: 0,
            daily_reward_count: 0
          }
        };
      }

      // 3. 检查是否已经获得过奖励
      const existingReward = await this.checkExistingReward(user_id, annotation_id);
      if (existingReward) {
        return {
          success: false,
          user_id,
          annotation_id,
          calculated_reward: 0,
          actual_reward: 0,
          distribution_reason: 'User already received reward for this annotation',
          geofence_verification: geofenceResult,
          fraud_check_result: fraudCheckResult,
          timestamp: new Date().toISOString(),
          metadata: {
            user_level: 1,
            time_decay_applied: 0,
            pool_balance_before: 0,
            pool_balance_after: 0,
            daily_reward_count: 0
          }
        };
      }

      // 4. 获取用户信息和等级
      const userInfo = await this.getUserInfo(user_id);
      const userLevel = this.calculateUserLevel(userInfo);

      // 5. 检查每日奖励限制
      const todayRewardCount = await this.getTodayRewardCount(user_id);
      const rewardConfig = await this.getRewardConfiguration(annotation_id);
      
      if (todayRewardCount >= rewardConfig.max_rewards_per_day) {
        return {
          success: false,
          user_id,
          annotation_id,
          calculated_reward: 0,
          actual_reward: 0,
          distribution_reason: 'Daily reward limit exceeded',
          geofence_verification: geofenceResult,
          fraud_check_result: fraudCheckResult,
          timestamp: new Date().toISOString(),
          metadata: {
            user_level: userLevel,
            time_decay_applied: 0,
            pool_balance_before: 0,
            pool_balance_after: 0,
            daily_reward_count: todayRewardCount
          }
        };
      }

      // 6. 计算动态奖励
      const calculatedReward = await this.calculateDynamicReward({
        annotation_id,
        user_level: userLevel,
        geofence_distance: geofenceResult.distance_meters,
        fraud_risk_score: fraudCheckResult.risk_score
      });

      // 7. 检查奖励池余额
      const poolBalance = await this.getRewardPoolBalance(annotation_id);
      const actualReward = Math.min(calculatedReward, poolBalance);

      if (actualReward < rewardConfig.min_reward_amount) {
        return {
          success: false,
          user_id,
          annotation_id,
          calculated_reward: calculatedReward,
          actual_reward: 0,
          distribution_reason: 'Insufficient reward pool balance',
          geofence_verification: geofenceResult,
          fraud_check_result: fraudCheckResult,
          timestamp: new Date().toISOString(),
          metadata: {
            user_level: userLevel,
            time_decay_applied: 0,
            pool_balance_before: poolBalance,
            pool_balance_after: poolBalance,
            daily_reward_count: todayRewardCount
          }
        };
      }

      // 8. 执行奖励分发事务
      const rewardId = await this.executeRewardDistribution({
        user_id,
        annotation_id,
        reward_amount: actualReward,
        geofence_result: geofenceResult,
        fraud_check_result: fraudCheckResult,
        user_level: userLevel,
        pool_balance_before: poolBalance
      });

      // 9. 更新缓存
      this.distributionCache.set(cacheKey, {
        timestamp: Date.now(),
        reward_amount: actualReward
      });

      return {
        success: true,
        reward_id: rewardId,
        user_id,
        annotation_id,
        calculated_reward: calculatedReward,
        actual_reward: actualReward,
        distribution_reason: 'Reward distributed successfully',
        geofence_verification: geofenceResult,
        fraud_check_result: fraudCheckResult,
        timestamp: new Date().toISOString(),
        metadata: {
          user_level: userLevel,
          time_decay_applied: this.calculateTimeDecay(annotation_id),
          pool_balance_before: poolBalance,
          pool_balance_after: poolBalance - actualReward,
          daily_reward_count: todayRewardCount + 1
        }
      };

    } catch (error) {
      console.error('Reward distribution error:', error);
      throw new Error(`Failed to distribute reward: ${error.message}`);
    }
  }

  /**
   * 动态奖励计算算法
   */
  private async calculateDynamicReward(params: {
    annotation_id: string;
    user_level: number;
    geofence_distance: number;
    fraud_risk_score: number;
  }): Promise<number> {
    try {
      const { annotation_id, user_level, geofence_distance, fraud_risk_score } = params;

      // 获取奖励配置
      const config = await this.getRewardConfiguration(annotation_id);
      const annotation = await this.getAnnotationInfo(annotation_id);

      // 基础奖励金额（来自标注费用）
      let rewardAmount = config.base_fee * 0.7; // 70%的标注费用作为奖励

      // 1. 时间衰减因子
      const daysSinceCreation = this.calculateDaysSinceCreation(annotation.created_at);
      const timeDecayFactor = Math.pow(config.time_decay_factor, daysSinceCreation);
      rewardAmount *= timeDecayFactor;

      // 2. 用户等级倍数
      const levelMultiplier = USER_LEVEL_MULTIPLIERS[user_level] || 1.0;
      rewardAmount *= levelMultiplier;

      // 3. 距离奖励（越近奖励越高）
      const maxDistance = 200; // 最大有效距离200米
      const distanceFactor = Math.max(0.5, 1 - (geofence_distance / maxDistance));
      rewardAmount *= distanceFactor;

      // 4. 反作弊惩罚
      const fraudPenalty = Math.max(0.1, 1 - fraud_risk_score);
      rewardAmount *= fraudPenalty;

      // 5. 标注类型奖励倍数
      const categoryMultiplier = this.getCategoryMultiplier(annotation.smell_category);
      rewardAmount *= categoryMultiplier;

      // 6. 稀缺性奖励（该地区标注数量少的话增加奖励）
      const scarcityMultiplier = await this.calculateScarcityMultiplier(annotation.location);
      rewardAmount *= scarcityMultiplier;

      // 确保最小奖励金额
      rewardAmount = Math.max(rewardAmount, config.min_reward_amount);

      // 四舍五入到两位小数
      return Math.round(rewardAmount * 100) / 100;

    } catch (error) {
      console.error('Dynamic reward calculation error:', error);
      return DEFAULT_REWARD_CONFIG.min_reward_amount;
    }
  }

  /**
   * 执行奖励分发事务
   */
  private async executeRewardDistribution(params: {
    user_id: string;
    annotation_id: string;
    reward_amount: number;
    geofence_result: GeofenceResult;
    fraud_check_result: any;
    user_level: number;
    pool_balance_before: number;
  }): Promise<string> {
    const {
      user_id,
      annotation_id,
      reward_amount,
      geofence_result,
      fraud_check_result,
      user_level,
      pool_balance_before
    } = params;

    try {
      // 开始事务
      await this.db.sql`BEGIN`;

      // 1. 创建奖励记录
      const rewardRecord = await this.db.sql`
        INSERT INTO reward_distributions (
          user_id, 
          annotation_id, 
          reward_amount, 
          distribution_method,
          geofence_distance,
          fraud_risk_score,
          user_level_at_distribution,
          status,
          created_at,
          metadata
        ) VALUES (
          ${user_id},
          ${annotation_id},
          ${reward_amount},
          'geofence_trigger',
          ${geofence_result.distance_meters},
          ${fraud_check_result.risk_score},
          ${user_level},
          'completed',
          NOW(),
          ${JSON.stringify({
            geofence_verification: geofence_result,
            fraud_check: fraud_check_result,
            pool_balance_before
          })}
        ) RETURNING id
      `;

      const rewardId = rewardRecord[0].id;

      // 2. 更新用户钱包
      const userWallet = await this.db.sql`
        SELECT id, balance FROM wallets WHERE user_id = ${user_id} LIMIT 1
      `;

      if (userWallet.length === 0) {
        // 创建新钱包
        await this.db.sql`
          INSERT INTO wallets (user_id, balance, total_earned, currency, created_at, updated_at)
          VALUES (${user_id}, ${reward_amount}, ${reward_amount}, 'usd', NOW(), NOW())
        `;
      } else {
        // 更新现有钱包
        await this.db.sql`
          UPDATE wallets 
          SET balance = balance + ${reward_amount},
              total_earned = total_earned + ${reward_amount},
              updated_at = NOW()
          WHERE user_id = ${user_id}
        `;
      }

      // 3. 更新奖励池余额
      await this.db.sql`
        UPDATE annotations 
        SET current_reward_pool = current_reward_pool - ${reward_amount},
            updated_at = NOW()
        WHERE id = ${annotation_id}
      `;

      // 4. 创建交易记录
      await this.db.sql`
        INSERT INTO transactions (
          user_id,
          type,
          amount,
          currency,
          status,
          completed_at,
          description,
          metadata
        ) VALUES (
          ${user_id},
          'lbs_reward',
          ${reward_amount},
          'usd',
          'completed',
          NOW(),
          'LBS reward for annotation discovery',
          ${JSON.stringify({
            annotation_id,
            reward_distribution_id: rewardId,
            geofence_distance: geofence_result.distance_meters,
            user_level
          })}
        )
      `;

      // 5. 更新用户统计
      await this.updateUserRewardStatistics(user_id, reward_amount);

      // 提交事务
      await this.db.sql`COMMIT`;

      return rewardId;

    } catch (error) {
      // 回滚事务
      await this.db.sql`ROLLBACK`;
      throw error;
    }
  }

  /**
   * 获取奖励配置
   */
  private async getRewardConfiguration(annotation_id: string): Promise<RewardConfiguration> {
    try {
      const result = await this.db.sql`
        SELECT 
          rc.*,
          a.payment_amount
        FROM reward_configurations rc
        LEFT JOIN annotations a ON rc.annotation_id = a.id
        WHERE rc.annotation_id = ${annotation_id}
      `;

      if (result.length > 0) {
        const config = result[0];
        return {
          annotation_id: config.annotation_id,
          base_fee: parseFloat(config.base_fee || config.payment_amount || DEFAULT_REWARD_CONFIG.base_fee),
          time_decay_factor: parseFloat(config.time_decay_factor || DEFAULT_REWARD_CONFIG.time_decay_factor),
          user_level_multiplier: parseFloat(config.user_level_multiplier || DEFAULT_REWARD_CONFIG.user_level_multiplier),
          max_rewards_per_day: parseInt(config.max_rewards_per_day || DEFAULT_REWARD_CONFIG.max_rewards_per_day),
          min_reward_amount: parseFloat(config.min_reward_amount || DEFAULT_REWARD_CONFIG.min_reward_amount),
          created_at: config.created_at,
          updated_at: config.updated_at
        };
      }

      // 使用默认配置
      return {
        annotation_id,
        ...DEFAULT_REWARD_CONFIG,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

    } catch (error) {
      console.error('Get reward configuration error:', error);
      return {
        annotation_id,
        ...DEFAULT_REWARD_CONFIG,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    }
  }

  /**
   * 检查用户是否已经获得该标注的奖励
   */
  private async checkExistingReward(user_id: string, annotation_id: string): Promise<boolean> {
    try {
      const result = await this.db.sql`
        SELECT id FROM reward_distributions 
        WHERE user_id = ${user_id} AND annotation_id = ${annotation_id}
        LIMIT 1
      `;
      return result.length > 0;
    } catch (error) {
      console.error('Check existing reward error:', error);
      return false;
    }
  }

  /**
   * 获取今日奖励数量
   */
  private async getTodayRewardCount(user_id: string): Promise<number> {
    try {
      const today = new Date().toISOString().split('T')[0];
      const result = await this.db.sql`
        SELECT COUNT(*) as count 
        FROM reward_distributions 
        WHERE user_id = ${user_id} 
          AND DATE(created_at) = ${today}
          AND status = 'completed'
      `;
      return parseInt(result[0]?.count || '0');
    } catch (error) {
      console.error('Get today reward count error:', error);
      return 0;
    }
  }

  /**
   * 获取奖励池余额
   */
  private async getRewardPoolBalance(annotation_id: string): Promise<number> {
    try {
      const result = await this.db.sql`
        SELECT current_reward_pool FROM annotations WHERE id = ${annotation_id}
      `;
      return parseFloat(result[0]?.current_reward_pool || '0');
    } catch (error) {
      console.error('Get reward pool balance error:', error);
      return 0;
    }
  }

  /**
   * 获取用户信息
   */
  private async getUserInfo(user_id: string): Promise<any> {
    try {
      const result = await this.db.sql`
        SELECT 
          u.*,
          w.total_earned,
          COUNT(rd.id) as reward_count
        FROM users u
        LEFT JOIN wallets w ON u.id = w.user_id
        LEFT JOIN reward_distributions rd ON u.id = rd.user_id AND rd.status = 'completed'
        WHERE u.id = ${user_id}
        GROUP BY u.id, w.total_earned
      `;
      return result[0] || {};
    } catch (error) {
      console.error('Get user info error:', error);
      return {};
    }
  }

  /**
   * 获取标注信息
   */
  private async getAnnotationInfo(annotation_id: string): Promise<any> {
    try {
      const result = await this.db.sql`
        SELECT * FROM annotations WHERE id = ${annotation_id}
      `;
      return result[0] || {};
    } catch (error) {
      console.error('Get annotation info error:', error);
      return {};
    }
  }

  /**
   * 计算用户等级
   */
  private calculateUserLevel(userInfo: any): number {
    const totalEarned = parseFloat(userInfo.total_earned || '0');
    const rewardCount = parseInt(userInfo.reward_count || '0');

    if (totalEarned >= 100 || rewardCount >= 50) return 5; // 大师
    if (totalEarned >= 50 || rewardCount >= 25) return 4;  // 专家
    if (totalEarned >= 20 || rewardCount >= 10) return 3;  // 活跃
    if (totalEarned >= 5 || rewardCount >= 3) return 2;    // 普通
    return 1; // 新手
  }

  /**
   * 计算时间衰减
   */
  private calculateTimeDecay(annotation_id: string): number {
    // 实现时间衰减逻辑
    return 0.95; // 示例值
  }

  /**
   * 计算创建后天数
   */
  private calculateDaysSinceCreation(created_at: string): number {
    const createdDate = new Date(created_at);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - createdDate.getTime());
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  /**
   * 获取分类倍数
   */
  private getCategoryMultiplier(category: string): number {
    const multipliers: { [key: string]: number } = {
      'sewage': 1.5,
      'garbage': 1.3,
      'chemical': 2.0,
      'food': 1.1,
      'other': 1.0
    };
    return multipliers[category] || 1.0;
  }

  /**
   * 计算稀缺性倍数
   */
  private async calculateScarcityMultiplier(location: any): Promise<number> {
    try {
      const lat = parseFloat(location.latitude);
      const lng = parseFloat(location.longitude);
      const radius = 0.01; // 约1km半径

      const nearbyCount = await this.db.sql`
        SELECT COUNT(*) as count 
        FROM annotations 
        WHERE status = 'active'
          AND ABS((location->>'latitude')::float - ${lat}) < ${radius}
          AND ABS((location->>'longitude')::float - ${lng}) < ${radius}
      `;

      const count = parseInt(nearbyCount[0]?.count || '0');
      
      // 标注越少，稀缺性倍数越高
      if (count <= 1) return 2.0;
      if (count <= 3) return 1.5;
      if (count <= 5) return 1.2;
      return 1.0;

    } catch (error) {
      console.error('Calculate scarcity multiplier error:', error);
      return 1.0;
    }
  }

  /**
   * 更新用户奖励统计
   */
  private async updateUserRewardStatistics(user_id: string, reward_amount: number): Promise<void> {
    try {
      await this.db.sql`
        INSERT INTO user_reward_statistics (
          user_id,
          total_rewards_received,
          total_reward_amount,
          last_reward_at,
          updated_at
        ) VALUES (
          ${user_id},
          1,
          ${reward_amount},
          NOW(),
          NOW()
        )
        ON CONFLICT (user_id)
        DO UPDATE SET
          total_rewards_received = user_reward_statistics.total_rewards_received + 1,
          total_reward_amount = user_reward_statistics.total_reward_amount + ${reward_amount},
          last_reward_at = NOW(),
          updated_at = NOW()
      `;
    } catch (error) {
      console.error('Update user reward statistics error:', error);
      // 不抛出错误，因为这不是关键操作
    }
  }

  /**
   * 获取奖励历史记录
   */
  async getRewardHistory(params: {
    user_id?: string;
    annotation_id?: string;
    limit?: number;
    offset?: number;
    start_date?: string;
    end_date?: string;
  }): Promise<RewardHistoryRecord[]> {
    try {
      const {
        user_id,
        annotation_id,
        limit = 50,
        offset = 0,
        start_date,
        end_date
      } = params;

      let whereClause = 'WHERE rd.status = \'completed\'';
      const queryParams: any[] = [];

      if (user_id) {
        whereClause += ` AND rd.user_id = $${queryParams.length + 1}`;
        queryParams.push(user_id);
      }

      if (annotation_id) {
        whereClause += ` AND rd.annotation_id = $${queryParams.length + 1}`;
        queryParams.push(annotation_id);
      }

      if (start_date) {
        whereClause += ` AND rd.created_at >= $${queryParams.length + 1}`;
        queryParams.push(start_date);
      }

      if (end_date) {
        whereClause += ` AND rd.created_at <= $${queryParams.length + 1}`;
        queryParams.push(end_date);
      }

      const result = await this.db.sql`
        SELECT 
          rd.id,
          rd.user_id,
          rd.annotation_id,
          rd.reward_amount,
          rd.distribution_method,
          rd.geofence_distance,
          rd.fraud_risk_score,
          rd.user_level_at_distribution,
          rd.created_at,
          rd.metadata,
          u.username,
          a.smell_category,
          a.location
        FROM reward_distributions rd
        LEFT JOIN users u ON rd.user_id = u.id
        LEFT JOIN annotations a ON rd.annotation_id = a.id
        ${whereClause}
        ORDER BY rd.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      return result.map(row => ({
        id: row.id,
        user_id: row.user_id,
        annotation_id: row.annotation_id,
        reward_amount: parseFloat(row.reward_amount),
        distribution_method: row.distribution_method,
        geofence_distance: parseFloat(row.geofence_distance),
        fraud_risk_score: parseFloat(row.fraud_risk_score),
        user_level_at_distribution: parseInt(row.user_level_at_distribution),
        created_at: row.created_at,
        metadata: row.metadata
      }));

    } catch (error) {
      console.error('Get reward history error:', error);
      throw new Error(`Failed to get reward history: ${error.message}`);
    }
  }

  /**
   * 获取奖励统计
   */
  async getRewardStatistics(params: {
    start_date?: string;
    end_date?: string;
    annotation_id?: string;
  }): Promise<RewardStatistics> {
    try {
      const { start_date, end_date, annotation_id } = params;

      let whereClause = 'WHERE rd.status = \'completed\'';
      if (start_date) {
        whereClause += ` AND rd.created_at >= '${start_date}'`;
      }
      if (end_date) {
        whereClause += ` AND rd.created_at <= '${end_date}'`;
      }
      if (annotation_id) {
        whereClause += ` AND rd.annotation_id = '${annotation_id}'`;
      }

      // 总体统计
      const totalStats = await this.db.sql`
        SELECT 
          COUNT(*) as total_distributed,
          COUNT(DISTINCT rd.user_id) as total_recipients,
          AVG(rd.reward_amount) as average_reward
        FROM reward_distributions rd
        ${whereClause}
      `;

      // 按日期分组统计
      const dailyStats = await this.db.sql`
        SELECT 
          DATE(rd.created_at) as date,
          COUNT(*) as count,
          SUM(rd.reward_amount) as total_amount
        FROM reward_distributions rd
        ${whereClause}
        GROUP BY DATE(rd.created_at)
        ORDER BY date DESC
        LIMIT 30
      `;

      // 顶级赚取者
      const topEarners = await this.db.sql`
        SELECT 
          rd.user_id,
          u.username,
          SUM(rd.reward_amount) as total_earned,
          COUNT(*) as reward_count
        FROM reward_distributions rd
        LEFT JOIN users u ON rd.user_id = u.id
        ${whereClause}
        GROUP BY rd.user_id, u.username
        ORDER BY total_earned DESC
        LIMIT 10
      `;

      // 标注表现统计
      const annotationPerformance = await this.db.sql`
        SELECT 
          rd.annotation_id,
          SUM(rd.reward_amount) as total_distributed,
          COUNT(DISTINCT rd.user_id) as unique_recipients,
          a.current_reward_pool
        FROM reward_distributions rd
        LEFT JOIN annotations a ON rd.annotation_id = a.id
        ${whereClause}
        GROUP BY rd.annotation_id, a.current_reward_pool
        ORDER BY total_distributed DESC
        LIMIT 20
      `;

      const stats = totalStats[0] || { total_distributed: 0, total_recipients: 0, average_reward: 0 };

      return {
        total_distributed: parseInt(stats.total_distributed),
        total_recipients: parseInt(stats.total_recipients),
        average_reward: parseFloat(stats.average_reward) || 0,
        distribution_by_day: dailyStats.map(row => ({
          date: row.date,
          count: parseInt(row.count),
          total_amount: parseFloat(row.total_amount)
        })),
        top_earners: topEarners.map(row => ({
          user_id: row.user_id,
          username: row.username,
          total_earned: parseFloat(row.total_earned),
          reward_count: parseInt(row.reward_count)
        })),
        annotation_performance: annotationPerformance.map(row => ({
          annotation_id: row.annotation_id,
          total_distributed: parseFloat(row.total_distributed),
          unique_recipients: parseInt(row.unique_recipients),
          current_pool_balance: parseFloat(row.current_reward_pool) || 0
        }))
      };

    } catch (error) {
      console.error('Get reward statistics error:', error);
      throw new Error(`Failed to get reward statistics: ${error.message}`);
    }
  }

  /**
   * 配置奖励参数
   */
  async configureReward(params: {
    annotation_id: string;
    base_fee?: number;
    time_decay_factor?: number;
    user_level_multiplier?: number;
    max_rewards_per_day?: number;
    min_reward_amount?: number;
  }): Promise<RewardConfiguration> {
    try {
      const validatedParams = rewardConfigSchema.parse(params);
      const { annotation_id } = validatedParams;

      // 检查是否存在配置
      const existing = await this.db.sql`
        SELECT * FROM reward_configurations WHERE annotation_id = ${annotation_id}
      `;

      let result;
      if (existing.length > 0) {
        // 更新现有配置
        result = await this.db.sql`
          UPDATE reward_configurations 
          SET 
            base_fee = COALESCE(${validatedParams.base_fee}, base_fee),
            time_decay_factor = COALESCE(${validatedParams.time_decay_factor}, time_decay_factor),
            user_level_multiplier = COALESCE(${validatedParams.user_level_multiplier}, user_level_multiplier),
            max_rewards_per_day = COALESCE(${validatedParams.max_rewards_per_day}, max_rewards_per_day),
            min_reward_amount = COALESCE(${validatedParams.min_reward_amount}, min_reward_amount),
            updated_at = NOW()
          WHERE annotation_id = ${annotation_id}
          RETURNING *
        `;
      } else {
        // 创建新配置
        result = await this.db.sql`
          INSERT INTO reward_configurations (
            annotation_id,
            base_fee,
            time_decay_factor,
            user_level_multiplier,
            max_rewards_per_day,
            min_reward_amount,
            created_at,
            updated_at
          ) VALUES (
            ${annotation_id},
            ${validatedParams.base_fee || DEFAULT_REWARD_CONFIG.base_fee},
            ${validatedParams.time_decay_factor || DEFAULT_REWARD_CONFIG.time_decay_factor},
            ${validatedParams.user_level_multiplier || DEFAULT_REWARD_CONFIG.user_level_multiplier},
            ${validatedParams.max_rewards_per_day || DEFAULT_REWARD_CONFIG.max_rewards_per_day},
            ${validatedParams.min_reward_amount || DEFAULT_REWARD_CONFIG.min_reward_amount},
            NOW(),
            NOW()
          ) RETURNING *
        `;
      }

      const config = result[0];
      return {
        annotation_id: config.annotation_id,
        base_fee: parseFloat(config.base_fee),
        time_decay_factor: parseFloat(config.time_decay_factor),
        user_level_multiplier: parseFloat(config.user_level_multiplier),
        max_rewards_per_day: parseInt(config.max_rewards_per_day),
        min_reward_amount: parseFloat(config.min_reward_amount),
        created_at: config.created_at,
        updated_at: config.updated_at
      };

    } catch (error) {
      console.error('Configure reward error:', error);
      throw new Error(`Failed to configure reward: ${error.message}`);
    }
  }

  /**
   * 初始化奖励分发相关的数据库表
   */
  async initializeRewardTables(): Promise<boolean> {
    try {
      // 奖励分发表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS reward_distributions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
          reward_amount DECIMAL(10, 2) NOT NULL,
          distribution_method VARCHAR(50) NOT NULL DEFAULT 'geofence_trigger',
          geofence_distance DECIMAL(10, 2),
          fraud_risk_score DECIMAL(3, 2) DEFAULT 0,
          user_level_at_distribution INTEGER DEFAULT 1,
          status VARCHAR(20) DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          metadata JSONB DEFAULT '{}'::jsonb,
          UNIQUE(user_id, annotation_id) -- 防止重复奖励
        )
      `;

      // 奖励配置表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS reward_configurations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
          base_fee DECIMAL(10, 2) DEFAULT 1.0,
          time_decay_factor DECIMAL(3, 2) DEFAULT 0.95,
          user_level_multiplier DECIMAL(3, 2) DEFAULT 1.0,
          max_rewards_per_day INTEGER DEFAULT 10,
          min_reward_amount DECIMAL(10, 2) DEFAULT 0.10,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;

      // 用户奖励统计表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS user_reward_statistics (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          total_rewards_received INTEGER DEFAULT 0,
          total_reward_amount DECIMAL(10, 2) DEFAULT 0,
          last_reward_at TIMESTAMP WITH TIME ZONE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;

      // 创建索引
      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_distributions_user_id 
        ON reward_distributions(user_id)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_distributions_annotation_id 
        ON reward_distributions(annotation_id)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_distributions_created_at 
        ON reward_distributions(created_at)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_distributions_status 
        ON reward_distributions(status)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_configurations_annotation_id 
        ON reward_configurations(annotation_id)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_user_reward_statistics_user_id 
        ON user_reward_statistics(user_id)
      `;

      console.log('Reward distribution tables initialized successfully');
      return true;

    } catch (error) {
      console.error('Initialize reward tables error:', error);
      return false;
    }
  }

  /**
   * 清理缓存
   */
  clearCache(): void {
    this.distributionCache.clear();
  }

  /**
   * 获取缓存统计
   */
  getCacheStats(): { size: number; entries: Array<{ key: string; timestamp: number; reward_amount: number }> } {
    const entries = Array.from(this.distributionCache.entries()).map(([key, value]) => ({
      key,
      timestamp: value.timestamp,
      reward_amount: value.reward_amount
    }));

    return {
      size: this.distributionCache.size,
      entries
    };
  }
}

// 导出工具函数
export { DEFAULT_REWARD_CONFIG, USER_LEVEL_MULTIPLIERS };