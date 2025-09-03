import { NeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { z } from 'zod';

// 验证模式
const poolOperationSchema = z.object({
  annotation_id: z.string().uuid(),
  amount: z.number().min(0),
  operation_type: z.enum(['deposit', 'withdraw', 'reserve', 'release']),
  source: z.string(),
  description: z.string().optional()
});

const poolConfigSchema = z.object({
  annotation_id: z.string().uuid(),
  initial_pool_size: z.number().min(0),
  min_pool_threshold: z.number().min(0),
  max_pool_size: z.number().min(0),
  auto_refill_enabled: z.boolean().default(true),
  refill_threshold: z.number().min(0).max(1).default(0.2), // 20%阈值时自动补充
  commission_rate: z.number().min(0).max(1).default(0.3) // 平台佣金30%
});

// 奖励池状态接口
export interface RewardPoolStatus {
  annotation_id: string;
  current_balance: number;
  reserved_amount: number;
  available_balance: number;
  total_deposited: number;
  total_distributed: number;
  total_withdrawn: number;
  pool_configuration: PoolConfiguration;
  last_activity_at: string;
  created_at: string;
  updated_at: string;
}

// 奖励池配置接口
export interface PoolConfiguration {
  annotation_id: string;
  initial_pool_size: number;
  min_pool_threshold: number;
  max_pool_size: number;
  auto_refill_enabled: boolean;
  refill_threshold: number;
  commission_rate: number;
  created_at: string;
  updated_at: string;
}

// 奖励池操作记录接口
export interface PoolOperationRecord {
  id: string;
  annotation_id: string;
  operation_type: 'deposit' | 'withdraw' | 'reserve' | 'release' | 'distribute' | 'refill';
  amount: number;
  source: string;
  description?: string;
  balance_before: number;
  balance_after: number;
  created_at: string;
  metadata: any;
}

// 奖励池分析接口
export interface PoolAnalytics {
  annotation_id: string;
  pool_efficiency: number; // 奖励分发效率 (0-1)
  burn_rate: number; // 每日消耗速率
  estimated_days_remaining: number;
  recipient_diversity: number; // 接收者多样性
  average_reward_per_user: number;
  peak_usage_hours: Array<{
    hour: number;
    distribution_count: number;
  }>;
  geographic_distribution: Array<{
    region: string;
    distribution_count: number;
    total_amount: number;
  }>;
}

/**
 * 奖励池管理系统
 * 负责管理每个标注的奖励资金分配、余额追踪和资金流控制
 */
export class RewardPoolManager {
  private db: NeonDatabase;
  private env: Env;
  
  // 池状态缓存，提高查询性能
  private poolStatusCache = new Map<string, {
    status: RewardPoolStatus;
    cached_at: number;
  }>();
  
  private readonly CACHE_TTL = 2 * 60 * 1000; // 2分钟缓存时间

  constructor(env: Env) {
    this.env = env;
    this.db = new NeonDatabase(env.DATABASE_URL);
  }

  /**
   * 创建新的奖励池
   */
  async createRewardPool(params: {
    annotation_id: string;
    initial_pool_size: number;
    min_pool_threshold?: number;
    max_pool_size?: number;
    auto_refill_enabled?: boolean;
    refill_threshold?: number;
    commission_rate?: number;
  }): Promise<RewardPoolStatus> {
    try {
      const validatedConfig = poolConfigSchema.parse(params);
      const { annotation_id, initial_pool_size } = validatedConfig;

      // 检查奖励池是否已存在
      const existingPool = await this.db.sql`
        SELECT id FROM reward_pools WHERE annotation_id = ${annotation_id}
      `;

      if (existingPool.length > 0) {
        throw new Error(`Reward pool already exists for annotation ${annotation_id}`);
      }

      // 开始事务
      await this.db.sql`BEGIN`;

      try {
        // 1. 创建奖励池配置
        await this.db.sql`
          INSERT INTO reward_pool_configurations (
            annotation_id,
            initial_pool_size,
            min_pool_threshold,
            max_pool_size,
            auto_refill_enabled,
            refill_threshold,
            commission_rate,
            created_at,
            updated_at
          ) VALUES (
            ${annotation_id},
            ${initial_pool_size},
            ${validatedConfig.min_pool_threshold || initial_pool_size * 0.1},
            ${validatedConfig.max_pool_size || initial_pool_size * 2},
            ${validatedConfig.auto_refill_enabled !== undefined ? validatedConfig.auto_refill_enabled : true},
            ${validatedConfig.refill_threshold || 0.2},
            ${validatedConfig.commission_rate || 0.3},
            NOW(),
            NOW()
          )
        `;

        // 2. 创建奖励池状态记录
        const poolResult = await this.db.sql`
          INSERT INTO reward_pools (
            annotation_id,
            current_balance,
            reserved_amount,
            total_deposited,
            total_distributed,
            total_withdrawn,
            last_activity_at,
            created_at,
            updated_at
          ) VALUES (
            ${annotation_id},
            ${initial_pool_size},
            0,
            ${initial_pool_size},
            0,
            0,
            NOW(),
            NOW(),
            NOW()
          ) RETURNING *
        `;

        // 3. 记录初始存款操作
        await this.recordPoolOperation({
          annotation_id,
          operation_type: 'deposit',
          amount: initial_pool_size,
          source: 'initial_funding',
          description: 'Initial pool funding from annotation creation',
          balance_before: 0,
          balance_after: initial_pool_size
        });

        // 4. 更新标注表的奖励池余额
        await this.db.sql`
          UPDATE annotations 
          SET current_reward_pool = ${initial_pool_size}, updated_at = NOW()
          WHERE id = ${annotation_id}
        `;

        await this.db.sql`COMMIT`;

        // 清除缓存
        this.poolStatusCache.delete(annotation_id);

        // 返回奖励池状态
        return await this.getPoolStatus(annotation_id);

      } catch (error) {
        await this.db.sql`ROLLBACK`;
        throw error;
      }

    } catch (error) {
      console.error('Create reward pool error:', error);
      throw new Error(`Failed to create reward pool: ${error.message}`);
    }
  }

  /**
   * 获取奖励池状态
   */
  async getPoolStatus(annotation_id: string): Promise<RewardPoolStatus> {
    try {
      // 检查缓存
      const cached = this.poolStatusCache.get(annotation_id);
      if (cached && (Date.now() - cached.cached_at) < this.CACHE_TTL) {
        return cached.status;
      }

      // 从数据库获取
      const result = await this.db.sql`
        SELECT 
          rp.*,
          rpc.initial_pool_size,
          rpc.min_pool_threshold,
          rpc.max_pool_size,
          rpc.auto_refill_enabled,
          rpc.refill_threshold,
          rpc.commission_rate,
          rpc.created_at as config_created_at,
          rpc.updated_at as config_updated_at
        FROM reward_pools rp
        JOIN reward_pool_configurations rpc ON rp.annotation_id = rpc.annotation_id
        WHERE rp.annotation_id = ${annotation_id}
      `;

      if (result.length === 0) {
        throw new Error(`Reward pool not found for annotation ${annotation_id}`);
      }

      const row = result[0];
      const status: RewardPoolStatus = {
        annotation_id: row.annotation_id,
        current_balance: parseFloat(row.current_balance),
        reserved_amount: parseFloat(row.reserved_amount),
        available_balance: parseFloat(row.current_balance) - parseFloat(row.reserved_amount),
        total_deposited: parseFloat(row.total_deposited),
        total_distributed: parseFloat(row.total_distributed),
        total_withdrawn: parseFloat(row.total_withdrawn),
        pool_configuration: {
          annotation_id: row.annotation_id,
          initial_pool_size: parseFloat(row.initial_pool_size),
          min_pool_threshold: parseFloat(row.min_pool_threshold),
          max_pool_size: parseFloat(row.max_pool_size),
          auto_refill_enabled: row.auto_refill_enabled,
          refill_threshold: parseFloat(row.refill_threshold),
          commission_rate: parseFloat(row.commission_rate),
          created_at: row.config_created_at,
          updated_at: row.config_updated_at
        },
        last_activity_at: row.last_activity_at,
        created_at: row.created_at,
        updated_at: row.updated_at
      };

      // 更新缓存
      this.poolStatusCache.set(annotation_id, {
        status,
        cached_at: Date.now()
      });

      return status;

    } catch (error) {
      console.error('Get pool status error:', error);
      throw new Error(`Failed to get pool status: ${error.message}`);
    }
  }

  /**
   * 向奖励池存入资金
   */
  async depositToPool(params: {
    annotation_id: string;
    amount: number;
    source: string;
    description?: string;
  }): Promise<RewardPoolStatus> {
    try {
      const validatedOperation = poolOperationSchema.parse({
        ...params,
        operation_type: 'deposit'
      });

      const { annotation_id, amount, source, description } = validatedOperation;

      // 获取当前状态
      const currentStatus = await this.getPoolStatus(annotation_id);
      const config = currentStatus.pool_configuration;

      // 检查最大池大小限制
      const newBalance = currentStatus.current_balance + amount;
      if (newBalance > config.max_pool_size) {
        throw new Error(`Deposit would exceed maximum pool size: ${config.max_pool_size}`);
      }

      // 开始事务
      await this.db.sql`BEGIN`;

      try {
        // 更新奖励池余额
        await this.db.sql`
          UPDATE reward_pools 
          SET 
            current_balance = current_balance + ${amount},
            total_deposited = total_deposited + ${amount},
            last_activity_at = NOW(),
            updated_at = NOW()
          WHERE annotation_id = ${annotation_id}
        `;

        // 记录操作
        await this.recordPoolOperation({
          annotation_id,
          operation_type: 'deposit',
          amount,
          source,
          description: description || 'Pool deposit',
          balance_before: currentStatus.current_balance,
          balance_after: newBalance
        });

        // 更新标注表
        await this.db.sql`
          UPDATE annotations 
          SET current_reward_pool = ${newBalance}, updated_at = NOW()
          WHERE id = ${annotation_id}
        `;

        await this.db.sql`COMMIT`;

        // 清除缓存
        this.poolStatusCache.delete(annotation_id);

        return await this.getPoolStatus(annotation_id);

      } catch (error) {
        await this.db.sql`ROLLBACK`;
        throw error;
      }

    } catch (error) {
      console.error('Deposit to pool error:', error);
      throw new Error(`Failed to deposit to pool: ${error.message}`);
    }
  }

  /**
   * 从奖励池提取资金
   */
  async withdrawFromPool(params: {
    annotation_id: string;
    amount: number;
    source: string;
    description?: string;
  }): Promise<RewardPoolStatus> {
    try {
      const validatedOperation = poolOperationSchema.parse({
        ...params,
        operation_type: 'withdraw'
      });

      const { annotation_id, amount, source, description } = validatedOperation;

      // 获取当前状态
      const currentStatus = await this.getPoolStatus(annotation_id);

      // 检查可用余额
      if (currentStatus.available_balance < amount) {
        throw new Error(`Insufficient available balance: ${currentStatus.available_balance} < ${amount}`);
      }

      const newBalance = currentStatus.current_balance - amount;

      // 开始事务
      await this.db.sql`BEGIN`;

      try {
        // 更新奖励池余额
        await this.db.sql`
          UPDATE reward_pools 
          SET 
            current_balance = current_balance - ${amount},
            total_withdrawn = total_withdrawn + ${amount},
            last_activity_at = NOW(),
            updated_at = NOW()
          WHERE annotation_id = ${annotation_id}
        `;

        // 记录操作
        await this.recordPoolOperation({
          annotation_id,
          operation_type: 'withdraw',
          amount,
          source,
          description: description || 'Pool withdrawal',
          balance_before: currentStatus.current_balance,
          balance_after: newBalance
        });

        // 更新标注表
        await this.db.sql`
          UPDATE annotations 
          SET current_reward_pool = ${newBalance}, updated_at = NOW()
          WHERE id = ${annotation_id}
        `;

        await this.db.sql`COMMIT`;

        // 清除缓存
        this.poolStatusCache.delete(annotation_id);

        return await this.getPoolStatus(annotation_id);

      } catch (error) {
        await this.db.sql`ROLLBACK`;
        throw error;
      }

    } catch (error) {
      console.error('Withdraw from pool error:', error);
      throw new Error(`Failed to withdraw from pool: ${error.message}`);
    }
  }

  /**
   * 预留奖励资金（在实际分发前先预留）
   */
  async reserveReward(annotation_id: string, amount: number, source: string): Promise<boolean> {
    try {
      const currentStatus = await this.getPoolStatus(annotation_id);
      
      // 检查可用余额
      if (currentStatus.available_balance < amount) {
        return false;
      }

      await this.db.sql`
        UPDATE reward_pools 
        SET 
          reserved_amount = reserved_amount + ${amount},
          last_activity_at = NOW(),
          updated_at = NOW()
        WHERE annotation_id = ${annotation_id}
      `;

      // 记录预留操作
      await this.recordPoolOperation({
        annotation_id,
        operation_type: 'reserve',
        amount,
        source,
        description: 'Reward amount reserved for distribution',
        balance_before: currentStatus.current_balance,
        balance_after: currentStatus.current_balance
      });

      // 清除缓存
      this.poolStatusCache.delete(annotation_id);
      return true;

    } catch (error) {
      console.error('Reserve reward error:', error);
      return false;
    }
  }

  /**
   * 释放预留的奖励资金（取消分发时）
   */
  async releaseReservedReward(annotation_id: string, amount: number, source: string): Promise<void> {
    try {
      await this.db.sql`
        UPDATE reward_pools 
        SET 
          reserved_amount = reserved_amount - ${amount},
          last_activity_at = NOW(),
          updated_at = NOW()
        WHERE annotation_id = ${annotation_id}
      `;

      const currentStatus = await this.getPoolStatus(annotation_id);

      // 记录释放操作
      await this.recordPoolOperation({
        annotation_id,
        operation_type: 'release',
        amount,
        source,
        description: 'Reserved amount released back to available balance',
        balance_before: currentStatus.current_balance,
        balance_after: currentStatus.current_balance
      });

      // 清除缓存
      this.poolStatusCache.delete(annotation_id);

    } catch (error) {
      console.error('Release reserved reward error:', error);
      throw new Error(`Failed to release reserved reward: ${error.message}`);
    }
  }

  /**
   * 执行奖励分发（从预留金额中扣除）
   */
  async executeRewardDistribution(annotation_id: string, amount: number, recipient_id: string): Promise<void> {
    try {
      const currentStatus = await this.getPoolStatus(annotation_id);

      // 开始事务
      await this.db.sql`BEGIN`;

      try {
        // 从预留金额和总余额中扣除
        await this.db.sql`
          UPDATE reward_pools 
          SET 
            current_balance = current_balance - ${amount},
            reserved_amount = reserved_amount - ${amount},
            total_distributed = total_distributed + ${amount},
            last_activity_at = NOW(),
            updated_at = NOW()
          WHERE annotation_id = ${annotation_id}
        `;

        // 记录分发操作
        await this.recordPoolOperation({
          annotation_id,
          operation_type: 'distribute',
          amount,
          source: 'reward_distribution',
          description: `Reward distributed to user ${recipient_id}`,
          balance_before: currentStatus.current_balance,
          balance_after: currentStatus.current_balance - amount,
          metadata: { recipient_id }
        });

        // 更新标注表
        await this.db.sql`
          UPDATE annotations 
          SET current_reward_pool = current_reward_pool - ${amount}, updated_at = NOW()
          WHERE id = ${annotation_id}
        `;

        await this.db.sql`COMMIT`;

        // 检查是否需要自动补充
        await this.checkAndExecuteAutoRefill(annotation_id);

        // 清除缓存
        this.poolStatusCache.delete(annotation_id);

      } catch (error) {
        await this.db.sql`ROLLBACK`;
        throw error;
      }

    } catch (error) {
      console.error('Execute reward distribution error:', error);
      throw new Error(`Failed to execute reward distribution: ${error.message}`);
    }
  }

  /**
   * 自动补充奖励池
   */
  private async checkAndExecuteAutoRefill(annotation_id: string): Promise<void> {
    try {
      const status = await this.getPoolStatus(annotation_id);
      const config = status.pool_configuration;

      // 检查是否启用自动补充
      if (!config.auto_refill_enabled) {
        return;
      }

      // 检查是否达到补充阈值
      const refillThresholdAmount = config.initial_pool_size * config.refill_threshold;
      if (status.current_balance > refillThresholdAmount) {
        return;
      }

      // 计算补充金额（补充到初始金额的50%）
      const targetAmount = config.initial_pool_size * 0.5;
      const refillAmount = targetAmount - status.current_balance;

      if (refillAmount > 0) {
        // 执行自动补充（这里应该集成支付系统或从标注者钱包扣费）
        await this.depositToPool({
          annotation_id,
          amount: refillAmount,
          source: 'auto_refill',
          description: 'Automatic pool refill triggered by low balance'
        });

        console.log(`Auto refill executed for annotation ${annotation_id}: ${refillAmount}`);
      }

    } catch (error) {
      console.error('Auto refill error:', error);
      // 不抛出错误，避免影响主要业务流程
    }
  }

  /**
   * 获取奖励池操作历史
   */
  async getPoolOperationHistory(params: {
    annotation_id: string;
    limit?: number;
    offset?: number;
    operation_type?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<PoolOperationRecord[]> {
    try {
      const {
        annotation_id,
        limit = 50,
        offset = 0,
        operation_type,
        start_date,
        end_date
      } = params;

      let whereClause = `WHERE annotation_id = '${annotation_id}'`;
      
      if (operation_type) {
        whereClause += ` AND operation_type = '${operation_type}'`;
      }
      if (start_date) {
        whereClause += ` AND created_at >= '${start_date}'`;
      }
      if (end_date) {
        whereClause += ` AND created_at <= '${end_date}'`;
      }

      const result = await this.db.sql`
        SELECT * FROM reward_pool_operations
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      return result.map(row => ({
        id: row.id,
        annotation_id: row.annotation_id,
        operation_type: row.operation_type,
        amount: parseFloat(row.amount),
        source: row.source,
        description: row.description,
        balance_before: parseFloat(row.balance_before),
        balance_after: parseFloat(row.balance_after),
        created_at: row.created_at,
        metadata: row.metadata
      }));

    } catch (error) {
      console.error('Get pool operation history error:', error);
      throw new Error(`Failed to get pool operation history: ${error.message}`);
    }
  }

  /**
   * 获取奖励池分析数据
   */
  async getPoolAnalytics(annotation_id: string, days: number = 30): Promise<PoolAnalytics> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      // 获取分发统计
      const distributionStats = await this.db.sql`
        SELECT 
          COUNT(DISTINCT rd.user_id) as unique_recipients,
          COUNT(*) as total_distributions,
          AVG(rd.reward_amount) as avg_reward_per_user,
          SUM(rd.reward_amount) as total_distributed
        FROM reward_distributions rd
        WHERE rd.annotation_id = ${annotation_id}
          AND rd.created_at >= ${startDate.toISOString()}
          AND rd.status = 'completed'
      `;

      // 获取按小时的分发模式
      const hourlyDistribution = await this.db.sql`
        SELECT 
          EXTRACT(HOUR FROM created_at) as hour,
          COUNT(*) as distribution_count
        FROM reward_distributions
        WHERE annotation_id = ${annotation_id}
          AND created_at >= ${startDate.toISOString()}
          AND status = 'completed'
        GROUP BY EXTRACT(HOUR FROM created_at)
        ORDER BY hour
      `;

      const stats = distributionStats[0] || {
        unique_recipients: 0,
        total_distributions: 0,
        avg_reward_per_user: 0,
        total_distributed: 0
      };

      const poolStatus = await this.getPoolStatus(annotation_id);
      
      // 计算燃烧速率（每日消耗速率）
      const totalDistributed = parseFloat(stats.total_distributed || '0');
      const burnRate = totalDistributed / days;

      // 预估剩余天数
      const estimatedDaysRemaining = burnRate > 0 
        ? Math.floor(poolStatus.available_balance / burnRate)
        : Infinity;

      // 计算池效率（实际分发 / 总存款）
      const poolEfficiency = poolStatus.total_deposited > 0
        ? poolStatus.total_distributed / poolStatus.total_deposited
        : 0;

      // 接收者多样性（不同用户获得奖励的比例）
      const recipientDiversity = parseInt(stats.total_distributions) > 0
        ? parseInt(stats.unique_recipients) / parseInt(stats.total_distributions)
        : 0;

      return {
        annotation_id,
        pool_efficiency: Math.round(poolEfficiency * 100) / 100,
        burn_rate: Math.round(burnRate * 100) / 100,
        estimated_days_remaining: estimatedDaysRemaining === Infinity ? -1 : estimatedDaysRemaining,
        recipient_diversity: Math.round(recipientDiversity * 100) / 100,
        average_reward_per_user: Math.round(parseFloat(stats.avg_reward_per_user || '0') * 100) / 100,
        peak_usage_hours: hourlyDistribution.map(row => ({
          hour: parseInt(row.hour),
          distribution_count: parseInt(row.distribution_count)
        })),
        geographic_distribution: [] // TODO: 实现地理分布分析
      };

    } catch (error) {
      console.error('Get pool analytics error:', error);
      throw new Error(`Failed to get pool analytics: ${error.message}`);
    }
  }

  /**
   * 批量获取多个奖励池状态
   */
  async getBatchPoolStatus(annotation_ids: string[]): Promise<RewardPoolStatus[]> {
    try {
      const results: RewardPoolStatus[] = [];
      
      // 并行获取所有奖励池状态
      const statusPromises = annotation_ids.map(id => 
        this.getPoolStatus(id).catch(error => {
          console.error(`Failed to get pool status for ${id}:`, error);
          return null;
        })
      );

      const statuses = await Promise.all(statusPromises);
      
      return statuses.filter(status => status !== null) as RewardPoolStatus[];

    } catch (error) {
      console.error('Get batch pool status error:', error);
      throw new Error(`Failed to get batch pool status: ${error.message}`);
    }
  }

  /**
   * 记录奖励池操作
   */
  private async recordPoolOperation(params: {
    annotation_id: string;
    operation_type: string;
    amount: number;
    source: string;
    description?: string;
    balance_before: number;
    balance_after: number;
    metadata?: any;
  }): Promise<void> {
    try {
      await this.db.sql`
        INSERT INTO reward_pool_operations (
          annotation_id,
          operation_type,
          amount,
          source,
          description,
          balance_before,
          balance_after,
          metadata,
          created_at
        ) VALUES (
          ${params.annotation_id},
          ${params.operation_type},
          ${params.amount},
          ${params.source},
          ${params.description || ''},
          ${params.balance_before},
          ${params.balance_after},
          ${JSON.stringify(params.metadata || {})},
          NOW()
        )
      `;
    } catch (error) {
      console.error('Record pool operation error:', error);
      // 不抛出错误，因为这是辅助操作
    }
  }

  /**
   * 初始化奖励池相关数据库表
   */
  async initializePoolTables(): Promise<boolean> {
    try {
      // 奖励池状态表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS reward_pools (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
          current_balance DECIMAL(10, 2) DEFAULT 0,
          reserved_amount DECIMAL(10, 2) DEFAULT 0,
          total_deposited DECIMAL(10, 2) DEFAULT 0,
          total_distributed DECIMAL(10, 2) DEFAULT 0,
          total_withdrawn DECIMAL(10, 2) DEFAULT 0,
          last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;

      // 奖励池配置表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS reward_pool_configurations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          annotation_id UUID NOT NULL UNIQUE REFERENCES annotations(id) ON DELETE CASCADE,
          initial_pool_size DECIMAL(10, 2) NOT NULL,
          min_pool_threshold DECIMAL(10, 2) DEFAULT 0,
          max_pool_size DECIMAL(10, 2) DEFAULT 1000,
          auto_refill_enabled BOOLEAN DEFAULT true,
          refill_threshold DECIMAL(3, 2) DEFAULT 0.2,
          commission_rate DECIMAL(3, 2) DEFAULT 0.3,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;

      // 奖励池操作记录表
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS reward_pool_operations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
          operation_type VARCHAR(20) NOT NULL CHECK (operation_type IN ('deposit', 'withdraw', 'reserve', 'release', 'distribute', 'refill')),
          amount DECIMAL(10, 2) NOT NULL,
          source VARCHAR(100) NOT NULL,
          description TEXT,
          balance_before DECIMAL(10, 2) NOT NULL,
          balance_after DECIMAL(10, 2) NOT NULL,
          metadata JSONB DEFAULT '{}'::jsonb,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;

      // 创建索引
      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_pools_annotation_id 
        ON reward_pools(annotation_id)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_annotation_id 
        ON reward_pool_operations(annotation_id)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_created_at 
        ON reward_pool_operations(created_at)
      `;

      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_reward_pool_operations_operation_type 
        ON reward_pool_operations(operation_type)
      `;

      console.log('Reward pool tables initialized successfully');
      return true;

    } catch (error) {
      console.error('Initialize pool tables error:', error);
      return false;
    }
  }

  /**
   * 清理缓存
   */
  clearCache(): void {
    this.poolStatusCache.clear();
  }

  /**
   * 获取缓存统计
   */
  getCacheStats(): { size: number; entries: string[] } {
    return {
      size: this.poolStatusCache.size,
      entries: Array.from(this.poolStatusCache.keys())
    };
  }
}

export { poolOperationSchema, poolConfigSchema };