import { RewardDistributionEngine, RewardDistributionResult } from '../services/rewardDistributionEngine';
import { RewardPoolManager, RewardPoolStatus, PoolAnalytics } from '../services/rewardPoolManager';
import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

// 验证模式
const distributeRewardSchema = z.object({
  annotation_id: z.string().uuid(),
  user_location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180)
  }),
  trigger_timestamp: z.string().datetime().optional()
});

const createPoolSchema = z.object({
  annotation_id: z.string().uuid(),
  initial_pool_size: z.number().min(0.01),
  min_pool_threshold: z.number().min(0).optional(),
  max_pool_size: z.number().min(0).optional(),
  auto_refill_enabled: z.boolean().optional(),
  refill_threshold: z.number().min(0).max(1).optional(),
  commission_rate: z.number().min(0).max(1).optional()
});

const poolOperationSchema = z.object({
  annotation_id: z.string().uuid(),
  amount: z.number().min(0.01),
  source: z.string(),
  description: z.string().optional()
});

const rewardConfigurationSchema = z.object({
  annotation_id: z.string().uuid(),
  base_fee: z.number().min(0).optional(),
  time_decay_factor: z.number().min(0).max(1).optional(),
  user_level_multiplier: z.number().min(0.1).max(5).optional(),
  max_rewards_per_day: z.number().min(1).max(100).optional(),
  min_reward_amount: z.number().min(0.01).optional()
});

const historyQuerySchema = z.object({
  user_id: z.string().uuid().optional(),
  annotation_id: z.string().uuid().optional(),
  limit: z.number().min(1).max(100).default(20),
  offset: z.number().min(0).default(0),
  start_date: z.string().datetime().optional(),
  end_date: z.string().datetime().optional()
});

/**
 * 初始化奖励系统数据库表
 */
export const initializeRewardTables: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user || user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'Admin access required'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const rewardEngine = new RewardDistributionEngine(env);
    const poolManager = new RewardPoolManager(env);

    // 初始化所有相关表
    const engineResult = await rewardEngine.initializeRewardTables();
    const poolResult = await poolManager.initializePoolTables();

    if (engineResult && poolResult) {
      return new Response(JSON.stringify({
        success: true,
        message: 'Reward system tables initialized successfully',
        details: {
          reward_distribution_tables: engineResult,
          reward_pool_tables: poolResult
        }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({
        error: 'Initialization failed',
        message: 'Failed to initialize some reward system tables',
        details: {
          reward_distribution_tables: engineResult,
          reward_pool_tables: poolResult
        }
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

  } catch (error) {
    console.error('Initialize reward tables error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to initialize reward tables: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 分发奖励（用户进入地理围栏时触发）
 */
export const distributeReward: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = distributeRewardSchema.parse(body);

    const rewardEngine = new RewardDistributionEngine(env);
    const result: RewardDistributionResult = await rewardEngine.distributeReward({
      user_id: user.id,
      annotation_id: validatedData.annotation_id,
      user_location: validatedData.user_location,
      trigger_timestamp: validatedData.trigger_timestamp
    });

    const statusCode = result.success ? 200 : 400;

    return new Response(JSON.stringify({
      success: result.success,
      data: result,
      message: result.distribution_reason
    }), {
      status: statusCode,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Distribute reward error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to distribute reward: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 创建奖励池
 */
export const createRewardPool: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = createPoolSchema.parse(body);

    const poolManager = new RewardPoolManager(env);
    const poolStatus: RewardPoolStatus = await poolManager.createRewardPool(validatedData);

    return new Response(JSON.stringify({
      success: true,
      data: poolStatus,
      message: `Reward pool created successfully for annotation ${validatedData.annotation_id}`
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Create reward pool error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to create reward pool: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励池状态
 */
export const getRewardPoolStatus: RouteHandler = async (request, env) => {
  try {
    const url = new URL(request.url);
    const annotation_id = url.searchParams.get('annotation_id');

    if (!annotation_id) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'annotation_id parameter is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证UUID格式
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(annotation_id)) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Invalid annotation_id format'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const poolManager = new RewardPoolManager(env);
    const poolStatus: RewardPoolStatus = await poolManager.getPoolStatus(annotation_id);

    return new Response(JSON.stringify({
      success: true,
      data: poolStatus,
      message: 'Pool status retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get reward pool status error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get pool status: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 向奖励池存入资金
 */
export const depositToRewardPool: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = poolOperationSchema.parse(body);

    const poolManager = new RewardPoolManager(env);
    const poolStatus: RewardPoolStatus = await poolManager.depositToPool({
      ...validatedData,
      source: validatedData.source || `user_${user.id}`
    });

    return new Response(JSON.stringify({
      success: true,
      data: poolStatus,
      message: `Successfully deposited ${validatedData.amount} to reward pool`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Deposit to reward pool error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to deposit to reward pool: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 从奖励池提取资金
 */
export const withdrawFromRewardPool: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = poolOperationSchema.parse(body);

    // TODO: 添加权限检查，确保用户只能从自己的标注奖励池中提取
    // const hasPermission = await checkUserPermissionForAnnotation(user.id, validatedData.annotation_id);

    const poolManager = new RewardPoolManager(env);
    const poolStatus: RewardPoolStatus = await poolManager.withdrawFromPool({
      ...validatedData,
      source: validatedData.source || `user_${user.id}`
    });

    return new Response(JSON.stringify({
      success: true,
      data: poolStatus,
      message: `Successfully withdrawn ${validatedData.amount} from reward pool`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Withdraw from reward pool error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to withdraw from reward pool: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励历史记录
 */
export const getRewardHistory: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const queryParams = {
      user_id: url.searchParams.get('user_id') || undefined,
      annotation_id: url.searchParams.get('annotation_id') || undefined,
      limit: parseInt(url.searchParams.get('limit') || '20'),
      offset: parseInt(url.searchParams.get('offset') || '0'),
      start_date: url.searchParams.get('start_date') || undefined,
      end_date: url.searchParams.get('end_date') || undefined
    };

    const validatedParams = historyQuerySchema.parse(queryParams);

    // 如果不是管理员，只能查看自己的奖励历史
    if (user.role !== 'admin' && validatedParams.user_id && validatedParams.user_id !== user.id) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'You can only access your own reward history'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 如果没有指定用户ID且不是管理员，默认查看自己的历史
    if (!validatedParams.user_id && user.role !== 'admin') {
      validatedParams.user_id = user.id;
    }

    const rewardEngine = new RewardDistributionEngine(env);
    const history = await rewardEngine.getRewardHistory(validatedParams);

    return new Response(JSON.stringify({
      success: true,
      data: history,
      pagination: {
        limit: validatedParams.limit,
        offset: validatedParams.offset,
        has_more: history.length === validatedParams.limit
      },
      message: 'Reward history retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get reward history error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid query parameters',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get reward history: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励统计
 */
export const getRewardStatistics: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const annotation_id = url.searchParams.get('annotation_id') || undefined;
    const start_date = url.searchParams.get('start_date') || undefined;
    const end_date = url.searchParams.get('end_date') || undefined;

    const rewardEngine = new RewardDistributionEngine(env);
    const statistics = await rewardEngine.getRewardStatistics({
      annotation_id,
      start_date,
      end_date
    });

    return new Response(JSON.stringify({
      success: true,
      data: statistics,
      message: 'Reward statistics retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get reward statistics error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get reward statistics: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 配置奖励参数
 */
export const configureReward: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = rewardConfigurationSchema.parse(body);

    // TODO: 添加权限检查，确保用户只能配置自己的标注
    // const hasPermission = await checkUserPermissionForAnnotation(user.id, validatedData.annotation_id);

    const rewardEngine = new RewardDistributionEngine(env);
    const configuration = await rewardEngine.configureReward(validatedData);

    return new Response(JSON.stringify({
      success: true,
      data: configuration,
      message: `Reward configuration updated for annotation ${validatedData.annotation_id}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Configure reward error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to configure reward: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励池分析数据
 */
export const getPoolAnalytics: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const annotation_id = url.searchParams.get('annotation_id');
    const days = parseInt(url.searchParams.get('days') || '30');

    if (!annotation_id) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'annotation_id parameter is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证UUID格式
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(annotation_id)) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Invalid annotation_id format'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const poolManager = new RewardPoolManager(env);
    const analytics: PoolAnalytics = await poolManager.getPoolAnalytics(annotation_id, days);

    return new Response(JSON.stringify({
      success: true,
      data: analytics,
      message: 'Pool analytics retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get pool analytics error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get pool analytics: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励池操作历史
 */
export const getPoolOperationHistory: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const annotation_id = url.searchParams.get('annotation_id');
    const limit = parseInt(url.searchParams.get('limit') || '50');
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const operation_type = url.searchParams.get('operation_type') || undefined;
    const start_date = url.searchParams.get('start_date') || undefined;
    const end_date = url.searchParams.get('end_date') || undefined;

    if (!annotation_id) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'annotation_id parameter is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const poolManager = new RewardPoolManager(env);
    const history = await poolManager.getPoolOperationHistory({
      annotation_id,
      limit,
      offset,
      operation_type,
      start_date,
      end_date
    });

    return new Response(JSON.stringify({
      success: true,
      data: history,
      pagination: {
        limit,
        offset,
        has_more: history.length === limit
      },
      message: 'Pool operation history retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get pool operation history error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get pool operation history: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 清理奖励系统缓存 (管理员专用)
 */
export const clearRewardCaches: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user || user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'Admin access required'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const rewardEngine = new RewardDistributionEngine(env);
    const poolManager = new RewardPoolManager(env);

    const engineStats = rewardEngine.getCacheStats();
    const poolStats = poolManager.getCacheStats();

    rewardEngine.clearCache();
    poolManager.clearCache();

    return new Response(JSON.stringify({
      success: true,
      data: {
        before_clear: {
          reward_engine: engineStats,
          pool_manager: poolStats
        },
        cleared_entries: {
          reward_engine: engineStats.size,
          pool_manager: poolStats.size
        }
      },
      message: 'Reward system caches cleared successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Clear reward caches error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to clear reward caches: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * 获取奖励系统健康状态
 */
export const getRewardSystemHealth: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user || user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'Admin access required'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const rewardEngine = new RewardDistributionEngine(env);
    const poolManager = new RewardPoolManager(env);

    // 获取缓存统计
    const engineCacheStats = rewardEngine.getCacheStats();
    const poolCacheStats = poolManager.getCacheStats();

    // 获取数据库统计（简单检查）
    const db = rewardEngine['db']; // 访问私有属性进行健康检查

    const healthStats = await db.sql`
      SELECT 
        (SELECT COUNT(*) FROM reward_distributions WHERE status = 'completed') as total_rewards_distributed,
        (SELECT COUNT(DISTINCT user_id) FROM reward_distributions WHERE status = 'completed') as unique_reward_recipients,
        (SELECT COUNT(*) FROM reward_pools) as total_reward_pools,
        (SELECT SUM(current_balance) FROM reward_pools) as total_pool_balance
    `;

    const stats = healthStats[0] || {
      total_rewards_distributed: 0,
      unique_reward_recipients: 0,
      total_reward_pools: 0,
      total_pool_balance: 0
    };

    return new Response(JSON.stringify({
      success: true,
      data: {
        system_status: 'healthy',
        timestamp: new Date().toISOString(),
        cache_statistics: {
          reward_engine: engineCacheStats,
          pool_manager: poolCacheStats
        },
        database_statistics: {
          total_rewards_distributed: parseInt(stats.total_rewards_distributed),
          unique_reward_recipients: parseInt(stats.unique_reward_recipients),
          total_reward_pools: parseInt(stats.total_reward_pools),
          total_pool_balance: parseFloat(stats.total_pool_balance) || 0
        },
        version: '1.0.0'
      },
      message: 'Reward system health status retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get reward system health error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get reward system health: ${error.message}`,
      system_status: 'unhealthy',
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};