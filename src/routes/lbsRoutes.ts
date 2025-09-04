import { Router, Request, Response } from 'express';
import { GeofenceService } from '../services/geofenceService';
import { RewardCalculationService } from '../services/rewardCalculationService';
import { AntiFraudService } from '../services/antiFraudService';
import { authMiddleware } from '../middleware/auth';
import {
  LocationReportRequest,

  ClaimRewardRequest,
  ClaimRewardResponse,
  LocationReport,
  LBSReward,
} from '../types/lbs';
import { db } from '../config/database';

// 扩展Request类型以包含user属性
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

const router = Router();

// 初始化服务
const geofenceService = new GeofenceService();
const rewardCalculationService = new RewardCalculationService();
const antiFraudService = new AntiFraudService();

// Public routes - no authentication required
/**
 * GET /api/v1/lbs/locations
 * 获取位置信息（公共接口）
 */
router.get('/locations', async (req: Request, res: Response) => {
  try {
    const { latitude, longitude, radius = 1000 } = req.query;

    if (!latitude || !longitude) {
      res.status(400).json({
        code: 400,
        message: '缺少位置参数',
        data: null,
      });
      return;
    }

    const lat = parseFloat(latitude as string);
    const lng = parseFloat(longitude as string);
    const radiusKm = parseFloat(radius as string) / 1000; // 转换为公里

    if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      res.status(400).json({
        code: 400,
        message: '位置坐标无效',
        data: null,
      });
      return;
    }

    // 添加查询超时保护
    const locationQueryTimeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Location query timeout')), 5000);
    });

    const locationQuery = db('annotations')
      .select(
        'id',
        'location',
        'smell_intensity',
        'content as description',
        'status',
        'created_at'
      )
      .where('status', 'active')
      .where(
        db.raw('(location->>?)::float BETWEEN ? AND ?', ['latitude', lat - 0.01, lat + 0.01])
      )
      .where(
        db.raw('(location->>?)::float BETWEEN ? AND ?', ['longitude', lng - 0.01, lng + 0.01])
      )
      .limit(50)
      .orderBy('created_at', 'desc');

    const locations = await Promise.race([locationQuery, locationQueryTimeout]);

    res.json({
      code: 200,
      message: '获取位置信息成功',
      data: {
        locations: Array.isArray(locations) ? locations.map(loc => {
          const location = typeof loc.location === 'string' ? JSON.parse(loc.location) : loc.location;
          return {
            id: loc.id,
            latitude: parseFloat(location.latitude),
            longitude: parseFloat(location.longitude),
            smellIntensity: loc.smell_intensity,
            description: loc.description,
            status: loc.status,
            createdAt: loc.created_at,
          };
        }) : [],
        count: Array.isArray(locations) ? locations.length : 0,
        radius: parseFloat(radius as string),
      },
    });
  } catch (error) {
    console.error('获取位置信息失败:', error);
    res.status(500).json({
      code: 500,
      message: '获取位置信息失败',
      data: null,
    });
  }
});

// Protected routes - authentication required
router.use(authMiddleware);

/**
 * POST /api/v1/lbs/report-location
 * 位置上报接口
 */
router.post('/report-location', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id; // 从JWT中获取用户ID
    if (!userId) {
      res.status(401).json({
        code: 401,
        message: '用户未登录',
        data: null,
      });
      return;
    }

    const locationData: LocationReportRequest = req.body;

    // 验证请求数据
    const validation = validateLocationRequest(locationData);
    if (!validation.valid) {
      res.status(400).json({
        code: 400,
        message: validation.message,
        data: null,
      });
      return;
    }

    // 创建位置记录
    const locationReport: LocationReport = {
      id: '', // 将由数据库生成
      userId,
      latitude: locationData.latitude,
      longitude: locationData.longitude,
      accuracy: locationData.accuracy,
      timestamp: new Date(),
      reportType: 'manual',
      ...(locationData.deviceInfo && { deviceInfo: locationData.deviceInfo }),
    };

    // 1. 防作弊检测
    const fraudResult = await antiFraudService.detectFraud(
      userId,
      locationReport,
      '', // 此时还没有特定的标注ID
    );

    if (fraudResult.isFraudulent) {
      res.status(403).json({
        code: 403,
        message: '检测到可疑行为',
        data: {
          fraudScore: fraudResult.fraudScore,
          reasons: fraudResult.reasons,
        },
      });
      return;
    }

    // 2. 保存位置记录
    const savedLocation = await saveLocationReport(locationReport);

    // 3. 检测地理围栏触发（添加超时保护）
    let geofenceTriggers: Array<{
      annotationId: string;
      distance: number;
      triggered: boolean;
    }> = [];
    try {
      const geofenceTimeout = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Geofence check timeout')), 8000);
      });
      
      const geofencePromise = geofenceService.checkGeofenceTriggers(
        locationData.latitude,
        locationData.longitude,
        userId,
      );
      
      geofenceTriggers = (await Promise.race([geofencePromise, geofenceTimeout])) as Array<{
        annotationId: string;
        distance: number;
        triggered: boolean;
      }>;
    } catch (error) {
      console.error('地理围栏检测超时或失败:', error);
      // 超时时返回空数组，允许位置上报继续进行
      geofenceTriggers = [];
    }

    const rewards: Array<{
      annotationId: string;
      amount: number;
      rewardId: string;
      distance: number;
    }> = [];

    // 处理每个触发的地理围栏
    for (const trigger of geofenceTriggers) {
      if (!trigger.triggered) {
        continue;
      }

      // 再次进行针对特定标注的防作弊检测
      const specificFraudResult = await antiFraudService.detectFraud(
        userId,
        locationReport,
        trigger.annotationId,
      );

      if (specificFraudResult.isFraudulent) {
        console.log(`用户${userId}在标注${trigger.annotationId}处检测到作弊行为`);
        continue;
      }

      // 计算奖励
      const rewardAmount = await rewardCalculationService.calculateRewardWithDB(
        trigger.annotationId,
        userId,
        'discovery', // 默认为发现奖励
      );

      if (rewardAmount > 0) {
        // 创建奖励记录
        const reward = await createRewardRecord({
          userId,
          annotationId: trigger.annotationId,
          amount: rewardAmount,
          rewardType: 'discovery',
          locationReportId: savedLocation.id,
        });

        rewards.push({
          annotationId: trigger.annotationId,
          amount: rewardAmount,
          rewardId: reward.id,
          distance: trigger.distance,
        });
      }
    }

    res.json({
      code: 200,
      message: '位置上报成功',
      data: {
        locationId: savedLocation.id,
        triggeredGeofences: geofenceTriggers.length,
        rewards,
        totalRewardAmount: rewards.reduce((sum, r) => sum + r.amount, 0),
      },
    });
  } catch (error) {
    console.error('位置上报失败:', error);
    res.status(500).json({
      code: 500,
      message: '位置上报失败',
      data: null,
    });
  }
});

/**
 * GET /api/v1/lbs/rewards
 * 查询用户奖励记录
 */
router.get('/rewards', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const { page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    const rewards = await db('lbs_rewards as r')
      .leftJoin('annotations as a', 'r.annotation_id', 'a.id')
      .where('r.user_id', userId)
      .select(
        'r.*',
        'a.description as annotation_description',
      )
      .orderBy('r.discovered_at', 'desc')
      .limit(Number(limit))
      .offset(offset);

    const formattedRewards = rewards.map((reward: any) => ({
      id: reward.id,
      amount: parseFloat(reward.reward_amount),
      rewardType: reward.reward_type,
      status: reward.status,
      discoveredAt: reward.discovered_at,
      annotation: {
        id: reward.annotation_id,
        description: reward.annotation_description,
      },
    }));

    return res.json({
      rewards: formattedRewards,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: formattedRewards.length,
      },
    });
  } catch (error) {
    console.error('获取奖励记录失败:', error);
    return res.status(500).json({ error: '获取奖励记录失败' });
  }
});

/**
 * POST /api/v1/lbs/claim-reward
 * 领取奖励接口
 */
router.post('/claim-reward', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({
        code: 401,
        message: '用户未登录',
        data: null,
      });
      return;
    }

    const { rewardIds }: ClaimRewardRequest = req.body;

    if (!rewardIds || !Array.isArray(rewardIds) || rewardIds.length === 0) {
      res.status(400).json({
        code: 400,
        message: '请选择要领取的奖励',
        data: null,
      });
      return;
    }

    // 验证奖励记录
    const rewards = await db('lbs_rewards')
      .whereIn('id', rewardIds)
      .where('user_id', userId)
      .where('status', 'verified')
      .select('*');

    const rewardList = Array.isArray(rewards) ? rewards : [];
    if (rewardList.length === 0) {
      res.status(404).json({
        code: 404,
        message: '未找到可领取的奖励',
        data: null,
      });
      return;
    }

    // 验证所有奖励都属于当前用户且状态为verified
    if (rewardList.length !== rewardIds.length) {
      res.status(400).json({
        code: 400,
        message: '部分奖励无法领取',
        data: null,
      });
      return;
    }

    // 计算总金额
    const totalAmount: number = (rewardList as any[]).reduce((sum: number, r) => sum + parseFloat((r as Record<string, any>)['amount']), 0);

    // 更新奖励状态
    await db('lbs_rewards')
      .whereIn('id', rewardIds)
      .where('user_id', userId)
      .update({
        status: 'claimed',
        claimed_at: db.fn.now(),
        updated_at: db.fn.now(),
      });

    // 更新用户钱包余额
    await db('users')
      .where('id', userId)
      .increment('wallet_balance', totalAmount)
      .update('updated_at', db.fn.now());

    // 创建钱包交易记录
    await db('wallet_transactions').insert({
      user_id: userId,
      type: 'reward_claim',
      amount: totalAmount,
      description: '领取LBS奖励',
      reference_type: 'lbs_rewards',
      reference_ids: JSON.stringify(rewardIds),
      status: 'completed',
    });

    const response: ClaimRewardResponse = {
      success: true,
      amount: totalAmount,
      claimedRewards: rewardList.map(r => formatRewardRecord(r as Record<string, any>)),
      newWalletBalance: await getUserWalletBalance(userId),
    };

    res.json({
      code: 200,
      message: '奖励领取成功',
      data: response,
    });
  } catch (error) {
    console.error('领取奖励失败:', error);
    res.status(500).json({
      code: 500,
      message: '领取奖励失败',
      data: null,
    });
  }
});

/**
 * GET /api/v1/lbs/stats
 * 获取用户LBS统计信息
 */
router.get('/stats', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: '用户未认证' });
    }

    const stats = await db('lbs_rewards')
      .where({ user_id: userId, status: 'verified' })
      .select(
        db.raw('COUNT(*) as total_rewards'),
        db.raw('COALESCE(SUM(amount), 0) as total_amount'),
        db.raw('COUNT(CASE WHEN created_at >= NOW() - INTERVAL \'30 days\' THEN 1 END) as monthly_rewards'),
        db.raw('COALESCE(SUM(CASE WHEN created_at >= NOW() - INTERVAL \'30 days\' THEN amount ELSE 0 END), 0) as monthly_amount'),
      )
      .first();

    return res.json({
      totalRewards: parseInt((stats as any)?.total_rewards || '0'),
      totalAmount: parseFloat((stats as any)?.total_amount || '0'),
      monthlyRewards: parseInt((stats as any)?.monthly_rewards || '0'),
      monthlyAmount: parseFloat((stats as any)?.monthly_amount || '0'),
    });
  } catch (error) {
    console.error('获取LBS统计失败:', error);
    return res.status(500).json({ error: '获取统计失败' });
  }
});

// 辅助函数

/**
 * 验证位置上报请求
 */
function validateLocationRequest(data: LocationReportRequest): { valid: boolean; message?: string } {
  if (!data.latitude || !data.longitude) {
    return { valid: false, message: '缺少位置坐标' };
  }

  if (data.latitude < -90 || data.latitude > 90) {
    return { valid: false, message: '纬度范围无效' };
  }

  if (data.longitude < -180 || data.longitude > 180) {
    return { valid: false, message: '经度范围无效' };
  }

  if (data.accuracy && data.accuracy > 1000) {
    return { valid: false, message: 'GPS精度过低' };
  }

  return { valid: true };
}

/**
 * 保存位置记录
 */
async function saveLocationReport(locationReport: LocationReport): Promise<LocationReport> {
  const result = await db('location_reports')
    .insert({
      user_id: locationReport.userId,
      latitude: locationReport.latitude,
      longitude: locationReport.longitude,
      accuracy: locationReport.accuracy,
      timestamp: locationReport.timestamp,
      device_info: JSON.stringify(locationReport.deviceInfo || {}),
      report_type: locationReport.reportType,
    })
    .returning('id');

  return {
    ...locationReport,
    id: result[0].id,
  };
}

/**
 * 创建奖励记录
 */
async function createRewardRecord(data: {
  userId: string;
  annotationId: string;
  amount: number;
  rewardType: LBSReward['rewardType'];
  locationReportId: string;
}): Promise<LBSReward> {
  const result = await db('lbs_rewards')
    .insert({
      user_id: data.userId,
      annotation_id: data.annotationId,
      amount: data.amount,
      reward_type: data.rewardType,
      location_report_id: data.locationReportId,
      status: 'verified',
    })
    .returning('*');

  return formatRewardRecord(result[0]);
}

/**
 * 格式化奖励记录
 */
function formatRewardRecord(row: Record<string, any>): LBSReward {
  const reward: LBSReward = {
    id: row['id'],
    userId: row['user_id'],
    annotationId: row['annotation_id'],
    amount: parseFloat(row['amount']),
    rewardType: row['reward_type'],
    status: row['status'],
    locationReportId: row['location_report_id'],
    createdAt: new Date(row['created_at']),
    updatedAt: new Date(row['updated_at']),
  } as LBSReward;

  if (row['claimed_at']) {
    reward.claimedAt = new Date(row['claimed_at']);
  }

  return reward;
}

/**
 * 获取用户钱包余额
 */
async function getUserWalletBalance(userId: string): Promise<number> {
  const result = await db('users')
    .where('id', userId)
    .select('wallet_balance')
    .first();

  return result ? parseFloat(result.wallet_balance) : 0;
}

export default router;
