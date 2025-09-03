import { Request, Response, NextFunction } from 'express';
import { db } from '@/config/database';
import {
  createValidationError,
  createNotFoundError,
  createConflictError,
} from '@/middleware/errorHandler';
import { asyncHandler } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { cacheService } from '@/config/redis';
import { v4 as uuidv4 } from 'uuid';

// Interfaces
interface LocationData {
  latitude: number;
  longitude: number;
  accuracy?: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  locationName?: string;
  address?: string;
}

interface CheckinData extends LocationData {
  checkinType?: 'manual' | 'auto' | 'scheduled';
  notes?: string;
}

interface RewardData {
  userId: string;
  rewardType: 'checkin' | 'distance' | 'exploration' | 'social' | 'annotation' | 'payment' | 'referral' | 'achievement';
  rewardCategory: string;
  points: number;
  coins?: number;
  cashValue?: number;
  description: string;
  sourceId?: string;
  sourceType?: string;
  locationId?: string;
  latitude?: number;
  longitude?: number;
  multiplier?: number;
}

// Update user location
export const updateUserLocation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { latitude, longitude, accuracy, altitude, speed, heading, locationName, address } = req.body as LocationData;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  if (!latitude || !longitude) {
    throw createValidationError('location', '经纬度不能为空');
  }

  // Validate coordinates
  if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
    throw createValidationError('coordinates', '经纬度格式不正确');
  }

  try {
    // Set all previous locations as not current
    await db('user_locations')
      .where({ user_id: userId })
      .update({ is_current: false });

    // Insert new location
    const [location] = await db('user_locations')
      .insert({
        id: uuidv4(),
        user_id: userId,
        latitude,
        longitude,
        location_name: locationName,
        address,
        accuracy,
        altitude,
        speed,
        heading,
        location_type: 'manual',
        is_current: true,
      })
      .returning('*');

    // Update user stats
    await db('user_stats')
      .insert({
        id: uuidv4(),
        user_id: userId,
        last_location_update: new Date(),
      })
      .onConflict('user_id')
      .merge({
        last_location_update: new Date(),
        updated_at: new Date(),
      });

    // Cache current location
    await cacheService.set(
      `user_location:${userId}`,
      JSON.stringify({ latitude, longitude, locationName, address }),
      3600, // 1 hour
    );

    logger.info('用户位置更新成功', { userId, latitude, longitude });

    res.json({
      success: true,
      message: '位置更新成功',
      data: {
        location,
      },
    });
  } catch (error) {
    logger.error('位置更新失败', { userId, error });
    throw error;
  }
});

// User check-in
export const checkinUser = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { latitude, longitude, locationName, address, checkinType = 'manual', notes } = req.body as CheckinData;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  if (!latitude || !longitude) {
    throw createValidationError('location', '经纬度不能为空');
  }

  try {
    // Check if user already checked in today at this location
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Simple distance check for SQLite (approximate)
    const existingCheckin = await db('checkin_records')
      .where('user_id', userId)
      .where('created_at', '>=', today)
      .whereRaw('ABS(latitude - ?) < 0.001 AND ABS(longitude - ?) < 0.001', [latitude, longitude])
      .first();

    if (existingCheckin) {
      throw createConflictError('今天已在此位置签到过了');
    }

    // Get user's consecutive checkin days
    const userStats = await db('user_stats')
      .where('user_id', userId)
      .first();

    let consecutiveDays = 1;
    let bonusMultiplier = 1.0;

    if (userStats?.last_checkin_at) {
      const lastCheckin = new Date(userStats.last_checkin_at);
      const yesterday = new Date(today);
      yesterday.setDate(yesterday.getDate() - 1);

      if (lastCheckin >= yesterday) {
        consecutiveDays = (userStats.consecutive_checkins || 0) + 1;
        // Bonus multiplier for consecutive checkins
        bonusMultiplier = Math.min(1 + (consecutiveDays - 1) * 0.1, 3.0);
      }
    }

    // Check if this is first time at this location
    const isFirstTime = !(await db('checkin_records')
      .where('user_id', userId)
      .whereRaw('ABS(latitude - ?) < 0.005 AND ABS(longitude - ?) < 0.005', [latitude, longitude])
      .first());

    if (isFirstTime) {
      bonusMultiplier *= 1.5; // 50% bonus for new locations
    }

    // Check for location hotspots (simplified for SQLite)
    const hotspot = await db('location_hotspots')
      .where('is_active', true)
      .whereRaw('ABS(latitude - ?) < 0.01 AND ABS(longitude - ?) < 0.01', [latitude, longitude])
      .first();

    if (hotspot) {
      bonusMultiplier *= hotspot.reward_multiplier;
    }

    // Calculate points earned
    const basePoints = 10;
    const pointsEarned = Math.floor(basePoints * bonusMultiplier);

    // Create checkin record
    const [checkin] = await db('checkin_records')
      .insert({
        id: uuidv4(),
        user_id: userId,
        latitude,
        longitude,
        location_name: locationName,
        address,
        checkin_type: checkinType,
        points_earned: pointsEarned,
        bonus_multiplier: bonusMultiplier,
        consecutive_days: consecutiveDays,
        is_first_time: isFirstTime,
        notes,
      })
      .returning('*');

    // Create reward record
    await createRewardRecord({
      userId,
      rewardType: 'checkin',
      rewardCategory: 'daily_checkin',
      points: pointsEarned,
      description: `签到奖励${isFirstTime ? '(首次到访)' : ''}${hotspot ? `(${hotspot.name})` : ''}`,
      sourceId: checkin.id,
      sourceType: 'checkin',
      latitude,
      longitude,
      multiplier: bonusMultiplier,
    });

    // Update user stats
    await db('user_stats')
      .insert({
        id: uuidv4(),
        user_id: userId,
        total_points: pointsEarned,
        available_points: pointsEarned,
        total_checkins: 1,
        consecutive_checkins: consecutiveDays,
        max_consecutive_checkins: consecutiveDays,
        last_checkin_at: new Date(),
      })
      .onConflict('user_id')
      .merge({
        total_points: db.raw('user_stats.total_points + ?', [pointsEarned]),
        available_points: db.raw('user_stats.available_points + ?', [pointsEarned]),
        total_checkins: db.raw('user_stats.total_checkins + 1'),
        consecutive_checkins: consecutiveDays,
        max_consecutive_checkins: db.raw('GREATEST(user_stats.max_consecutive_checkins, ?)', [consecutiveDays]),
        last_checkin_at: new Date(),
        updated_at: new Date(),
      });

    // Update hotspot stats if applicable
    if (hotspot) {
      await db('location_hotspots')
        .where('id', hotspot.id)
        .increment('checkin_count', 1)
        .increment('popularity_score', Math.floor(pointsEarned / 2));
    }

    logger.info('用户签到成功', { userId, checkinId: checkin.id, pointsEarned, consecutiveDays });

    res.json({
      success: true,
      message: '签到成功',
      data: {
        checkin,
        pointsEarned,
        consecutiveDays,
        bonusMultiplier,
        isFirstTime,
        hotspot: hotspot ? { name: hotspot.name, category: hotspot.category } : null,
      },
    });
  } catch (error) {
    logger.error('签到失败', { userId, error });
    throw error;
  }
});

// Find nearby users
export const findNearbyUsers = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { latitude, longitude, radius = 1000 } = req.query;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  if (!latitude || !longitude) {
    throw createValidationError('location', '经纬度不能为空');
  }

  try {
    // Find nearby users (simplified for SQLite)
    const radiusInDegrees = parseInt(radius as string) / 111000; // Approximate conversion
    const nearbyUsers = await db('user_locations')
      .join('users', 'user_locations.user_id', 'users.id')
      .leftJoin('user_stats', 'users.id', 'user_stats.user_id')
      .select(
        'users.id',
        'users.username',
        'users.display_name',
        'users.avatar_url',
        'user_locations.latitude',
        'user_locations.longitude',
        'user_stats.level_id',
        'user_stats.total_points',
      )
      .where('users.status', 'active')
      .where('user_locations.is_current', true)
      .whereNot('users.id', userId)
      .whereRaw('ABS(user_locations.latitude - ?) < ? AND ABS(user_locations.longitude - ?) < ?', [
        parseFloat(latitude as string), radiusInDegrees,
        parseFloat(longitude as string), radiusInDegrees,
      ])
      .limit(50);

    // Calculate approximate distance and update nearby users records
    for (const nearbyUser of nearbyUsers) {
      const distance = Math.sqrt(
        Math.pow((nearbyUser.latitude - parseFloat(latitude as string)) * 111000, 2) +
        Math.pow((nearbyUser.longitude - parseFloat(longitude as string)) * 111000, 2),
      );

      // Check if record exists
      const existingRecord = await db('nearby_users')
        .where({ user_id: userId, nearby_user_id: nearbyUser.id })
        .first();

      if (existingRecord) {
        await db('nearby_users')
          .where({ user_id: userId, nearby_user_id: nearbyUser.id })
          .update({
            distance,
            latitude: parseFloat(latitude as string),
            longitude: parseFloat(longitude as string),
            nearby_latitude: nearbyUser.latitude,
            nearby_longitude: nearbyUser.longitude,
            last_seen_at: new Date(),
          });
      } else {
        await db('nearby_users')
          .insert({
            id: uuidv4(),
            user_id: userId,
            nearby_user_id: nearbyUser.id,
            distance,
            latitude: parseFloat(latitude as string),
            longitude: parseFloat(longitude as string),
            nearby_latitude: nearbyUser.latitude,
            nearby_longitude: nearbyUser.longitude,
            last_seen_at: new Date(),
          });
      }

      // Add distance to the user object for response
      nearbyUser.distance = distance;
    }

    logger.info('附近用户查找成功', { userId, count: nearbyUsers.length });

    res.json({
      success: true,
      message: '附近用户查找成功',
      data: {
        users: nearbyUsers,
        total: nearbyUsers.length,
      },
    });
  } catch (error) {
    logger.error('附近用户查找失败', { userId, error });
    throw error;
  }
});

// Get user rewards
export const getUserRewards = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { page = 1, limit = 20, status, rewardType } = req.query;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  try {
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);

    let query = db('reward_records')
      .where('user_id', userId);

    if (status) {
      query = query.where('status', status as string);
    }

    if (rewardType) {
      query = query.where('reward_type', rewardType as string);
    }

    const [rewards, totalCount] = await Promise.all([
      query
        .clone()
        .orderBy('created_at', 'desc')
        .limit(parseInt(limit as string))
        .offset(offset),
      query.clone().count('* as count').first(),
    ]);

    res.json({
      success: true,
      message: '奖励记录获取成功',
      data: {
        rewards,
        pagination: {
          page: parseInt(page as string),
          limit: parseInt(limit as string),
          total: parseInt(totalCount?.['count'] as string || '0'),
          totalPages: Math.ceil(parseInt(totalCount?.['count'] as string || '0') / parseInt(limit as string)),
        },
      },
    });
  } catch (error) {
    logger.error('奖励记录获取失败', { userId, error });
    throw error;
  }
});

// Claim reward
export const claimReward = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { rewardId } = req.params;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  try {
    // Find the reward
    const reward = await db('reward_records')
      .where({ id: rewardId, user_id: userId, status: 'pending' })
      .first();

    if (!reward) {
      throw createNotFoundError('奖励不存在或已领取');
    }

    // Check if reward is expired
    if (reward.expires_at && new Date(reward.expires_at) < new Date()) {
      await db('reward_records')
        .where('id', rewardId)
        .update({ status: 'expired' });

      throw createValidationError('reward', '奖励已过期');
    }

    // Update reward status
    await db('reward_records')
      .where('id', rewardId)
      .update({
        status: 'claimed',
        claimed_at: new Date(),
      });

    // Update user stats
    await db('user_stats')
      .where('user_id', userId)
      .increment('available_points', reward.points)
      .increment('available_coins', reward.coins || 0);

    logger.info('奖励领取成功', { userId, rewardId, points: reward.points });

    res.json({
      success: true,
      message: '奖励领取成功',
      data: {
        reward,
        pointsEarned: reward.points,
        coinsEarned: reward.coins || 0,
      },
    });
  } catch (error) {
    logger.error('奖励领取失败', { userId, rewardId, error });
    throw error;
  }
});

// Get user stats
export const getUserStats = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw createValidationError('auth', '用户未认证');
  }

  try {
    const stats = await db('user_stats')
      .where('user_id', userId)
      .first();

    if (!stats) {
      // Create initial stats if not exists
      const [newStats] = await db('user_stats')
        .insert({
          id: uuidv4(),
          user_id: userId,
        })
        .returning('*');

      res.json({
        success: true,
        message: '用户统计获取成功',
        data: { stats: newStats },
      });
      return;
    }

    // Get recent checkins
    const recentCheckins = await db('checkin_records')
      .where('user_id', userId)
      .orderBy('created_at', 'desc')
      .limit(5);

    // Get pending rewards count
    const pendingRewardsCount = await db('reward_records')
      .where({ user_id: userId, status: 'pending' })
      .count('* as count')
      .first();

    res.json({
      success: true,
      message: '用户统计获取成功',
      data: {
        stats,
        recentCheckins,
        pendingRewardsCount: parseInt(pendingRewardsCount?.['count'] as string || '0'),
      },
    });
  } catch (error) {
    logger.error('用户统计获取失败', { userId, error });
    throw error;
  }
});

// Get location hotspots
export const getLocationHotspots = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { latitude, longitude, radius = 5000, category } = req.query;

  try {
    let query = db('location_hotspots')
      .where('is_active', true);

    if (latitude && longitude) {
      const radiusInDegrees = parseInt(radius as string) / 111000; // Approximate conversion
      query = query
        .whereRaw('ABS(latitude - ?) < ? AND ABS(longitude - ?) < ?', [
          parseFloat(latitude as string), radiusInDegrees,
          parseFloat(longitude as string), radiusInDegrees,
        ]);
    }

    if (category) {
      query = query.where('category', category as string);
    }

    const hotspots = await query.limit(50);

    res.json({
      success: true,
      message: '热点位置获取成功',
      data: {
        hotspots,
        total: hotspots.length,
      },
    });
  } catch (error) {
    logger.error('热点位置获取失败', { error });
    throw error;
  }
});

// Helper function to create reward record
async function createRewardRecord(rewardData: RewardData): Promise<void> {
  await db('reward_records')
    .insert({
      id: uuidv4(),
      user_id: rewardData.userId,
      reward_type: rewardData.rewardType,
      reward_category: rewardData.rewardCategory,
      points: rewardData.points,
      coins: rewardData.coins || 0,
      cash_value: rewardData.cashValue || 0,
      description: rewardData.description,
      source_id: rewardData.sourceId,
      source_type: rewardData.sourceType,
      location_id: rewardData.locationId,
      latitude: rewardData.latitude,
      longitude: rewardData.longitude,
      multiplier: rewardData.multiplier || 1.0,
      status: 'pending',
    });
}

export default {
  updateUserLocation,
  checkinUser,
  findNearbyUsers,
  getUserRewards,
  claimReward,
  getUserStats,
  getLocationHotspots,
};
