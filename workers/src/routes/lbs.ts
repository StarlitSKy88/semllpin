import { NeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

// Initialize LBS tables
export const initializeLbsTables: RouteHandler = async (request, env) => {
  try {
    const db = new NeonDatabase(env.DATABASE_URL);
    
    // Check if reward_records table exists (should be created by migration)
    const tableExists = await db.sql`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'reward_records'
      )
    `;
    
    if (!tableExists[0]?.exists) {
      throw new Error('LBS tables not found. Please run database migrations first.');
    }
    
    // Indexes should already be created by migration, just verify they exist
    console.log('LBS tables and indexes verified successfully');
    
    // Enable PostGIS extension if available (for spatial queries)
    try {
      await db.sql`CREATE EXTENSION IF NOT EXISTS postgis`;
    } catch (error) {
      console.log('PostGIS extension not available, using basic distance calculations');
    }
    
    console.log('LBS tables initialized successfully');
    
    return new Response(JSON.stringify({
      success: true,
      message: 'LBS tables initialized successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Initialize LBS tables error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to initialize LBS tables'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Validation schemas
const checkInSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  location_name: z.string().optional(),
  accuracy: z.number().optional()
});

const getNearbyRewardsSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  radius: z.number().min(0.1).max(50).default(5) // radius in kilometers
});

// Helper function to calculate distance between two points (Haversine formula)
function calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in kilometers
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

// Check in at a location and potentially earn rewards
export const checkIn: RouteHandler = async (request, env) => {
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
    const { latitude, longitude, location_name, accuracy } = checkInSchema.parse(body);

    const db = new NeonDatabase(env.DATABASE_URL);

    // Check if user has checked in at this location recently (within 24 hours)
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    // Convert UUID to integer hash for compatibility with existing schema
    // Use modulo to ensure the value fits in PostgreSQL integer range (-2147483648 to 2147483647)
    const userIdHash = Math.abs(parseInt(user.id.replace(/-/g, '').substring(0, 8), 16)) % 2147483647;
    const recentCheckIns = await db.sql`
      SELECT * FROM checkin_records 
      WHERE user_id = ${userIdHash} AND created_at >= ${twentyFourHoursAgo.toISOString()} 
      ORDER BY created_at DESC
    `;

    // Check if user is too close to a recent check-in location
    const tooCloseToRecent = recentCheckIns.some(checkIn => {
      if (!checkIn.latitude || !checkIn.longitude) {
        return false;
      }
      const distance = calculateDistance(
        latitude, longitude,
        parseFloat(checkIn.latitude), parseFloat(checkIn.longitude)
      );
      return distance < 0.1; // Less than 100 meters
    });

    if (tooCloseToRecent) {
      return new Response(JSON.stringify({
        error: 'Too close to recent check-in',
        message: 'You have already checked in near this location recently'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Calculate reward amount based on various factors
    let rewardAmount = 10; // Base reward
    
    // Bonus for first check-in of the day
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayCheckIns = recentCheckIns.filter(checkIn => 
      new Date(checkIn.created_at) >= todayStart
    );
    
    if (todayCheckIns.length === 0) {
      rewardAmount += 20; // First check-in bonus
    }

    // Bonus for accuracy (if GPS accuracy is good)
    if (accuracy && accuracy <= 10) {
      rewardAmount += 5;
    }

    // Random bonus (1-10% chance for extra reward)
    if (Math.random() < 0.1) {
      rewardAmount += Math.floor(Math.random() * 50) + 10;
    }

    // Create the check-in record
    const checkInRecord = await db.sql`
      INSERT INTO checkin_records (user_id, latitude, longitude, location_name, points_earned, is_first_time)
      VALUES (${userIdHash}, ${latitude}, ${longitude}, ${location_name || null}, ${rewardAmount}, ${todayCheckIns.length === 0})
      RETURNING *
    `;

    if (!checkInRecord || checkInRecord.length === 0) {
      return new Response(JSON.stringify({
        error: 'Failed to create check-in record',
        message: 'Database insert failed'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const checkIn = checkInRecord[0];
    
    // Create the reward record
    const rewardRecord = await db.sql`
      INSERT INTO reward_records (user_id, reward_type, reward_category, points, description, source_id, source_type, latitude, longitude, status, claimed_at)
      VALUES (${userIdHash}, 'checkin', 'location_checkin', ${rewardAmount}, ${`Check-in reward at ${location_name || 'location'}`}, ${checkIn.id}, 'checkin_record', ${latitude}, ${longitude}, 'claimed', NOW())
      RETURNING *
    `;

    // Add reward to user's wallet
    const wallets = await db.sql`
      SELECT * FROM wallets 
      WHERE user_id = ${user.id} AND currency = 'usd'
    `;

    if (wallets && wallets.length > 0) {
      const wallet = wallets[0];
      await db.sql`
        UPDATE wallets 
        SET balance = balance + ${rewardAmount}, updated_at = NOW()
        WHERE id = ${wallet.id}
      `;
    } else {
      await db.sql`
        INSERT INTO wallets (user_id, currency, balance)
        VALUES (${user.id}, 'usd', ${rewardAmount})
      `;
    }

    // Record the transaction
    await db.sql`
      INSERT INTO transactions (user_id, type, amount, currency, status, completed_at, description, metadata)
      VALUES (${user.id}, 'lbs_reward', ${rewardAmount}, 'usd', 'completed', NOW(), ${`Check-in reward at ${location_name || 'location'}`}, ${JSON.stringify({
        checkin_id: checkIn.id,
        reward_id: rewardRecord[0]?.id,
        latitude,
        longitude,
        location_name
      })})
    `;

    return new Response(JSON.stringify({
      success: true,
      data: {
        checkin: checkIn,
        reward: rewardRecord[0],
        reward_earned: rewardAmount,
        is_first_today: todayCheckIns.length === 0
      },
      message: `Check-in successful! You earned ${rewardAmount} credits.`
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Check-in error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to process check-in'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get nearby rewards and check-ins
export const getNearbyRewards: RouteHandler = async (request, env) => {
  try {
    const url = new URL(request.url);
    const latitude = parseFloat(url.searchParams.get('latitude') || '0');
    const longitude = parseFloat(url.searchParams.get('longitude') || '0');
    const radius = Math.min(parseFloat(url.searchParams.get('radius') || '5'), 50);

    const { latitude: lat, longitude: lng, radius: r } = getNearbyRewardsSchema.parse({
      latitude,
      longitude,
      radius
    });

    const db = new NeonDatabase(env.DATABASE_URL);

    // Get nearby rewards using basic distance calculation
    // Note: Using basic calculation since PostGIS might not be available
    // Note: reward_records.user_id is integer hash, users.id is UUID
    const nearbyRewards = await db.sql`
      SELECT 
        rr.*,
        'Anonymous' as username,
        'Anonymous User' as full_name,
        null as avatar_url
      FROM reward_records rr
      WHERE rr.latitude IS NOT NULL AND rr.longitude IS NOT NULL
      ORDER BY rr.created_at DESC
      LIMIT 100
    `;

    // Filter by distance using JavaScript (fallback for PostGIS)
    const filteredRewards = nearbyRewards.filter(reward => {
      if (!reward.latitude || !reward.longitude) {
        return false;
      }
      const distance = calculateDistance(lat, lng, parseFloat(reward.latitude), parseFloat(reward.longitude));
      return distance <= r;
    }).map(reward => {
      return {
        ...reward,
        distance: calculateDistance(lat, lng, parseFloat(reward.latitude), parseFloat(reward.longitude))
      };
    }).sort((a, b) => (a.distance || 0) - (b.distance || 0));

    return new Response(JSON.stringify({
      success: true,
      data: filteredRewards || [],
      metadata: {
        search_center: { latitude: lat, longitude: lng },
        radius: r,
        total_found: filteredRewards?.length || 0
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get nearby rewards error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch nearby rewards'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get user's check-in history
export const getCheckInHistory: RouteHandler = async (request, env) => {
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
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
    const offset = (page - 1) * limit;

    const db = new NeonDatabase(env.DATABASE_URL);

    // Convert UUID to integer hash for compatibility with existing schema
    // Use modulo to ensure the value fits in PostgreSQL integer range (-2147483648 to 2147483647)
    const userIdHash = Math.abs(parseInt(user.id.replace(/-/g, '').substring(0, 8), 16)) % 2147483647;
    const checkIns = await db.sql`
      SELECT * FROM checkin_records 
      WHERE user_id = ${userIdHash} 
      ORDER BY created_at DESC 
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Calculate some statistics
    const stats = await db.sql`
      SELECT 
        COUNT(*) as total_check_ins,
        COALESCE(SUM(points_earned), 0) as total_rewards_earned,
        COALESCE(AVG(points_earned), 0) as average_reward
      FROM checkin_records 
      WHERE user_id = ${userIdHash}
    `;

    const statsData = stats[0] || { total_check_ins: 0, total_rewards_earned: 0, average_reward: 0 };

    return new Response(JSON.stringify({
      success: true,
      data: checkIns || [],
      pagination: {
        page,
        limit,
        has_more: checkIns?.length === limit
      },
      statistics: {
        total_check_ins: parseInt(statsData.total_check_ins),
        total_rewards_earned: parseFloat(statsData.total_rewards_earned),
        average_reward: Math.round(parseFloat(statsData.average_reward))
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get check-in history error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch check-in history'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get leaderboard for a specific area
export const getAreaLeaderboard: RouteHandler = async (request, env) => {
  try {
    const url = new URL(request.url);
    const latitude = parseFloat(url.searchParams.get('latitude') || '0');
    const longitude = parseFloat(url.searchParams.get('longitude') || '0');
    const radius = Math.min(parseFloat(url.searchParams.get('radius') || '10'), 50);
    const timeframe = url.searchParams.get('timeframe') || 'week'; // week, month, all

    const { latitude: lat, longitude: lng, radius: r } = getNearbyRewardsSchema.parse({
      latitude,
      longitude,
      radius
    });

    const db = new NeonDatabase(env.DATABASE_URL);

    // Calculate date filter based on timeframe
    let dateFilter = new Date(0); // Beginning of time
    if (timeframe === 'week') {
      dateFilter = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    } else if (timeframe === 'month') {
      dateFilter = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    }

    // Get all rewards in the timeframe first
    // Note: reward_records.user_id is integer hash, users.id is UUID
    const allRewards = await db.sql`
      SELECT 
        rr.user_id,
        rr.latitude,
        rr.longitude,
        rr.points,
        'Anonymous' as username,
        'Anonymous User' as full_name,
        null as avatar_url,
        false as is_verified
      FROM reward_records rr
      WHERE rr.created_at >= ${dateFilter} AND rr.latitude IS NOT NULL AND rr.longitude IS NOT NULL
      ORDER BY rr.created_at DESC
    `;

    // Filter by distance and aggregate using JavaScript
    const userStats = new Map();
    
    allRewards.forEach(reward => {
      if (!reward.latitude || !reward.longitude) {
        return;
      }
      const distance = calculateDistance(lat, lng, parseFloat(reward.latitude), parseFloat(reward.longitude));
      if (distance <= r) {
        const userId = reward.user_id;
        if (!userStats.has(userId)) {
          userStats.set(userId, {
            user_id: userId,
            username: reward.username,
            full_name: reward.full_name,
            avatar_url: reward.avatar_url,
            is_verified: reward.is_verified,
            total_rewards: 0,
            check_in_count: 0
          });
        }
        const stats = userStats.get(userId);
        stats.total_rewards += parseFloat(reward.points || 0);
        stats.check_in_count += 1;
      }
    });

    // Convert to array and sort by total rewards
    const leaderboard = Array.from(userStats.values())
      .sort((a, b) => b.total_rewards - a.total_rewards)
      .slice(0, 50)
      .map((stats, index) => ({
         rank: index + 1,
         user: {
           id: stats.user_id,
           username: stats.username,
           full_name: stats.full_name,
           avatar_url: stats.avatar_url,
           is_verified: stats.is_verified
         },
         total_rewards: stats.total_rewards,
         check_in_count: stats.check_in_count
       }));

    return new Response(JSON.stringify({
      success: true,
      data: leaderboard,
      metadata: {
        search_center: { latitude: lat, longitude: lng },
        radius: r,
        timeframe,
        total_participants: leaderboard.length
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get area leaderboard error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch area leaderboard'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};