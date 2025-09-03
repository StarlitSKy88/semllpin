/**
 * SmellPin LBS Reward System - Reward Calculation Engine
 * Components: RWD-001 to RWD-004
 * Dynamic reward algorithms, real-time pool management, instant distribution, and comprehensive analytics
 */

import { EventEmitter } from 'events';
import { logger } from '../../utils/logger';
import { RedisService } from '../RedisService';
import { GeoPoint, GeographicData } from './GeographicCoreSystem';

// Types and Interfaces
export interface RewardPool {
  id: string;
  name: string;
  totalAmount: number;
  remainingAmount: number;
  currency: 'USD' | 'EUR' | 'CNY' | 'POINTS';
  startDate: Date;
  endDate: Date;
  isActive: boolean;
  rules: RewardRule[];
  distributionStrategy: 'EQUAL' | 'WEIGHTED' | 'DYNAMIC' | 'TIERED';
  geographicScope?: {
    regions: string[];
    excludedRegions: string[];
    boundingBox?: {
      north: number;
      south: number;
      east: number;
      west: number;
    };
  };
  timeConstraints?: {
    allowedHours: number[];
    allowedDays: number[];
    timezone: string;
  };
  metadata?: Record<string, any>;
}

export interface RewardRule {
  id: string;
  name: string;
  type: 'BASE' | 'MULTIPLIER' | 'BONUS' | 'PENALTY' | 'CONDITIONAL';
  condition: RewardCondition;
  value: number;
  maxApplications?: number;
  priority: number;
  isActive: boolean;
}

export interface RewardCondition {
  type: 'LOCATION_RARITY' | 'TIME_BASED' | 'USER_LEVEL' | 'STREAK' | 'DISTANCE' | 'FREQUENCY' | 'SOCIAL' | 'WEATHER' | 'EVENT';
  operator: 'EQUALS' | 'GREATER_THAN' | 'LESS_THAN' | 'BETWEEN' | 'IN' | 'NOT_IN' | 'EXISTS' | 'NOT_EXISTS';
  value: any;
  metadata?: Record<string, any>;
}

export interface RewardCalculation {
  userId: string;
  location: GeoPoint;
  baseReward: number;
  multipliers: Array<{ rule: string; multiplier: number; reason: string }>;
  bonuses: Array<{ rule: string; bonus: number; reason: string }>;
  penalties: Array<{ rule: string; penalty: number; reason: string }>;
  totalReward: number;
  currency: string;
  calculationDetails: {
    locationRarityScore: number;
    popularityBonus: number;
    timeMultiplier: number;
    streakBonus: number;
    levelMultiplier: number;
    socialBonus: number;
    weatherBonus: number;
    eventBonus: number;
  };
  appliedRules: string[];
  timestamp: Date;
}

export interface RewardDistribution {
  id: string;
  userId: string;
  amount: number;
  currency: string;
  poolId: string;
  transactionId: string;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'REVERSED';
  location: GeoPoint;
  metadata: {
    calculationId: string;
    reason: string;
    appliedRules: string[];
    geographicData?: GeographicData;
  };
  createdAt: Date;
  processedAt?: Date;
  failureReason?: string;
}

export interface UserRewardHistory {
  userId: string;
  totalEarned: number;
  totalDistributions: number;
  averageReward: number;
  bestReward: number;
  currentStreak: number;
  longestStreak: number;
  lastRewardDate?: Date;
  rewardsByLocation: Record<string, number>;
  rewardsByTimeOfDay: Record<string, number>;
  monthlyEarnings: Array<{ month: string; amount: number }>;
  levelProgress: {
    currentLevel: number;
    currentXP: number;
    nextLevelXP: number;
    levelBenefits: string[];
  };
}

export interface RewardAnalytics {
  totalRewardsDistributed: number;
  totalUsers: number;
  averageRewardPerUser: number;
  averageRewardPerLocation: number;
  topEarningUsers: Array<{ userId: string; totalEarned: number }>;
  topRewardingLocations: Array<{ location: GeoPoint; totalRewards: number; checkInCount: number }>;
  rewardTrendsByHour: Array<{ hour: number; totalRewards: number; userCount: number }>;
  rewardTrendsByDay: Array<{ day: string; totalRewards: number; userCount: number }>;
  poolUtilization: Array<{ poolId: string; utilized: number; remaining: number; efficiency: number }>;
  geographicDistribution: Array<{ region: string; totalRewards: number; userCount: number }>;
}

/**
 * RWD-001: Dynamic Reward Algorithms Based on Location Popularity
 * Intelligent reward calculation considering multiple factors
 */
export class DynamicRewardAlgorithm extends EventEmitter {
  private redis: RedisService;
  private rewardRules: Map<string, RewardRule> = new Map();
  private locationPopularityCache: Map<string, number> = new Map();

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.initializeDefaultRules();
  }

  /**
   * Calculate dynamic reward for a location check-in
   */
  public async calculateReward(
    userId: string,
    location: GeoPoint,
    geographicData: GeographicData,
    userHistory: UserRewardHistory
  ): Promise<RewardCalculation> {
    const startTime = Date.now();

    // Base reward calculation
    const baseReward = await this.calculateBaseReward(location, geographicData);

    // Calculate all multipliers and bonuses
    const [
      locationFactors,
      timeFactors,
      userFactors,
      socialFactors,
      environmentalFactors
    ] = await Promise.all([
      this.calculateLocationFactors(location, geographicData),
      this.calculateTimeFactors(location),
      this.calculateUserFactors(userId, userHistory, location),
      this.calculateSocialFactors(userId, location),
      this.calculateEnvironmentalFactors(location)
    ]);

    const multipliers: Array<{ rule: string; multiplier: number; reason: string }> = [];
    const bonuses: Array<{ rule: string; bonus: number; reason: string }> = [];
    const penalties: Array<{ rule: string; penalty: number; reason: string }> = [];

    // Apply location-based factors
    if (locationFactors.rarityMultiplier > 1) {
      multipliers.push({
        rule: 'LOCATION_RARITY',
        multiplier: locationFactors.rarityMultiplier,
        reason: `Rare location (rarity score: ${locationFactors.rarityScore.toFixed(2)})`
      });
    }

    if (locationFactors.categoryMultiplier !== 1) {
      multipliers.push({
        rule: 'CATEGORY_BONUS',
        multiplier: locationFactors.categoryMultiplier,
        reason: `Category: ${geographicData.category || 'unknown'}`
      });
    }

    // Apply time-based factors
    if (timeFactors.timeMultiplier !== 1) {
      multipliers.push({
        rule: 'TIME_BASED',
        multiplier: timeFactors.timeMultiplier,
        reason: timeFactors.reason
      });
    }

    // Apply user-specific factors
    if (userFactors.levelMultiplier > 1) {
      multipliers.push({
        rule: 'USER_LEVEL',
        multiplier: userFactors.levelMultiplier,
        reason: `Level ${userHistory.levelProgress.currentLevel} bonus`
      });
    }

    if (userFactors.streakBonus > 0) {
      bonuses.push({
        rule: 'STREAK_BONUS',
        bonus: userFactors.streakBonus,
        reason: `${userHistory.currentStreak} day streak`
      });
    }

    // Apply social factors
    if (socialFactors.socialBonus > 0) {
      bonuses.push({
        rule: 'SOCIAL_BONUS',
        bonus: socialFactors.socialBonus,
        reason: socialFactors.reason
      });
    }

    // Apply environmental factors
    if (environmentalFactors.weatherBonus > 0) {
      bonuses.push({
        rule: 'WEATHER_BONUS',
        bonus: environmentalFactors.weatherBonus,
        reason: environmentalFactors.reason
      });
    }

    if (environmentalFactors.eventBonus > 0) {
      bonuses.push({
        rule: 'EVENT_BONUS',
        bonus: environmentalFactors.eventBonus,
        reason: environmentalFactors.reason
      });
    }

    // Calculate total reward
    let totalReward = baseReward;
    
    // Apply multipliers
    multipliers.forEach(({ multiplier }) => {
      totalReward *= multiplier;
    });

    // Apply bonuses
    bonuses.forEach(({ bonus }) => {
      totalReward += bonus;
    });

    // Apply penalties
    penalties.forEach(({ penalty }) => {
      totalReward -= penalty;
    });

    // Ensure minimum reward
    totalReward = Math.max(totalReward, 1);

    const calculation: RewardCalculation = {
      userId,
      location,
      baseReward,
      multipliers,
      bonuses,
      penalties,
      totalReward,
      currency: 'POINTS',
      calculationDetails: {
        locationRarityScore: locationFactors.rarityScore,
        popularityBonus: locationFactors.popularityBonus,
        timeMultiplier: timeFactors.timeMultiplier,
        streakBonus: userFactors.streakBonus,
        levelMultiplier: userFactors.levelMultiplier,
        socialBonus: socialFactors.socialBonus,
        weatherBonus: environmentalFactors.weatherBonus,
        eventBonus: environmentalFactors.eventBonus
      },
      appliedRules: [
        ...multipliers.map(m => m.rule),
        ...bonuses.map(b => b.rule),
        ...penalties.map(p => p.rule)
      ],
      timestamp: new Date()
    };

    const processingTime = Date.now() - startTime;
    
    logger.info('Reward calculated', {
      userId,
      location,
      baseReward,
      totalReward,
      processingTime,
      appliedRules: calculation.appliedRules.length
    });

    // Cache calculation for analytics
    await this.cacheCalculation(calculation);

    this.emit('reward_calculated', calculation);

    return calculation;
  }

  /**
   * Calculate base reward based on location characteristics
   */
  private async calculateBaseReward(
    location: GeoPoint,
    geographicData: GeographicData
  ): Promise<number> {
    // Base reward algorithm considering multiple factors
    let baseReward = 10; // Default base reward

    // Adjust based on location type and category
    const categoryRewards: Record<string, number> = {
      'restaurant': 10,
      'shopping': 12,
      'entertainment': 15,
      'tourist': 20,
      'business': 8,
      'transport': 8,
      'residential': 5,
      'park': 12,
      'culture': 18,
      'sports': 15
    };

    if (geographicData.category && categoryRewards[geographicData.category]) {
      baseReward = categoryRewards[geographicData.category];
    }

    // Adjust based on GPS accuracy (more accurate = higher reward)
    if (location.accuracy) {
      const accuracyBonus = Math.max(0, (20 - location.accuracy) / 20);
      baseReward += accuracyBonus * 2;
    }

    return Math.round(baseReward);
  }

  /**
   * Calculate location-specific factors
   */
  private async calculateLocationFactors(
    location: GeoPoint,
    geographicData: GeographicData
  ): Promise<{
    rarityScore: number;
    rarityMultiplier: number;
    categoryMultiplier: number;
    popularityBonus: number;
  }> {
    // Calculate location rarity
    const rarityScore = await this.calculateLocationRarity(location);
    const rarityMultiplier = 1 + (rarityScore * 0.5); // Up to 1.5x multiplier

    // Category-based multipliers
    const categoryMultipliers: Record<string, number> = {
      'tourist': 1.5,
      'culture': 1.4,
      'entertainment': 1.3,
      'sports': 1.2,
      'shopping': 1.1,
      'restaurant': 1.0,
      'business': 0.9,
      'transport': 0.8,
      'residential': 0.7
    };

    const categoryMultiplier = categoryMultipliers[geographicData.category || 'restaurant'] || 1.0;

    // Popularity bonus (inverse of popularity - reward rare places more)
    const popularityBonus = geographicData.popularity 
      ? Math.max(0, (1 - geographicData.popularity) * 5) 
      : 0;

    return {
      rarityScore,
      rarityMultiplier,
      categoryMultiplier,
      popularityBonus
    };
  }

  /**
   * Calculate time-based factors
   */
  private async calculateTimeFactors(location: GeoPoint): Promise<{
    timeMultiplier: number;
    reason: string;
  }> {
    const now = new Date();
    const hour = now.getHours();
    const dayOfWeek = now.getDay();

    // Time-based multipliers
    let timeMultiplier = 1.0;
    let reason = 'Standard time';

    // Peak hours (lower rewards due to high activity)
    if ((hour >= 12 && hour <= 14) || (hour >= 18 && hour <= 20)) {
      timeMultiplier = 0.9;
      reason = 'Peak hours';
    }

    // Off-peak hours (higher rewards)
    if ((hour >= 6 && hour <= 9) || (hour >= 21 && hour <= 23)) {
      timeMultiplier = 1.2;
      reason = 'Off-peak hours';
    }

    // Late night/early morning (highest rewards)
    if (hour >= 0 && hour <= 6) {
      timeMultiplier = 1.5;
      reason = 'Late night/early morning';
    }

    // Weekend bonus
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      timeMultiplier *= 1.1;
      reason += ' + weekend bonus';
    }

    return { timeMultiplier, reason };
  }

  /**
   * Calculate user-specific factors
   */
  private async calculateUserFactors(
    userId: string,
    userHistory: UserRewardHistory,
    location: GeoPoint
  ): Promise<{
    levelMultiplier: number;
    streakBonus: number;
    newLocationBonus: number;
  }> {
    // Level-based multiplier
    const level = userHistory.levelProgress.currentLevel;
    const levelMultiplier = 1 + (level * 0.05); // 5% per level

    // Streak bonus (flat bonus, not multiplier)
    const streakBonus = Math.min(userHistory.currentStreak * 2, 20); // Max 20 bonus

    // New location bonus
    const locationKey = `${location.latitude.toFixed(4)},${location.longitude.toFixed(4)}`;
    const hasVisitedBefore = userHistory.rewardsByLocation[locationKey] > 0;
    const newLocationBonus = hasVisitedBefore ? 0 : 5;

    return {
      levelMultiplier,
      streakBonus,
      newLocationBonus
    };
  }

  /**
   * Calculate social factors
   */
  private async calculateSocialFactors(
    userId: string,
    location: GeoPoint
  ): Promise<{
    socialBonus: number;
    reason: string;
  }> {
    // Check for nearby friends or social interactions
    const nearbyFriends = await this.getNearbyFriends(userId, location);
    const recentSocialActivity = await this.getRecentSocialActivity(userId);

    let socialBonus = 0;
    let reason = '';

    if (nearbyFriends.length > 0) {
      socialBonus += nearbyFriends.length * 2; // 2 bonus per nearby friend
      reason = `${nearbyFriends.length} nearby friends`;
    }

    if (recentSocialActivity.shares > 0) {
      socialBonus += recentSocialActivity.shares * 1; // 1 bonus per recent share
      reason += reason ? ' + recent shares' : 'recent shares';
    }

    if (recentSocialActivity.likes > 0) {
      socialBonus += Math.min(recentSocialActivity.likes * 0.5, 5); // Max 5 from likes
      reason += reason ? ' + likes' : 'likes';
    }

    return { socialBonus, reason };
  }

  /**
   * Calculate environmental factors
   */
  private async calculateEnvironmentalFactors(
    location: GeoPoint
  ): Promise<{
    weatherBonus: number;
    eventBonus: number;
    reason: string;
  }> {
    const [weatherData, eventData] = await Promise.all([
      this.getWeatherData(location),
      this.getEventData(location)
    ]);

    let weatherBonus = 0;
    let eventBonus = 0;
    let reason = '';

    // Weather-based bonuses
    if (weatherData) {
      if (weatherData.condition === 'rain' || weatherData.condition === 'snow') {
        weatherBonus = 3; // Bonus for checking in during bad weather
        reason = 'bad weather bonus';
      } else if (weatherData.condition === 'sunny' && weatherData.temperature > 30) {
        weatherBonus = 2; // Bonus for hot weather
        reason = 'hot weather bonus';
      } else if (weatherData.temperature < 5) {
        weatherBonus = 2; // Bonus for cold weather
        reason = 'cold weather bonus';
      }
    }

    // Event-based bonuses
    if (eventData && eventData.events.length > 0) {
      const nearbyEvents = eventData.events.filter(event => event.distance < 500); // Within 500m
      if (nearbyEvents.length > 0) {
        eventBonus = nearbyEvents.length * 3; // 3 bonus per nearby event
        reason += reason ? ' + nearby events' : 'nearby events';
      }
    }

    return { weatherBonus, eventBonus, reason };
  }

  /**
   * Calculate location rarity score based on historical data
   */
  private async calculateLocationRarity(location: GeoPoint): Promise<number> {
    const gridKey = this.getLocationGrid(location, 100); // 100m grid
    const checkInCount = await this.getLocationCheckInCount(gridKey);
    
    // Rarity score: inverse log scale, 0-1 range
    // More check-ins = lower rarity score
    const rarityScore = Math.max(0, 1 - Math.log10(checkInCount + 1) / 3);
    
    return rarityScore;
  }

  // Initialize default reward rules
  private initializeDefaultRules(): void {
    const defaultRules: RewardRule[] = [
      {
        id: 'base_reward',
        name: 'Base Check-in Reward',
        type: 'BASE',
        condition: { type: 'LOCATION_RARITY', operator: 'EXISTS', value: true },
        value: 10,
        priority: 100,
        isActive: true
      },
      {
        id: 'rarity_multiplier',
        name: 'Location Rarity Multiplier',
        type: 'MULTIPLIER',
        condition: { type: 'LOCATION_RARITY', operator: 'GREATER_THAN', value: 0.5 },
        value: 1.5,
        priority: 90,
        isActive: true
      },
      {
        id: 'streak_bonus',
        name: 'Daily Streak Bonus',
        type: 'BONUS',
        condition: { type: 'STREAK', operator: 'GREATER_THAN', value: 1 },
        value: 2,
        priority: 80,
        isActive: true
      },
      {
        id: 'level_multiplier',
        name: 'User Level Multiplier',
        type: 'MULTIPLIER',
        condition: { type: 'USER_LEVEL', operator: 'GREATER_THAN', value: 1 },
        value: 1.05,
        priority: 70,
        isActive: true
      },
      {
        id: 'new_location_bonus',
        name: 'New Location Discovery Bonus',
        type: 'BONUS',
        condition: { type: 'FREQUENCY', operator: 'EQUALS', value: 0 },
        value: 5,
        priority: 85,
        isActive: true
      }
    ];

    defaultRules.forEach(rule => {
      this.rewardRules.set(rule.id, rule);
    });
  }

  // Helper methods
  private getLocationGrid(location: GeoPoint, gridSize: number): string {
    const gridX = Math.floor(location.latitude * 111000 / gridSize);
    const gridY = Math.floor(location.longitude * 111000 / gridSize);
    return `${gridX},${gridY}`;
  }

  private async getLocationCheckInCount(gridKey: string): Promise<number> {
    const cacheKey = `checkin_count:${gridKey}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return parseInt(cached, 10);
    }
    
    // Mock data - in production would query database
    const mockCount = Math.floor(Math.random() * 1000) + 1;
    await this.redis.setWithExpiry(cacheKey, mockCount.toString(), 3600);
    
    return mockCount;
  }

  private async getNearbyFriends(userId: string, location: GeoPoint): Promise<string[]> {
    // Mock implementation - would check friend locations in production
    return [];
  }

  private async getRecentSocialActivity(userId: string): Promise<{ shares: number; likes: number }> {
    // Mock implementation - would query social activity
    return { shares: 0, likes: 0 };
  }

  private async getWeatherData(location: GeoPoint): Promise<{ condition: string; temperature: number } | null> {
    // Mock weather data - would integrate with weather API
    const conditions = ['sunny', 'cloudy', 'rain', 'snow'];
    return {
      condition: conditions[Math.floor(Math.random() * conditions.length)],
      temperature: Math.floor(Math.random() * 40) - 10 // -10 to 30 degrees
    };
  }

  private async getEventData(location: GeoPoint): Promise<{ events: Array<{ name: string; distance: number }> } | null> {
    // Mock event data - would integrate with events API
    return {
      events: []
    };
  }

  private async cacheCalculation(calculation: RewardCalculation): Promise<void> {
    const cacheKey = `reward_calculation:${calculation.userId}:${Date.now()}`;
    await this.redis.setWithExpiry(
      cacheKey,
      JSON.stringify(calculation),
      86400 // 24 hours
    );
  }
}

/**
 * RWD-002: Real-time Reward Pool Management
 * Dynamic pool allocation and management system
 */
export class RewardPoolManager extends EventEmitter {
  private redis: RedisService;
  private pools: Map<string, RewardPool> = new Map();
  private poolLocks: Map<string, boolean> = new Map();

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.initializeDefaultPools();
  }

  /**
   * Create a new reward pool
   */
  public async createRewardPool(poolData: Omit<RewardPool, 'id'>): Promise<string> {
    const poolId = `pool_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const pool: RewardPool = {
      ...poolData,
      id: poolId
    };

    await this.savePool(pool);
    this.pools.set(poolId, pool);

    logger.info(`Reward pool created: ${poolId}`, { 
      totalAmount: pool.totalAmount,
      currency: pool.currency,
      strategy: pool.distributionStrategy
    });

    this.emit('pool_created', pool);

    return poolId;
  }

  /**
   * Allocate reward from appropriate pool
   */
  public async allocateFromPool(
    calculation: RewardCalculation,
    geographicData: GeographicData
  ): Promise<{
    poolId: string;
    allocated: boolean;
    allocatedAmount: number;
    remainingInPool: number;
    reason: string;
  }> {
    // Find best matching pool
    const eligiblePools = await this.findEligiblePools(calculation, geographicData);
    
    if (eligiblePools.length === 0) {
      return {
        poolId: '',
        allocated: false,
        allocatedAmount: 0,
        remainingInPool: 0,
        reason: 'No eligible pools found'
      };
    }

    // Select best pool based on priority and availability
    const selectedPool = this.selectBestPool(eligiblePools, calculation);
    
    // Try to allocate with lock
    const allocatedAmount = await this.allocateWithLock(
      selectedPool.id,
      calculation.totalReward
    );

    if (allocatedAmount > 0) {
      const pool = await this.getPool(selectedPool.id);
      
      this.emit('pool_allocation', {
        poolId: selectedPool.id,
        userId: calculation.userId,
        amount: allocatedAmount,
        remainingAmount: pool?.remainingAmount || 0
      });

      return {
        poolId: selectedPool.id,
        allocated: true,
        allocatedAmount,
        remainingInPool: pool?.remainingAmount || 0,
        reason: 'Successfully allocated from pool'
      };
    }

    return {
      poolId: selectedPool.id,
      allocated: false,
      allocatedAmount: 0,
      remainingInPool: selectedPool.remainingAmount,
      reason: 'Insufficient funds in pool'
    };
  }

  /**
   * Get pool statistics
   */
  public async getPoolStats(poolId: string): Promise<{
    totalDistributed: number;
    remainingAmount: number;
    utilizationRate: number;
    averageReward: number;
    totalRecipients: number;
    distributionRate: number; // rewards per hour
  }> {
    const pool = await this.getPool(poolId);
    if (!pool) {
      throw new Error(`Pool not found: ${poolId}`);
    }

    const totalDistributed = pool.totalAmount - pool.remainingAmount;
    const utilizationRate = totalDistributed / pool.totalAmount;

    // Get distribution statistics
    const distributions = await this.getPoolDistributions(poolId);
    const totalRecipients = new Set(distributions.map(d => d.userId)).size;
    const averageReward = totalRecipients > 0 ? totalDistributed / totalRecipients : 0;

    // Calculate distribution rate
    const poolAge = Date.now() - pool.startDate.getTime();
    const poolAgeHours = poolAge / (1000 * 60 * 60);
    const distributionRate = poolAgeHours > 0 ? distributions.length / poolAgeHours : 0;

    return {
      totalDistributed,
      remainingAmount: pool.remainingAmount,
      utilizationRate,
      averageReward,
      totalRecipients,
      distributionRate
    };
  }

  /**
   * Rebalance pools based on usage patterns
   */
  public async rebalancePools(): Promise<void> {
    const activePools = Array.from(this.pools.values()).filter(pool => pool.isActive);
    
    for (const pool of activePools) {
      const stats = await this.getPoolStats(pool.id);
      
      // If pool is underutilized and nearing expiry, redistribute
      if (stats.utilizationRate < 0.3 && this.isNearingExpiry(pool)) {
        await this.redistributePool(pool);
      }
      
      // If pool is overutilized, consider increasing allocation
      if (stats.utilizationRate > 0.9 && stats.distributionRate > 10) {
        await this.requestPoolIncrease(pool, stats);
      }
    }

    this.emit('pools_rebalanced', { timestamp: new Date() });
  }

  /**
   * Find pools eligible for a reward calculation
   */
  private async findEligiblePools(
    calculation: RewardCalculation,
    geographicData: GeographicData
  ): Promise<RewardPool[]> {
    const eligiblePools: RewardPool[] = [];
    const currentTime = new Date();

    for (const pool of this.pools.values()) {
      if (!pool.isActive) continue;
      
      // Check time constraints
      if (currentTime < pool.startDate || currentTime > pool.endDate) continue;
      
      // Check if pool has sufficient funds
      if (pool.remainingAmount < calculation.totalReward) continue;

      // Check geographic constraints
      if (pool.geographicScope) {
        if (!this.isLocationInScope(calculation.location, geographicData, pool.geographicScope)) {
          continue;
        }
      }

      // Check time constraints (hour/day restrictions)
      if (pool.timeConstraints) {
        if (!this.isTimeInConstraints(currentTime, pool.timeConstraints)) {
          continue;
        }
      }

      eligiblePools.push(pool);
    }

    return eligiblePools;
  }

  /**
   * Select the best pool from eligible pools
   */
  private selectBestPool(eligiblePools: RewardPool[], calculation: RewardCalculation): RewardPool {
    // Sort by priority factors:
    // 1. Distribution strategy compatibility
    // 2. Remaining amount ratio
    // 3. Geographic specificity
    
    return eligiblePools.sort((a, b) => {
      // Prefer pools with higher remaining ratio
      const aRatio = a.remainingAmount / a.totalAmount;
      const bRatio = b.remainingAmount / b.totalAmount;
      
      if (Math.abs(aRatio - bRatio) > 0.1) {
        return bRatio - aRatio;
      }

      // Prefer geographically specific pools
      const aSpecific = a.geographicScope ? 1 : 0;
      const bSpecific = b.geographicScope ? 1 : 0;
      
      return bSpecific - aSpecific;
    })[0];
  }

  /**
   * Allocate amount from pool with distributed locking
   */
  private async allocateWithLock(poolId: string, amount: number): Promise<number> {
    const lockKey = `pool_lock:${poolId}`;
    const lockValue = `${Date.now()}_${Math.random()}`;
    
    try {
      // Acquire lock with 5-second timeout
      const lockAcquired = await this.redis.setNX(lockKey, lockValue, 5);
      
      if (!lockAcquired) {
        // Wait briefly and try again
        await new Promise(resolve => setTimeout(resolve, 100));
        return this.allocateWithLock(poolId, amount);
      }

      const pool = await this.getPool(poolId);
      if (!pool) {
        return 0;
      }

      if (pool.remainingAmount >= amount) {
        pool.remainingAmount -= amount;
        await this.savePool(pool);
        this.pools.set(poolId, pool);
        
        return amount;
      }

      return 0;

    } finally {
      // Release lock
      await this.redis.delete(lockKey);
    }
  }

  // Helper methods
  private initializeDefaultPools(): void {
    const defaultPools: Omit<RewardPool, 'id'>[] = [
      {
        name: 'General Rewards Pool',
        totalAmount: 100000,
        remainingAmount: 100000,
        currency: 'POINTS',
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        isActive: true,
        rules: [],
        distributionStrategy: 'DYNAMIC'
      },
      {
        name: 'Tourist Location Bonus Pool',
        totalAmount: 50000,
        remainingAmount: 50000,
        currency: 'POINTS',
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        isActive: true,
        rules: [],
        distributionStrategy: 'WEIGHTED',
        geographicScope: {
          regions: ['tourist'],
          excludedRegions: []
        }
      }
    ];

    defaultPools.forEach(async (poolData) => {
      await this.createRewardPool(poolData);
    });
  }

  private async savePool(pool: RewardPool): Promise<void> {
    const cacheKey = `reward_pool:${pool.id}`;
    await this.redis.setWithExpiry(
      cacheKey,
      JSON.stringify(pool),
      86400 * 32 // 32 days
    );
  }

  private async getPool(poolId: string): Promise<RewardPool | null> {
    const cached = this.pools.get(poolId);
    if (cached) return cached;

    const cacheKey = `reward_pool:${poolId}`;
    const poolData = await this.redis.get(cacheKey);
    
    if (poolData) {
      const pool = JSON.parse(poolData);
      this.pools.set(poolId, pool);
      return pool;
    }

    return null;
  }

  private async getPoolDistributions(poolId: string): Promise<RewardDistribution[]> {
    // In production, would query database for pool distributions
    return [];
  }

  private isLocationInScope(
    location: GeoPoint,
    geographicData: GeographicData,
    scope: RewardPool['geographicScope']
  ): boolean {
    if (!scope) return true;

    // Check bounding box
    if (scope.boundingBox) {
      const bbox = scope.boundingBox;
      if (location.latitude < bbox.south || location.latitude > bbox.north ||
          location.longitude < bbox.west || location.longitude > bbox.east) {
        return false;
      }
    }

    // Check region inclusion
    if (scope.regions.length > 0) {
      const locationRegion = geographicData.category || geographicData.district || '';
      if (!scope.regions.some(region => locationRegion.toLowerCase().includes(region.toLowerCase()))) {
        return false;
      }
    }

    // Check region exclusion
    if (scope.excludedRegions.length > 0) {
      const locationRegion = geographicData.category || geographicData.district || '';
      if (scope.excludedRegions.some(region => locationRegion.toLowerCase().includes(region.toLowerCase()))) {
        return false;
      }
    }

    return true;
  }

  private isTimeInConstraints(
    time: Date,
    constraints: RewardPool['timeConstraints']
  ): boolean {
    if (!constraints) return true;

    const hour = time.getHours();
    const day = time.getDay();

    if (constraints.allowedHours.length > 0 && !constraints.allowedHours.includes(hour)) {
      return false;
    }

    if (constraints.allowedDays.length > 0 && !constraints.allowedDays.includes(day)) {
      return false;
    }

    return true;
  }

  private isNearingExpiry(pool: RewardPool): boolean {
    const now = Date.now();
    const timeToExpiry = pool.endDate.getTime() - now;
    const totalDuration = pool.endDate.getTime() - pool.startDate.getTime();
    
    return timeToExpiry < (totalDuration * 0.1); // Less than 10% time remaining
  }

  private async redistributePool(pool: RewardPool): Promise<void> {
    logger.info(`Redistributing underutilized pool: ${pool.id}`, {
      remainingAmount: pool.remainingAmount,
      utilizationRate: (pool.totalAmount - pool.remainingAmount) / pool.totalAmount
    });

    // Implementation would redistribute to other pools or extend expiry
    this.emit('pool_redistributed', { poolId: pool.id, amount: pool.remainingAmount });
  }

  private async requestPoolIncrease(pool: RewardPool, stats: any): Promise<void> {
    logger.info(`Requesting pool increase for high-demand pool: ${pool.id}`, stats);

    // Implementation would request additional funding or auto-increase
    this.emit('pool_increase_requested', { poolId: pool.id, stats });
  }
}

/**
 * RWD-003: Instant Reward Distribution System
 * High-performance reward distribution with transaction tracking
 */
export class RewardDistributionSystem extends EventEmitter {
  private redis: RedisService;
  private distributionQueue: RewardDistribution[] = [];
  private processing: boolean = false;
  private batchSize: number = 100;
  private batchInterval: number = 1000; // 1 second

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.startDistributionProcessor();
  }

  /**
   * Queue reward for instant distribution
   */
  public async distributeReward(
    calculation: RewardCalculation,
    poolAllocation: any,
    geographicData: GeographicData
  ): Promise<RewardDistribution> {
    const distributionId = `dist_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const distribution: RewardDistribution = {
      id: distributionId,
      userId: calculation.userId,
      amount: poolAllocation.allocatedAmount,
      currency: calculation.currency,
      poolId: poolAllocation.poolId,
      transactionId: '', // Will be set during processing
      status: 'PENDING',
      location: calculation.location,
      metadata: {
        calculationId: `calc_${Date.now()}`,
        reason: `Location check-in reward`,
        appliedRules: calculation.appliedRules,
        geographicData
      },
      createdAt: new Date()
    };

    // Add to queue for processing
    this.distributionQueue.push(distribution);
    
    // Cache distribution record
    await this.cacheDistribution(distribution);

    logger.info(`Reward queued for distribution`, {
      distributionId,
      userId: calculation.userId,
      amount: distribution.amount,
      queueLength: this.distributionQueue.length
    });

    this.emit('reward_queued', distribution);

    return distribution;
  }

  /**
   * Process distribution queue in batches
   */
  private async startDistributionProcessor(): Promise<void> {
    setInterval(async () => {
      if (this.processing || this.distributionQueue.length === 0) return;
      
      this.processing = true;
      
      try {
        const batch = this.distributionQueue.splice(0, this.batchSize);
        await this.processBatch(batch);
      } catch (error) {
        logger.error('Distribution batch processing failed', { error });
      } finally {
        this.processing = false;
      }
    }, this.batchInterval);
  }

  /**
   * Process a batch of distributions
   */
  private async processBatch(batch: RewardDistribution[]): Promise<void> {
    const startTime = Date.now();

    const processingPromises = batch.map(distribution => 
      this.processDistribution(distribution)
    );

    const results = await Promise.allSettled(processingPromises);
    
    let successful = 0;
    let failed = 0;

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        successful++;
      } else {
        failed++;
        logger.error(`Distribution failed: ${batch[index].id}`, { 
          error: result.reason,
          distribution: batch[index]
        });
      }
    });

    const processingTime = Date.now() - startTime;

    logger.info(`Batch processing completed`, {
      batchSize: batch.length,
      successful,
      failed,
      processingTime
    });

    this.emit('batch_processed', {
      batchSize: batch.length,
      successful,
      failed,
      processingTime
    });
  }

  /**
   * Process individual distribution
   */
  private async processDistribution(distribution: RewardDistribution): Promise<void> {
    try {
      distribution.status = 'PROCESSING';
      await this.updateDistribution(distribution);

      // Generate transaction ID
      distribution.transactionId = `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Execute the actual reward distribution
      await this.executeDistribution(distribution);

      // Update user balance and history
      await this.updateUserRewards(distribution);

      // Mark as completed
      distribution.status = 'COMPLETED';
      distribution.processedAt = new Date();
      
      await this.updateDistribution(distribution);

      this.emit('reward_distributed', distribution);

      logger.debug(`Reward distributed successfully`, {
        distributionId: distribution.id,
        userId: distribution.userId,
        amount: distribution.amount
      });

    } catch (error) {
      distribution.status = 'FAILED';
      distribution.failureReason = error instanceof Error ? error.message : 'Unknown error';
      
      await this.updateDistribution(distribution);
      
      this.emit('distribution_failed', { distribution, error });
      
      throw error;
    }
  }

  /**
   * Execute the actual reward distribution (integrate with payment system)
   */
  private async executeDistribution(distribution: RewardDistribution): Promise<void> {
    // This would integrate with actual payment systems
    // For now, we'll simulate the distribution
    
    await new Promise(resolve => setTimeout(resolve, 50)); // Simulate API call
    
    // Record transaction in blockchain or payment system
    await this.recordTransaction(distribution);
  }

  /**
   * Update user reward balance and history
   */
  private async updateUserRewards(distribution: RewardDistribution): Promise<void> {
    const userKey = `user_rewards:${distribution.userId}`;
    const cached = await this.redis.get(userKey);
    
    let userRewards: UserRewardHistory;
    
    if (cached) {
      userRewards = JSON.parse(cached);
    } else {
      userRewards = {
        userId: distribution.userId,
        totalEarned: 0,
        totalDistributions: 0,
        averageReward: 0,
        bestReward: 0,
        currentStreak: 0,
        longestStreak: 0,
        rewardsByLocation: {},
        rewardsByTimeOfDay: {},
        monthlyEarnings: [],
        levelProgress: {
          currentLevel: 1,
          currentXP: 0,
          nextLevelXP: 100,
          levelBenefits: []
        }
      };
    }

    // Update totals
    userRewards.totalEarned += distribution.amount;
    userRewards.totalDistributions += 1;
    userRewards.averageReward = userRewards.totalEarned / userRewards.totalDistributions;
    userRewards.bestReward = Math.max(userRewards.bestReward, distribution.amount);
    userRewards.lastRewardDate = new Date();

    // Update location-based rewards
    const locationKey = `${distribution.location.latitude.toFixed(4)},${distribution.location.longitude.toFixed(4)}`;
    userRewards.rewardsByLocation[locationKey] = (userRewards.rewardsByLocation[locationKey] || 0) + distribution.amount;

    // Update time-based rewards
    const hourKey = new Date().getHours().toString();
    userRewards.rewardsByTimeOfDay[hourKey] = (userRewards.rewardsByTimeOfDay[hourKey] || 0) + distribution.amount;

    // Update monthly earnings
    const monthKey = new Date().toISOString().substring(0, 7); // YYYY-MM
    let monthlyEntry = userRewards.monthlyEarnings.find(me => me.month === monthKey);
    
    if (monthlyEntry) {
      monthlyEntry.amount += distribution.amount;
    } else {
      userRewards.monthlyEarnings.push({ month: monthKey, amount: distribution.amount });
    }

    // Update level progress
    userRewards.levelProgress.currentXP += distribution.amount;
    while (userRewards.levelProgress.currentXP >= userRewards.levelProgress.nextLevelXP) {
      userRewards.levelProgress.currentXP -= userRewards.levelProgress.nextLevelXP;
      userRewards.levelProgress.currentLevel += 1;
      userRewards.levelProgress.nextLevelXP = Math.floor(userRewards.levelProgress.nextLevelXP * 1.5);
    }

    // Update streak (simplified - in production would check daily check-ins)
    userRewards.currentStreak += 1;
    userRewards.longestStreak = Math.max(userRewards.longestStreak, userRewards.currentStreak);

    // Save updated user rewards
    await this.redis.setWithExpiry(userKey, JSON.stringify(userRewards), 86400 * 365); // 1 year
  }

  /**
   * Record transaction for audit trail
   */
  private async recordTransaction(distribution: RewardDistribution): Promise<void> {
    const transactionRecord = {
      transactionId: distribution.transactionId,
      type: 'REWARD_DISTRIBUTION',
      userId: distribution.userId,
      amount: distribution.amount,
      currency: distribution.currency,
      location: distribution.location,
      timestamp: new Date(),
      metadata: distribution.metadata
    };

    const transactionKey = `transaction:${distribution.transactionId}`;
    await this.redis.setWithExpiry(
      transactionKey,
      JSON.stringify(transactionRecord),
      86400 * 365 // 1 year
    );
  }

  /**
   * Get distribution status
   */
  public async getDistributionStatus(distributionId: string): Promise<RewardDistribution | null> {
    const cacheKey = `distribution:${distributionId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return null;
  }

  /**
   * Get user reward history
   */
  public async getUserRewardHistory(userId: string): Promise<UserRewardHistory | null> {
    const userKey = `user_rewards:${userId}`;
    const cached = await this.redis.get(userKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return null;
  }

  // Helper methods
  private async cacheDistribution(distribution: RewardDistribution): Promise<void> {
    const cacheKey = `distribution:${distribution.id}`;
    await this.redis.setWithExpiry(
      cacheKey,
      JSON.stringify(distribution),
      86400 * 7 // 7 days
    );
  }

  private async updateDistribution(distribution: RewardDistribution): Promise<void> {
    await this.cacheDistribution(distribution);
  }
}

/**
 * RWD-004: Comprehensive Reward History and Analytics
 * Advanced analytics and reporting system
 */
export class RewardAnalyticsEngine extends EventEmitter {
  private redis: RedisService;
  private analyticsCache: Map<string, any> = new Map();
  private readonly ANALYTICS_CACHE_TTL = 3600; // 1 hour

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.startAnalyticsProcessor();
  }

  /**
   * Generate comprehensive reward analytics
   */
  public async generateAnalytics(timeRange?: {
    startDate: Date;
    endDate: Date;
  }): Promise<RewardAnalytics> {
    const cacheKey = timeRange 
      ? `analytics:${timeRange.startDate.getTime()}-${timeRange.endDate.getTime()}`
      : 'analytics:all';

    // Check cache first
    const cached = this.analyticsCache.get(cacheKey);
    if (cached && cached.timestamp > Date.now() - (this.ANALYTICS_CACHE_TTL * 1000)) {
      return cached.data;
    }

    const startTime = Date.now();

    // Generate analytics in parallel
    const [
      totalStats,
      topUsers,
      topLocations,
      hourlyTrends,
      dailyTrends,
      poolStats,
      geoDistribution
    ] = await Promise.all([
      this.calculateTotalStats(timeRange),
      this.getTopEarningUsers(timeRange),
      this.getTopRewardingLocations(timeRange),
      this.getHourlyTrends(timeRange),
      this.getDailyTrends(timeRange),
      this.getPoolUtilization(timeRange),
      this.getGeographicDistribution(timeRange)
    ]);

    const analytics: RewardAnalytics = {
      totalRewardsDistributed: totalStats.totalRewards,
      totalUsers: totalStats.totalUsers,
      averageRewardPerUser: totalStats.avgRewardPerUser,
      averageRewardPerLocation: totalStats.avgRewardPerLocation,
      topEarningUsers: topUsers,
      topRewardingLocations: topLocations,
      rewardTrendsByHour: hourlyTrends,
      rewardTrendsByDay: dailyTrends,
      poolUtilization: poolStats,
      geographicDistribution: geoDistribution
    };

    const processingTime = Date.now() - startTime;

    // Cache results
    this.analyticsCache.set(cacheKey, {
      data: analytics,
      timestamp: Date.now()
    });

    logger.info(`Analytics generated`, {
      timeRange,
      processingTime,
      totalRewards: analytics.totalRewardsDistributed,
      totalUsers: analytics.totalUsers
    });

    this.emit('analytics_generated', { analytics, processingTime });

    return analytics;
  }

  /**
   * Generate user-specific analytics
   */
  public async generateUserAnalytics(userId: string): Promise<{
    totalEarned: number;
    rank: number;
    percentile: number;
    rewardHistory: Array<{ date: string; amount: number; location: string }>;
    locationBreakdown: Array<{ location: string; amount: number; visits: number }>;
    timePatterns: Array<{ hour: number; amount: number }>;
    achievements: Array<{ name: string; earnedAt: Date; reward: number }>;
    predictions: {
      nextLevelETA: string;
      projectedMonthlyEarnings: number;
      suggestedLocations: Array<{ location: string; expectedReward: number }>;
    };
  }> {
    const userRewards = await this.getUserRewardData(userId);
    if (!userRewards) {
      throw new Error(`User not found: ${userId}`);
    }

    // Calculate user rank
    const userRank = await this.calculateUserRank(userId, userRewards.totalEarned);
    const totalUsers = await this.getTotalUsersCount();
    const percentile = ((totalUsers - userRank) / totalUsers) * 100;

    // Get detailed history
    const rewardHistory = await this.getUserRewardHistory(userId);
    const locationBreakdown = await this.getUserLocationBreakdown(userId);
    const timePatterns = await this.getUserTimePatterns(userId);
    const achievements = await this.getUserAchievements(userId);
    const predictions = await this.generateUserPredictions(userId, userRewards);

    return {
      totalEarned: userRewards.totalEarned,
      rank: userRank,
      percentile,
      rewardHistory,
      locationBreakdown,
      timePatterns,
      achievements,
      predictions
    };
  }

  /**
   * Generate location-specific analytics
   */
  public async generateLocationAnalytics(location: GeoPoint, radiusMeters: number = 500): Promise<{
    totalRewards: number;
    uniqueUsers: number;
    averageReward: number;
    checkInCount: number;
    popularTimes: Array<{ hour: number; checkInCount: number; avgReward: number }>;
    rewardTrend: Array<{ date: string; totalRewards: number; userCount: number }>;
    userDistribution: Array<{ level: number; userCount: number; avgReward: number }>;
    nearbyLocations: Array<{ location: GeoPoint; distance: number; avgReward: number }>;
  }> {
    const locationKey = this.getLocationKey(location, radiusMeters);
    
    // Get location data
    const locationData = await this.getLocationData(locationKey);
    const nearbyLocations = await this.getNearbyLocations(location, radiusMeters * 2);
    
    return {
      totalRewards: locationData.totalRewards,
      uniqueUsers: locationData.uniqueUsers,
      averageReward: locationData.averageReward,
      checkInCount: locationData.checkInCount,
      popularTimes: locationData.popularTimes,
      rewardTrend: locationData.rewardTrend,
      userDistribution: locationData.userDistribution,
      nearbyLocations: nearbyLocations
    };
  }

  /**
   * Start periodic analytics processor
   */
  private startAnalyticsProcessor(): void {
    // Process analytics every 5 minutes
    setInterval(async () => {
      try {
        await this.processRealtimeAnalytics();
      } catch (error) {
        logger.error('Analytics processing failed', { error });
      }
    }, 300000); // 5 minutes
  }

  /**
   * Process real-time analytics
   */
  private async processRealtimeAnalytics(): Promise<void> {
    // Update real-time metrics
    await Promise.all([
      this.updateRealtimeMetrics(),
      this.updateLeaderboards(),
      this.updateLocationHotspots(),
      this.detectAnomalies()
    ]);

    this.emit('realtime_analytics_updated', { timestamp: new Date() });
  }

  // Helper methods for analytics calculations
  private async calculateTotalStats(timeRange?: { startDate: Date; endDate: Date }): Promise<{
    totalRewards: number;
    totalUsers: number;
    avgRewardPerUser: number;
    avgRewardPerLocation: number;
  }> {
    // Mock implementation - in production would query actual data
    return {
      totalRewards: 1000000,
      totalUsers: 5000,
      avgRewardPerUser: 200,
      avgRewardPerLocation: 150
    };
  }

  private async getTopEarningUsers(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ userId: string; totalEarned: number }>> {
    // Mock implementation
    return Array.from({ length: 10 }, (_, i) => ({
      userId: `user_${i + 1}`,
      totalEarned: 1000 - (i * 100)
    }));
  }

  private async getTopRewardingLocations(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ location: GeoPoint; totalRewards: number; checkInCount: number }>> {
    // Mock implementation
    return Array.from({ length: 10 }, (_, i) => ({
      location: {
        latitude: 40.7128 + (Math.random() - 0.5) * 0.1,
        longitude: -74.0060 + (Math.random() - 0.5) * 0.1
      },
      totalRewards: 5000 - (i * 500),
      checkInCount: 100 - (i * 10)
    }));
  }

  private async getHourlyTrends(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ hour: number; totalRewards: number; userCount: number }>> {
    return Array.from({ length: 24 }, (_, hour) => ({
      hour,
      totalRewards: Math.floor(Math.random() * 1000) + 500,
      userCount: Math.floor(Math.random() * 100) + 50
    }));
  }

  private async getDailyTrends(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ day: string; totalRewards: number; userCount: number }>> {
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    return days.map(day => ({
      day,
      totalRewards: Math.floor(Math.random() * 5000) + 2000,
      userCount: Math.floor(Math.random() * 500) + 200
    }));
  }

  private async getPoolUtilization(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ poolId: string; utilized: number; remaining: number; efficiency: number }>> {
    // Mock implementation
    return [
      { poolId: 'general_pool', utilized: 75000, remaining: 25000, efficiency: 0.75 },
      { poolId: 'tourist_pool', utilized: 30000, remaining: 20000, efficiency: 0.60 }
    ];
  }

  private async getGeographicDistribution(timeRange?: { startDate: Date; endDate: Date }): Promise<Array<{ region: string; totalRewards: number; userCount: number }>> {
    const regions = ['North America', 'Europe', 'Asia', 'South America', 'Africa', 'Oceania'];
    return regions.map(region => ({
      region,
      totalRewards: Math.floor(Math.random() * 10000) + 5000,
      userCount: Math.floor(Math.random() * 1000) + 500
    }));
  }

  private async getUserRewardData(userId: string): Promise<UserRewardHistory | null> {
    const userKey = `user_rewards:${userId}`;
    const cached = await this.redis.get(userKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return null;
  }

  private async calculateUserRank(userId: string, totalEarned: number): Promise<number> {
    // In production, would use sorted sets or database queries
    return Math.floor(Math.random() * 1000) + 1;
  }

  private async getTotalUsersCount(): Promise<number> {
    return 5000; // Mock data
  }

  private async getUserRewardHistory(userId: string): Promise<Array<{ date: string; amount: number; location: string }>> {
    // Mock implementation
    return Array.from({ length: 30 }, (_, i) => ({
      date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      amount: Math.floor(Math.random() * 50) + 10,
      location: `Location ${Math.floor(Math.random() * 10) + 1}`
    }));
  }

  private async getUserLocationBreakdown(userId: string): Promise<Array<{ location: string; amount: number; visits: number }>> {
    return Array.from({ length: 10 }, (_, i) => ({
      location: `Location ${i + 1}`,
      amount: Math.floor(Math.random() * 200) + 50,
      visits: Math.floor(Math.random() * 20) + 5
    }));
  }

  private async getUserTimePatterns(userId: string): Promise<Array<{ hour: number; amount: number }>> {
    return Array.from({ length: 24 }, (_, hour) => ({
      hour,
      amount: Math.floor(Math.random() * 100) + 10
    }));
  }

  private async getUserAchievements(userId: string): Promise<Array<{ name: string; earnedAt: Date; reward: number }>> {
    return [
      { name: 'First Check-in', earnedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), reward: 50 },
      { name: '10-Day Streak', earnedAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000), reward: 100 },
      { name: 'Explorer', earnedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000), reward: 75 }
    ];
  }

  private async generateUserPredictions(userId: string, userRewards: UserRewardHistory): Promise<{
    nextLevelETA: string;
    projectedMonthlyEarnings: number;
    suggestedLocations: Array<{ location: string; expectedReward: number }>;
  }> {
    const xpNeeded = userRewards.levelProgress.nextLevelXP - userRewards.levelProgress.currentXP;
    const avgDailyEarnings = userRewards.totalEarned / Math.max(userRewards.totalDistributions, 1);
    const daysToNextLevel = Math.ceil(xpNeeded / avgDailyEarnings);
    
    return {
      nextLevelETA: `${daysToNextLevel} days`,
      projectedMonthlyEarnings: avgDailyEarnings * 30,
      suggestedLocations: [
        { location: 'Tourist Area Downtown', expectedReward: 45 },
        { location: 'Historic District', expectedReward: 38 },
        { location: 'Shopping Center', expectedReward: 32 }
      ]
    };
  }

  private getLocationKey(location: GeoPoint, radius: number): string {
    return `loc:${location.latitude.toFixed(4)},${location.longitude.toFixed(4)}:${radius}`;
  }

  private async getLocationData(locationKey: string): Promise<any> {
    // Mock location data
    return {
      totalRewards: Math.floor(Math.random() * 10000) + 1000,
      uniqueUsers: Math.floor(Math.random() * 500) + 100,
      averageReward: Math.floor(Math.random() * 50) + 20,
      checkInCount: Math.floor(Math.random() * 1000) + 200,
      popularTimes: Array.from({ length: 24 }, (_, hour) => ({
        hour,
        checkInCount: Math.floor(Math.random() * 50) + 10,
        avgReward: Math.floor(Math.random() * 30) + 15
      })),
      rewardTrend: Array.from({ length: 30 }, (_, i) => ({
        date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        totalRewards: Math.floor(Math.random() * 500) + 100,
        userCount: Math.floor(Math.random() * 50) + 10
      })),
      userDistribution: Array.from({ length: 5 }, (_, level) => ({
        level: level + 1,
        userCount: Math.floor(Math.random() * 100) + 20,
        avgReward: Math.floor(Math.random() * 40) + 20
      }))
    };
  }

  private async getNearbyLocations(center: GeoPoint, radiusMeters: number): Promise<Array<{ location: GeoPoint; distance: number; avgReward: number }>> {
    return Array.from({ length: 5 }, (_, i) => ({
      location: {
        latitude: center.latitude + (Math.random() - 0.5) * 0.01,
        longitude: center.longitude + (Math.random() - 0.5) * 0.01
      },
      distance: Math.floor(Math.random() * radiusMeters),
      avgReward: Math.floor(Math.random() * 40) + 20
    }));
  }

  private async updateRealtimeMetrics(): Promise<void> {
    // Update real-time metrics dashboard
  }

  private async updateLeaderboards(): Promise<void> {
    // Update user and location leaderboards
  }

  private async updateLocationHotspots(): Promise<void> {
    // Update trending locations
  }

  private async detectAnomalies(): Promise<void> {
    // Detect unusual reward patterns
  }
}

/**
 * Main Reward Calculation Engine class that orchestrates all reward components
 */
export class RewardCalculationEngine {
  private dynamicAlgorithm: DynamicRewardAlgorithm;
  private poolManager: RewardPoolManager;
  private distributionSystem: RewardDistributionSystem;
  private analyticsEngine: RewardAnalyticsEngine;
  private redis: RedisService;

  constructor(redis: RedisService) {
    this.redis = redis;
    this.dynamicAlgorithm = new DynamicRewardAlgorithm(redis);
    this.poolManager = new RewardPoolManager(redis);
    this.distributionSystem = new RewardDistributionSystem(redis);
    this.analyticsEngine = new RewardAnalyticsEngine(redis);

    logger.info('Reward Calculation Engine initialized');
  }

  // Expose all engines for external use
  public get algorithm() { return this.dynamicAlgorithm; }
  public get pools() { return this.poolManager; }
  public get distribution() { return this.distributionSystem; }
  public get analytics() { return this.analyticsEngine; }

  /**
   * Complete reward processing pipeline
   */
  public async processReward(
    userId: string,
    location: GeoPoint,
    geographicData: any
  ): Promise<{
    calculation: RewardCalculation;
    distribution: RewardDistribution;
    success: boolean;
    message: string;
  }> {
    const startTime = Date.now();

    try {
      // Step 1: Get user reward history
      const userHistory = await this.distributionSystem.getUserRewardHistory(userId) || {
        userId,
        totalEarned: 0,
        totalDistributions: 0,
        averageReward: 0,
        bestReward: 0,
        currentStreak: 0,
        longestStreak: 0,
        rewardsByLocation: {},
        rewardsByTimeOfDay: {},
        monthlyEarnings: [],
        levelProgress: {
          currentLevel: 1,
          currentXP: 0,
          nextLevelXP: 100,
          levelBenefits: []
        }
      };

      // Step 2: Calculate reward
      const calculation = await this.dynamicAlgorithm.calculateReward(
        userId,
        location,
        geographicData,
        userHistory
      );

      // Step 3: Allocate from pool
      const poolAllocation = await this.poolManager.allocateFromPool(
        calculation,
        geographicData
      );

      if (!poolAllocation.allocated) {
        return {
          calculation,
          distribution: {} as RewardDistribution,
          success: false,
          message: `Failed to allocate reward: ${poolAllocation.reason}`
        };
      }

      // Step 4: Distribute reward
      const distribution = await this.distributionSystem.distributeReward(
        calculation,
        poolAllocation,
        geographicData
      );

      const processingTime = Date.now() - startTime;

      logger.info('Reward processed successfully', {
        userId,
        location,
        calculatedReward: calculation.totalReward,
        allocatedAmount: poolAllocation.allocatedAmount,
        distributionId: distribution.id,
        processingTime
      });

      return {
        calculation,
        distribution,
        success: true,
        message: 'Reward processed successfully'
      };

    } catch (error) {
      logger.error('Reward processing failed', { userId, location, error });
      
      return {
        calculation: {} as RewardCalculation,
        distribution: {} as RewardDistribution,
        success: false,
        message: `Reward processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Health check for all reward components
   */
  public async healthCheck(): Promise<{
    algorithm: boolean;
    poolManager: boolean;
    distributionSystem: boolean;
    analyticsEngine: boolean;
    overall: boolean;
  }> {
    const checks = {
      algorithm: true, // Would implement actual health checks
      poolManager: true,
      distributionSystem: true,
      analyticsEngine: true,
      overall: true
    };

    checks.overall = Object.values(checks).slice(0, -1).every(Boolean);

    return checks;
  }

  /**
   * Get system performance metrics
   */
  public async getPerformanceMetrics(): Promise<{
    rewardsProcessedPerSecond: number;
    averageProcessingTime: number;
    totalRewardsDistributed: number;
    activeUsers: number;
    poolUtilization: number;
  }> {
    // This would aggregate actual performance metrics
    return {
      rewardsProcessedPerSecond: 50,
      averageProcessingTime: 150, // milliseconds
      totalRewardsDistributed: 1000000,
      activeUsers: 5000,
      poolUtilization: 0.75
    };
  }
}