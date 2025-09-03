/**
 * SmellPin LBS Reward System - Master System Integration
 * Complete API integration, performance optimization, and system orchestration
 */

import { EventEmitter } from 'events';
import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';
import { RedisService } from '../RedisService';
import { 
  GeographicCoreSystem, 
  GeoPoint, 
  GeofenceZone, 
  LocationValidation,
  GeographicData
} from './GeographicCoreSystem';
import { 
  AntiFraudSecuritySystem, 
  DeviceFingerprint, 
  FraudDetectionResult,
  AnomalyEvent
} from './AntiFraudSecuritySystem';
import { 
  RewardCalculationEngine,
  RewardCalculation,
  RewardDistribution,
  UserRewardHistory,
  RewardAnalytics
} from './RewardCalculationEngine';
import { LBSTestingFramework } from './LBSTestingFramework';

// API Types and Interfaces
export interface LBSCheckInRequest {
  location: {
    latitude: number;
    longitude: number;
    accuracy?: number;
    altitude?: number;
    source?: 'gps' | 'network' | 'passive' | 'fused';
  };
  deviceInfo: {
    userAgent: string;
    screenResolution: string;
    timezone: string;
    language: string;
    platform: string;
    hardware?: string;
    networkInfo?: string;
    batteryLevel?: number;
    sensors?: string[];
    installedApps?: string[];
  };
  sessionData: {
    duration: number;
    interactionCount: number;
    features: string[];
    metadata?: Record<string, any>;
  };
  previousLocations?: Array<{
    latitude: number;
    longitude: number;
    accuracy?: number;
    timestamp: string;
  }>;
}

export interface LBSCheckInResponse {
  success: boolean;
  data?: {
    reward: {
      amount: number;
      currency: string;
      calculation: {
        baseReward: number;
        multipliers: Array<{ rule: string; multiplier: number; reason: string }>;
        bonuses: Array<{ rule: string; bonus: number; reason: string }>;
        totalReward: number;
      };
      distribution: {
        id: string;
        status: string;
        transactionId?: string;
      };
    };
    location: {
      validated: boolean;
      accuracy: number;
      address?: string;
      category?: string;
      popularity?: number;
      geofences: string[];
    };
    security: {
      riskScore: number;
      trusted: boolean;
      restrictions?: string[];
    };
    user: {
      level: number;
      totalEarnings: number;
      streak: number;
      nextLevelProgress: number;
    };
  };
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
  metadata: {
    processingTime: number;
    requestId: string;
    timestamp: string;
    version: string;
  };
}

export interface LBSSystemStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: {
    geographic: {
      status: 'healthy' | 'degraded' | 'unhealthy';
      responseTime: number;
      accuracy: number;
    };
    fraud: {
      status: 'healthy' | 'degraded' | 'unhealthy';
      responseTime: number;
      detectionRate: number;
      falsePositiveRate: number;
    };
    rewards: {
      status: 'healthy' | 'degraded' | 'unhealthy';
      responseTime: number;
      distributionSuccessRate: number;
      queueDepth: number;
    };
  };
  performance: {
    concurrentUsers: number;
    requestsPerSecond: number;
    averageResponseTime: number;
    errorRate: number;
  };
  resources: {
    cpu: number;
    memory: number;
    redis: number;
    database: number;
  };
}

export interface LBSAnalyticsRequest {
  timeRange?: {
    startDate: string;
    endDate: string;
  };
  filters?: {
    userId?: string;
    location?: {
      latitude: number;
      longitude: number;
      radius: number;
    };
    categories?: string[];
  };
  groupBy?: 'hour' | 'day' | 'week' | 'month';
  limit?: number;
}

/**
 * Performance Optimization Engine
 * Handles caching, rate limiting, and performance monitoring
 */
export class PerformanceOptimizer extends EventEmitter {
  private redis: RedisService;
  private cache: Map<string, any> = new Map();
  private rateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
  private performanceMetrics: Map<string, number[]> = new Map();
  
  // Configuration
  private readonly CACHE_TTL = {
    LOCATION_DATA: 300,      // 5 minutes
    USER_HISTORY: 600,       // 10 minutes
    GEOFENCES: 1800,         // 30 minutes
    ANALYTICS: 3600,         // 1 hour
    FRAUD_PATTERNS: 7200     // 2 hours
  };

  private readonly RATE_LIMITS = {
    CHECKIN: { requests: 10, window: 60 },        // 10 checkins per minute
    ANALYTICS: { requests: 100, window: 3600 },   // 100 analytics requests per hour
    ADMIN: { requests: 1000, window: 3600 }       // 1000 admin requests per hour
  };

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.startPerformanceMonitoring();
  }

  /**
   * Multi-layer caching system
   */
  public async get<T>(key: string, fetchFn?: () => Promise<T>, ttl?: number): Promise<T | null> {
    // Layer 1: Memory cache (fastest)
    if (this.cache.has(key)) {
      const cached = this.cache.get(key);
      if (cached.expiry > Date.now()) {
        return cached.data;
      } else {
        this.cache.delete(key);
      }
    }

    // Layer 2: Redis cache (fast)
    const redisData = await this.redis.get(key);
    if (redisData) {
      const data = JSON.parse(redisData);
      // Store in memory cache for faster access
      this.cache.set(key, {
        data,
        expiry: Date.now() + (ttl || 60000) // Default 1 minute in memory
      });
      return data;
    }

    // Layer 3: Fetch from source (slowest)
    if (fetchFn) {
      const data = await fetchFn();
      await this.set(key, data, ttl);
      return data;
    }

    return null;
  }

  public async set(key: string, data: any, ttl?: number): Promise<void> {
    const cacheTTL = ttl || 300; // Default 5 minutes
    
    // Store in both layers
    this.cache.set(key, {
      data,
      expiry: Date.now() + Math.min(cacheTTL * 1000, 60000) // Max 1 minute in memory
    });
    
    await this.redis.setWithExpiry(key, JSON.stringify(data), cacheTTL);
  }

  /**
   * Intelligent rate limiting
   */
  public checkRateLimit(key: string, type: keyof typeof this.RATE_LIMITS): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const config = this.RATE_LIMITS[type];
    const now = Date.now();
    const windowStart = now - (config.window * 1000);
    
    let limiter = this.rateLimiter.get(key);
    
    if (!limiter || limiter.resetTime <= now) {
      limiter = {
        count: 0,
        resetTime: now + (config.window * 1000)
      };
    }

    limiter.count++;
    this.rateLimiter.set(key, limiter);

    const allowed = limiter.count <= config.requests;
    const remaining = Math.max(0, config.requests - limiter.count);

    return {
      allowed,
      remaining,
      resetTime: limiter.resetTime
    };
  }

  /**
   * Performance monitoring and optimization
   */
  public recordMetric(name: string, value: number): void {
    if (!this.performanceMetrics.has(name)) {
      this.performanceMetrics.set(name, []);
    }
    
    const metrics = this.performanceMetrics.get(name)!;
    metrics.push(value);
    
    // Keep only last 100 measurements
    if (metrics.length > 100) {
      metrics.shift();
    }
    
    // Emit alerts for performance degradation
    if (metrics.length >= 10) {
      const recent = metrics.slice(-10);
      const average = recent.reduce((sum, val) => sum + val, 0) / recent.length;
      
      if (name === 'response_time' && average > 1000) {
        this.emit('performance_alert', {
          metric: name,
          value: average,
          threshold: 1000,
          message: 'High response time detected'
        });
      }
    }
  }

  public getMetrics(): Record<string, { average: number; min: number; max: number; count: number }> {
    const summary: Record<string, any> = {};
    
    this.performanceMetrics.forEach((values, name) => {
      if (values.length > 0) {
        summary[name] = {
          average: values.reduce((sum, val) => sum + val, 0) / values.length,
          min: Math.min(...values),
          max: Math.max(...values),
          count: values.length
        };
      }
    });
    
    return summary;
  }

  /**
   * Adaptive cache warming
   */
  public async warmCache(): Promise<void> {
    // Pre-load frequently accessed data
    const popularLocations = await this.getPopularLocations();
    for (const location of popularLocations) {
      const key = `location_data:${location.latitude.toFixed(4)},${location.longitude.toFixed(4)}`;
      // Cache location data proactively
    }
  }

  /**
   * Cache invalidation patterns
   */
  public async invalidateUserCache(userId: string): Promise<void> {
    const patterns = [
      `user_rewards:${userId}`,
      `user_history:${userId}`,
      `user_behavior:${userId}`,
      `user_fingerprints:${userId}`
    ];
    
    for (const pattern of patterns) {
      this.cache.delete(pattern);
      await this.redis.delete(pattern);
    }
  }

  public async invalidateLocationCache(location: GeoPoint): Promise<void> {
    const key = `location_data:${location.latitude.toFixed(4)},${location.longitude.toFixed(4)}`;
    this.cache.delete(key);
    await this.redis.delete(key);
  }

  // Helper methods
  private startPerformanceMonitoring(): void {
    setInterval(() => {
      this.cleanupMemoryCache();
      this.cleanupRateLimiters();
    }, 60000); // Every minute
  }

  private cleanupMemoryCache(): void {
    const now = Date.now();
    for (const [key, cached] of this.cache.entries()) {
      if (cached.expiry <= now) {
        this.cache.delete(key);
      }
    }
  }

  private cleanupRateLimiters(): void {
    const now = Date.now();
    for (const [key, limiter] of this.rateLimiter.entries()) {
      if (limiter.resetTime <= now) {
        this.rateLimiter.delete(key);
      }
    }
  }

  private async getPopularLocations(): Promise<GeoPoint[]> {
    // Mock implementation - would get from analytics
    return [
      { latitude: 40.7128, longitude: -74.0060 },
      { latitude: 34.0522, longitude: -118.2437 },
      { latitude: 41.8781, longitude: -87.6298 }
    ];
  }
}

/**
 * Request/Response Processing Pipeline
 * Handles validation, transformation, and response formatting
 */
export class LBSRequestProcessor extends EventEmitter {
  private optimizer: PerformanceOptimizer;

  constructor(optimizer: PerformanceOptimizer) {
    super();
    this.optimizer = optimizer;
  }

  /**
   * Validate and transform incoming request
   */
  public validateCheckInRequest(req: Request): {
    valid: boolean;
    data?: LBSCheckInRequest;
    errors?: string[];
  } {
    const errors: string[] = [];
    
    try {
      const { location, deviceInfo, sessionData, previousLocations } = req.body;

      // Validate location
      if (!location || typeof location.latitude !== 'number' || typeof location.longitude !== 'number') {
        errors.push('Valid location coordinates required');
      }

      if (location && (location.latitude < -90 || location.latitude > 90)) {
        errors.push('Latitude must be between -90 and 90');
      }

      if (location && (location.longitude < -180 || location.longitude > 180)) {
        errors.push('Longitude must be between -180 and 180');
      }

      // Validate device info
      if (!deviceInfo || !deviceInfo.userAgent || !deviceInfo.platform) {
        errors.push('Device information required');
      }

      // Validate session data
      if (!sessionData || typeof sessionData.duration !== 'number') {
        errors.push('Valid session data required');
      }

      if (errors.length > 0) {
        return { valid: false, errors };
      }

      // Transform and normalize data
      const transformedData: LBSCheckInRequest = {
        location: {
          latitude: parseFloat(location.latitude.toFixed(6)),
          longitude: parseFloat(location.longitude.toFixed(6)),
          accuracy: location.accuracy || undefined,
          altitude: location.altitude || undefined,
          source: location.source || 'gps'
        },
        deviceInfo: {
          userAgent: deviceInfo.userAgent,
          screenResolution: deviceInfo.screenResolution || 'unknown',
          timezone: deviceInfo.timezone || 'UTC',
          language: deviceInfo.language || 'en-US',
          platform: deviceInfo.platform,
          hardware: deviceInfo.hardware,
          networkInfo: deviceInfo.networkInfo,
          batteryLevel: deviceInfo.batteryLevel,
          sensors: deviceInfo.sensors || [],
          installedApps: deviceInfo.installedApps || []
        },
        sessionData: {
          duration: sessionData.duration,
          interactionCount: sessionData.interactionCount || 1,
          features: sessionData.features || ['checkin'],
          metadata: sessionData.metadata || {}
        },
        previousLocations: previousLocations?.map((loc: any) => ({
          latitude: parseFloat(loc.latitude.toFixed(6)),
          longitude: parseFloat(loc.longitude.toFixed(6)),
          accuracy: loc.accuracy,
          timestamp: loc.timestamp
        })) || []
      };

      return { valid: true, data: transformedData };

    } catch (error) {
      return {
        valid: false,
        errors: [`Invalid request format: ${error instanceof Error ? error.message : 'Unknown error'}`]
      };
    }
  }

  /**
   * Format successful check-in response
   */
  public formatCheckInResponse(
    requestId: string,
    processingStartTime: number,
    results: {
      rewardResult: any;
      locationResult: any;
      fraudResult: FraudDetectionResult;
      userHistory: UserRewardHistory;
    }
  ): LBSCheckInResponse {
    const processingTime = Date.now() - processingStartTime;

    return {
      success: true,
      data: {
        reward: {
          amount: results.rewardResult.calculation.totalReward,
          currency: results.rewardResult.calculation.currency,
          calculation: {
            baseReward: results.rewardResult.calculation.baseReward,
            multipliers: results.rewardResult.calculation.multipliers,
            bonuses: results.rewardResult.calculation.bonuses,
            totalReward: results.rewardResult.calculation.totalReward
          },
          distribution: {
            id: results.rewardResult.distribution.id,
            status: results.rewardResult.distribution.status,
            transactionId: results.rewardResult.distribution.transactionId
          }
        },
        location: {
          validated: results.locationResult.isValidLocation,
          accuracy: results.locationResult.validation?.accuracy || 0,
          address: results.locationResult.locationData?.address,
          category: results.locationResult.locationData?.category,
          popularity: results.locationResult.locationData?.popularity,
          geofences: results.locationResult.geofences?.map((g: GeofenceZone) => g.name) || []
        },
        security: {
          riskScore: results.fraudResult.riskScore,
          trusted: !results.fraudResult.isFraudulent,
          restrictions: results.fraudResult.isFraudulent ? 
            [results.fraudResult.recommendedAction] : undefined
        },
        user: {
          level: results.userHistory.levelProgress.currentLevel,
          totalEarnings: results.userHistory.totalEarned,
          streak: results.userHistory.currentStreak,
          nextLevelProgress: (results.userHistory.levelProgress.currentXP / 
            results.userHistory.levelProgress.nextLevelXP) * 100
        }
      },
      metadata: {
        processingTime,
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      }
    };
  }

  /**
   * Format error response
   */
  public formatErrorResponse(
    requestId: string,
    processingStartTime: number,
    error: {
      code: string;
      message: string;
      details?: Record<string, any>;
    }
  ): LBSCheckInResponse {
    const processingTime = Date.now() - processingStartTime;

    return {
      success: false,
      error,
      metadata: {
        processingTime,
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      }
    };
  }

  /**
   * Generate request ID
   */
  public generateRequestId(): string {
    return `lbs_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * System Health Monitor
 * Monitors system health and triggers alerts
 */
export class SystemHealthMonitor extends EventEmitter {
  private geographicSystem: GeographicCoreSystem;
  private fraudSystem: AntiFraudSecuritySystem;
  private rewardEngine: RewardCalculationEngine;
  private optimizer: PerformanceOptimizer;
  
  private healthStatus: LBSSystemStatus;
  private alertThresholds = {
    responseTime: 1000,      // 1 second
    errorRate: 0.05,         // 5%
    cpuUsage: 80,            // 80%
    memoryUsage: 85,         // 85%
    queueDepth: 1000,        // 1000 items
    detectionRate: 0.90,     // 90%
    falsePositiveRate: 0.10  // 10%
  };

  constructor(
    geographicSystem: GeographicCoreSystem,
    fraudSystem: AntiFraudSecuritySystem,
    rewardEngine: RewardCalculationEngine,
    optimizer: PerformanceOptimizer
  ) {
    super();
    this.geographicSystem = geographicSystem;
    this.fraudSystem = fraudSystem;
    this.rewardEngine = rewardEngine;
    this.optimizer = optimizer;
    
    this.healthStatus = this.initializeHealthStatus();
    this.startHealthMonitoring();
  }

  /**
   * Get current system status
   */
  public getSystemStatus(): LBSSystemStatus {
    return { ...this.healthStatus };
  }

  /**
   * Perform health check on all components
   */
  public async performHealthCheck(): Promise<LBSSystemStatus> {
    const startTime = Date.now();

    try {
      // Test all components in parallel
      const [geoHealth, fraudHealth, rewardHealth] = await Promise.allSettled([
        this.checkGeographicHealth(),
        this.checkFraudHealth(),
        this.checkRewardHealth()
      ]);

      // Update component statuses
      this.healthStatus.components.geographic = geoHealth.status === 'fulfilled' ? 
        geoHealth.value : { status: 'unhealthy', responseTime: 0, accuracy: 0 };

      this.healthStatus.components.fraud = fraudHealth.status === 'fulfilled' ? 
        fraudHealth.value : { status: 'unhealthy', responseTime: 0, detectionRate: 0, falsePositiveRate: 1 };

      this.healthStatus.components.rewards = rewardHealth.status === 'fulfilled' ? 
        rewardHealth.value : { status: 'unhealthy', responseTime: 0, distributionSuccessRate: 0, queueDepth: 0 };

      // Update performance metrics
      await this.updatePerformanceMetrics();
      
      // Update resource metrics
      await this.updateResourceMetrics();

      // Determine overall status
      this.updateOverallStatus();

      const checkTime = Date.now() - startTime;
      logger.debug('Health check completed', { 
        checkTime, 
        overallStatus: this.healthStatus.status 
      });

      return this.getSystemStatus();

    } catch (error) {
      logger.error('Health check failed', { error });
      this.healthStatus.status = 'unhealthy';
      return this.getSystemStatus();
    }
  }

  /**
   * Check geographic system health
   */
  private async checkGeographicHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    responseTime: number;
    accuracy: number;
  }> {
    const startTime = Date.now();
    
    try {
      // Test with known location
      const testLocation: GeoPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: new Date()
      };

      const result = await this.geographicSystem.processLocationForRewards(
        testLocation,
        'health_check_user'
      );

      const responseTime = Date.now() - startTime;
      const accuracy = result.validation?.accuracy || 0;

      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
      
      if (responseTime > this.alertThresholds.responseTime) {
        status = 'degraded';
      }
      
      if (!result.isValidLocation || accuracy > 50) {
        status = 'unhealthy';
      }

      return { status, responseTime, accuracy };

    } catch (error) {
      logger.error('Geographic health check failed', { error });
      return { status: 'unhealthy', responseTime: Date.now() - startTime, accuracy: 0 };
    }
  }

  /**
   * Check fraud system health
   */
  private async checkFraudHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    responseTime: number;
    detectionRate: number;
    falsePositiveRate: number;
  }> {
    const startTime = Date.now();
    
    try {
      // Test with benign request
      const testLocation: GeoPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: new Date()
      };

      const result = await this.fraudSystem.detectFraud(
        'health_check_user',
        testLocation,
        { userAgent: 'health_check', platform: 'test' },
        { duration: 30, interactionCount: 1, features: ['test'] }
      );

      const responseTime = Date.now() - startTime;
      
      // Get system stats (mock for health check)
      const stats = await this.fraudSystem.getSystemStats();
      
      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
      
      if (responseTime > this.alertThresholds.responseTime) {
        status = 'degraded';
      }
      
      if (stats.detectionAccuracy < this.alertThresholds.detectionRate) {
        status = 'unhealthy';
      }

      return {
        status,
        responseTime,
        detectionRate: stats.detectionAccuracy,
        falsePositiveRate: 1 - stats.detectionAccuracy // Simplified
      };

    } catch (error) {
      logger.error('Fraud health check failed', { error });
      return { 
        status: 'unhealthy', 
        responseTime: Date.now() - startTime, 
        detectionRate: 0, 
        falsePositiveRate: 1 
      };
    }
  }

  /**
   * Check reward system health
   */
  private async checkRewardHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    responseTime: number;
    distributionSuccessRate: number;
    queueDepth: number;
  }> {
    const startTime = Date.now();
    
    try {
      // Test reward processing
      const testLocation: GeoPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: new Date()
      };

      const result = await this.rewardEngine.processReward(
        'health_check_user',
        testLocation,
        {} as GeographicData
      );

      const responseTime = Date.now() - startTime;
      
      // Get performance metrics
      const performance = await this.rewardEngine.getPerformanceMetrics();
      
      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
      
      if (responseTime > this.alertThresholds.responseTime) {
        status = 'degraded';
      }
      
      if (!result.success || performance.poolUtilization > 0.95) {
        status = 'unhealthy';
      }

      return {
        status,
        responseTime,
        distributionSuccessRate: result.success ? 1 : 0,
        queueDepth: 0 // Would get from actual queue
      };

    } catch (error) {
      logger.error('Reward health check failed', { error });
      return { 
        status: 'unhealthy', 
        responseTime: Date.now() - startTime, 
        distributionSuccessRate: 0, 
        queueDepth: 0 
      };
    }
  }

  /**
   * Update performance metrics
   */
  private async updatePerformanceMetrics(): Promise<void> {
    const metrics = this.optimizer.getMetrics();
    
    this.healthStatus.performance = {
      concurrentUsers: 0, // Would track actual concurrent users
      requestsPerSecond: metrics['requests_per_second']?.average || 0,
      averageResponseTime: metrics['response_time']?.average || 0,
      errorRate: metrics['error_rate']?.average || 0
    };
  }

  /**
   * Update resource utilization metrics
   */
  private async updateResourceMetrics(): Promise<void> {
    const memoryUsage = process.memoryUsage();
    
    this.healthStatus.resources = {
      cpu: 0, // Would implement actual CPU monitoring
      memory: (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100,
      redis: 0, // Would implement Redis memory monitoring
      database: 0 // Would implement database monitoring
    };
  }

  /**
   * Update overall system status
   */
  private updateOverallStatus(): void {
    const components = [
      this.healthStatus.components.geographic.status,
      this.healthStatus.components.fraud.status,
      this.healthStatus.components.rewards.status
    ];

    if (components.every(status => status === 'healthy')) {
      this.healthStatus.status = 'healthy';
    } else if (components.some(status => status === 'unhealthy')) {
      this.healthStatus.status = 'unhealthy';
    } else {
      this.healthStatus.status = 'degraded';
    }

    // Check performance thresholds
    if (this.healthStatus.performance.averageResponseTime > this.alertThresholds.responseTime ||
        this.healthStatus.performance.errorRate > this.alertThresholds.errorRate) {
      this.healthStatus.status = 'degraded';
    }

    // Check resource thresholds
    if (this.healthStatus.resources.cpu > this.alertThresholds.cpuUsage ||
        this.healthStatus.resources.memory > this.alertThresholds.memoryUsage) {
      this.healthStatus.status = 'degraded';
    }
  }

  /**
   * Start continuous health monitoring
   */
  private startHealthMonitoring(): void {
    // Perform health check every 30 seconds
    setInterval(async () => {
      try {
        const previousStatus = this.healthStatus.status;
        await this.performHealthCheck();
        
        // Emit events on status changes
        if (previousStatus !== this.healthStatus.status) {
          this.emit('status_changed', {
            previous: previousStatus,
            current: this.healthStatus.status,
            timestamp: new Date()
          });

          logger.info(`System status changed: ${previousStatus} -> ${this.healthStatus.status}`);
        }

        // Emit alerts for unhealthy status
        if (this.healthStatus.status === 'unhealthy') {
          this.emit('system_alert', {
            level: 'critical',
            message: 'System is unhealthy',
            components: this.healthStatus.components,
            timestamp: new Date()
          });
        }

      } catch (error) {
        logger.error('Health monitoring failed', { error });
      }
    }, 30000);
  }

  private initializeHealthStatus(): LBSSystemStatus {
    return {
      status: 'healthy',
      components: {
        geographic: {
          status: 'healthy',
          responseTime: 0,
          accuracy: 0
        },
        fraud: {
          status: 'healthy',
          responseTime: 0,
          detectionRate: 0,
          falsePositiveRate: 0
        },
        rewards: {
          status: 'healthy',
          responseTime: 0,
          distributionSuccessRate: 0,
          queueDepth: 0
        }
      },
      performance: {
        concurrentUsers: 0,
        requestsPerSecond: 0,
        averageResponseTime: 0,
        errorRate: 0
      },
      resources: {
        cpu: 0,
        memory: 0,
        redis: 0,
        database: 0
      }
    };
  }
}

/**
 * Main LBS Master System
 * Orchestrates all components and provides unified API
 */
export class LBSMasterSystem extends EventEmitter {
  private geographicSystem: GeographicCoreSystem;
  private fraudSystem: AntiFraudSecuritySystem;
  private rewardEngine: RewardCalculationEngine;
  private testingFramework: LBSTestingFramework;
  
  private optimizer: PerformanceOptimizer;
  private requestProcessor: LBSRequestProcessor;
  private healthMonitor: SystemHealthMonitor;
  private redis: RedisService;

  // System configuration
  private readonly config = {
    version: '1.0.0',
    maxConcurrentRequests: 10000,
    defaultTimeout: 30000, // 30 seconds
    enableTesting: process.env['NODE_ENV'] !== 'production'
  };

  constructor(redis: RedisService) {
    super();
    this.redis = redis;

    // Initialize core systems
    this.geographicSystem = new GeographicCoreSystem(redis);
    this.fraudSystem = new AntiFraudSecuritySystem(redis);
    this.rewardEngine = new RewardCalculationEngine(redis);
    this.testingFramework = new LBSTestingFramework(
      this.geographicSystem,
      this.fraudSystem,
      this.rewardEngine,
      redis
    );

    // Initialize integration systems
    this.optimizer = new PerformanceOptimizer(redis);
    this.requestProcessor = new LBSRequestProcessor(this.optimizer);
    this.healthMonitor = new SystemHealthMonitor(
      this.geographicSystem,
      this.fraudSystem,
      this.rewardEngine,
      this.optimizer
    );

    this.initializeEventHandlers();
    logger.info('LBS Master System initialized', { version: this.config.version });
  }

  /**
   * Main check-in processing endpoint
   */
  public async processCheckIn(req: Request, res: Response, next: NextFunction): Promise<void> {
    const requestId = this.requestProcessor.generateRequestId();
    const processingStartTime = Date.now();
    
    try {
      // Rate limiting
      const userId = req.user?.id || 'anonymous';
      const rateLimitCheck = this.optimizer.checkRateLimit(`checkin:${userId}`, 'CHECKIN');
      
      if (!rateLimitCheck.allowed) {
        const errorResponse = this.requestProcessor.formatErrorResponse(
          requestId,
          processingStartTime,
          {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            details: { resetTime: rateLimitCheck.resetTime }
          }
        );
        
        res.status(429).json(errorResponse);
        return;
      }

      // Request validation
      const validation = this.requestProcessor.validateCheckInRequest(req);
      if (!validation.valid) {
        const errorResponse = this.requestProcessor.formatErrorResponse(
          requestId,
          processingStartTime,
          {
            code: 'INVALID_REQUEST',
            message: 'Request validation failed',
            details: { errors: validation.errors }
          }
        );
        
        res.status(400).json(errorResponse);
        return;
      }

      const requestData = validation.data!;

      // Convert request to internal format
      const location: GeoPoint = {
        ...requestData.location,
        timestamp: new Date()
      };

      const previousLocations: GeoPoint[] = requestData.previousLocations?.map(loc => ({
        ...loc,
        timestamp: new Date(loc.timestamp)
      })) || [];

      // Process through all systems in parallel where possible
      const [locationResult, fraudResult] = await Promise.all([
        this.geographicSystem.processLocationForRewards(location, userId, previousLocations[0]),
        this.fraudSystem.detectFraud(
          userId,
          location,
          requestData.deviceInfo,
          requestData.sessionData,
          previousLocations
        )
      ]);

      // Security check - block fraudulent requests
      if (fraudResult.isFraudulent && fraudResult.recommendedAction === 'BLOCK') {
        const errorResponse = this.requestProcessor.formatErrorResponse(
          requestId,
          processingStartTime,
          {
            code: 'SECURITY_BLOCK',
            message: 'Request blocked due to security concerns',
            details: { riskScore: fraudResult.riskScore }
          }
        );
        
        res.status(403).json(errorResponse);
        return;
      }

      // Location validation check
      if (!locationResult.isValidLocation) {
        const errorResponse = this.requestProcessor.formatErrorResponse(
          requestId,
          processingStartTime,
          {
            code: 'INVALID_LOCATION',
            message: 'Location validation failed',
            details: { validation: locationResult.validation }
          }
        );
        
        res.status(400).json(errorResponse);
        return;
      }

      // Process reward if security and location checks pass
      const rewardResult = await this.rewardEngine.processReward(
        userId,
        location,
        locationResult.locationData
      );

      if (!rewardResult.success) {
        const errorResponse = this.requestProcessor.formatErrorResponse(
          requestId,
          processingStartTime,
          {
            code: 'REWARD_PROCESSING_FAILED',
            message: rewardResult.message,
            details: { rewardResult }
          }
        );
        
        res.status(500).json(errorResponse);
        return;
      }

      // Get user history for response
      const userHistory = await this.rewardEngine.distribution.getUserRewardHistory(userId) || {
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

      // Format successful response
      const response = this.requestProcessor.formatCheckInResponse(
        requestId,
        processingStartTime,
        {
          rewardResult,
          locationResult,
          fraudResult,
          userHistory
        }
      );

      // Record performance metrics
      const processingTime = Date.now() - processingStartTime;
      this.optimizer.recordMetric('response_time', processingTime);
      this.optimizer.recordMetric('requests_per_second', 1);

      // Add rate limit headers
      res.setHeader('X-RateLimit-Remaining', rateLimitCheck.remaining);
      res.setHeader('X-RateLimit-Reset', rateLimitCheck.resetTime);
      
      res.status(200).json(response);

      // Emit success event
      this.emit('checkin_processed', {
        requestId,
        userId,
        location,
        processingTime,
        rewardAmount: rewardResult.calculation.totalReward
      });

    } catch (error) {
      logger.error('Check-in processing failed', { 
        requestId, 
        userId: req.user?.id,
        error 
      });

      const errorResponse = this.requestProcessor.formatErrorResponse(
        requestId,
        processingStartTime,
        {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Internal server error occurred',
          details: { error: error instanceof Error ? error.message : 'Unknown error' }
        }
      );

      this.optimizer.recordMetric('error_rate', 1);
      res.status(500).json(errorResponse);
    }
  }

  /**
   * System status endpoint
   */
  public async getSystemStatus(req: Request, res: Response): Promise<void> {
    try {
      const status = await this.healthMonitor.performHealthCheck();
      
      res.status(status.status === 'healthy' ? 200 : 503).json({
        success: true,
        data: status,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Status check failed', { error });
      
      res.status(500).json({
        success: false,
        error: {
          code: 'STATUS_CHECK_FAILED',
          message: 'Failed to retrieve system status'
        }
      });
    }
  }

  /**
   * Analytics endpoint
   */
  public async getAnalytics(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required for analytics'
          }
        });
        return;
      }

      // Rate limiting for analytics
      const rateLimitCheck = this.optimizer.checkRateLimit(`analytics:${userId}`, 'ANALYTICS');
      if (!rateLimitCheck.allowed) {
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Analytics rate limit exceeded'
          }
        });
        return;
      }

      // Parse request parameters
      const { timeRange, filters, groupBy, limit } = req.query;
      
      // Get analytics (cached)
      const cacheKey = `analytics:${userId}:${JSON.stringify(req.query)}`;
      const analytics = await this.optimizer.get(
        cacheKey,
        () => this.rewardEngine.analytics.generateUserAnalytics(userId),
        this.optimizer['CACHE_TTL']['ANALYTICS']
      );

      res.json({
        success: true,
        data: analytics,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Analytics request failed', { error });
      
      res.status(500).json({
        success: false,
        error: {
          code: 'ANALYTICS_FAILED',
          message: 'Failed to retrieve analytics data'
        }
      });
    }
  }

  /**
   * Testing endpoint (development/staging only)
   */
  public async runTests(req: Request, res: Response): Promise<void> {
    if (!this.config.enableTesting) {
      res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'Testing endpoints not available in production'
        }
      });
      return;
    }

    try {
      const { testType, quick } = req.query;
      
      let results;
      
      if (quick === 'true') {
        results = await this.testingFramework.runQuickValidation();
      } else {
        results = await this.testingFramework.runCompleteTestSuite();
      }

      res.json({
        success: true,
        data: results,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Test execution failed', { error });
      
      res.status(500).json({
        success: false,
        error: {
          code: 'TEST_EXECUTION_FAILED',
          message: 'Failed to execute tests'
        }
      });
    }
  }

  /**
   * Initialize system and perform startup checks
   */
  public async initialize(): Promise<void> {
    try {
      logger.info('Initializing LBS Master System...');

      // Warm up caches
      await this.optimizer.warmCache();

      // Perform initial health check
      const initialHealth = await this.healthMonitor.performHealthCheck();
      logger.info('Initial system health check', { status: initialHealth.status });

      // Run quick validation if in development
      if (this.config.enableTesting) {
        const validation = await this.testingFramework.runQuickValidation();
        if (!validation.systemReady) {
          logger.warn('System validation warnings detected', {
            criticalIssues: validation.criticalIssues,
            warnings: validation.warnings
          });
        }
      }

      logger.info('LBS Master System initialization complete');
      this.emit('system_ready', { timestamp: new Date() });

    } catch (error) {
      logger.error('System initialization failed', { error });
      throw error;
    }
  }

  /**
   * Graceful shutdown
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down LBS Master System...');
    
    try {
      // Clean up resources
      // ... cleanup code ...
      
      logger.info('LBS Master System shutdown complete');
      this.emit('system_shutdown', { timestamp: new Date() });
    } catch (error) {
      logger.error('Error during shutdown', { error });
    }
  }

  // Event handlers
  private initializeEventHandlers(): void {
    // Performance alerts
    this.optimizer.on('performance_alert', (alert) => {
      logger.warn('Performance alert', alert);
      this.emit('system_alert', {
        type: 'performance',
        level: 'warning',
        ...alert
      });
    });

    // Health status changes
    this.healthMonitor.on('status_changed', (change) => {
      logger.info('System status changed', change);
      this.emit('system_status_changed', change);
    });

    // Critical system alerts
    this.healthMonitor.on('system_alert', (alert) => {
      logger.error('Critical system alert', alert);
      this.emit('critical_alert', alert);
    });

    // Fraud detection alerts
    this.fraudSystem.spoofing.on('spoofing_detected', (detection) => {
      logger.warn('GPS spoofing detected', detection);
      this.emit('security_alert', {
        type: 'gps_spoofing',
        ...detection
      });
    });

    // Reward system events
    this.rewardEngine.distribution.on('reward_distributed', (distribution) => {
      this.emit('reward_distributed', distribution);
    });
  }
}

// Export the master system for use in API routes
export { LBSMasterSystem as default };