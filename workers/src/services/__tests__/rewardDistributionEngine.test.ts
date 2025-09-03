import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RewardDistributionEngine, RewardDistributionResult, DEFAULT_REWARD_CONFIG } from '../rewardDistributionEngine';
import { RewardPoolManager } from '../rewardPoolManager';
import { GeofencingService } from '../geofencing';
import { AntiFraudService } from '../antiFraudService';

// Mock the dependencies
vi.mock('../geofencing');
vi.mock('../antiFraudService');
vi.mock('../rewardPoolManager');
vi.mock('../../utils/neon-database');

// Mock environment
const mockEnv = {
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test'
};

describe('RewardDistributionEngine', () => {
  let rewardEngine: RewardDistributionEngine;
  let mockGeofencingService: any;
  let mockAntiFraudService: any;
  let mockDb: any;

  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testAnnotationId = '550e8400-e29b-41d4-a716-446655440001';
  const testUserLocation = { latitude: 40.7128, longitude: -74.0060 };

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();

    // Mock database
    mockDb = {
      sql: vi.fn()
    };

    // Mock geofencing service
    mockGeofencingService = {
      checkGeofence: vi.fn()
    };

    // Mock anti-fraud service
    mockAntiFraudService = {
      analyzeUserBehavior: vi.fn()
    };

    // Create instance with mocked dependencies
    rewardEngine = new RewardDistributionEngine(mockEnv as any);
    
    // Inject mocks (accessing private properties for testing)
    (rewardEngine as any).db = mockDb;
    (rewardEngine as any).geofencingService = mockGeofencingService;
    (rewardEngine as any).antiFraudService = mockAntiFraudService;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('distributeReward', () => {
    it('should successfully distribute reward when all conditions are met', async () => {
      // Setup mocks for successful reward distribution
      const mockGeofenceResult = {
        is_within_geofence: true,
        distance_meters: 50,
        reward_eligible: true,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      const mockFraudResult = {
        is_suspicious: false,
        risk_score: 0.1,
        flags: []
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);
      mockAntiFraudService.analyzeUserBehavior.mockResolvedValue(mockFraudResult);

      // Mock database responses
      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT * FROM reward_distributions')) {
          return []; // No existing reward
        }
        if (query.strings[0].includes('SELECT COUNT(*) as count')) {
          return [{ count: '0' }]; // No rewards today
        }
        if (query.strings[0].includes('SELECT.*FROM reward_configurations')) {
          return [{
            annotation_id: testAnnotationId,
            base_fee: '2.00',
            time_decay_factor: '0.95',
            max_rewards_per_day: '10',
            min_reward_amount: '0.10'
          }];
        }
        if (query.strings[0].includes('SELECT current_reward_pool')) {
          return [{ current_reward_pool: '10.00' }];
        }
        if (query.strings[0].includes('SELECT.*FROM users')) {
          return [{
            id: testUserId,
            total_earned: '5.00',
            reward_count: '2'
          }];
        }
        if (query.strings[0].includes('SELECT * FROM annotations')) {
          return [{
            id: testAnnotationId,
            created_at: new Date().toISOString(),
            smell_category: 'sewage',
            location: { latitude: 40.7128, longitude: -74.0060 }
          }];
        }
        if (query.strings[0].includes('INSERT INTO reward_distributions')) {
          return [{ id: 'reward-123' }];
        }
        if (query.strings[0].includes('SELECT * FROM wallets')) {
          return [{
            id: 'wallet-123',
            balance: '10.00'
          }];
        }
        if (query.strings[0].includes('BEGIN') || query.strings[0].includes('COMMIT')) {
          return [];
        }
        return []; // Default empty response
      });

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(true);
      expect(result.reward_id).toBe('reward-123');
      expect(result.actual_reward).toBeGreaterThan(0);
      expect(result.geofence_verification).toEqual(mockGeofenceResult);
      expect(result.fraud_check_result).toEqual(mockFraudResult);
      expect(result.distribution_reason).toBe('Reward distributed successfully');
    });

    it('should reject reward when user is outside geofence', async () => {
      const mockGeofenceResult = {
        is_within_geofence: false,
        distance_meters: 300,
        reward_eligible: false,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(false);
      expect(result.actual_reward).toBe(0);
      expect(result.distribution_reason).toBe('User not within geofence');
      expect(mockAntiFraudService.analyzeUserBehavior).not.toHaveBeenCalled();
    });

    it('should reject reward when fraud risk is too high', async () => {
      const mockGeofenceResult = {
        is_within_geofence: true,
        distance_meters: 50,
        reward_eligible: true,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      const mockFraudResult = {
        is_suspicious: true,
        risk_score: 0.8,
        flags: ['suspicious_location_pattern', 'rapid_movement']
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);
      mockAntiFraudService.analyzeUserBehavior.mockResolvedValue(mockFraudResult);

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(false);
      expect(result.actual_reward).toBe(0);
      expect(result.distribution_reason).toBe('High fraud risk detected');
      expect(result.fraud_check_result).toEqual(mockFraudResult);
    });

    it('should reject reward when user already received reward for this annotation', async () => {
      const mockGeofenceResult = {
        is_within_geofence: true,
        distance_meters: 50,
        reward_eligible: true,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      const mockFraudResult = {
        is_suspicious: false,
        risk_score: 0.1,
        flags: []
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);
      mockAntiFraudService.analyzeUserBehavior.mockResolvedValue(mockFraudResult);

      // Mock existing reward
      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT id FROM reward_distributions')) {
          return [{ id: 'existing-reward' }]; // Existing reward found
        }
        return [];
      });

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(false);
      expect(result.actual_reward).toBe(0);
      expect(result.distribution_reason).toBe('User already received reward for this annotation');
    });

    it('should reject reward when daily limit exceeded', async () => {
      const mockGeofenceResult = {
        is_within_geofence: true,
        distance_meters: 50,
        reward_eligible: true,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      const mockFraudResult = {
        is_suspicious: false,
        risk_score: 0.1,
        flags: []
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);
      mockAntiFraudService.analyzeUserBehavior.mockResolvedValue(mockFraudResult);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT id FROM reward_distributions')) {
          return []; // No existing reward for this annotation
        }
        if (query.strings[0].includes('SELECT COUNT(*) as count')) {
          return [{ count: '10' }]; // Already at daily limit
        }
        if (query.strings[0].includes('SELECT.*FROM reward_configurations')) {
          return [{
            annotation_id: testAnnotationId,
            max_rewards_per_day: '10'
          }];
        }
        return [];
      });

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(false);
      expect(result.actual_reward).toBe(0);
      expect(result.distribution_reason).toBe('Daily reward limit exceeded');
    });

    it('should reject reward when pool balance is insufficient', async () => {
      const mockGeofenceResult = {
        is_within_geofence: true,
        distance_meters: 50,
        reward_eligible: true,
        reward_radius: 100,
        annotation: {
          id: testAnnotationId,
          location: { latitude: 40.7128, longitude: -74.0060 },
          reward_type: 'standard'
        }
      };

      const mockFraudResult = {
        is_suspicious: false,
        risk_score: 0.1,
        flags: []
      };

      mockGeofencingService.checkGeofence.mockResolvedValue(mockGeofenceResult);
      mockAntiFraudService.analyzeUserBehavior.mockResolvedValue(mockFraudResult);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT id FROM reward_distributions')) {
          return []; // No existing reward
        }
        if (query.strings[0].includes('SELECT COUNT(*) as count')) {
          return [{ count: '0' }]; // No rewards today
        }
        if (query.strings[0].includes('SELECT.*FROM reward_configurations')) {
          return [{
            annotation_id: testAnnotationId,
            base_fee: '2.00',
            min_reward_amount: '0.50'
          }];
        }
        if (query.strings[0].includes('SELECT current_reward_pool')) {
          return [{ current_reward_pool: '0.05' }]; // Insufficient balance
        }
        if (query.strings[0].includes('SELECT.*FROM users')) {
          return [{
            id: testUserId,
            total_earned: '0',
            reward_count: '0'
          }];
        }
        if (query.strings[0].includes('SELECT * FROM annotations')) {
          return [{
            id: testAnnotationId,
            created_at: new Date().toISOString(),
            smell_category: 'other',
            location: { latitude: 40.7128, longitude: -74.0060 }
          }];
        }
        return [];
      });

      const result: RewardDistributionResult = await rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      });

      expect(result.success).toBe(false);
      expect(result.actual_reward).toBe(0);
      expect(result.distribution_reason).toBe('Insufficient reward pool balance');
    });
  });

  describe('getRewardHistory', () => {
    it('should return reward history for user', async () => {
      const mockHistoryData = [
        {
          id: 'reward-1',
          user_id: testUserId,
          annotation_id: testAnnotationId,
          reward_amount: '1.50',
          distribution_method: 'geofence_trigger',
          geofence_distance: '45.5',
          fraud_risk_score: '0.1',
          user_level_at_distribution: '2',
          created_at: '2025-09-01T10:00:00Z',
          metadata: '{"test": true}',
          username: 'testuser',
          smell_category: 'sewage',
          location: { latitude: 40.7128, longitude: -74.0060 }
        }
      ];

      mockDb.sql.mockResolvedValue(mockHistoryData);

      const history = await rewardEngine.getRewardHistory({
        user_id: testUserId,
        limit: 10
      });

      expect(history).toHaveLength(1);
      expect(history[0].id).toBe('reward-1');
      expect(history[0].reward_amount).toBe(1.50);
      expect(history[0].user_id).toBe(testUserId);
      expect(history[0].annotation_id).toBe(testAnnotationId);
    });

    it('should return empty array when no history found', async () => {
      mockDb.sql.mockResolvedValue([]);

      const history = await rewardEngine.getRewardHistory({
        user_id: testUserId
      });

      expect(history).toHaveLength(0);
    });
  });

  describe('getRewardStatistics', () => {
    it('should return comprehensive reward statistics', async () => {
      const mockTotalStats = [{
        total_distributed: '25',
        total_recipients: '10',
        average_reward: '1.25'
      }];

      const mockDailyStats = [
        { date: '2025-09-01', count: '5', total_amount: '7.50' },
        { date: '2025-08-31', count: '3', total_amount: '4.20' }
      ];

      const mockTopEarners = [
        { user_id: testUserId, username: 'testuser', total_earned: '5.50', reward_count: '3' },
        { user_id: 'user-2', username: 'user2', total_earned: '4.25', reward_count: '2' }
      ];

      const mockAnnotationPerformance = [
        { annotation_id: testAnnotationId, total_distributed: '10.00', unique_recipients: '5', current_reward_pool: '15.00' }
      ];

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('COUNT(*) as total_distributed')) {
          return mockTotalStats;
        }
        if (query.strings[0].includes('DATE(rd.created_at) as date')) {
          return mockDailyStats;
        }
        if (query.strings[0].includes('SUM(rd.reward_amount) as total_earned')) {
          return mockTopEarners;
        }
        if (query.strings[0].includes('COUNT(DISTINCT rd.user_id) as unique_recipients')) {
          return mockAnnotationPerformance;
        }
        return [];
      });

      const statistics = await rewardEngine.getRewardStatistics({});

      expect(statistics.total_distributed).toBe(25);
      expect(statistics.total_recipients).toBe(10);
      expect(statistics.average_reward).toBe(1.25);
      expect(statistics.distribution_by_day).toHaveLength(2);
      expect(statistics.top_earners).toHaveLength(2);
      expect(statistics.annotation_performance).toHaveLength(1);
    });
  });

  describe('configureReward', () => {
    it('should create new reward configuration', async () => {
      const configParams = {
        annotation_id: testAnnotationId,
        base_fee: 2.5,
        time_decay_factor: 0.9,
        max_rewards_per_day: 15
      };

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT * FROM reward_configurations')) {
          return []; // No existing config
        }
        if (query.strings[0].includes('INSERT INTO reward_configurations')) {
          return [{
            annotation_id: testAnnotationId,
            base_fee: '2.5',
            time_decay_factor: '0.9',
            user_level_multiplier: '1.0',
            max_rewards_per_day: '15',
            min_reward_amount: '0.10',
            created_at: '2025-09-01T10:00:00Z',
            updated_at: '2025-09-01T10:00:00Z'
          }];
        }
        return [];
      });

      const configuration = await rewardEngine.configureReward(configParams);

      expect(configuration.annotation_id).toBe(testAnnotationId);
      expect(configuration.base_fee).toBe(2.5);
      expect(configuration.time_decay_factor).toBe(0.9);
      expect(configuration.max_rewards_per_day).toBe(15);
    });

    it('should update existing reward configuration', async () => {
      const configParams = {
        annotation_id: testAnnotationId,
        base_fee: 3.0
      };

      const existingConfig = {
        annotation_id: testAnnotationId,
        base_fee: '2.0',
        time_decay_factor: '0.95',
        user_level_multiplier: '1.0',
        max_rewards_per_day: '10',
        min_reward_amount: '0.10',
        created_at: '2025-09-01T09:00:00Z',
        updated_at: '2025-09-01T09:00:00Z'
      };

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT * FROM reward_configurations')) {
          return [existingConfig]; // Existing config
        }
        if (query.strings[0].includes('UPDATE reward_configurations')) {
          return [{
            ...existingConfig,
            base_fee: '3.0',
            updated_at: '2025-09-01T10:00:00Z'
          }];
        }
        return [];
      });

      const configuration = await rewardEngine.configureReward(configParams);

      expect(configuration.base_fee).toBe(3.0);
      expect(configuration.time_decay_factor).toBe(0.95); // Should preserve existing values
    });
  });

  describe('initializeRewardTables', () => {
    it('should successfully initialize all reward tables', async () => {
      mockDb.sql.mockResolvedValue([]);

      const result = await rewardEngine.initializeRewardTables();

      expect(result).toBe(true);
      expect(mockDb.sql).toHaveBeenCalledTimes(13); // Number of table creation and index creation calls
    });

    it('should handle database errors gracefully', async () => {
      mockDb.sql.mockRejectedValue(new Error('Database connection failed'));

      const result = await rewardEngine.initializeRewardTables();

      expect(result).toBe(false);
    });
  });

  describe('clearCache and getCacheStats', () => {
    it('should clear cache and return stats', () => {
      // Add some mock data to cache
      const cacheKey = `${testUserId}:${testAnnotationId}`;
      (rewardEngine as any).distributionCache.set(cacheKey, {
        timestamp: Date.now(),
        reward_amount: 1.5
      });

      let stats = rewardEngine.getCacheStats();
      expect(stats.size).toBe(1);
      expect(stats.entries).toHaveLength(1);

      rewardEngine.clearCache();

      stats = rewardEngine.getCacheStats();
      expect(stats.size).toBe(0);
      expect(stats.entries).toHaveLength(0);
    });
  });

  describe('input validation', () => {
    it('should throw validation error for invalid user_id', async () => {
      await expect(rewardEngine.distributeReward({
        user_id: 'invalid-uuid',
        annotation_id: testAnnotationId,
        user_location: testUserLocation
      })).rejects.toThrow();
    });

    it('should throw validation error for invalid annotation_id', async () => {
      await expect(rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: 'invalid-uuid',
        user_location: testUserLocation
      })).rejects.toThrow();
    });

    it('should throw validation error for invalid location coordinates', async () => {
      await expect(rewardEngine.distributeReward({
        user_id: testUserId,
        annotation_id: testAnnotationId,
        user_location: { latitude: 91, longitude: -74.0060 } // Invalid latitude
      })).rejects.toThrow();
    });
  });
});