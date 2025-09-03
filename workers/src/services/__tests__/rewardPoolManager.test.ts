import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RewardPoolManager, RewardPoolStatus, PoolAnalytics } from '../rewardPoolManager';

// Mock the database utility
vi.mock('../../utils/neon-database');

// Mock environment
const mockEnv = {
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test'
};

describe('RewardPoolManager', () => {
  let poolManager: RewardPoolManager;
  let mockDb: any;

  const testAnnotationId = '550e8400-e29b-41d4-a716-446655440001';
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();

    // Mock database
    mockDb = {
      sql: vi.fn()
    };

    // Create instance with mocked dependencies
    poolManager = new RewardPoolManager(mockEnv as any);
    
    // Inject mock database
    (poolManager as any).db = mockDb;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('createRewardPool', () => {
    it('should successfully create new reward pool', async () => {
      const poolParams = {
        annotation_id: testAnnotationId,
        initial_pool_size: 10.0,
        min_pool_threshold: 1.0,
        max_pool_size: 50.0,
        auto_refill_enabled: true,
        refill_threshold: 0.2,
        commission_rate: 0.3
      };

      // Mock database responses for pool creation
      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT id FROM reward_pools')) {
          return []; // No existing pool
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_configurations')) {
          return [];
        }
        if (query.strings[0].includes('INSERT INTO reward_pools')) {
          return [{
            annotation_id: testAnnotationId,
            current_balance: '10.0',
            reserved_amount: '0',
            total_deposited: '10.0',
            total_distributed: '0',
            total_withdrawn: '0',
            last_activity_at: '2025-09-01T10:00:00Z',
            created_at: '2025-09-01T10:00:00Z',
            updated_at: '2025-09-01T10:00:00Z'
          }];
        }
        if (query.strings[0].includes('SELECT.*FROM reward_pools.*JOIN reward_pool_configurations')) {
          return [{
            annotation_id: testAnnotationId,
            current_balance: '10.0',
            reserved_amount: '0',
            total_deposited: '10.0',
            total_distributed: '0',
            total_withdrawn: '0',
            initial_pool_size: '10.0',
            min_pool_threshold: '1.0',
            max_pool_size: '50.0',
            auto_refill_enabled: true,
            refill_threshold: '0.2',
            commission_rate: '0.3',
            last_activity_at: '2025-09-01T10:00:00Z',
            created_at: '2025-09-01T10:00:00Z',
            updated_at: '2025-09-01T10:00:00Z',
            config_created_at: '2025-09-01T10:00:00Z',
            config_updated_at: '2025-09-01T10:00:00Z'
          }];
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_operations')) {
          return [];
        }
        if (query.strings[0].includes('UPDATE annotations')) {
          return [];
        }
        if (query.strings[0].includes('BEGIN') || query.strings[0].includes('COMMIT')) {
          return [];
        }
        return [];
      });

      const poolStatus: RewardPoolStatus = await poolManager.createRewardPool(poolParams);

      expect(poolStatus.annotation_id).toBe(testAnnotationId);
      expect(poolStatus.current_balance).toBe(10.0);
      expect(poolStatus.available_balance).toBe(10.0);
      expect(poolStatus.total_deposited).toBe(10.0);
      expect(poolStatus.pool_configuration.initial_pool_size).toBe(10.0);
      expect(poolStatus.pool_configuration.auto_refill_enabled).toBe(true);
    });

    it('should throw error if pool already exists', async () => {
      const poolParams = {
        annotation_id: testAnnotationId,
        initial_pool_size: 10.0
      };

      // Mock existing pool
      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('SELECT id FROM reward_pools')) {
          return [{ id: 'existing-pool' }];
        }
        return [];
      });

      await expect(poolManager.createRewardPool(poolParams)).rejects.toThrow(
        `Reward pool already exists for annotation ${testAnnotationId}`
      );
    });
  });

  describe('getPoolStatus', () => {
    it('should return pool status from database', async () => {
      const mockPoolData = {
        annotation_id: testAnnotationId,
        current_balance: '15.50',
        reserved_amount: '2.00',
        total_deposited: '20.00',
        total_distributed: '4.50',
        total_withdrawn: '0.00',
        initial_pool_size: '20.00',
        min_pool_threshold: '2.00',
        max_pool_size: '100.00',
        auto_refill_enabled: true,
        refill_threshold: '0.2',
        commission_rate: '0.3',
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z',
        config_created_at: '2025-09-01T10:00:00Z',
        config_updated_at: '2025-09-01T10:00:00Z'
      };

      mockDb.sql.mockResolvedValue([mockPoolData]);

      const poolStatus: RewardPoolStatus = await poolManager.getPoolStatus(testAnnotationId);

      expect(poolStatus.annotation_id).toBe(testAnnotationId);
      expect(poolStatus.current_balance).toBe(15.50);
      expect(poolStatus.reserved_amount).toBe(2.00);
      expect(poolStatus.available_balance).toBe(13.50);
      expect(poolStatus.total_deposited).toBe(20.00);
      expect(poolStatus.total_distributed).toBe(4.50);
      expect(poolStatus.pool_configuration.auto_refill_enabled).toBe(true);
    });

    it('should throw error if pool not found', async () => {
      mockDb.sql.mockResolvedValue([]);

      await expect(poolManager.getPoolStatus(testAnnotationId)).rejects.toThrow(
        `Reward pool not found for annotation ${testAnnotationId}`
      );
    });

    it('should use cache when available', async () => {
      const mockPoolData = {
        annotation_id: testAnnotationId,
        current_balance: '10.00',
        reserved_amount: '0.00',
        total_deposited: '10.00',
        total_distributed: '0.00',
        total_withdrawn: '0.00',
        initial_pool_size: '10.00',
        min_pool_threshold: '1.00',
        max_pool_size: '50.00',
        auto_refill_enabled: true,
        refill_threshold: '0.2',
        commission_rate: '0.3',
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z',
        config_created_at: '2025-09-01T10:00:00Z',
        config_updated_at: '2025-09-01T10:00:00Z'
      };

      mockDb.sql.mockResolvedValue([mockPoolData]);

      // First call should hit database
      await poolManager.getPoolStatus(testAnnotationId);
      expect(mockDb.sql).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await poolManager.getPoolStatus(testAnnotationId);
      expect(mockDb.sql).toHaveBeenCalledTimes(1); // Still only called once
    });
  });

  describe('depositToPool', () => {
    it('should successfully deposit funds to pool', async () => {
      const depositParams = {
        annotation_id: testAnnotationId,
        amount: 5.0,
        source: 'user_deposit',
        description: 'Additional funding'
      };

      // Mock current pool status
      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 10.0,
        reserved_amount: 0,
        available_balance: 10.0,
        total_deposited: 10.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 10.0,
          min_pool_threshold: 1.0,
          max_pool_size: 50.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      // Mock the getPoolStatus method
      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('UPDATE reward_pools')) {
          return [];
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_operations')) {
          return [];
        }
        if (query.strings[0].includes('UPDATE annotations')) {
          return [];
        }
        if (query.strings[0].includes('BEGIN') || query.strings[0].includes('COMMIT')) {
          return [];
        }
        return [];
      });

      const result: RewardPoolStatus = await poolManager.depositToPool(depositParams);

      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('UPDATE reward_pools')
      ]));
      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('INSERT INTO reward_pool_operations')
      ]));
    });

    it('should reject deposit if it exceeds max pool size', async () => {
      const depositParams = {
        annotation_id: testAnnotationId,
        amount: 50.0,
        source: 'user_deposit'
      };

      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 40.0,
        reserved_amount: 0,
        available_balance: 40.0,
        total_deposited: 40.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 10.0,
          min_pool_threshold: 1.0,
          max_pool_size: 50.0, // Max is 50, current is 40, trying to add 50 = 90 > 50
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      await expect(poolManager.depositToPool(depositParams)).rejects.toThrow(
        'Deposit would exceed maximum pool size: 50'
      );
    });
  });

  describe('withdrawFromPool', () => {
    it('should successfully withdraw funds from pool', async () => {
      const withdrawParams = {
        annotation_id: testAnnotationId,
        amount: 5.0,
        source: 'user_withdrawal',
        description: 'Withdraw excess funds'
      };

      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 20.0,
        reserved_amount: 2.0,
        available_balance: 18.0,
        total_deposited: 20.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 20.0,
          min_pool_threshold: 2.0,
          max_pool_size: 100.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('UPDATE reward_pools')) {
          return [];
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_operations')) {
          return [];
        }
        if (query.strings[0].includes('UPDATE annotations')) {
          return [];
        }
        if (query.strings[0].includes('BEGIN') || query.strings[0].includes('COMMIT')) {
          return [];
        }
        return [];
      });

      const result: RewardPoolStatus = await poolManager.withdrawFromPool(withdrawParams);

      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('UPDATE reward_pools')
      ]));
    });

    it('should reject withdrawal if insufficient available balance', async () => {
      const withdrawParams = {
        annotation_id: testAnnotationId,
        amount: 20.0,
        source: 'user_withdrawal'
      };

      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 10.0,
        reserved_amount: 8.0,
        available_balance: 2.0, // Only 2.0 available, trying to withdraw 20.0
        total_deposited: 10.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 10.0,
          min_pool_threshold: 1.0,
          max_pool_size: 50.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      await expect(poolManager.withdrawFromPool(withdrawParams)).rejects.toThrow(
        'Insufficient available balance: 2 < 20'
      );
    });
  });

  describe('reserveReward and releaseReservedReward', () => {
    it('should successfully reserve reward amount', async () => {
      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 20.0,
        reserved_amount: 0,
        available_balance: 20.0,
        total_deposited: 20.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 20.0,
          min_pool_threshold: 2.0,
          max_pool_size: 100.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('UPDATE reward_pools')) {
          return [];
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_operations')) {
          return [];
        }
        return [];
      });

      const result = await poolManager.reserveReward(testAnnotationId, 5.0, 'reward_system');

      expect(result).toBe(true);
      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('UPDATE reward_pools')
      ]));
    });

    it('should reject reservation if insufficient available balance', async () => {
      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 5.0,
        reserved_amount: 4.0,
        available_balance: 1.0,
        total_deposited: 5.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 5.0,
          min_pool_threshold: 0.5,
          max_pool_size: 50.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      const result = await poolManager.reserveReward(testAnnotationId, 5.0, 'reward_system');

      expect(result).toBe(false);
    });

    it('should successfully release reserved reward', async () => {
      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue({
        annotation_id: testAnnotationId,
        current_balance: 20.0,
        reserved_amount: 5.0,
        available_balance: 15.0,
        total_deposited: 20.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 20.0,
          min_pool_threshold: 2.0,
          max_pool_size: 100.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      });

      mockDb.sql.mockResolvedValue([]);

      await expect(poolManager.releaseReservedReward(testAnnotationId, 2.0, 'cancelled_reward')).resolves.not.toThrow();

      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('UPDATE reward_pools')
      ]));
    });
  });

  describe('executeRewardDistribution', () => {
    it('should successfully execute reward distribution', async () => {
      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 20.0,
        reserved_amount: 5.0,
        available_balance: 15.0,
        total_deposited: 20.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 20.0,
          min_pool_threshold: 2.0,
          max_pool_size: 100.0,
          auto_refill_enabled: false, // Disable auto refill for test
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('UPDATE reward_pools')) {
          return [];
        }
        if (query.strings[0].includes('INSERT INTO reward_pool_operations')) {
          return [];
        }
        if (query.strings[0].includes('UPDATE annotations')) {
          return [];
        }
        if (query.strings[0].includes('BEGIN') || query.strings[0].includes('COMMIT')) {
          return [];
        }
        return [];
      });

      await expect(poolManager.executeRewardDistribution(testAnnotationId, 2.5, testUserId)).resolves.not.toThrow();

      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('BEGIN')
      ]));
      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('UPDATE reward_pools')
      ]));
      expect(mockDb.sql).toHaveBeenCalledWith(expect.arrayContaining([
        expect.stringContaining('COMMIT')
      ]));
    });
  });

  describe('getPoolOperationHistory', () => {
    it('should return pool operation history', async () => {
      const mockHistoryData = [
        {
          id: 'op-1',
          annotation_id: testAnnotationId,
          operation_type: 'deposit',
          amount: '10.0',
          source: 'initial_funding',
          description: 'Initial pool funding',
          balance_before: '0.0',
          balance_after: '10.0',
          created_at: '2025-09-01T10:00:00Z',
          metadata: '{}'
        },
        {
          id: 'op-2',
          annotation_id: testAnnotationId,
          operation_type: 'distribute',
          amount: '2.5',
          source: 'reward_distribution',
          description: 'Reward distributed',
          balance_before: '10.0',
          balance_after: '7.5',
          created_at: '2025-09-01T11:00:00Z',
          metadata: '{"recipient_id": "' + testUserId + '"}'
        }
      ];

      mockDb.sql.mockResolvedValue(mockHistoryData);

      const history = await poolManager.getPoolOperationHistory({
        annotation_id: testAnnotationId,
        limit: 10
      });

      expect(history).toHaveLength(2);
      expect(history[0].operation_type).toBe('deposit');
      expect(history[0].amount).toBe(10.0);
      expect(history[1].operation_type).toBe('distribute');
      expect(history[1].amount).toBe(2.5);
    });
  });

  describe('getPoolAnalytics', () => {
    it('should return comprehensive pool analytics', async () => {
      const mockDistributionStats = [{
        unique_recipients: '5',
        total_distributions: '10',
        avg_reward_per_user: '1.25',
        total_distributed: '12.50'
      }];

      const mockHourlyStats = [
        { hour: '9', distribution_count: '2' },
        { hour: '14', distribution_count: '5' },
        { hour: '18', distribution_count: '3' }
      ];

      const mockPoolStatus = {
        annotation_id: testAnnotationId,
        current_balance: 7.5,
        reserved_amount: 0,
        available_balance: 7.5,
        total_deposited: 20.0,
        total_distributed: 12.5,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 20.0,
          min_pool_threshold: 2.0,
          max_pool_size: 100.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      mockDb.sql.mockImplementation((query: any) => {
        if (query.strings[0].includes('COUNT(DISTINCT rd.user_id) as unique_recipients')) {
          return mockDistributionStats;
        }
        if (query.strings[0].includes('EXTRACT(HOUR FROM created_at) as hour')) {
          return mockHourlyStats;
        }
        return [];
      });

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockPoolStatus);

      const analytics: PoolAnalytics = await poolManager.getPoolAnalytics(testAnnotationId, 30);

      expect(analytics.annotation_id).toBe(testAnnotationId);
      expect(analytics.pool_efficiency).toBe(0.63); // 12.5 / 20.0 = 0.625
      expect(analytics.burn_rate).toBe(0.42); // 12.5 / 30 days ≈ 0.42
      expect(analytics.recipient_diversity).toBe(0.5); // 5 unique / 10 total = 0.5
      expect(analytics.average_reward_per_user).toBe(1.25);
      expect(analytics.peak_usage_hours).toHaveLength(3);
      expect(analytics.estimated_days_remaining).toBeGreaterThan(0);
    });
  });

  describe('getBatchPoolStatus', () => {
    it('should return status for multiple pools', async () => {
      const annotationIds = [testAnnotationId, 'annotation-2', 'annotation-3'];
      
      const mockStatus1 = {
        annotation_id: testAnnotationId,
        current_balance: 10.0,
        reserved_amount: 0,
        available_balance: 10.0,
        total_deposited: 10.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {} as any,
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      const mockStatus2 = {
        annotation_id: 'annotation-2',
        current_balance: 15.0,
        reserved_amount: 2.0,
        available_balance: 13.0,
        total_deposited: 15.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {} as any,
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus')
        .mockResolvedValueOnce(mockStatus1)
        .mockResolvedValueOnce(mockStatus2)
        .mockRejectedValueOnce(new Error('Pool not found')); // Third pool fails

      const results = await poolManager.getBatchPoolStatus(annotationIds);

      expect(results).toHaveLength(2); // Only 2 successful results
      expect(results[0].annotation_id).toBe(testAnnotationId);
      expect(results[1].annotation_id).toBe('annotation-2');
    });
  });

  describe('initializePoolTables', () => {
    it('should successfully initialize all pool tables', async () => {
      mockDb.sql.mockResolvedValue([]);

      const result = await poolManager.initializePoolTables();

      expect(result).toBe(true);
      expect(mockDb.sql).toHaveBeenCalledTimes(10); // Number of table and index creation calls
    });

    it('should handle initialization errors gracefully', async () => {
      mockDb.sql.mockRejectedValue(new Error('Database error'));

      const result = await poolManager.initializePoolTables();

      expect(result).toBe(false);
    });
  });

  describe('cache management', () => {
    it('should manage cache correctly', () => {
      const cacheStats = poolManager.getCacheStats();
      expect(cacheStats.size).toBe(0);
      expect(cacheStats.entries).toHaveLength(0);

      // Manually add something to cache for testing
      const poolCache = (poolManager as any).poolStatusCache;
      poolCache.set(testAnnotationId, {
        status: { annotation_id: testAnnotationId } as any,
        cached_at: Date.now()
      });

      const statsAfter = poolManager.getCacheStats();
      expect(statsAfter.size).toBe(1);
      expect(statsAfter.entries).toContain(testAnnotationId);

      poolManager.clearCache();

      const statsCleared = poolManager.getCacheStats();
      expect(statsCleared.size).toBe(0);
    });
  });

  describe('input validation', () => {
    it('should validate pool creation parameters', async () => {
      await expect(poolManager.createRewardPool({
        annotation_id: 'invalid-uuid',
        initial_pool_size: 10.0
      })).rejects.toThrow();
    });

    it('should validate negative amounts', async () => {
      const mockCurrentStatus = {
        annotation_id: testAnnotationId,
        current_balance: 10.0,
        reserved_amount: 0,
        available_balance: 10.0,
        total_deposited: 10.0,
        total_distributed: 0,
        total_withdrawn: 0,
        pool_configuration: {
          annotation_id: testAnnotationId,
          initial_pool_size: 10.0,
          min_pool_threshold: 1.0,
          max_pool_size: 50.0,
          auto_refill_enabled: true,
          refill_threshold: 0.2,
          commission_rate: 0.3,
          created_at: '2025-09-01T10:00:00Z',
          updated_at: '2025-09-01T10:00:00Z'
        },
        last_activity_at: '2025-09-01T10:00:00Z',
        created_at: '2025-09-01T10:00:00Z',
        updated_at: '2025-09-01T10:00:00Z'
      };

      vi.spyOn(poolManager, 'getPoolStatus').mockResolvedValue(mockCurrentStatus);

      await expect(poolManager.depositToPool({
        annotation_id: testAnnotationId,
        amount: -5.0,
        source: 'test'
      })).rejects.toThrow();
    });
  });
});