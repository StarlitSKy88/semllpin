import { RewardCalculationService } from '../../../src/services/rewardCalculationService';
import { RewardCalculationParams } from '../../../src/types/lbs';

// Create comprehensive mock for database that properly handles chaining
const createQueryBuilder = (finalResult: any) => {
  const builder = {
    select: jest.fn(),
    where: jest.fn(),
    whereIn: jest.fn(),
    orderBy: jest.fn(),
    limit: jest.fn(),
    count: jest.fn(),
    first: jest.fn(),
  };
  
  // Make all methods return this for chaining
  builder.select.mockReturnValue(builder);
  builder.where.mockReturnValue(builder);
  builder.whereIn.mockReturnValue(builder);
  builder.orderBy.mockReturnValue(builder);
  builder.count.mockReturnValue(builder);  // count can also be chained
  
  // Terminal methods (methods that typically end the query)
  builder.limit.mockImplementation(() => Promise.resolve(finalResult));
  builder.first.mockImplementation(() => Promise.resolve(finalResult[0] || null));
  
  // Make the builder itself thenable for cases where no terminal method is called
  (builder as any).then = (resolve: any, reject: any) => resolve(finalResult);
  (builder as any)[Symbol.toStringTag] = 'Promise';
  
  // Also make it awaitable directly
  (builder as any).valueOf = () => finalResult;
  
  return builder;
};

// Mock database config
jest.mock('../../../src/config/database', () => {
  const mockDb = jest.fn() as any;
  mockDb.raw = jest.fn();
  mockDb.fn = { now: jest.fn() };
  return { db: mockDb };
});

import { db } from '../../../src/config/database';

describe('RewardCalculationService', () => {
  let service: RewardCalculationService;
  let mockDb: any;

  const mockParams: RewardCalculationParams = {
    annotationId: 'annotation-123',
    userId: 'user-456',
    locationData: {
      latitude: 39.9042,
      longitude: 116.4074,
      accuracy: 15,
      stayDuration: 45,
    },
    rewardType: 'first_finder',
    baseAmount: 100,
  };

  beforeEach(() => {
    service = new RewardCalculationService();
    mockDb = db as any;
    jest.clearAllMocks();
  });

  describe('calculateReward', () => {
    it('should calculate reward successfully for eligible user', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date('2024-01-01'),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            id: 'geofence-123',
            annotation_id: 'annotation-123',
            min_accuracy_meters: 20,
            min_stay_duration: 30,
            reward_base_percentage: '60.0',
            time_decay_enabled: true,
            first_finder_bonus: '20.0',
            combo_bonus_enabled: true,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        return createQueryBuilder([]);
      });

      // Mock raw SQL calls
      mockDb.raw.mockImplementation((sql: string) => {
        if (sql.includes('calculate_time_decay_factor')) {
          return Promise.resolve([{ decay_factor: '0.8' }]);
        }
        if (sql.includes('is_first_finder')) {
          return Promise.resolve([{ is_first: true }]);
        }
        return Promise.resolve([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.eligibility.eligible).toBe(true);
      expect(result.finalAmount).toBeGreaterThan(0);
      expect(result.breakdown.baseAmount).toBe(60); // 100 * 0.6
      expect(result.breakdown.timeDecayFactor).toBe(0.8);
      expect(result.breakdown.firstFinderBonus).toBe(20);
    });

    it('should reject reward for insufficient GPS accuracy', async () => {
      const invalidParams = {
        ...mockParams,
        locationData: {
          ...mockParams.locationData,
          accuracy: 25, // Exceeds min_accuracy_meters (20)
        },
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date(),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        return createQueryBuilder([]);
      });

      const result = await service.calculateReward(invalidParams);

      expect(result.eligibility.eligible).toBe(false);
      expect(result.eligibility.reasons).toContain('GPS精度不足，要求20米以内');
      expect(result.finalAmount).toBe(0);
    });

    it('should reject reward for insufficient stay duration', async () => {
      const invalidParams = {
        ...mockParams,
        locationData: {
          ...mockParams.locationData,
          stayDuration: 20, // Less than min_stay_duration (30)
        },
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date(),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        return createQueryBuilder([]);
      });

      const result = await service.calculateReward(invalidParams);

      expect(result.eligibility.eligible).toBe(false);
      expect(result.eligibility.reasons).toContain('停留时间不足，要求30秒以上');
    });

    it('should reject reward if user already received reward for annotation', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date(),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: 1 }]); // Existing reward (number not string)
        }
        
        return createQueryBuilder([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.eligibility.eligible).toBe(false);
      expect(result.eligibility.reasons).toContain('用户已获得该标注奖励');
    });

    it('should handle annotation not found', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([]); // No annotation found
        }
        return createQueryBuilder([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.eligibility.eligible).toBe(false);
      expect(result.eligibility.reasons).toContain('标注不存在');
    });

    it('should apply correct time decay factor', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
            reward_base_percentage: '60.0',
            time_decay_enabled: true,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        return createQueryBuilder([]);
      });

      mockDb.raw.mockImplementation((sql: string) => {
        if (sql.includes('calculate_time_decay_factor')) {
          return Promise.resolve([{ decay_factor: '0.3' }]); // Lower decay for old annotation
        }
        return Promise.resolve([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.breakdown.timeDecayFactor).toBe(0.3);
    });

    it('should calculate combo bonus correctly', async () => {
      const comboParams = {
        ...mockParams,
        rewardType: 'combo' as const,
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 100,
            created_at: new Date(),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
            reward_base_percentage: '60.0',
            combo_bonus_enabled: true,
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        if (table === 'lbs_reward_stats') {
          return createQueryBuilder([{ current_combo_streak: 15 }]);
        }
        
        return createQueryBuilder([]);
      });

      mockDb.raw.mockImplementation((sql: string) => {
        if (sql.includes('calculate_time_decay_factor')) {
          return Promise.resolve([{ decay_factor: '0.8' }]);
        }
        return Promise.resolve([]);
      });

      const result = await service.calculateReward(comboParams);

      // Combo streak 15 should give 15% bonus
      expect(result.breakdown.comboBonus).toBe(15);
    });

    it('should handle database errors gracefully', async () => {
      // Make the db function itself throw an error
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          throw new Error('Database connection error');
        }
        return createQueryBuilder([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.eligibility.eligible).toBe(false);
      // Database errors in getAnnotation are caught and result in "标注不存在"
      // This is the actual behavior based on current implementation
      expect(result.eligibility.reasons).toContain('标注不存在');
    });

    it('should ensure minimum reward amount', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'annotations') {
          return createQueryBuilder([{
            id: 'annotation-123',
            amount: 0.001, // Very low amount
            created_at: new Date(),
            status: 'active'
          }]);
        }
        
        if (table === 'geofence_configs') {
          return createQueryBuilder([{
            min_accuracy_meters: 20,
            min_stay_duration: 30,
            reward_base_percentage: '60.0',
            first_finder_bonus: '20.0',
          }]);
        }
        
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '0' }]);
        }
        
        return createQueryBuilder([]);
      });

      mockDb.raw.mockImplementation((sql: string) => {
        if (sql.includes('calculate_time_decay_factor')) {
          return Promise.resolve([{ decay_factor: '1.0' }]);
        }
        if (sql.includes('is_first_finder')) {
          return Promise.resolve([{ is_first: true }]);
        }
        return Promise.resolve([]);
      });

      const result = await service.calculateReward(mockParams);

      expect(result.finalAmount).toBeGreaterThanOrEqual(0.01);
    });
  });

  describe('calculateRewardWithDB', () => {
    it('should call database function correctly', async () => {
      mockDb.raw.mockResolvedValue([{ reward_amount: '25.50' }]);

      const result = await service.calculateRewardWithDB(
        'annotation-123',
        'user-456',
        'first_finder'
      );

      expect(mockDb.raw).toHaveBeenCalledWith(
        expect.stringContaining('calculate_lbs_reward_amount'),
        ['annotation-123', 'user-456', 'first_finder']
      );
      expect(result).toBe(25.50);
    });

    it('should handle database errors', async () => {
      mockDb.raw.mockRejectedValue(new Error('Database error'));

      await expect(
        service.calculateRewardWithDB('annotation-123', 'user-456', 'first_finder')
      ).rejects.toThrow('数据库奖励计算失败');
    });

    it('should handle null/undefined results', async () => {
      mockDb.raw.mockResolvedValue([{ reward_amount: null }]);

      const result = await service.calculateRewardWithDB(
        'annotation-123',
        'user-456',
        'first_finder'
      );

      expect(result).toBe(0);
    });
  });

  describe('private method testing through reflection', () => {
    it('should handle time decay correctly for different time periods', () => {
      // Access private method for testing
      const calculateTimeDecayFactorLocal = (service as any).calculateTimeDecayFactorLocal.bind(service);

      const testCases = [
        { hoursAgo: 12, expectedDecay: 0.70 }, // Within 24 hours
        { hoursAgo: 48, expectedDecay: 0.50 }, // 1-7 days
        { hoursAgo: 240, expectedDecay: 0.30 }, // 7-30 days
        { hoursAgo: 1440, expectedDecay: 0.10 }, // Over 30 days
      ];

      testCases.forEach(testCase => {
        const createdAt = new Date(Date.now() - testCase.hoursAgo * 60 * 60 * 1000);
        const decayFactor = calculateTimeDecayFactorLocal(createdAt);
        expect(decayFactor).toBe(testCase.expectedDecay);
      });
    });
  });
});