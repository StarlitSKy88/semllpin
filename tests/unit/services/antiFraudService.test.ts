import { AntiFraudService } from '../../../src/services/antiFraudService';
import { LocationReport, AntiFraudResult } from '../../../src/types/lbs';

// Create comprehensive mock for database that properly handles chaining
const createQueryBuilder = (finalResult: any) => {
  const builder = {
    select: jest.fn(),
    where: jest.fn(),
    whereIn: jest.fn(),
    whereRaw: jest.fn(),
    whereNotNull: jest.fn(),
    orderBy: jest.fn(),
    limit: jest.fn(),
    count: jest.fn(),
    first: jest.fn(),
    distinct: jest.fn(),
    insert: jest.fn(),
  };
  
  // Make all methods return this for chaining
  builder.where.mockReturnValue(builder);
  builder.whereIn.mockReturnValue(builder);
  builder.whereRaw.mockReturnValue(builder);
  builder.whereNotNull.mockReturnValue(builder);
  builder.orderBy.mockReturnValue(builder);
  builder.distinct.mockReturnValue(builder);
  builder.limit.mockReturnValue(builder);
  
  // count() should return the builder for chaining, but also be thenable
  builder.count.mockImplementation(() => {
    const countBuilder = Object.assign({}, builder);
    (countBuilder as any).then = (resolve: any, reject: any) => resolve(finalResult);
    (countBuilder as any)[Symbol.toStringTag] = 'Promise';
    return countBuilder;
  });
  
  // select() can be chainable OR terminal depending on context
  builder.select.mockImplementation((...args: any[]) => {
    // Make a new builder that's thenable for terminal select calls
    const terminalBuilder = Object.assign({}, builder);
    (terminalBuilder as any).then = (resolve: any, reject: any) => resolve(finalResult);
    (terminalBuilder as any)[Symbol.toStringTag] = 'Promise';
    return terminalBuilder;
  });
  
  // Terminal methods (methods that typically end the query)
  builder.first.mockImplementation(() => Promise.resolve(Array.isArray(finalResult) ? finalResult[0] || null : finalResult));
  builder.insert.mockImplementation(() => Promise.resolve([{ id: 1 }]));
  
  // Make the builder itself thenable for cases where no terminal method is called
  (builder as any).then = (resolve: any, reject: any) => resolve(finalResult);
  (builder as any)[Symbol.toStringTag] = 'Promise';
  
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

describe('AntiFraudService', () => {
  let antiFraudService: AntiFraudService;
  let mockDb: any;

  const mockLocationData: LocationReport = {
    id: 'location-123',
    userId: 'user-123',
    latitude: 39.9042,
    longitude: 116.4074,
    accuracy: 15,
    timestamp: new Date(),
    reportType: 'manual',
    deviceInfo: {
      platform: 'iOS',
      version: '14.0',
      deviceId: 'device-123',
      userAgent: 'SmellPin/1.0',
    },
  };

  beforeEach(() => {
    antiFraudService = new AntiFraudService();
    mockDb = db as any;
    jest.clearAllMocks();
  });

  describe('detectFraud', () => {
    const userId = 'user-123';
    const annotationId = 'annotation-456';

    it('should detect no fraud for normal behavior', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '30' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.isFraudulent).toBe(false);
      expect(result.fraudScore).toBeLessThan(0.7);
      expect(result.reasons).toHaveLength(0);
      expect(result.checkResults).toHaveLength(5);
    });

    it('should detect GPS spoofing with poor accuracy', async () => {
      const poorAccuracyLocation = {
        ...mockLocationData,
        accuracy: 100, // Poor accuracy > 50m threshold
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, poorAccuracyLocation, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('GPS精度不足')
      )).toBe(true);
    });

    it('should detect abnormal movement speed', async () => {
      // Mock recent location showing impossible speed
      const recentLocation = {
        latitude: 40.7128, // NYC coordinates (very far from Beijing)
        longitude: -74.0060,
        timestamp: new Date(Date.now() - 60000), // 1 minute ago
        accuracy: 10,
      };

      // Add current location to make sure we have at least 2 locations for movement detection
      const currentLocationRecord = {
        latitude: mockLocationData.latitude,
        longitude: mockLocationData.longitude,
        timestamp: mockLocationData.timestamp,
        accuracy: mockLocationData.accuracy,
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          // Return multiple locations to ensure movement detection triggers
          return createQueryBuilder([recentLocation, currentLocationRecord]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('移动速度异常')
      )).toBe(true);
    });

    it('should detect teleportation patterns', async () => {
      // Mock recent location showing teleportation (large distance, short time)
      const recentLocation = {
        latitude: 31.2304, // Shanghai coordinates
        longitude: 121.4737,
        timestamp: new Date(Date.now() - 30000), // 30 seconds ago
        accuracy: 5,
      };

      // Add current location to ensure we have multiple locations
      const currentLocationRecord = {
        latitude: mockLocationData.latitude,
        longitude: mockLocationData.longitude,
        timestamp: mockLocationData.timestamp,
        accuracy: mockLocationData.accuracy,
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([recentLocation, currentLocationRecord]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);
      
      // Should detect either teleportation OR abnormal movement speed (both indicate suspicious behavior)
      expect(result.checkResults.some(check => 
        !check.passed && (check.reason.includes('疑似瞬移') || check.reason.includes('移动速度异常'))
      )).toBe(true);
    });

    it('should detect high frequency location reporting', async () => {
      // Mock very recent location (< 10 seconds)
      const veryRecentLocation = {
        latitude: 39.9041,
        longitude: 116.4075,
        timestamp: new Date(Date.now() - 5000), // 5 seconds ago
        accuracy: 10,
      };

      // Add current location to ensure we have multiple locations
      const currentLocationRecord = {
        latitude: mockLocationData.latitude,
        longitude: mockLocationData.longitude,
        timestamp: mockLocationData.timestamp,
        accuracy: mockLocationData.accuracy,
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([veryRecentLocation, currentLocationRecord]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('位置上报频率过高')
      )).toBe(true);
    });

    it('should detect duplicate location reports', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          if (table === 'location_reports') {
            const builder = createQueryBuilder([{ count: '8' }]);
            builder.first.mockImplementation(() => Promise.resolve({ count: '8' }));
            return builder;
          }
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('同一位置重复上报')
      )).toBe(true);
    });

    it('should detect suspicious reward patterns', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '25' }]); // count() returns array with first element containing count
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('24小时内获得奖励')
      )).toBe(true);
    });

    it('should detect new account abuse', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '10' }]); // count() returns array
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '0.5' }]); // Very new account
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('新账号异常活跃')
      )).toBe(true);
    });

    it('should detect device inconsistency', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          // This is the distinct call for device info
          return createQueryBuilder([
            { device_info: '{"platform":"iOS","deviceId":"device1"}' },
            { device_info: '{"platform":"Android","deviceId":"device2"}' },
            { device_info: '{"platform":"iOS","deviceId":"device3"}' },
            { device_info: '{"platform":"Android","deviceId":"device4"}' },
          ]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '5' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('7天内使用')
      )).toBe(true);
    });

    it('should handle missing device info', async () => {
      const locationWithoutDevice = {
        ...mockLocationData,
        deviceInfo: undefined,
      };

      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, locationWithoutDevice, annotationId);

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('缺少设备信息')
      )).toBe(true);
    });

    it('should handle database errors gracefully', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          const errorBuilder = {
            where: jest.fn().mockReturnThis(),
            orderBy: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            select: jest.fn().mockImplementation(() => {
              throw new Error('Database connection failed');
            })
          };
          return errorBuilder;
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      // Should handle errors gracefully - some checks fail but system continues
      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('检测失败')
      )).toBe(true);
      expect(result.fraudScore).toBeGreaterThan(0);
      // With partial failures, fraud score should be moderate but not necessarily above threshold
      expect(typeof result.fraudScore).toBe('number');
      expect(result.checkResults).toHaveLength(5);
    });

    it('should calculate fraud score correctly', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '15' }]); // Moderate rewards
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '5' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(result.fraudScore).toBeGreaterThan(0);
      expect(result.fraudScore).toBeLessThan(1);
      expect(typeof result.fraudScore).toBe('number');
    });

    it('should log anti-fraud results', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          const builder = createQueryBuilder([{ id: 1 }]);
          builder.insert = jest.fn().mockResolvedValue([{ id: 1 }]);
          return builder;
        }
        return createQueryBuilder([]);
      });

      await antiFraudService.detectFraud(userId, mockLocationData, annotationId);

      expect(mockDb).toHaveBeenCalledWith('anti_fraud_logs');
    });
  });

  describe('getUserFraudHistory', () => {
    const userId = 'user-123';

    it('should retrieve user fraud history successfully', async () => {
      const mockLogs = [
        {
          id: 1,
          user_id: userId,
          annotation_id: 'annotation-1',
          location_data: '{"latitude":39.9042}',
          fraud_score: '0.8',
          is_fraudulent: true,
          check_results: '[]',
          detection_timestamp: new Date(),
        },
      ];

      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder(mockLogs);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.getUserFraudHistory(userId, 30);

      expect(result).toHaveLength(1);
      expect(result[0]).toMatchObject({
        id: 1,
        userId: userId,
        detectionType: 'location_fraud',
        riskScore: 0.8,
      });
    });

    it('should handle empty fraud history', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.getUserFraudHistory(userId);

      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle database errors in fraud history', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          throw new Error('Database error');
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.getUserFraudHistory(userId);

      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('shouldBlockUser', () => {
    const userId = 'user-123';

    it('should block user with high risk score', async () => {
      const result = await antiFraudService.shouldBlockUser(userId, 0.95);

      expect(result.shouldBlock).toBe(true);
      expect(result.reason).toBe('High risk score detected');
    });

    it('should block user with multiple recent violations', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ violation_count: '5' }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.shouldBlockUser(userId, 0.5);

      expect(result.shouldBlock).toBe(true);
      expect(result.reason).toBe('Multiple violations detected in 24 hours');
    });

    it('should block user with moderate risk and violations', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ violation_count: '2' }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.shouldBlockUser(userId, 0.65);

      expect(result.shouldBlock).toBe(true);
      expect(result.reason).toBe('Multiple violations with elevated risk score');
    });

    it('should not block user with low risk and no violations', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ violation_count: '0' }]);
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.shouldBlockUser(userId, 0.3);

      expect(result.shouldBlock).toBe(false);
      expect(result.reason).toBeUndefined();
    });

    it('should handle database errors conservatively', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'anti_fraud_logs') {
          throw new Error('Database error');
        }
        return createQueryBuilder([]);
      });

      const result = await antiFraudService.shouldBlockUser(userId, 0.8);

      expect(result.shouldBlock).toBe(false);
      expect(result.reason).toBe('Error in block check, allowing user');
    });
  });

  describe('distance calculation', () => {
    it('should calculate distance correctly', () => {
      const service = new AntiFraudService();
      
      // Access private method through reflection
      const calculateDistance = (service as any).calculateDistance.bind(service);

      // Test known distance (Beijing to Shanghai ~= 1067km)
      const distance = calculateDistance(39.9042, 116.4074, 31.2304, 121.4737);
      
      expect(distance).toBeGreaterThan(1000000); // > 1000km in meters
      expect(distance).toBeLessThan(1200000); // < 1200km in meters
    });

    it('should handle same location', () => {
      const service = new AntiFraudService();
      const calculateDistance = (service as any).calculateDistance.bind(service);

      const distance = calculateDistance(39.9042, 116.4074, 39.9042, 116.4074);
      
      expect(distance).toBe(0);
    });
  });

  describe('fraud score calculation', () => {
    it('should calculate weighted fraud score', () => {
      const service = new AntiFraudService();
      const calculateFraudScore = (service as any).calculateFraudScore.bind(service);

      const checks = [
        { passed: true, score: 0.1 },
        { passed: false, score: 0.8 },
        { passed: true, score: 0.2 },
        { passed: false, score: 0.9 },
      ];

      const fraudScore = calculateFraudScore(checks);
      
      expect(fraudScore).toBeGreaterThan(0);
      expect(fraudScore).toBeLessThanOrEqual(1);
      expect(fraudScore).toBe((0.1 + 0.8 + 0.2 + 0.9) / 4);
    });

    it('should handle empty checks', () => {
      const service = new AntiFraudService();
      const calculateFraudScore = (service as any).calculateFraudScore.bind(service);

      const fraudScore = calculateFraudScore([]);
      
      expect(fraudScore).toBe(0);
    });
  });

  describe('edge cases and performance', () => {
    it('should handle concurrent fraud detection', async () => {
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const promises = Array(10).fill(0).map((_, i) =>
        antiFraudService.detectFraud(`user-${i}`, mockLocationData, `annotation-${i}`)
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toHaveProperty('isFraudulent');
        expect(result).toHaveProperty('fraudScore');
        expect(result).toHaveProperty('checkResults');
      });
    });

    it('should complete fraud detection within reasonable time', async () => {
      const userId = 'user-123';
      const annotationId = 'annotation-456';
      
      mockDb.mockImplementation((table: string) => {
        if (table === 'location_reports') {
          return createQueryBuilder([]);
        }
        if (table === 'lbs_rewards') {
          return createQueryBuilder([{ count: '2' }]);
        }
        if (table === 'users') {
          return createQueryBuilder([{ age_days: '10' }]);
        }
        if (table === 'anti_fraud_logs') {
          return createQueryBuilder([{ id: 1 }]);
        }
        return createQueryBuilder([]);
      });

      const startTime = Date.now();
      await antiFraudService.detectFraud(userId, mockLocationData, annotationId);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});