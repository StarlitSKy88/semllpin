/**
 * GPS Spoofing Detection Tests
 * Tests the anti-fraud system's ability to detect GPS manipulation
 */

import { AntiFraudService } from '../../src/services/antiFraudService';
import { LocationReport } from '../../src/types/lbs';
import { TestDataFactory, SecurityTestUtils } from '../setup/testUtils';
import { db } from '../../src/config/database';

describe('GPS Spoofing Detection', () => {
  let antiFraudService: AntiFraudService;
  let testUserId: string;

  beforeAll(async () => {
    antiFraudService = new AntiFraudService();
    
    // Create test user
    const testUser = await db('users').insert({
      id: 'gps-test-user-123',
      email: 'gps-test@example.com',
      username: 'gpstest',
      password: 'TestPassword123!',
      created_at: new Date(),
    }).returning('*');
    
    testUserId = testUser[0].id;
  });

  afterAll(async () => {
    // Cleanup test data
    await db('anti_fraud_logs').where('user_id', testUserId).del();
    await db('location_reports').where('user_id', testUserId).del();
    await db('users').where('id', testUserId).del();
  });

  describe('Teleportation Detection', () => {
    it('should detect impossible movement between distant locations', async () => {
      const spoofedLocations = SecurityTestUtils.generateSpoofedLocations();
      const teleportCase = spoofedLocations[0];

      // Insert first location
      await db('location_reports').insert({
        user_id: testUserId,
        latitude: teleportCase.from.lat,
        longitude: teleportCase.from.lon,
        accuracy: 10,
        timestamp: new Date(Date.now() - teleportCase.timeGap),
        device_info: JSON.stringify({ platform: 'iOS' }),
      });

      // Test second location (should be flagged as teleportation)
      const suspiciousLocation: LocationReport = {
        latitude: teleportCase.to.lat,
        longitude: teleportCase.to.lon,
        accuracy: 10,
        stayDuration: 30,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        suspiciousLocation,
        'test-annotation-123'
      );

      expect(result.isFraudulent).toBe(true);
      expect(result.fraudScore).toBeGreaterThan(0.8);
      expect(result.reasons).toEqual(
        expect.arrayContaining([
          expect.stringContaining('瞬移')
        ])
      );
    });

    it('should detect unrealistic speed patterns', async () => {
      const spoofedLocations = SecurityTestUtils.generateSpoofedLocations();
      const speedCase = spoofedLocations[1];

      // Insert starting location
      await db('location_reports').insert({
        user_id: testUserId,
        latitude: speedCase.from.lat,
        longitude: speedCase.from.lon,
        accuracy: 5,
        timestamp: new Date(Date.now() - speedCase.timeGap),
        device_info: JSON.stringify({ platform: 'Android' }),
      });

      // Test ending location (unrealistic speed)
      const highSpeedLocation: LocationReport = {
        latitude: speedCase.to.lat,
        longitude: speedCase.to.lon,
        accuracy: 5,
        stayDuration: 45,
        timestamp: new Date(),
        deviceInfo: { platform: 'Android', version: '11' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        highSpeedLocation,
        'test-annotation-456'
      );

      expect(result.isFraudulent).toBe(true);
      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('移动速度异常')
      )).toBe(true);
    });

    it('should allow reasonable movement patterns', async () => {
      const reasonableStartLocation = {
        latitude: 39.9042,
        longitude: 116.4074,
      };

      const reasonableEndLocation = {
        latitude: 39.9052, // ~1km away
        longitude: 116.4084,
      };

      // Insert starting location
      await db('location_reports').insert({
        user_id: testUserId,
        latitude: reasonableStartLocation.latitude,
        longitude: reasonableStartLocation.longitude,
        accuracy: 8,
        timestamp: new Date(Date.now() - 300000), // 5 minutes ago
        device_info: JSON.stringify({ platform: 'iOS' }),
      });

      // Test reasonable movement
      const reasonableLocation: LocationReport = {
        latitude: reasonableEndLocation.latitude,
        longitude: reasonableEndLocation.longitude,
        accuracy: 8,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        reasonableLocation,
        'test-annotation-789'
      );

      expect(result.isFraudulent).toBe(false);
      expect(result.fraudScore).toBeLessThan(0.5);
    });
  });

  describe('Accuracy Manipulation Detection', () => {
    it('should flag reports with suspiciously poor accuracy', async () => {
      const poorAccuracyLocation: LocationReport = {
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 150, // Very poor accuracy
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        poorAccuracyLocation,
        'test-annotation-poor-gps'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('GPS精度不足')
      )).toBe(true);
    });

    it('should flag reports with impossibly perfect accuracy', async () => {
      const perfectAccuracyLocation: LocationReport = {
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 0.1, // Impossibly perfect accuracy
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        perfectAccuracyLocation,
        'test-annotation-perfect-gps'
      );

      // Perfect accuracy might be suspicious but not necessarily fraudulent
      // Check if it's flagged or handled appropriately
      expect(result.fraudScore).toBeGreaterThan(0);
    });

    it('should accept normal GPS accuracy ranges', async () => {
      const normalAccuracyLocation: LocationReport = {
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 12, // Normal GPS accuracy
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        normalAccuracyLocation,
        'test-annotation-normal-gps'
      );

      // GPS accuracy check should pass
      const accuracyCheck = result.checkResults.find(check => 
        check.reason.includes('GPS精度')
      );
      expect(accuracyCheck?.passed).toBe(true);
    });
  });

  describe('Pattern-Based Detection', () => {
    it('should detect suspiciously regular location updates', async () => {
      const spoofedLocations = SecurityTestUtils.generateSpoofedLocations();
      const regularPattern = spoofedLocations[2];

      // Insert multiple locations with too regular pattern
      for (const coord of regularPattern.coordinates) {
        await db('location_reports').insert({
          user_id: testUserId,
          latitude: coord.lat,
          longitude: coord.lon,
          accuracy: 10,
          timestamp: coord.timestamp,
          device_info: JSON.stringify({ platform: 'iOS' }),
        });

        // Small delay to ensure sequential timestamps
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      // Test the pattern detection
      const testLocation: LocationReport = {
        latitude: 39.9045,
        longitude: 116.4077,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        testLocation,
        'test-annotation-pattern'
      );

      // Should detect the regular pattern as suspicious
      expect(result.fraudScore).toBeGreaterThan(0.3);
    });

    it('should detect duplicate location flooding', async () => {
      const duplicateLocation = {
        latitude: 39.9100,
        longitude: 116.4100,
      };

      // Insert many duplicate locations
      for (let i = 0; i < 10; i++) {
        await db('location_reports').insert({
          user_id: testUserId,
          latitude: duplicateLocation.latitude,
          longitude: duplicateLocation.longitude,
          accuracy: 8,
          timestamp: new Date(Date.now() - (i * 60000)), // 1 minute intervals
          device_info: JSON.stringify({ platform: 'Android' }),
        });
      }

      const floodLocation: LocationReport = {
        latitude: duplicateLocation.latitude,
        longitude: duplicateLocation.longitude,
        accuracy: 8,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'Android', version: '11' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        floodLocation,
        'test-annotation-flood'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('重复上报')
      )).toBe(true);
    });

    it('should detect high-frequency location reporting', async () => {
      // Insert very recent location
      await db('location_reports').insert({
        user_id: testUserId,
        latitude: 39.9200,
        longitude: 116.4200,
        accuracy: 10,
        timestamp: new Date(Date.now() - 5000), // 5 seconds ago
        device_info: JSON.stringify({ platform: 'iOS' }),
      });

      const highFrequencyLocation: LocationReport = {
        latitude: 39.9201,
        longitude: 116.4201,
        accuracy: 10,
        stayDuration: 30,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        highFrequencyLocation,
        'test-annotation-frequency'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('频率过高')
      )).toBe(true);
    });
  });

  describe('Device Consistency Checks', () => {
    it('should detect device switching patterns', async () => {
      const devices = [
        { platform: 'iOS', version: '14.0', deviceId: 'device-1' },
        { platform: 'Android', version: '11', deviceId: 'device-2' },
        { platform: 'iOS', version: '15.0', deviceId: 'device-3' },
        { platform: 'Android', version: '12', deviceId: 'device-4' },
      ];

      // Insert location reports from multiple devices
      for (let i = 0; i < devices.length; i++) {
        await db('location_reports').insert({
          user_id: testUserId,
          latitude: 39.9300 + i * 0.001,
          longitude: 116.4300 + i * 0.001,
          accuracy: 10,
          timestamp: new Date(Date.now() - (i * 86400000)), // Daily intervals
          device_info: JSON.stringify(devices[i]),
        });
      }

      const deviceSwitchLocation: LocationReport = {
        latitude: 39.9350,
        longitude: 116.4350,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: devices[0],
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        deviceSwitchLocation,
        'test-annotation-device-switch'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('不同设备')
      )).toBe(true);
    });

    it('should handle missing device information', async () => {
      const noDeviceLocation: LocationReport = {
        latitude: 39.9400,
        longitude: 116.4400,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        // No deviceInfo provided
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        noDeviceLocation,
        'test-annotation-no-device'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('缺少设备信息')
      )).toBe(true);
    });
  });

  describe('Behavioral Analysis', () => {
    it('should detect new account with suspicious activity', async () => {
      // Create very new user account
      const newUser = await db('users').insert({
        id: 'new-suspicious-user',
        email: 'new-suspicious@example.com',
        username: 'newsuspicious',
        password: 'TestPassword123!',
        created_at: new Date(), // Just created
      }).returning('*');

      // Simulate high reward activity for new account
      for (let i = 0; i < 15; i++) {
        await db('lbs_rewards').insert({
          id: `reward-${i}`,
          user_id: newUser[0].id,
          annotation_id: `annotation-${i}`,
          reward_type: 'first_finder',
          amount: 25.00,
          status: 'verified',
          created_at: new Date(Date.now() - i * 3600000), // Hourly
        });
      }

      const suspiciousNewUserLocation: LocationReport = {
        latitude: 39.9500,
        longitude: 116.4500,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        newUser[0].id,
        suspiciousNewUserLocation,
        'test-annotation-new-user'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('新账号异常活跃')
      )).toBe(true);

      // Cleanup
      await db('lbs_rewards').where('user_id', newUser[0].id).del();
      await db('users').where('id', newUser[0].id).del();
    });

    it('should detect excessive daily reward claims', async () => {
      // Insert many recent rewards
      const rewardPromises = [];
      for (let i = 0; i < 25; i++) { // Over daily limit
        rewardPromises.push(
          db('lbs_rewards').insert({
            id: `daily-reward-${i}`,
            user_id: testUserId,
            annotation_id: `daily-annotation-${i}`,
            reward_type: 'combo',
            amount: 15.00,
            status: 'claimed',
            created_at: new Date(Date.now() - i * 60000), // Minute intervals
          })
        );
      }
      await Promise.all(rewardPromises);

      const excessiveClaimLocation: LocationReport = {
        latitude: 39.9600,
        longitude: 116.4600,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        excessiveClaimLocation,
        'test-annotation-excessive'
      );

      expect(result.checkResults.some(check => 
        !check.passed && check.reason.includes('24小时内获得奖励')
      )).toBe(true);

      // Cleanup excessive rewards
      await db('lbs_rewards').where('user_id', testUserId).del();
    });
  });

  describe('Risk Scoring Accuracy', () => {
    it('should calculate appropriate fraud scores for different risk levels', async () => {
      const testCases = [
        {
          name: 'Low Risk',
          location: {
            latitude: 39.9000,
            longitude: 116.4000,
            accuracy: 12,
            stayDuration: 90,
            timestamp: new Date(),
            deviceInfo: { platform: 'iOS', version: '14.0' },
          },
          expectedScoreRange: [0, 0.3],
        },
        {
          name: 'Medium Risk',
          location: {
            latitude: 39.9000,
            longitude: 116.4000,
            accuracy: 35, // Moderate accuracy
            stayDuration: 25, // Short stay
            timestamp: new Date(),
            deviceInfo: { platform: 'Android', version: '11' },
          },
          expectedScoreRange: [0.3, 0.7],
        },
        {
          name: 'High Risk',
          location: {
            latitude: 40.7128, // Very far from previous locations
            longitude: -74.0060,
            accuracy: 80, // Poor accuracy
            stayDuration: 15, // Very short stay
            timestamp: new Date(),
            // Missing device info
          },
          expectedScoreRange: [0.7, 1.0],
        },
      ];

      for (const testCase of testCases) {
        const result = await antiFraudService.detectFraud(
          testUserId,
          testCase.location as LocationReport,
          `test-${testCase.name.toLowerCase().replace(' ', '-')}`
        );

        expect(result.fraudScore).toBeGreaterThanOrEqual(testCase.expectedScoreRange[0]);
        expect(result.fraudScore).toBeLessThanOrEqual(testCase.expectedScoreRange[1]);
      }
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      // Mock database error
      const originalDb = db;
      jest.spyOn(db, 'raw').mockRejectedValueOnce(new Error('Database connection failed'));

      const errorLocation: LocationReport = {
        latitude: 39.9700,
        longitude: 116.4700,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        errorLocation,
        'test-annotation-error'
      );

      // Should default to fraudulent on system error
      expect(result.isFraudulent).toBe(true);
      expect(result.fraudScore).toBe(1.0);
      expect(result.reasons).toContain('防作弊检测系统错误');

      // Restore original db
      jest.restoreAllMocks();
    });

    it('should handle malformed location data', async () => {
      const malformedLocation = {
        latitude: 'invalid' as any,
        longitude: null as any,
        accuracy: -5, // Negative accuracy
        stayDuration: 0,
        timestamp: new Date('invalid date'),
        deviceInfo: 'not an object' as any,
      };

      const result = await antiFraudService.detectFraud(
        testUserId,
        malformedLocation,
        'test-annotation-malformed'
      );

      // Should handle gracefully and likely flag as suspicious
      expect(result).toHaveProperty('isFraudulent');
      expect(result).toHaveProperty('fraudScore');
      expect(typeof result.fraudScore).toBe('number');
    });

    it('should handle concurrent fraud detection requests', async () => {
      const concurrentLocations = Array.from({ length: 10 }, (_, i) => ({
        latitude: 39.9800 + i * 0.001,
        longitude: 116.4800 + i * 0.001,
        accuracy: 10,
        stayDuration: 60,
        timestamp: new Date(Date.now() + i * 1000),
        deviceInfo: { platform: 'iOS', version: '14.0' },
      }));

      const promises = concurrentLocations.map((location, i) =>
        antiFraudService.detectFraud(
          testUserId,
          location,
          `concurrent-annotation-${i}`
        )
      );

      const results = await Promise.all(promises);

      // All requests should complete successfully
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toHaveProperty('isFraudulent');
        expect(result).toHaveProperty('fraudScore');
        expect(result).toHaveProperty('checkResults');
      });
    });
  });
});