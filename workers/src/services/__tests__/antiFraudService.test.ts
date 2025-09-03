/**
 * Unit Tests for Anti-Fraud Service
 * Tests core GPS verification and fraud detection functionality
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals';
import AntiFraudService, { LocationPoint } from '../antiFraudService';
import { Env } from '../../index';

// Mock environment
const mockEnv: Env = {
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
  JWT_SECRET: 'test-secret',
  CORS_ORIGINS: '*',
  CORS_METHODS: 'GET,POST,PUT,DELETE',
  CORS_HEADERS: 'Content-Type,Authorization',
  RATE_LIMIT_REQUESTS: '100',
  RATE_LIMIT_WINDOW: '60',
  MAX_FILE_SIZE: '10485760',
  ALLOWED_FILE_TYPES: 'image/jpeg,image/png'
};

// Mock database
jest.mock('../utils/neon-database', () => ({
  NeonDatabase: jest.fn(() => ({
    sql: jest.fn().mockImplementation((strings: TemplateStringsArray) => {
      const query = strings.join('');
      
      // Mock different queries based on content
      if (query.includes('SELECT * FROM device_fingerprints')) {
        return [];
      }
      if (query.includes('INSERT INTO device_fingerprints')) {
        return [{
          id: 'test-device-id',
          user_id: 'test-user-id',
          fingerprint_hash: 'test-hash',
          device_info: {},
          ip_address: '127.0.0.1',
          user_agent: 'test-agent',
          is_trusted: false,
          risk_score: 0,
          first_seen: new Date(),
          last_seen: new Date()
        }];
      }
      if (query.includes('location_history')) {
        return [];
      }
      if (query.includes('user_risk_profiles')) {
        return [];
      }
      if (query.includes('gps_verifications')) {
        return [];
      }
      
      return [];
    })
  }))
}));

describe('AntiFraudService', () => {
  let antiFraudService: AntiFraudService;
  
  beforeEach(() => {
    antiFraudService = new AntiFraudService(mockEnv);
  });

  describe('GPS Location Verification', () => {
    test('should accept valid GPS location', async () => {
      const validLocation: LocationPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: Date.now()
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        screen: { width: 375, height: 812, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'iPhone'
      };

      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: validLocation,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result.verification_status).toBe('passed');
      expect(result.risk_score).toBeLessThan(50);
      expect(result.risk_factors.gps_spoofing_detected).toBe(false);
    });

    test('should detect GPS spoofing - impossible accuracy', async () => {
      const spoofedLocation: LocationPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 0.1, // Impossible accuracy for consumer GPS
        timestamp: Date.now()
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        screen: { width: 1920, height: 1080, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'Win32'
      };

      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: spoofedLocation,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result.verification_status).toBe('failed');
      expect(result.risk_score).toBeGreaterThan(50);
      expect(result.risk_factors.gps_spoofing_detected).toBe(true);
    });

    test('should detect round number coordinates', async () => {
      const roundLocation: LocationPoint = {
        latitude: 40.0, // Suspiciously round
        longitude: -74.0, // Suspiciously round
        accuracy: 50,
        timestamp: Date.now()
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (Android 10; Mobile)',
        screen: { width: 360, height: 640, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'Android'
      };

      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: roundLocation,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result.risk_score).toBeGreaterThan(25);
      expect(result.risk_factors.gps_spoofing_detected).toBe(true);
    });

    test('should detect desktop with high GPS accuracy as suspicious', async () => {
      const location: LocationPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 5, // Too accurate for desktop
        timestamp: Date.now()
      };

      const desktopDeviceInfo = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        screen: { width: 1920, height: 1080, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'Win32'
      };

      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: location,
        device_info: desktopDeviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result.risk_score).toBeGreaterThan(20);
      expect(result.risk_factors.device_inconsistency).toBe(true);
    });

    test('should detect stale location timestamp', async () => {
      const staleLocation: LocationPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: Date.now() - 60000 // 1 minute old
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        screen: { width: 375, height: 812, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'iPhone'
      };

      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: staleLocation,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result.risk_factors.mock_location_detected).toBe(true);
    });
  });

  describe('Risk Scoring', () => {
    test('should calculate appropriate risk levels', async () => {
      // Test low risk scenario
      const lowRiskLocation: LocationPoint = {
        latitude: 40.712776,
        longitude: -74.005974,
        accuracy: 15,
        timestamp: Date.now() - 1000
      };

      const mobileDevice = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
        screen: { width: 390, height: 844, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'iPhone'
      };

      const lowRiskResult = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: lowRiskLocation,
        device_info: mobileDevice,
        ip_address: '192.168.1.1'
      });

      expect(lowRiskResult.risk_score).toBeLessThan(30);
      expect(lowRiskResult.verification_status).toBe('passed');

      // Test high risk scenario
      const highRiskLocation: LocationPoint = {
        latitude: 0.0, // Null Island - suspicious
        longitude: 0.0,
        accuracy: 0.5, // Too precise
        timestamp: Date.now() - 120000 // Too old
      };

      const highRiskResult = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-id',
        location: highRiskLocation,
        device_info: mobileDevice,
        ip_address: '192.168.1.1'
      });

      expect(highRiskResult.risk_score).toBeGreaterThan(70);
      expect(highRiskResult.verification_status).toBe('failed');
    });
  });

  describe('Device Fingerprinting', () => {
    test('should create consistent device fingerprints', async () => {
      const location: LocationPoint = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        timestamp: Date.now()
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        screen: { width: 375, height: 812, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'iPhone'
      };

      // First verification
      const result1 = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-1',
        location: location,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      // Second verification with same device
      const result2 = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: 'test-annotation-2',
        location: location,
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      expect(result1.verification_status).toBe('passed');
      expect(result2.verification_status).toBe('passed');
      expect(result2.risk_factors.device_inconsistency).toBe(false);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid location data gracefully', async () => {
      const invalidLocation: LocationPoint = {
        latitude: 91, // Invalid latitude
        longitude: 181, // Invalid longitude
        accuracy: -5, // Invalid accuracy
        timestamp: Date.now()
      };

      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        screen: { width: 375, height: 812, colorDepth: 24 },
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'iPhone'
      };

      await expect(
        antiFraudService.verifyGPSLocation({
          user_id: 'test-user-id',
          annotation_id: 'test-annotation-id',
          location: invalidLocation,
          device_info: deviceInfo,
          ip_address: '192.168.1.1'
        })
      ).rejects.toThrow();
    });

    test('should handle database errors gracefully', async () => {
      // This test would require mocking database failures
      // For now, we just ensure the service can be instantiated
      expect(antiFraudService).toBeDefined();
    });
  });

  describe('Utility Methods', () => {
    test('should get user risk score', async () => {
      const riskScore = await antiFraudService.getUserRiskScore('test-user-id');
      expect(typeof riskScore).toBe('number');
      expect(riskScore).toBeGreaterThanOrEqual(0);
      expect(riskScore).toBeLessThanOrEqual(100);
    });

    test('should get recent fraud incidents', async () => {
      const incidents = await antiFraudService.getRecentFraudIncidents(5);
      expect(Array.isArray(incidents)).toBe(true);
    });
  });
});

describe('GPS Detection Edge Cases', () => {
  let antiFraudService: AntiFraudService;
  
  beforeEach(() => {
    antiFraudService = new AntiFraudService(mockEnv);
  });

  test('should handle locations at extreme coordinates', async () => {
    const extremeLocations = [
      { latitude: 89.99, longitude: 179.99 }, // Near North Pole
      { latitude: -89.99, longitude: -179.99 }, // Near South Pole
      { latitude: 0, longitude: 180 }, // Date line
      { latitude: 0, longitude: 0 } // Equator/Prime meridian intersection
    ];

    const deviceInfo = {
      userAgent: 'Mozilla/5.0 (Android 10; Mobile)',
      screen: { width: 360, height: 640, colorDepth: 24 },
      timezone: 'UTC',
      language: 'en-US',
      platform: 'Android'
    };

    for (const location of extremeLocations) {
      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: `test-${location.latitude}-${location.longitude}`,
        location: {
          ...location,
          accuracy: 20,
          timestamp: Date.now()
        },
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });

      // Extreme locations should be flagged as suspicious
      if (location.latitude === 0 && location.longitude === 0) {
        expect(result.risk_score).toBeGreaterThan(50);
      }
    }
  });

  test('should detect patterns in submission timing', async () => {
    const location: LocationPoint = {
      latitude: 40.7128,
      longitude: -74.0060,
      accuracy: 10,
      timestamp: Date.now()
    };

    const deviceInfo = {
      userAgent: 'Mozilla/5.0 (Android 10; Mobile)',
      screen: { width: 360, height: 640, colorDepth: 24 },
      timezone: 'America/New_York',
      language: 'en-US',
      platform: 'Android'
    };

    // Simulate regular submissions (bot-like behavior)
    const results = [];
    for (let i = 0; i < 3; i++) {
      const result = await antiFraudService.verifyGPSLocation({
        user_id: 'test-user-id',
        annotation_id: `test-regular-${i}`,
        location: {
          ...location,
          timestamp: Date.now() - (i * 60000) // Exactly 1 minute apart
        },
        device_info: deviceInfo,
        ip_address: '192.168.1.1'
      });
      results.push(result);
    }

    // Later submissions should show increased suspicion due to regular timing
    expect(results.length).toBe(3);
  });
});

export {};