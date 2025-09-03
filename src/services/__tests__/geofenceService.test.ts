import { GeofenceService } from '../geofenceService';
import { jest } from '@jest/globals';
import { GeofenceConfig } from '../../types/lbs';

// Mock neon database
jest.mock('@neondatabase/serverless', () => ({
  neon: jest.fn(() => jest.fn())
}));

describe('GeofenceService', () => {
  let geofenceService: GeofenceService;
  const mockDatabaseUrl = 'postgresql://test:test@localhost:5432/test';
  
  beforeEach(() => {
    geofenceService = new GeofenceService(mockDatabaseUrl);
    jest.clearAllMocks();
  });

  describe('checkGeofenceTriggers', () => {
    it('should return triggered geofences when user is within range', async () => {
      const mockSql = jest.fn().mockResolvedValue([
        {
          annotation_id: 'ann1',
          distance: 50
        }
      ]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const result = await geofenceService.checkGeofenceTriggers(
        40.7128,
        -74.0060,
        'user123'
      );

      expect(mockSql).toHaveBeenCalled();
      expect(result).toEqual([
        {
          annotationId: 'ann1',
          distance: 50,
          triggered: true
        }
      ]);
    });

    it('should return empty array when no geofences triggered', async () => {
      const mockSql = jest.fn().mockResolvedValue([]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const result = await geofenceService.checkGeofenceTriggers(
        40.7128,
        -74.0060,
        'user123'
      );

      expect(result).toEqual([]);
    });

    it('should handle database errors gracefully', async () => {
      const mockSql = jest.fn().mockRejectedValue(new Error('Database error')) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      await expect(
        geofenceService.checkGeofenceTriggers(40.7128, -74.0060, 'user123')
      ).rejects.toThrow('地理围栏检测失败');
    });
  });

  describe('calculateDistance', () => {
    it('should calculate distance between two points correctly', () => {
      const lat1 = 40.7128; // New York
      const lng1 = -74.0060;
      const lat2 = 34.0522; // Los Angeles
      const lng2 = -118.2437;

      const distance = geofenceService.calculateDistance(lat1, lng1, lat2, lng2);
      
      // Distance between NYC and LA is approximately 3944 km
      expect(distance).toBeGreaterThan(3900000); // 3900 km in meters
      expect(distance).toBeLessThan(4000000); // 4000 km in meters
    });

    it('should return 0 for same coordinates', () => {
      const lat = 40.7128;
      const lng = -74.0060;

      const distance = geofenceService.calculateDistance(lat, lng, lat, lng);
      
      expect(distance).toBe(0);
    });

    it('should handle negative coordinates', () => {
      const lat1 = -33.8688; // Sydney
      const lng1 = 151.2093;
      const lat2 = 51.5074; // London
      const lng2 = -0.1278;

      const distance = geofenceService.calculateDistance(lat1, lng1, lat2, lng2);
      
      expect(distance).toBeGreaterThan(0);
      expect(typeof distance).toBe('number');
    });
  });

  describe('createGeofenceConfig', () => {
    it('should create geofence config successfully', async () => {
      const mockConfig = {
        id: 'config123',
        annotation_id: 'ann123',
        radius_meters: 100,
        detection_frequency: 30,
        min_accuracy_meters: 20,
        min_stay_duration: 10,
        max_speed_kmh: 50,
        is_active: true,
        reward_base_percentage: 0.8,
        time_decay_enabled: true,
        first_finder_bonus: 0.2,
        combo_bonus_enabled: false,
        created_at: new Date(),
        updated_at: new Date()
      };

      const mockSql = jest.fn().mockResolvedValue([mockConfig]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const configData = {
        annotationId: 'ann123',
        radiusMeters: 100,
        detectionFrequency: 30,
        minAccuracyMeters: 20,
        minStayDuration: 10,
        maxSpeedKmh: 50,
        isActive: true,
        rewardBasePercentage: 0.8,
        timeDecayEnabled: true,
        firstFinderBonus: 0.2,
        comboBonusEnabled: false
      };

      const result = await geofenceService.createGeofenceConfig(configData);

      expect(mockSql).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should handle creation errors gracefully', async () => {
      const mockSql = jest.fn().mockRejectedValue(new Error('Database error')) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const configData = {
        annotationId: 'ann123',
        radiusMeters: 100,
        detectionFrequency: 30,
        minAccuracyMeters: 20,
        minStayDuration: 10,
        maxSpeedKmh: 50,
        isActive: true,
        rewardBasePercentage: 0.8,
        timeDecayEnabled: true,
        firstFinderBonus: 0.2,
        comboBonusEnabled: false
      };

      await expect(
        geofenceService.createGeofenceConfig(configData)
      ).rejects.toThrow('创建地理围栏配置失败');
    });
  });

  describe('getGeofenceConfig', () => {
    it('should return geofence config when found', async () => {
      const mockConfig = {
        id: 'config123',
        annotation_id: 'ann123',
        radius_meters: 100,
        detection_frequency: 30,
        min_accuracy_meters: 20,
        min_stay_duration: 10,
        max_speed_kmh: '50',
        is_active: true,
        reward_base_percentage: '0.8',
        time_decay_enabled: true,
        first_finder_bonus: '0.2',
        combo_bonus_enabled: false,
        created_at: new Date(),
        updated_at: new Date()
      };

      const mockSql = jest.fn().mockResolvedValue([mockConfig]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const result = await geofenceService.getGeofenceConfig('ann123');

      expect(mockSql).toHaveBeenCalled();
      expect(result).toBeDefined();
      expect(result?.annotationId).toBe('ann123');
    });

    it('should return null when config not found', async () => {
      const mockSql = jest.fn().mockResolvedValue([]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const result = await geofenceService.getGeofenceConfig('nonexistent');

      expect(result).toBeNull();
    });

    it('should handle database errors gracefully', async () => {
      const mockSql = jest.fn().mockRejectedValue(new Error('Database error')) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      await expect(
        geofenceService.getGeofenceConfig('ann123')
      ).rejects.toThrow('获取地理围栏配置失败');
    });
  });

  describe('updateGeofenceConfig', () => {
    it('should update geofence config successfully', async () => {
      const mockConfig = {
        id: 'config123',
        annotation_id: 'ann123',
        radius_meters: 150,
        detection_frequency: 30,
        min_accuracy_meters: 20,
        min_stay_duration: 10,
        max_speed_kmh: '50',
        is_active: true,
        reward_base_percentage: '0.8',
        time_decay_enabled: true,
        first_finder_bonus: '0.2',
        combo_bonus_enabled: false,
        created_at: new Date(),
        updated_at: new Date()
      };

      const mockSql = jest.fn().mockResolvedValue([mockConfig]) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      const updates = { radiusMeters: 150 };
      const result = await geofenceService.updateGeofenceConfig('config123', updates);

      expect(mockSql).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should handle update errors gracefully', async () => {
      const mockSql = jest.fn().mockRejectedValue(new Error('Database error')) as jest.MockedFunction<any>;
      (geofenceService as any).sql = mockSql;

      await expect(
        geofenceService.updateGeofenceConfig('config123', { radiusMeters: 150 })
      ).rejects.toThrow('更新地理围栏配置失败');
    });
  });

  describe('validateGPSAccuracy', () => {
    it('should return true for accurate GPS', () => {
      const result = geofenceService.validateGPSAccuracy(15, 20);
      expect(result).toBe(true);
    });

    it('should return false for inaccurate GPS', () => {
      const result = geofenceService.validateGPSAccuracy(25, 20);
      expect(result).toBe(false);
    });
  });

  describe('validateMovementSpeed', () => {
    it('should return true for reasonable speed', () => {
      const previousLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        timestamp: new Date('2023-01-01T10:00:00Z')
      };
      const currentLocation = {
        latitude: 40.7130,
        longitude: -74.0062,
        timestamp: new Date('2023-01-01T10:01:00Z')
      };

      const result = geofenceService.validateMovementSpeed(
        previousLocation,
        currentLocation,
        50
      );

      expect(result).toBe(true);
    });

    it('should return false for unreasonable speed', () => {
      const previousLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        timestamp: new Date('2023-01-01T10:00:00Z')
      };
      const currentLocation = {
        latitude: 41.0000,
        longitude: -74.0000,
        timestamp: new Date('2023-01-01T10:00:30Z') // 30 seconds later
      };

      const result = geofenceService.validateMovementSpeed(
        previousLocation,
        currentLocation,
        50
      );

      expect(result).toBe(false);
    });
  });
});