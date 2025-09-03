import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { GeofencingService, calculateHaversineDistance, calculateVincentyDistance } from '../geofencing';

// Mock environment
const mockEnv = {
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
  JWT_SECRET: 'test-secret'
};

// Mock NeonDatabase
const mockSql = vi.fn();
const mockNeonDatabase = {
  sql: mockSql
};

vi.mock('../../utils/neon-database', () => ({
  NeonDatabase: vi.fn(() => mockNeonDatabase)
}));

describe('GeofencingService', () => {
  let geofencingService: GeofencingService;

  beforeAll(() => {
    geofencingService = new GeofencingService(mockEnv as any);
  });

  beforeEach(() => {
    vi.clearAllMocks();
    geofencingService.clearCache();
  });

  afterEach(() => {
    geofencingService.clearCache();
  });

  describe('Distance Calculation Algorithms', () => {
    test('calculateHaversineDistance should calculate correct distances', () => {
      // Test coordinates: Beijing to Shanghai (approximately 1068 km)
      const beijing = { lat: 39.9042, lng: 116.4074 };
      const shanghai = { lat: 31.2304, lng: 121.4737 };
      
      const distance = calculateHaversineDistance(
        beijing.lat, beijing.lng,
        shanghai.lat, shanghai.lng
      );

      // Should be approximately 1068 km (allowing for some precision variance)
      expect(distance).toBeGreaterThan(1050000); // 1050 km in meters
      expect(distance).toBeLessThan(1080000); // 1080 km in meters
    });

    test('calculateVincentyDistance should be more precise than Haversine', () => {
      // Test with same coordinates
      const lat1 = 40.7128, lng1 = -74.0060; // New York
      const lat2 = 34.0522, lng2 = -118.2437; // Los Angeles
      
      const haversineDistance = calculateHaversineDistance(lat1, lng1, lat2, lng2);
      const vincentyDistance = calculateVincentyDistance(lat1, lng1, lat2, lng2);

      // Vincenty should be different (more precise) than Haversine
      expect(Math.abs(haversineDistance - vincentyDistance)).toBeGreaterThan(0);
      
      // Both should be reasonable distances (around 3944 km)
      expect(haversineDistance).toBeGreaterThan(3900000);
      expect(haversineDistance).toBeLessThan(4000000);
      expect(vincentyDistance).toBeGreaterThan(3900000);
      expect(vincentyDistance).toBeLessThan(4000000);
    });

    test('should handle identical coordinates', () => {
      const distance = calculateHaversineDistance(40.7128, -74.0060, 40.7128, -74.0060);
      expect(distance).toBe(0);

      const vincentyDistance = calculateVincentyDistance(40.7128, -74.0060, 40.7128, -74.0060);
      expect(vincentyDistance).toBe(0);
    });

    test('should handle very short distances accurately', () => {
      // 1 meter apart (approximately)
      const lat1 = 40.7128, lng1 = -74.0060;
      const lat2 = 40.7128 + 0.00001, lng2 = -74.0060; // ~1.1 meters north

      const distance = calculateVincentyDistance(lat1, lng1, lat2, lng2);
      expect(distance).toBeGreaterThan(0.5);
      expect(distance).toBeLessThan(2);
    });
  });

  describe('checkGeofence', () => {
    test('should return true when user is within geofence', async () => {
      const mockAnnotationData = [{
        id: 'test-annotation-id',
        latitude: '40.7128',
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      mockSql.mockResolvedValueOnce(mockAnnotationData);

      const result = await geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'test-annotation-id'
      });

      expect(result.is_within_geofence).toBe(true);
      expect(result.distance_meters).toBe(0);
      expect(result.reward_eligible).toBe(true);
      expect(result.reward_radius).toBe(100);
    });

    test('should return false when user is outside geofence', async () => {
      const mockAnnotationData = [{
        id: 'test-annotation-id',
        latitude: '40.7128',
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      mockSql.mockResolvedValueOnce(mockAnnotationData);

      const result = await geofencingService.checkGeofence({
        user_location: { latitude: 40.7130, longitude: -74.0060 }, // ~200m away
        annotation_id: 'test-annotation-id'
      });

      expect(result.is_within_geofence).toBe(false);
      expect(result.distance_meters).toBeGreaterThan(100);
      expect(result.reward_eligible).toBe(false);
    });

    test('should use custom radius when provided', async () => {
      const mockAnnotationData = [{
        id: 'test-annotation-id',
        latitude: '40.7128',
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      mockSql.mockResolvedValueOnce(mockAnnotationData);

      const result = await geofencingService.checkGeofence({
        user_location: { latitude: 40.7130, longitude: -74.0060 },
        annotation_id: 'test-annotation-id',
        custom_radius: 300
      });

      expect(result.reward_radius).toBe(300);
      expect(result.is_within_geofence).toBe(true);
    });

    test('should handle annotation not found', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'nonexistent-id'
      })).rejects.toThrow('Annotation not found');
    });
  });

  describe('checkMultipleGeofences', () => {
    test('should check multiple annotations and sort by distance', async () => {
      const mockAnnotationData1 = [{
        id: 'annotation-1',
        latitude: '40.7128',
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      const mockAnnotationData2 = [{
        id: 'annotation-2',
        latitude: '40.7130',
        longitude: '-74.0060',
        annotation_type: 'premium',
        reward_radius: 200
      }];

      mockSql
        .mockResolvedValueOnce(mockAnnotationData1)
        .mockResolvedValueOnce(mockAnnotationData2);

      const results = await geofencingService.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: ['annotation-1', 'annotation-2']
      });

      expect(results).toHaveLength(2);
      expect(results[0].annotation.id).toBe('annotation-1'); // Closer one first
      expect(results[0].distance_meters).toBeLessThan(results[1].distance_meters);
    });

    test('should filter by max_distance', async () => {
      const mockAnnotationData = [{
        id: 'far-annotation',
        latitude: '40.7200', // Much further away
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      mockSql.mockResolvedValueOnce(mockAnnotationData);

      const results = await geofencingService.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: ['far-annotation'],
        max_distance: 500 // 500 meters max
      });

      // Should be filtered out because it's too far
      expect(results).toHaveLength(0);
    });
  });

  describe('configureGeofenceRadius', () => {
    test('should create new configuration', async () => {
      mockSql
        .mockResolvedValueOnce([]) // No existing config
        .mockResolvedValueOnce([{ // Insert result
          annotation_id: 'test-id',
          reward_radius: 150,
          annotation_type: 'premium',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }]);

      const result = await geofencingService.configureGeofenceRadius({
        annotation_id: 'test-id',
        reward_radius: 150,
        annotation_type: 'premium',
        created_by: 'user-id'
      });

      expect(result.reward_radius).toBe(150);
      expect(result.annotation_type).toBe('premium');
    });

    test('should update existing configuration', async () => {
      const existingConfig = {
        annotation_id: 'test-id',
        reward_radius: 100,
        annotation_type: 'standard'
      };

      mockSql
        .mockResolvedValueOnce([existingConfig]) // Existing config
        .mockResolvedValueOnce([{ // Update result
          annotation_id: 'test-id',
          reward_radius: 200,
          annotation_type: 'premium',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }]);

      const result = await geofencingService.configureGeofenceRadius({
        annotation_id: 'test-id',
        reward_radius: 200,
        annotation_type: 'premium',
        created_by: 'user-id'
      });

      expect(result.reward_radius).toBe(200);
      expect(result.annotation_type).toBe('premium');
    });
  });

  describe('Cache Management', () => {
    test('should cache annotation data', async () => {
      const mockAnnotationData = [{
        id: 'cached-annotation',
        latitude: '40.7128',
        longitude: '-74.0060',
        annotation_type: 'standard',
        reward_radius: 100
      }];

      mockSql.mockResolvedValueOnce(mockAnnotationData);

      // First call should hit database
      await geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'cached-annotation'
      });

      expect(mockSql).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'cached-annotation'
      });

      expect(mockSql).toHaveBeenCalledTimes(1); // Still just 1 call
    });

    test('should clear cache', () => {
      const initialStats = geofencingService.getCacheStats();
      
      // Add some mock data to cache (through private method simulation)
      geofencingService['locationCache'].set('test', {
        location: { latitude: 0, longitude: 0 },
        radius: 100,
        type: 'test',
        cached_at: Date.now()
      });

      const beforeClearStats = geofencingService.getCacheStats();
      expect(beforeClearStats.size).toBe(1);

      geofencingService.clearCache();

      const afterClearStats = geofencingService.getCacheStats();
      expect(afterClearStats.size).toBe(0);
    });

    test('should provide cache statistics', () => {
      const stats = geofencingService.getCacheStats();
      expect(stats).toHaveProperty('size');
      expect(stats).toHaveProperty('entries');
      expect(Array.isArray(stats.entries)).toBe(true);
    });
  });

  describe('Input Validation', () => {
    test('should validate coordinates', async () => {
      await expect(geofencingService.checkGeofence({
        user_location: { latitude: 91, longitude: 0 }, // Invalid latitude
        annotation_id: 'test-id'
      })).rejects.toThrow();

      await expect(geofencingService.checkGeofence({
        user_location: { latitude: 0, longitude: 181 }, // Invalid longitude
        annotation_id: 'test-id'
      })).rejects.toThrow();
    });

    test('should validate annotation ID format', async () => {
      await expect(geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'invalid-uuid'
      })).rejects.toThrow();
    });

    test('should validate radius bounds', async () => {
      await expect(geofencingService.configureGeofenceRadius({
        annotation_id: '550e8400-e29b-41d4-a716-446655440000',
        reward_radius: 25, // Too small
        created_by: '550e8400-e29b-41d4-a716-446655440001'
      })).rejects.toThrow();

      await expect(geofencingService.configureGeofenceRadius({
        annotation_id: '550e8400-e29b-41d4-a716-446655440000',
        reward_radius: 1500, // Too large
        created_by: '550e8400-e29b-41d4-a716-446655440001'
      })).rejects.toThrow();
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      mockSql.mockRejectedValueOnce(new Error('Database connection failed'));

      await expect(geofencingService.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: '550e8400-e29b-41d4-a716-446655440000'
      })).rejects.toThrow('Failed to check geofence');
    });

    test('should handle empty annotation arrays', async () => {
      const results = await geofencingService.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: []
      });

      expect(results).toHaveLength(0);
    });
  });
});

describe('Geofencing Performance Tests', () => {
  let geofencingService: GeofencingService;

  beforeAll(() => {
    geofencingService = new GeofencingService(mockEnv as any);
  });

  test('should handle batch processing efficiently', async () => {
    const batchSize = 50;
    const annotationIds = Array.from({ length: batchSize }, (_, i) => 
      `550e8400-e29b-41d4-a716-44665544${i.toString().padStart(4, '0')}`
    );

    // Mock database responses
    for (let i = 0; i < batchSize; i++) {
      mockSql.mockResolvedValueOnce([{
        id: annotationIds[i],
        latitude: (40 + Math.random() * 0.01).toString(),
        longitude: (-74 + Math.random() * 0.01).toString(),
        annotation_type: 'standard',
        reward_radius: 100
      }]);
    }

    const startTime = Date.now();
    
    const results = await geofencingService.checkMultipleGeofences({
      user_location: { latitude: 40.7128, longitude: -74.0060 },
      annotation_ids: annotationIds
    });

    const endTime = Date.now();
    const duration = endTime - startTime;

    expect(results.length).toBeLessThanOrEqual(batchSize);
    expect(duration).toBeLessThan(1000); // Should complete within 1 second
  });

  test('distance calculations should be performant', () => {
    const iterations = 1000;
    
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
      calculateVincentyDistance(
        40.7128 + Math.random() * 0.01,
        -74.0060 + Math.random() * 0.01,
        40.7128 + Math.random() * 0.01,
        -74.0060 + Math.random() * 0.01
      );
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Should be able to do 1000 calculations in reasonable time
    expect(duration).toBeLessThan(100); // Less than 100ms
  });
});