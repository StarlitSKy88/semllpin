import { BackendGeofencingService, calculateHaversineDistance, calculateVincentyDistance } from '../geofencing';
import { Pool, PoolClient } from 'pg';

// Mock PostgreSQL Pool and Client
const mockQuery = jest.fn();
const mockRelease = jest.fn();
const mockConnect = jest.fn();

const mockClient: Partial<PoolClient> = {
  query: mockQuery,
  release: mockRelease
};

const mockPool: Partial<Pool> = {
  connect: mockConnect
};

// Setup mocks
mockConnect.mockResolvedValue(mockClient as PoolClient);

describe('BackendGeofencingService', () => {
  let service: BackendGeofencingService;

  beforeAll(() => {
    service = new BackendGeofencingService(mockPool as Pool);
  });

  beforeEach(() => {
    jest.clearAllMocks();
    service.clearCache();
  });

  afterEach(() => {
    service.clearCache();
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

      // Should be approximately 1068 km
      expect(distance).toBeGreaterThan(1050000);
      expect(distance).toBeLessThan(1080000);
    });

    test('calculateVincentyDistance should be more precise than Haversine', () => {
      const lat1 = 40.7128, lng1 = -74.0060; // New York
      const lat2 = 34.0522, lng2 = -118.2437; // Los Angeles
      
      const haversineDistance = calculateHaversineDistance(lat1, lng1, lat2, lng2);
      const vincentyDistance = calculateVincentyDistance(lat1, lng1, lat2, lng2);

      // Vincenty should be different from Haversine
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
  });

  describe('checkGeofence', () => {
    test('should return true when user is within geofence', async () => {
      const mockAnnotationData = {
        rows: [{
          id: 'test-annotation-id',
          latitude: 40.7128,
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      mockQuery.mockResolvedValueOnce(mockAnnotationData);

      const result = await service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'test-annotation-id'
      });

      expect(result.is_within_geofence).toBe(true);
      expect(result.distance_meters).toBe(0);
      expect(result.reward_eligible).toBe(true);
      expect(result.reward_radius).toBe(100);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should return false when user is outside geofence', async () => {
      const mockAnnotationData = {
        rows: [{
          id: 'test-annotation-id',
          latitude: 40.7128,
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      mockQuery.mockResolvedValueOnce(mockAnnotationData);

      const result = await service.checkGeofence({
        user_location: { latitude: 40.7130, longitude: -74.0060 }, // ~200m away
        annotation_id: 'test-annotation-id'
      });

      expect(result.is_within_geofence).toBe(false);
      expect(result.distance_meters).toBeGreaterThan(100);
      expect(result.reward_eligible).toBe(false);
    });

    test('should use custom radius when provided', async () => {
      const mockAnnotationData = {
        rows: [{
          id: 'test-annotation-id',
          latitude: 40.7128,
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      mockQuery.mockResolvedValueOnce(mockAnnotationData);

      const result = await service.checkGeofence({
        user_location: { latitude: 40.7130, longitude: -74.0060 },
        annotation_id: 'test-annotation-id',
        custom_radius: 300
      });

      expect(result.reward_radius).toBe(300);
      expect(result.is_within_geofence).toBe(true);
    });

    test('should handle annotation not found', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await expect(service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'nonexistent-id'
      })).rejects.toThrow('Annotation not found');

      expect(mockRelease).toHaveBeenCalled();
    });

    test('should handle database errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Database connection failed'));

      await expect(service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'test-id'
      })).rejects.toThrow('Failed to check geofence');

      expect(mockRelease).toHaveBeenCalled();
    });
  });

  describe('checkMultipleGeofences', () => {
    test('should check multiple annotations and sort by distance', async () => {
      const mockAnnotationData1 = {
        rows: [{
          id: 'annotation-1',
          latitude: 40.7128,
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      const mockAnnotationData2 = {
        rows: [{
          id: 'annotation-2',
          latitude: 40.7130,
          longitude: -74.0060,
          annotation_type: 'premium',
          reward_radius: 200
        }]
      };

      mockQuery
        .mockResolvedValueOnce(mockAnnotationData1)
        .mockResolvedValueOnce(mockAnnotationData2);

      const results = await service.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: ['annotation-1', 'annotation-2']
      });

      expect(results).toHaveLength(2);
      expect(results[0].annotation.id).toBe('annotation-1'); // Closer one first
      expect(results[0].distance_meters).toBeLessThan(results[1].distance_meters);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should filter by max_distance', async () => {
      const mockAnnotationData = {
        rows: [{
          id: 'far-annotation',
          latitude: 40.7200, // Much further away
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      mockQuery.mockResolvedValueOnce(mockAnnotationData);

      const results = await service.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: ['far-annotation'],
        max_distance: 500
      });

      expect(results).toHaveLength(0);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should handle empty annotation arrays', async () => {
      const results = await service.checkMultipleGeofences({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_ids: []
      });

      expect(results).toHaveLength(0);
      expect(mockRelease).toHaveBeenCalled();
    });
  });

  describe('findNearbyAnnotations', () => {
    test('should find nearby annotations using PostGIS', async () => {
      const mockNearbyData = {
        rows: [
          {
            id: 'nearby-1',
            latitude: 40.7128,
            longitude: -74.0060,
            annotation_type: 'standard',
            reward_radius: 100,
            distance_meters: 50
          },
          {
            id: 'nearby-2',
            latitude: 40.7129,
            longitude: -74.0060,
            annotation_type: 'premium',
            reward_radius: 200,
            distance_meters: 111
          }
        ]
      };

      mockQuery.mockResolvedValueOnce(mockNearbyData);

      const results = await service.findNearbyAnnotations({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        search_radius: 500,
        limit: 10
      });

      expect(results).toHaveLength(2);
      expect(results[0].is_within_geofence).toBe(true);
      expect(results[1].is_within_geofence).toBe(false);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should fallback when PostGIS is not available', async () => {
      // Mock PostGIS query failure
      mockQuery
        .mockRejectedValueOnce(new Error('PostGIS not available'))
        .mockResolvedValueOnce({
          rows: [{
            id: 'fallback-annotation',
            latitude: 40.7128,
            longitude: -74.0060,
            annotation_type: 'standard',
            reward_radius: 100
          }]
        });

      const results = await service.findNearbyAnnotations({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        search_radius: 200
      });

      expect(results).toHaveLength(1);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should filter by annotation types', async () => {
      const mockNearbyData = {
        rows: [
          {
            id: 'smell-food',
            latitude: 40.7128,
            longitude: -74.0060,
            annotation_type: 'food',
            reward_radius: 100,
            distance_meters: 50
          }
        ]
      };

      mockQuery.mockResolvedValueOnce(mockNearbyData);

      const results = await service.findNearbyAnnotations({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        search_radius: 500,
        annotation_types: ['food', 'restaurant']
      });

      expect(results).toHaveLength(1);
      expect(results[0].annotation.reward_type).toBe('food');
    });
  });

  describe('configureGeofenceRadius', () => {
    test('should create new configuration', async () => {
      const existingConfigResult = { rows: [] };
      const insertResult = {
        rows: [{
          annotation_id: 'test-id',
          reward_radius: 150,
          annotation_type: 'premium',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }]
      };

      mockQuery
        .mockResolvedValueOnce(existingConfigResult)
        .mockResolvedValueOnce(insertResult);

      const result = await service.configureGeofenceRadius({
        annotation_id: 'test-id',
        reward_radius: 150,
        annotation_type: 'premium',
        created_by: 'user-id'
      });

      expect(result.reward_radius).toBe(150);
      expect(result.annotation_type).toBe('premium');
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should update existing configuration', async () => {
      const existingConfigResult = {
        rows: [{
          annotation_id: 'test-id',
          reward_radius: 100,
          annotation_type: 'standard'
        }]
      };
      const updateResult = {
        rows: [{
          annotation_id: 'test-id',
          reward_radius: 200,
          annotation_type: 'premium',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }]
      };

      mockQuery
        .mockResolvedValueOnce(existingConfigResult)
        .mockResolvedValueOnce(updateResult);

      const result = await service.configureGeofenceRadius({
        annotation_id: 'test-id',
        reward_radius: 200,
        annotation_type: 'premium',
        created_by: 'user-id'
      });

      expect(result.reward_radius).toBe(200);
      expect(result.annotation_type).toBe('premium');
      expect(mockRelease).toHaveBeenCalled();
    });
  });

  describe('Cache Management', () => {
    test('should cache annotation data', async () => {
      const mockAnnotationData = {
        rows: [{
          id: 'cached-annotation',
          latitude: 40.7128,
          longitude: -74.0060,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      };

      mockQuery.mockResolvedValue(mockAnnotationData);

      // First call should hit database
      await service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'cached-annotation'
      });

      expect(mockQuery).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'cached-annotation'
      });

      // Should still be just 1 database call (second used cache)
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    test('should clear cache', () => {
      // Add mock data to cache
      service['locationCache'].set('test', {
        location: { latitude: 0, longitude: 0 },
        radius: 100,
        type: 'test',
        cached_at: Date.now()
      });

      const beforeClearStats = service.getCacheStats();
      expect(beforeClearStats.size).toBe(1);

      service.clearCache();

      const afterClearStats = service.getCacheStats();
      expect(afterClearStats.size).toBe(0);
    });

    test('should provide cache statistics', () => {
      const stats = service.getCacheStats();
      expect(stats).toHaveProperty('size');
      expect(stats).toHaveProperty('entries');
      expect(Array.isArray(stats.entries)).toBe(true);
    });
  });

  describe('initializeGeofencingTables', () => {
    test('should initialize tables successfully', async () => {
      mockQuery
        .mockResolvedValueOnce(undefined) // CREATE TABLE IF NOT EXISTS
        .mockResolvedValueOnce(undefined) // CREATE INDEX
        .mockResolvedValueOnce(undefined) // CREATE EXTENSION
        .mockResolvedValueOnce(undefined); // CREATE SPATIAL INDEX

      const result = await service.initializeGeofencingTables();

      expect(result).toBe(true);
      expect(mockQuery).toHaveBeenCalledTimes(4);
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should handle PostGIS not available', async () => {
      mockQuery
        .mockResolvedValueOnce(undefined) // CREATE TABLE
        .mockResolvedValueOnce(undefined) // CREATE INDEX
        .mockRejectedValueOnce(new Error('PostGIS extension not available')); // PostGIS fails

      const result = await service.initializeGeofencingTables();

      expect(result).toBe(true); // Should still succeed without PostGIS
      expect(mockRelease).toHaveBeenCalled();
    });

    test('should handle initialization errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Database error'));

      const result = await service.initializeGeofencingTables();

      expect(result).toBe(false);
      expect(mockRelease).toHaveBeenCalled();
    });
  });

  describe('Input Validation', () => {
    test('should validate coordinates', async () => {
      await expect(service.checkGeofence({
        user_location: { latitude: 91, longitude: 0 },
        annotation_id: 'test-id'
      })).rejects.toThrow();

      await expect(service.checkGeofence({
        user_location: { latitude: 0, longitude: 181 },
        annotation_id: 'test-id'
      })).rejects.toThrow();

      expect(mockRelease).toHaveBeenCalled();
    });

    test('should validate annotation ID format', async () => {
      await expect(service.checkGeofence({
        user_location: { latitude: 40.7128, longitude: -74.0060 },
        annotation_id: 'invalid-uuid'
      })).rejects.toThrow();

      expect(mockRelease).toHaveBeenCalled();
    });

    test('should validate radius bounds', async () => {
      await expect(service.configureGeofenceRadius({
        annotation_id: '550e8400-e29b-41d4-a716-446655440000',
        reward_radius: 25,
        created_by: '550e8400-e29b-41d4-a716-446655440001'
      })).rejects.toThrow();

      await expect(service.configureGeofenceRadius({
        annotation_id: '550e8400-e29b-41d4-a716-446655440000',
        reward_radius: 1500,
        created_by: '550e8400-e29b-41d4-a716-446655440001'
      })).rejects.toThrow();

      expect(mockRelease).toHaveBeenCalled();
    });
  });
});

describe('Backend Geofencing Performance Tests', () => {
  let service: BackendGeofencingService;

  beforeAll(() => {
    service = new BackendGeofencingService(mockPool as Pool);
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should handle batch processing efficiently', async () => {
    const batchSize = 50;
    const annotationIds = Array.from({ length: batchSize }, (_, i) => 
      `550e8400-e29b-41d4-a716-44665544${i.toString().padStart(4, '0')}`
    );

    // Mock database responses for each annotation
    for (let i = 0; i < batchSize; i++) {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: annotationIds[i],
          latitude: 40 + Math.random() * 0.01,
          longitude: -74 + Math.random() * 0.01,
          annotation_type: 'standard',
          reward_radius: 100
        }]
      });
    }

    const startTime = Date.now();
    
    const results = await service.checkMultipleGeofences({
      user_location: { latitude: 40.7128, longitude: -74.0060 },
      annotation_ids: annotationIds
    });

    const endTime = Date.now();
    const duration = endTime - startTime;

    expect(results.length).toBeLessThanOrEqual(batchSize);
    expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
    expect(mockRelease).toHaveBeenCalled();
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
    
    expect(duration).toBeLessThan(200); // Less than 200ms for 1000 calculations
  });
});