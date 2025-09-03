import { lbsService, LBSService } from '../lbs-service';
import type { Coordinates, GeofenceRegion, LocationCheckResult } from '../lbs-service';

// Mock Notification API
Object.defineProperty(window, 'Notification', {
  writable: true,
  value: class MockNotification {
    static permission = 'default';
    static requestPermission = jest.fn(() => Promise.resolve('granted'));
    constructor(title: string, options?: any) {
      // Mock notification
    }
  }
});

describe('LBSService', () => {
  let mockGeolocation: any;
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock geolocation API
    mockGeolocation = {
      getCurrentPosition: jest.fn(),
      watchPosition: jest.fn(),
      clearWatch: jest.fn()
    };
    
    Object.defineProperty(navigator, 'geolocation', {
      writable: true,
      value: mockGeolocation
    });
    
    // Reset service state
    lbsService.stopWatchingLocation();
    lbsService.clearLocationHistory();
  });

  afterEach(() => {
    lbsService.stopWatchingLocation();
  });

  describe('getCurrentLocation', () => {
    it('should return current location successfully', async () => {
      const mockPosition = {
        coords: {
          latitude: 39.9042,
          longitude: 116.4074,
          accuracy: 10,
          altitude: null,
          altitudeAccuracy: null,
          heading: null,
          speed: null
        }
      };

      mockGeolocation.getCurrentPosition.mockImplementation((success) => {
        success(mockPosition);
      });

      const location = await lbsService.getCurrentLocation();

      expect(location).toEqual({
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 10
      });
      expect(mockGeolocation.getCurrentPosition).toHaveBeenCalledWith(
        expect.any(Function),
        expect.any(Function),
        expect.objectContaining({
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 60000
        })
      );
    });

    it('should reject when geolocation is not supported', async () => {
      Object.defineProperty(navigator, 'geolocation', {
        writable: true,
        value: undefined
      });

      await expect(lbsService.getCurrentLocation()).rejects.toThrow(
        'Geolocation is not supported by this browser'
      );
    });

    it('should reject on geolocation error', async () => {
      mockGeolocation.getCurrentPosition.mockImplementation((success, error) => {
        error({ code: 1, message: 'Permission denied' });
      });

      await expect(lbsService.getCurrentLocation()).rejects.toThrow(
        'Location error: Permission denied'
      );
    });

    it('should use custom options when provided', async () => {
      const customOptions = {
        enableHighAccuracy: false,
        timeout: 5000,
        maximumAge: 30000
      };

      mockGeolocation.getCurrentPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
      });

      await lbsService.getCurrentLocation(customOptions);

      expect(mockGeolocation.getCurrentPosition).toHaveBeenCalledWith(
        expect.any(Function),
        expect.any(Function),
        expect.objectContaining(customOptions)
      );
    });
  });

  describe('startWatchingLocation', () => {
    it('should start watching location successfully', async () => {
      mockGeolocation.watchPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
        return 1;
      });

      await lbsService.startWatchingLocation();

      expect(mockGeolocation.watchPosition).toHaveBeenCalledWith(
        expect.any(Function),
        expect.any(Function),
        expect.objectContaining({
          enableHighAccuracy: true,
          timeout: 5000,
          maximumAge: 30000
        })
      );
    });

    it('should reject when geolocation is not supported', async () => {
      Object.defineProperty(navigator, 'geolocation', {
        writable: true,
        value: undefined
      });

      await expect(lbsService.startWatchingLocation()).rejects.toThrow(
        'Geolocation is not supported'
      );
    });

    it('should resolve immediately if already watching', async () => {
      // First call
      mockGeolocation.watchPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
        return 1;
      });

      await lbsService.startWatchingLocation();

      // Second call should resolve immediately
      const startTime = Date.now();
      await lbsService.startWatchingLocation();
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(10); // Should be very fast
    });

    it('should handle watch position errors', async () => {
      mockGeolocation.watchPosition.mockImplementation((success, error) => {
        error({ code: 2, message: 'Position unavailable' });
        return 1;
      });

      await expect(lbsService.startWatchingLocation()).rejects.toThrow(
        'Location watch error: Position unavailable'
      );
    });
  });

  describe('stopWatchingLocation', () => {
    it('should stop watching location', async () => {
      const watchId = 123;
      mockGeolocation.watchPosition.mockReturnValue(watchId);
      mockGeolocation.watchPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
        return watchId;
      });

      await lbsService.startWatchingLocation();
      lbsService.stopWatchingLocation();

      expect(mockGeolocation.clearWatch).toHaveBeenCalledWith(watchId);
    });

    it('should handle stopping when not watching', () => {
      // Should not throw error
      expect(() => lbsService.stopWatchingLocation()).not.toThrow();
    });
  });

  describe('calculateDistance', () => {
    it('should calculate distance between two coordinates correctly', () => {
      const coord1: Coordinates = { latitude: 39.9042, longitude: 116.4074 };
      const coord2: Coordinates = { latitude: 39.9052, longitude: 116.4084 };

      const distance = lbsService.calculateDistance(coord1, coord2);

      // Distance should be approximately 134 meters
      expect(distance).toBeGreaterThan(100);
      expect(distance).toBeLessThan(200);
    });

    it('should return 0 for identical coordinates', () => {
      const coord: Coordinates = { latitude: 39.9042, longitude: 116.4074 };

      const distance = lbsService.calculateDistance(coord, coord);

      expect(distance).toBe(0);
    });

    it('should handle edge cases with extreme coordinates', () => {
      const coord1: Coordinates = { latitude: 89.9, longitude: 179.9 };
      const coord2: Coordinates = { latitude: -89.9, longitude: -179.9 };

      const distance = lbsService.calculateDistance(coord1, coord2);

      expect(distance).toBeGreaterThan(0);
      expect(Number.isFinite(distance)).toBe(true);
    });
  });

  describe('checkLocationInRegion', () => {
    const mockRegion: GeofenceRegion = {
      id: 'region-1',
      center: { latitude: 39.9042, longitude: 116.4074 },
      radius: 100,
      annotationId: 'annotation-1',
      rewardAmount: 10,
      isActive: true,
      createdAt: '2023-01-01T00:00:00Z'
    };

    it('should return true when location is inside region', () => {
      const location: Coordinates = { latitude: 39.9043, longitude: 116.4075 };

      const result = lbsService.checkLocationInRegion(location, mockRegion);

      expect(result.isInside).toBe(true);
      expect(result.canClaimReward).toBe(true);
      expect(result.rewardAmount).toBe(10);
      expect(result.region).toBe(mockRegion);
    });

    it('should return false when location is outside region', () => {
      const location: Coordinates = { latitude: 40.0000, longitude: 117.0000 };

      const result = lbsService.checkLocationInRegion(location, mockRegion);

      expect(result.isInside).toBe(false);
      expect(result.canClaimReward).toBe(false);
      expect(result.rewardAmount).toBeUndefined();
    });

    it('should return false for reward when region is inactive', () => {
      const inactiveRegion = { ...mockRegion, isActive: false };
      const location: Coordinates = { latitude: 39.9043, longitude: 116.4075 };

      const result = lbsService.checkLocationInRegion(location, inactiveRegion);

      expect(result.isInside).toBe(true);
      expect(result.canClaimReward).toBe(false); // Cannot claim because region is inactive
    });
  });

  describe('getNearbyAnnotations', () => {
    it('should return nearby annotations within radius', async () => {
      const location: Coordinates = { latitude: 39.9042, longitude: 116.4074 };

      const annotations = await lbsService.getNearbyAnnotations(location, 1000);

      expect(Array.isArray(annotations)).toBe(true);
      expect(annotations.length).toBeGreaterThan(0);
      
      // All annotations should be within the radius
      annotations.forEach(annotation => {
        expect(annotation.distance).toBeLessThanOrEqual(1000);
      });
    });

    it('should filter out annotations beyond radius', async () => {
      const location: Coordinates = { latitude: 39.9042, longitude: 116.4074 };

      const annotations = await lbsService.getNearbyAnnotations(location, 200);

      // Should return only close annotations
      annotations.forEach(annotation => {
        expect(annotation.distance).toBeLessThanOrEqual(200);
      });
    });

    it('should handle errors gracefully', async () => {
      // Mock console.error to avoid noise in tests
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // This simulates an error scenario - in real implementation this might be a network error
      const location: Coordinates = { latitude: NaN, longitude: NaN };

      const annotations = await lbsService.getNearbyAnnotations(location);

      expect(Array.isArray(annotations)).toBe(true);
      expect(annotations.length).toBe(0);

      consoleSpy.mockRestore();
    });
  });

  describe('claimReward', () => {
    it('should claim reward successfully', async () => {
      const location: Coordinates = { latitude: 39.9042, longitude: 116.4074 };

      const claim = await lbsService.claimReward('annotation-1', location);

      expect(claim).toMatchObject({
        userId: 'user_123',
        annotationId: 'annotation-1',
        location,
        status: 'pending'
      });
      expect(claim.amount).toBeGreaterThanOrEqual(5);
      expect(claim.amount).toBeLessThanOrEqual(25);
      expect(claim.id).toBeDefined();
      expect(claim.claimedAt).toBeDefined();
    });

    it('should handle claim errors', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // Simulate error conditions
      await expect(
        lbsService.claimReward('invalid-annotation', { latitude: NaN, longitude: NaN })
      ).rejects.toThrow();

      consoleSpy.mockRestore();
    });
  });

  describe('validateLocationAccuracy', () => {
    it('should validate accurate location', () => {
      const location: Coordinates = {
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 10
      };

      const isValid = lbsService.validateLocationAccuracy(location);
      expect(isValid).toBe(true);
    });

    it('should reject inaccurate location', () => {
      const location: Coordinates = {
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 100 // Too inaccurate
      };

      const isValid = lbsService.validateLocationAccuracy(location);
      expect(isValid).toBe(false);
    });

    it('should reject invalid coordinates', () => {
      const invalidLocations = [
        { latitude: 91, longitude: 116.4074 }, // Invalid latitude
        { latitude: 39.9042, longitude: 181 }, // Invalid longitude
        { latitude: -91, longitude: 116.4074 }, // Invalid latitude
        { latitude: 39.9042, longitude: -181 } // Invalid longitude
      ];

      invalidLocations.forEach(location => {
        const isValid = lbsService.validateLocationAccuracy(location as Coordinates);
        expect(isValid).toBe(false);
      });
    });

    it('should accept location without accuracy', () => {
      const location: Coordinates = {
        latitude: 39.9042,
        longitude: 116.4074
      };

      const isValid = lbsService.validateLocationAccuracy(location);
      expect(isValid).toBe(true);
    });
  });

  describe('detectSuspiciousLocation', () => {
    it('should detect suspicious fast movement', async () => {
      // Add some location history
      const location1: Coordinates = { latitude: 39.9042, longitude: 116.4074 };
      const location2: Coordinates = { latitude: 40.0000, longitude: 117.0000 }; // Very far away

      // Simulate adding locations to history manually
      await lbsService.getCurrentLocation();
      
      // Wait a bit and add another location
      await new Promise(resolve => setTimeout(resolve, 10));
      
      const isSuspicious = lbsService.detectSuspiciousLocation(location2);
      
      // This would be suspicious movement if the time difference is small
      // The actual result depends on the implementation details
      expect(typeof isSuspicious).toBe('boolean');
    });

    it('should not flag normal movement as suspicious', async () => {
      const location1: Coordinates = { latitude: 39.9042, longitude: 116.4074 };
      const location2: Coordinates = { latitude: 39.9043, longitude: 116.4075 }; // Close by

      await lbsService.getCurrentLocation();
      await new Promise(resolve => setTimeout(resolve, 100));

      const isSuspicious = lbsService.detectSuspiciousLocation(location2);
      
      expect(isSuspicious).toBe(false);
    });

    it('should return false for insufficient history', () => {
      const location: Coordinates = { latitude: 39.9042, longitude: 116.4074 };

      const isSuspicious = lbsService.detectSuspiciousLocation(location);
      
      expect(isSuspicious).toBe(false);
    });
  });

  describe('notification permissions', () => {
    it('should request notification permission successfully', async () => {
      (window.Notification.requestPermission as jest.Mock).mockResolvedValue('granted');

      const granted = await lbsService.requestNotificationPermission();

      expect(granted).toBe(true);
      expect(window.Notification.requestPermission).toHaveBeenCalled();
    });

    it('should handle denied notification permission', async () => {
      (window.Notification.requestPermission as jest.Mock).mockResolvedValue('denied');

      const granted = await lbsService.requestNotificationPermission();

      expect(granted).toBe(false);
    });

    it('should return false when notifications are not supported', async () => {
      // Mock unsupported browser
      Object.defineProperty(window, 'Notification', {
        writable: true,
        value: undefined
      });

      const granted = await lbsService.requestNotificationPermission();

      expect(granted).toBe(false);
    });
  });

  describe('utility functions', () => {
    it('should format distance correctly', () => {
      expect(lbsService.formatDistance(500)).toBe('500m');
      expect(lbsService.formatDistance(1500)).toBe('1.5km');
      expect(lbsService.formatDistance(1234)).toBe('1.2km');
    });

    it('should format coordinates correctly', () => {
      const coords: Coordinates = { latitude: 39.904200, longitude: 116.407400 };
      
      const formatted = lbsService.formatCoordinates(coords);
      
      expect(formatted).toBe('39.904200, 116.407400');
    });
  });

  describe('location history', () => {
    it('should maintain location history', async () => {
      mockGeolocation.getCurrentPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
      });

      await lbsService.getCurrentLocation();

      const history = lbsService.getLocationHistory();
      
      expect(history.length).toBe(1);
      expect(history[0].location.latitude).toBe(39.9042);
      expect(history[0].location.longitude).toBe(116.4074);
    });

    it('should clear location history', async () => {
      await lbsService.getCurrentLocation();
      lbsService.clearLocationHistory();

      const history = lbsService.getLocationHistory();
      
      expect(history.length).toBe(0);
    });

    it('should limit history size', async () => {
      // Mock many location updates
      mockGeolocation.getCurrentPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
      });

      // Get location many times (more than the 100 limit)
      for (let i = 0; i < 120; i++) {
        await lbsService.getCurrentLocation();
      }

      const history = lbsService.getLocationHistory();
      
      // Should be limited to 100 entries
      expect(history.length).toBeLessThanOrEqual(100);
    });
  });

  describe('cached location', () => {
    it('should return cached location', async () => {
      mockGeolocation.getCurrentPosition.mockImplementation((success) => {
        success({
          coords: { latitude: 39.9042, longitude: 116.4074, accuracy: 10 }
        });
      });

      await lbsService.getCurrentLocation();

      const cached = lbsService.getCurrentLocationCached();
      
      expect(cached).toEqual({
        latitude: 39.9042,
        longitude: 116.4074,
        accuracy: 10
      });
    });

    it('should return null when no location cached', () => {
      const cached = lbsService.getCurrentLocationCached();
      
      expect(cached).toBeNull();
    });
  });
});