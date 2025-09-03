import {
  calculateDistance,
  isPointInPolygon,
  generateGeofence,
  validateCoordinates,
  formatCoordinates,
  getLocationAccuracy,
  calculateBearing,
  getLocationFromAddress,
  isValidGPSAccuracy
} from '../geoUtils';
import { jest } from '@jest/globals';

// Mock external dependencies
jest.mock('node-geocoder');

describe('GeoUtils', () => {
  describe('calculateDistance', () => {
    it('should calculate distance between two points correctly', () => {
      // Beijing to Shanghai (approximately 1067 km)
      const beijing = { lat: 39.9042, lng: 116.4074 };
      const shanghai = { lat: 31.2304, lng: 121.4737 };
      
      const distance = calculateDistance(beijing, shanghai);
      
      // Allow 1% tolerance for calculation differences
      expect(distance).toBeCloseTo(1067000, -3); // Within 1000m tolerance
    });

    it('should return 0 for same coordinates', () => {
      const point = { lat: 39.9042, lng: 116.4074 };
      
      const distance = calculateDistance(point, point);
      
      expect(distance).toBe(0);
    });

    it('should calculate short distances accurately', () => {
      // Two points very close to each other (about 100m apart)
      const point1 = { lat: 39.9042, lng: 116.4074 };
      const point2 = { lat: 39.9051, lng: 116.4074 }; // ~100m north
      
      const distance = calculateDistance(point1, point2);
      
      expect(distance).toBeCloseTo(100, 0); // Within 1m tolerance
    });

    it('should handle edge cases with extreme coordinates', () => {
      const northPole = { lat: 90, lng: 0 };
      const southPole = { lat: -90, lng: 0 };
      
      const distance = calculateDistance(northPole, southPole);
      
      // Half circumference of Earth (approximately 20,015 km)
      expect(distance).toBeCloseTo(20015000, -4);
    });

    it('should handle longitude wrap-around', () => {
      const point1 = { lat: 0, lng: 179 };
      const point2 = { lat: 0, lng: -179 };
      
      const distance = calculateDistance(point1, point2);
      
      // Should be about 222 km (2 degrees at equator)
      expect(distance).toBeCloseTo(222000, -3);
    });

    it('should throw error for invalid coordinates', () => {
      const validPoint = { lat: 39.9042, lng: 116.4074 };
      const invalidPoint = { lat: 91, lng: 116.4074 }; // Invalid latitude
      
      expect(() => {
        calculateDistance(validPoint, invalidPoint);
      }).toThrow('Invalid coordinates');
    });
  });

  describe('isPointInPolygon', () => {
    it('should detect point inside simple polygon', () => {
      // Square polygon
      const polygon = [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
        { lat: 1, lng: 0 }
      ];
      
      const pointInside = { lat: 0.5, lng: 0.5 };
      
      expect(isPointInPolygon(pointInside, polygon)).toBe(true);
    });

    it('should detect point outside polygon', () => {
      const polygon = [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
        { lat: 1, lng: 0 }
      ];
      
      const pointOutside = { lat: 2, lng: 2 };
      
      expect(isPointInPolygon(pointOutside, polygon)).toBe(false);
    });

    it('should handle point on polygon edge', () => {
      const polygon = [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
        { lat: 1, lng: 0 }
      ];
      
      const pointOnEdge = { lat: 0, lng: 0.5 };
      
      expect(isPointInPolygon(pointOnEdge, polygon)).toBe(true);
    });

    it('should handle complex polygon shapes', () => {
      // L-shaped polygon
      const lShapedPolygon = [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 2 },
        { lat: 1, lng: 2 },
        { lat: 1, lng: 1 },
        { lat: 2, lng: 1 },
        { lat: 2, lng: 0 }
      ];
      
      const pointInside = { lat: 0.5, lng: 0.5 };
      const pointOutside = { lat: 1.5, lng: 1.5 };
      
      expect(isPointInPolygon(pointInside, lShapedPolygon)).toBe(true);
      expect(isPointInPolygon(pointOutside, lShapedPolygon)).toBe(false);
    });

    it('should throw error for invalid polygon', () => {
      const invalidPolygon = [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 }
      ]; // Less than 3 points
      
      const point = { lat: 0.5, lng: 0.5 };
      
      expect(() => {
        isPointInPolygon(point, invalidPolygon);
      }).toThrow('Polygon must have at least 3 points');
    });
  });

  describe('generateGeofence', () => {
    it('should generate circular geofence', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      const radius = 100; // 100 meters
      
      const geofence = generateGeofence(center, radius, 'circle');
      
      expect(geofence.type).toBe('circle');
      expect(geofence.center).toEqual(center);
      expect(geofence.radius).toBe(radius);
      expect(geofence.coordinates).toHaveLength(16); // Default 16 points for circle approximation
    });

    it('should generate square geofence', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      const radius = 100;
      
      const geofence = generateGeofence(center, radius, 'square');
      
      expect(geofence.type).toBe('square');
      expect(geofence.center).toEqual(center);
      expect(geofence.radius).toBe(radius);
      expect(geofence.coordinates).toHaveLength(4);
    });

    it('should generate polygon with custom point count', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      const radius = 100;
      const points = 8;
      
      const geofence = generateGeofence(center, radius, 'circle', points);
      
      expect(geofence.coordinates).toHaveLength(points);
    });

    it('should validate all generated points are within expected distance', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      const radius = 100;
      
      const geofence = generateGeofence(center, radius, 'circle');
      
      geofence.coordinates.forEach(point => {
        const distance = calculateDistance(center, point);
        expect(distance).toBeCloseTo(radius, 0);
      });
    });

    it('should throw error for invalid radius', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      
      expect(() => {
        generateGeofence(center, -10, 'circle');
      }).toThrow('Radius must be positive');
      
      expect(() => {
        generateGeofence(center, 0, 'circle');
      }).toThrow('Radius must be positive');
    });
  });

  describe('validateCoordinates', () => {
    it('should validate correct coordinates', () => {
      expect(validateCoordinates(39.9042, 116.4074)).toBe(true);
      expect(validateCoordinates(0, 0)).toBe(true);
      expect(validateCoordinates(-90, -180)).toBe(true);
      expect(validateCoordinates(90, 180)).toBe(true);
    });

    it('should reject invalid latitude', () => {
      expect(validateCoordinates(91, 116.4074)).toBe(false);
      expect(validateCoordinates(-91, 116.4074)).toBe(false);
      expect(validateCoordinates(NaN, 116.4074)).toBe(false);
      expect(validateCoordinates(Infinity, 116.4074)).toBe(false);
    });

    it('should reject invalid longitude', () => {
      expect(validateCoordinates(39.9042, 181)).toBe(false);
      expect(validateCoordinates(39.9042, -181)).toBe(false);
      expect(validateCoordinates(39.9042, NaN)).toBe(false);
      expect(validateCoordinates(39.9042, Infinity)).toBe(false);
    });

    it('should handle edge cases', () => {
      expect(validateCoordinates(90, 180)).toBe(true);
      expect(validateCoordinates(-90, -180)).toBe(true);
      expect(validateCoordinates(0, 0)).toBe(true);
    });
  });

  describe('formatCoordinates', () => {
    it('should format coordinates with default precision', () => {
      const formatted = formatCoordinates(39.904200123, 116.407400456);
      
      expect(formatted).toBe('39.9042, 116.4074');
    });

    it('should format coordinates with custom precision', () => {
      const formatted = formatCoordinates(39.904200123, 116.407400456, 6);
      
      expect(formatted).toBe('39.904200, 116.407400');
    });

    it('should handle negative coordinates', () => {
      const formatted = formatCoordinates(-39.904200123, -116.407400456);
      
      expect(formatted).toBe('-39.9042, -116.4074');
    });

    it('should handle zero coordinates', () => {
      const formatted = formatCoordinates(0, 0);
      
      expect(formatted).toBe('0.0000, 0.0000');
    });
  });

  describe('getLocationAccuracy', () => {
    it('should return high accuracy for GPS', () => {
      const accuracy = getLocationAccuracy('gps', 5);
      
      expect(accuracy.level).toBe('high');
      expect(accuracy.radius).toBe(5);
      expect(accuracy.confidence).toBeGreaterThan(0.9);
    });

    it('should return medium accuracy for network', () => {
      const accuracy = getLocationAccuracy('network', 50);
      
      expect(accuracy.level).toBe('medium');
      expect(accuracy.radius).toBe(50);
      expect(accuracy.confidence).toBeLessThan(0.9);
    });

    it('should return low accuracy for passive', () => {
      const accuracy = getLocationAccuracy('passive', 200);
      
      expect(accuracy.level).toBe('low');
      expect(accuracy.radius).toBe(200);
      expect(accuracy.confidence).toBeLessThan(0.7);
    });

    it('should adjust confidence based on radius', () => {
      const highAccuracy = getLocationAccuracy('gps', 3);
      const lowAccuracy = getLocationAccuracy('gps', 20);
      
      expect(highAccuracy.confidence).toBeGreaterThan(lowAccuracy.confidence);
    });
  });

  describe('calculateBearing', () => {
    it('should calculate bearing between two points', () => {
      const start = { lat: 39.9042, lng: 116.4074 };
      const end = { lat: 40.0042, lng: 116.4074 }; // Due north
      
      const bearing = calculateBearing(start, end);
      
      expect(bearing).toBeCloseTo(0, 1); // Should be close to 0° (north)
    });

    it('should calculate bearing for east direction', () => {
      const start = { lat: 39.9042, lng: 116.4074 };
      const end = { lat: 39.9042, lng: 117.4074 }; // Due east
      
      const bearing = calculateBearing(start, end);
      
      expect(bearing).toBeCloseTo(90, 1); // Should be close to 90° (east)
    });

    it('should calculate bearing for south direction', () => {
      const start = { lat: 39.9042, lng: 116.4074 };
      const end = { lat: 38.9042, lng: 116.4074 }; // Due south
      
      const bearing = calculateBearing(start, end);
      
      expect(bearing).toBeCloseTo(180, 1); // Should be close to 180° (south)
    });

    it('should calculate bearing for west direction', () => {
      const start = { lat: 39.9042, lng: 116.4074 };
      const end = { lat: 39.9042, lng: 115.4074 }; // Due west
      
      const bearing = calculateBearing(start, end);
      
      expect(bearing).toBeCloseTo(270, 1); // Should be close to 270° (west)
    });

    it('should return 0 for same coordinates', () => {
      const point = { lat: 39.9042, lng: 116.4074 };
      
      const bearing = calculateBearing(point, point);
      
      expect(bearing).toBe(0);
    });
  });

  describe('getLocationFromAddress', () => {
    let mockGeocoder: any;

    beforeEach(() => {
      mockGeocoder = {
        geocode: jest.fn()
      };
      
      // Mock the geocoder module
      jest.doMock('node-geocoder', () => {
        return jest.fn(() => mockGeocoder);
      });
    });

    it('should geocode address successfully', async () => {
      const mockResult = [{
        latitude: 39.9042,
        longitude: 116.4074,
        formattedAddress: 'Beijing, China',
        country: 'China',
        city: 'Beijing'
      }];
      
      mockGeocoder.geocode.mockResolvedValue(mockResult);
      
      const result = await getLocationFromAddress('Beijing, China');
      
      expect(result).toEqual({
        lat: 39.9042,
        lng: 116.4074,
        formattedAddress: 'Beijing, China',
        country: 'China',
        city: 'Beijing'
      });
    });

    it('should handle geocoding failure', async () => {
      mockGeocoder.geocode.mockResolvedValue([]);
      
      await expect(getLocationFromAddress('Invalid Address'))
        .rejects.toThrow('Address not found');
    });

    it('should handle geocoder errors', async () => {
      mockGeocoder.geocode.mockRejectedValue(new Error('Geocoding service unavailable'));
      
      await expect(getLocationFromAddress('Beijing, China'))
        .rejects.toThrow('Geocoding service unavailable');
    });

    it('should validate input address', async () => {
      await expect(getLocationFromAddress(''))
        .rejects.toThrow('Address cannot be empty');
      
      await expect(getLocationFromAddress('   '))
        .rejects.toThrow('Address cannot be empty');
    });
  });

  describe('isValidGPSAccuracy', () => {
    it('should accept high accuracy GPS readings', () => {
      expect(isValidGPSAccuracy(5)).toBe(true);
      expect(isValidGPSAccuracy(10)).toBe(true);
      expect(isValidGPSAccuracy(15)).toBe(true);
    });

    it('should reject low accuracy GPS readings', () => {
      expect(isValidGPSAccuracy(100)).toBe(false);
      expect(isValidGPSAccuracy(500)).toBe(false);
      expect(isValidGPSAccuracy(1000)).toBe(false);
    });

    it('should handle edge cases', () => {
      expect(isValidGPSAccuracy(20)).toBe(true); // Boundary case
      expect(isValidGPSAccuracy(21)).toBe(false); // Just over boundary
      expect(isValidGPSAccuracy(0)).toBe(true); // Perfect accuracy
      expect(isValidGPSAccuracy(-1)).toBe(false); // Invalid negative
    });

    it('should handle custom threshold', () => {
      expect(isValidGPSAccuracy(30, 50)).toBe(true);
      expect(isValidGPSAccuracy(60, 50)).toBe(false);
    });

    it('should reject invalid input types', () => {
      expect(isValidGPSAccuracy(NaN)).toBe(false);
      expect(isValidGPSAccuracy(Infinity)).toBe(false);
      expect(isValidGPSAccuracy(-Infinity)).toBe(false);
    });
  });

  describe('integration tests', () => {
    it('should work together for geofence validation', () => {
      const center = { lat: 39.9042, lng: 116.4074 };
      const radius = 100;
      
      // Generate a circular geofence
      const geofence = generateGeofence(center, radius, 'circle');
      
      // Test point inside the geofence
      const nearbyPoint = { lat: 39.9043, lng: 116.4075 };
      const distance = calculateDistance(center, nearbyPoint);
      
      expect(distance).toBeLessThan(radius);
      expect(isPointInPolygon(nearbyPoint, geofence.coordinates)).toBe(true);
    });

    it('should validate coordinates before processing', () => {
      const invalidLat = 91;
      const validLng = 116.4074;
      
      expect(validateCoordinates(invalidLat, validLng)).toBe(false);
      
      expect(() => {
        calculateDistance(
          { lat: invalidLat, lng: validLng },
          { lat: 39.9042, lng: 116.4074 }
        );
      }).toThrow('Invalid coordinates');
    });

    it('should format and validate coordinates consistently', () => {
      const lat = 39.904200123;
      const lng = 116.407400456;
      
      expect(validateCoordinates(lat, lng)).toBe(true);
      
      const formatted = formatCoordinates(lat, lng);
      const [formattedLat, formattedLng] = formatted.split(', ').map(Number);
      
      expect(formattedLat).toBeDefined();
      expect(formattedLng).toBeDefined();
      expect(validateCoordinates(formattedLat!, formattedLng!)).toBe(true);
    });
  });
});