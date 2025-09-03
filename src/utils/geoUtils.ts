const NodeGeocoder = require('node-geocoder');

// Types
export interface Coordinates {
  lat: number;
  lng: number;
}

export interface GeofenceResult {
  type: 'circle' | 'square';
  center: Coordinates;
  radius: number;
  coordinates: Coordinates[];
}

export interface LocationAccuracy {
  level: 'high' | 'medium' | 'low';
  radius: number;
  confidence: number;
}

export interface GeocodingResult {
  lat: number;
  lng: number;
  formattedAddress: string;
  country?: string;
  city?: string;
}

// Constants
const EARTH_RADIUS = 6371000; // Earth's radius in meters
const GPS_ACCURACY_THRESHOLD = 20; // Default GPS accuracy threshold in meters

/**
 * Calculate distance between two coordinates using Haversine formula
 * @param point1 First coordinate point
 * @param point2 Second coordinate point
 * @returns Distance in meters
 */
export function calculateDistance(point1: Coordinates, point2: Coordinates): number {
  // Validate coordinates
  if (!validateCoordinates(point1.lat, point1.lng) || !validateCoordinates(point2.lat, point2.lng)) {
    throw new Error('Invalid coordinates');
  }

  // Same point
  if (point1.lat === point2.lat && point1.lng === point2.lng) {
    return 0;
  }

  const lat1Rad = toRadians(point1.lat);
  const lat2Rad = toRadians(point2.lat);
  const deltaLatRad = toRadians(point2.lat - point1.lat);
  const deltaLngRad = toRadians(point2.lng - point1.lng);

  const a = Math.sin(deltaLatRad / 2) * Math.sin(deltaLatRad / 2) +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) *
    Math.sin(deltaLngRad / 2) * Math.sin(deltaLngRad / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return EARTH_RADIUS * c;
}

/**
 * Check if a point is inside a polygon using ray casting algorithm
 * @param point Point to check
 * @param polygon Array of coordinates forming the polygon
 * @returns True if point is inside polygon
 */
export function isPointInPolygon(point: Coordinates, polygon: Coordinates[]): boolean {
  if (polygon.length < 3) {
    throw new Error('Polygon must have at least 3 points');
  }

  let inside = false;
  const x = point.lng;
  const y = point.lat;

  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const pointI = polygon[i];
    const pointJ = polygon[j];

    if (!pointI || !pointJ) {
      continue;
    }

    const xi = pointI.lng;
    const yi = pointI.lat;
    const xj = pointJ.lng;
    const yj = pointJ.lat;

    if (((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) {
      inside = !inside;
    }
  }

  return inside;
}

/**
 * Generate a geofence around a center point
 * @param center Center coordinates
 * @param radius Radius in meters
 * @param type Type of geofence ('circle' or 'square')
 * @param points Number of points for circle approximation (default: 16)
 * @returns Geofence object
 */
export function generateGeofence(
  center: Coordinates,
  radius: number,
  type: 'circle' | 'square',
  points: number = 16,
): GeofenceResult {
  if (radius <= 0) {
    throw new Error('Radius must be positive');
  }

  if (!validateCoordinates(center.lat, center.lng)) {
    throw new Error('Invalid center coordinates');
  }

  const coordinates: Coordinates[] = [];

  if (type === 'circle') {
    // Generate circle approximation with specified number of points
    for (let i = 0; i < points; i++) {
      const angle = (2 * Math.PI * i) / points;
      const point = getPointAtDistance(center, radius, toDegrees(angle));
      coordinates.push(point);
    }
  } else if (type === 'square') {
    // Generate square geofence
    const diagonal = radius * Math.sqrt(2);
    const halfDiagonal = diagonal / 2;

    coordinates.push(
      getPointAtDistance(center, halfDiagonal, 45),   // NE
      getPointAtDistance(center, halfDiagonal, 135),  // SE
      getPointAtDistance(center, halfDiagonal, 225),  // SW
      getPointAtDistance(center, halfDiagonal, 315),   // NW
    );
  }

  return {
    type,
    center,
    radius,
    coordinates,
  };
}

/**
 * Validate latitude and longitude coordinates
 * @param lat Latitude
 * @param lng Longitude
 * @returns True if coordinates are valid
 */
export function validateCoordinates(lat: number, lng: number): boolean {
  return (
    typeof lat === 'number' &&
    typeof lng === 'number' &&
    !isNaN(lat) &&
    !isNaN(lng) &&
    isFinite(lat) &&
    isFinite(lng) &&
    lat >= -90 &&
    lat <= 90 &&
    lng >= -180 &&
    lng <= 180
  );
}

/**
 * Format coordinates to string with specified precision
 * @param lat Latitude
 * @param lng Longitude
 * @param precision Number of decimal places (default: 4)
 * @returns Formatted coordinate string
 */
export function formatCoordinates(lat: number, lng: number, precision: number = 4): string {
  return `${lat.toFixed(precision)}, ${lng.toFixed(precision)}`;
}

/**
 * Get location accuracy information based on source and radius
 * @param source Location source ('gps', 'network', 'passive')
 * @param radius Accuracy radius in meters
 * @returns Location accuracy object
 */
export function getLocationAccuracy(source: string, radius: number): LocationAccuracy {
  let level: 'high' | 'medium' | 'low';
  let confidence: number;

  // Determine accuracy level based on source and radius
  if (source === 'gps') {
    if (radius <= 10) {
      level = 'high';
      confidence = 0.95 - (radius / 100); // Higher confidence for lower radius
    } else if (radius <= 50) {
      level = 'medium';
      confidence = 0.85 - (radius / 200);
    } else {
      level = 'low';
      confidence = 0.7 - (radius / 500);
    }
  } else if (source === 'network') {
    level = 'medium';
    confidence = Math.max(0.3, 0.8 - (radius / 100));
  } else {
    level = 'low';
    confidence = Math.max(0.1, 0.6 - (radius / 200));
  }

  return {
    level,
    radius,
    confidence: Math.max(0.1, Math.min(0.99, confidence)),
  };
}

/**
 * Calculate bearing between two points
 * @param start Starting point
 * @param end Ending point
 * @returns Bearing in degrees (0-360)
 */
export function calculateBearing(start: Coordinates, end: Coordinates): number {
  if (start.lat === end.lat && start.lng === end.lng) {
    return 0;
  }

  const lat1Rad = toRadians(start.lat);
  const lat2Rad = toRadians(end.lat);
  const deltaLngRad = toRadians(end.lng - start.lng);

  const y = Math.sin(deltaLngRad) * Math.cos(lat2Rad);
  const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
    Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLngRad);

  let bearing = toDegrees(Math.atan2(y, x));

  // Normalize to 0-360 degrees
  bearing = (bearing + 360) % 360;

  return bearing;
}

/**
 * Get coordinates from address using geocoding
 * @param address Address string
 * @returns Promise with geocoding result
 */
export async function getLocationFromAddress(address: string): Promise<GeocodingResult> {
  if (!address || address.trim().length === 0) {
    throw new Error('Address cannot be empty');
  }

  const geocoder = NodeGeocoder({
    provider: 'openstreetmap',
  });

  try {
    const results = await geocoder.geocode(address);

    if (!results || results.length === 0) {
      throw new Error('Address not found');
    }

    const result = results[0];

    if (!result || result.latitude === undefined || result.longitude === undefined) {
      throw new Error('Invalid geocoding result');
    }

    return {
      lat: result.latitude,
      lng: result.longitude,
      formattedAddress: result.formattedAddress || address,
      country: result.country,
      city: result.city,
    };
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Geocoding failed');
  }
}

/**
 * Check if GPS accuracy is acceptable
 * @param accuracy Accuracy in meters
 * @param threshold Maximum acceptable accuracy (default: 20m)
 * @returns True if accuracy is acceptable
 */
export function isValidGPSAccuracy(accuracy: number, threshold: number = GPS_ACCURACY_THRESHOLD): boolean {
  return (
    typeof accuracy === 'number' &&
    !isNaN(accuracy) &&
    isFinite(accuracy) &&
    accuracy >= 0 &&
    accuracy <= threshold
  );
}

// Helper functions
function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

function toDegrees(radians: number): number {
  return radians * (180 / Math.PI);
}

/**
 * Get a point at specified distance and bearing from a center point
 * @param center Center coordinates
 * @param distance Distance in meters
 * @param bearing Bearing in degrees
 * @returns New coordinates
 */
function getPointAtDistance(center: Coordinates, distance: number, bearing: number): Coordinates {
  const bearingRad = toRadians(bearing);
  const lat1Rad = toRadians(center.lat);
  const lng1Rad = toRadians(center.lng);

  const lat2Rad = Math.asin(
    Math.sin(lat1Rad) * Math.cos(distance / EARTH_RADIUS) +
    Math.cos(lat1Rad) * Math.sin(distance / EARTH_RADIUS) * Math.cos(bearingRad),
  );

  const lng2Rad = lng1Rad + Math.atan2(
    Math.sin(bearingRad) * Math.sin(distance / EARTH_RADIUS) * Math.cos(lat1Rad),
    Math.cos(distance / EARTH_RADIUS) - Math.sin(lat1Rad) * Math.sin(lat2Rad),
  );

  return {
    lat: toDegrees(lat2Rad),
    lng: toDegrees(lng2Rad),
  };
}
