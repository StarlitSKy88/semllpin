import { NeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { z } from 'zod';

// Validation schemas
const coordinatesSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180)
});

const geofenceCheckSchema = z.object({
  user_location: coordinatesSchema,
  annotation_id: z.string().uuid(),
  custom_radius: z.number().min(50).max(1000).optional() // meters
});

const radiusConfigSchema = z.object({
  annotation_id: z.string().uuid(),
  reward_radius: z.number().min(50).max(1000), // meters
  annotation_type: z.string().optional(),
  created_by: z.string().uuid()
});

// Geographic constants
const EARTH_RADIUS_KM = 6371;
const EARTH_RADIUS_M = EARTH_RADIUS_KM * 1000;

// Default reward radius configuration
const DEFAULT_REWARD_RADIUS = {
  standard: 100, // meters
  premium: 200,  // meters
  event: 500,    // meters
  historical: 150 // meters
};

export interface GeofenceResult {
  is_within_geofence: boolean;
  distance_meters: number;
  reward_eligible: boolean;
  reward_radius: number;
  annotation: {
    id: string;
    location: {
      latitude: number;
      longitude: number;
    };
    reward_type?: string;
  };
}

export interface GeofenceConfiguration {
  annotation_id: string;
  reward_radius: number;
  annotation_type: string;
  created_at: string;
  updated_at: string;
}

/**
 * High-precision Haversine formula for calculating distance between two points on Earth
 * @param lat1 Latitude of first point (degrees)
 * @param lon1 Longitude of first point (degrees)
 * @param lat2 Latitude of second point (degrees)
 * @param lon2 Longitude of second point (degrees)
 * @returns Distance in meters
 */
export function calculateHaversineDistance(
  lat1: number, 
  lon1: number, 
  lat2: number, 
  lon2: number
): number {
  // Convert latitude and longitude from degrees to radians
  const lat1Rad = (lat1 * Math.PI) / 180;
  const lon1Rad = (lon1 * Math.PI) / 180;
  const lat2Rad = (lat2 * Math.PI) / 180;
  const lon2Rad = (lon2 * Math.PI) / 180;

  // Calculate differences
  const deltaLat = lat2Rad - lat1Rad;
  const deltaLon = lon2Rad - lon1Rad;

  // Haversine formula
  const a = 
    Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) * 
    Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  
  // Distance in meters
  const distanceMeters = EARTH_RADIUS_M * c;
  
  return Math.round(distanceMeters * 100) / 100; // Round to 2 decimal places
}

/**
 * Advanced Vincenty's formula for higher precision distance calculation
 * More accurate than Haversine for shorter distances
 * @param lat1 Latitude of first point (degrees)
 * @param lon1 Longitude of first point (degrees)
 * @param lat2 Latitude of second point (degrees)
 * @param lon2 Longitude of second point (degrees)
 * @returns Distance in meters
 */
export function calculateVincentyDistance(
  lat1: number, 
  lon1: number, 
  lat2: number, 
  lon2: number
): number {
  const a = 6378137; // WGS-84 semi-major axis (meters)
  const b = 6356752.314245; // WGS-84 semi-minor axis (meters)
  const f = 1 / 298.257223563; // WGS-84 flattening

  const L = ((lon2 - lon1) * Math.PI) / 180; // Difference in longitude
  const U1 = Math.atan((1 - f) * Math.tan((lat1 * Math.PI) / 180));
  const U2 = Math.atan((1 - f) * Math.tan((lat2 * Math.PI) / 180));

  const sinU1 = Math.sin(U1);
  const cosU1 = Math.cos(U1);
  const sinU2 = Math.sin(U2);
  const cosU2 = Math.cos(U2);

  let lambda = L;
  let lambdaP;
  let iterLimit = 100;
  let cosSqAlpha, sinSigma, cos2SigmaM, cosSigma, sigma;

  do {
    const sinLambda = Math.sin(lambda);
    const cosLambda = Math.cos(lambda);
    sinSigma = Math.sqrt(
      (cosU2 * sinLambda) * (cosU2 * sinLambda) +
      (cosU1 * sinU2 - sinU1 * cosU2 * cosLambda) *
      (cosU1 * sinU2 - sinU1 * cosU2 * cosLambda)
    );

    if (sinSigma === 0) return 0; // Co-incident points

    cosSigma = sinU1 * sinU2 + cosU1 * cosU2 * cosLambda;
    sigma = Math.atan2(sinSigma, cosSigma);

    const sinAlpha = (cosU1 * cosU2 * sinLambda) / sinSigma;
    cosSqAlpha = 1 - sinAlpha * sinAlpha;
    cos2SigmaM = cosSigma - (2 * sinU1 * sinU2) / cosSqAlpha;

    if (isNaN(cos2SigmaM)) cos2SigmaM = 0; // Equatorial line

    const C = (f / 16) * cosSqAlpha * (4 + f * (4 - 3 * cosSqAlpha));
    lambdaP = lambda;
    lambda = L + (1 - C) * f * sinAlpha *
      (sigma + C * sinSigma * (cos2SigmaM + C * cosSigma * (-1 + 2 * cos2SigmaM * cos2SigmaM)));
  } while (Math.abs(lambda - lambdaP) > 1e-12 && --iterLimit > 0);

  if (iterLimit === 0) {
    // Fallback to Haversine if Vincenty fails to converge
    return calculateHaversineDistance(lat1, lon1, lat2, lon2);
  }

  const uSq = (cosSqAlpha * (a * a - b * b)) / (b * b);
  const A = 1 + (uSq / 16384) * (4096 + uSq * (-768 + uSq * (320 - 175 * uSq)));
  const B = (uSq / 1024) * (256 + uSq * (-128 + uSq * (74 - 47 * uSq)));
  const deltaSigma = B * sinSigma * (cos2SigmaM + (B / 4) * (cosSigma * (-1 + 2 * cos2SigmaM * cos2SigmaM) -
    (B / 6) * cos2SigmaM * (-3 + 4 * sinSigma * sinSigma) * (-3 + 4 * cos2SigmaM * cos2SigmaM)));

  const s = b * A * (sigma - deltaSigma);
  
  return Math.round(s * 100) / 100; // Round to 2 decimal places
}

export class GeofencingService {
  private db: NeonDatabase;
  private env: Env;
  
  // Cache for annotation locations and configurations
  private locationCache = new Map<string, {
    location: { latitude: number; longitude: number };
    radius: number;
    type: string;
    cached_at: number;
  }>();
  
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  constructor(env: Env) {
    this.env = env;
    this.db = new NeonDatabase(env.DATABASE_URL);
  }

  /**
   * Check if user is within geofence of an annotation
   */
  async checkGeofence(params: {
    user_location: { latitude: number; longitude: number };
    annotation_id: string;
    custom_radius?: number;
  }): Promise<GeofenceResult> {
    try {
      // Validate input parameters
      const validatedParams = geofenceCheckSchema.parse(params);
      
      // Get annotation location and configuration
      const annotationData = await this.getAnnotationLocationAndConfig(validatedParams.annotation_id);
      
      if (!annotationData) {
        throw new Error(`Annotation not found: ${validatedParams.annotation_id}`);
      }

      const { location, radius: configuredRadius, type } = annotationData;
      const effectiveRadius = validatedParams.custom_radius || configuredRadius;

      // Calculate distance using Vincenty formula for higher precision
      const distance = calculateVincentyDistance(
        validatedParams.user_location.latitude,
        validatedParams.user_location.longitude,
        location.latitude,
        location.longitude
      );

      // Check if within geofence
      const isWithinGeofence = distance <= effectiveRadius;

      return {
        is_within_geofence: isWithinGeofence,
        distance_meters: distance,
        reward_eligible: isWithinGeofence,
        reward_radius: effectiveRadius,
        annotation: {
          id: validatedParams.annotation_id,
          location: location,
          reward_type: type
        }
      };

    } catch (error) {
      console.error('Geofence check error:', error);
      throw new Error(`Failed to check geofence: ${error.message}`);
    }
  }

  /**
   * Batch check multiple annotations for geofencing
   */
  async checkMultipleGeofences(params: {
    user_location: { latitude: number; longitude: number };
    annotation_ids: string[];
    max_distance?: number; // Filter annotations beyond this distance (meters)
  }): Promise<GeofenceResult[]> {
    try {
      const { user_location, annotation_ids, max_distance = 2000 } = params;
      
      // Validate user location
      coordinatesSchema.parse(user_location);
      
      if (annotation_ids.length === 0) {
        return [];
      }

      // Get all annotations data
      const annotationDataMap = new Map<string, any>();
      
      for (const annotationId of annotation_ids) {
        const data = await this.getAnnotationLocationAndConfig(annotationId);
        if (data) {
          annotationDataMap.set(annotationId, data);
        }
      }

      // Process all geofence checks
      const results: GeofenceResult[] = [];
      
      for (const [annotationId, annotationData] of annotationDataMap) {
        const { location, radius, type } = annotationData;
        
        // Quick distance check with Haversine (faster for filtering)
        const roughDistance = calculateHaversineDistance(
          user_location.latitude,
          user_location.longitude,
          location.latitude,
          location.longitude
        );

        // Skip if beyond max_distance
        if (roughDistance > max_distance) {
          continue;
        }

        // Precise distance calculation with Vincenty
        const preciseDistance = calculateVincentyDistance(
          user_location.latitude,
          user_location.longitude,
          location.latitude,
          location.longitude
        );

        const isWithinGeofence = preciseDistance <= radius;

        results.push({
          is_within_geofence: isWithinGeofence,
          distance_meters: preciseDistance,
          reward_eligible: isWithinGeofence,
          reward_radius: radius,
          annotation: {
            id: annotationId,
            location: location,
            reward_type: type
          }
        });
      }

      // Sort by distance (closest first)
      results.sort((a, b) => a.distance_meters - b.distance_meters);

      return results;

    } catch (error) {
      console.error('Multiple geofence check error:', error);
      throw new Error(`Failed to check multiple geofences: ${error.message}`);
    }
  }

  /**
   * Find all nearby annotations within a given radius using PostGIS if available
   */
  async findNearbyAnnotations(params: {
    user_location: { latitude: number; longitude: number };
    search_radius: number; // meters
    limit?: number;
    annotation_types?: string[];
  }): Promise<GeofenceResult[]> {
    try {
      const { user_location, search_radius, limit = 50, annotation_types } = params;
      
      coordinatesSchema.parse(user_location);
      
      // Try PostGIS spatial query first
      try {
        return await this.findNearbyAnnotationsPostGIS(params);
      } catch (error) {
        console.log('PostGIS not available, falling back to manual calculation');
        return await this.findNearbyAnnotationsFallback(params);
      }

    } catch (error) {
      console.error('Find nearby annotations error:', error);
      throw new Error(`Failed to find nearby annotations: ${error.message}`);
    }
  }

  /**
   * PostGIS-powered spatial query for high performance
   */
  private async findNearbyAnnotationsPostGIS(params: {
    user_location: { latitude: number; longitude: number };
    search_radius: number;
    limit?: number;
    annotation_types?: string[];
  }): Promise<GeofenceResult[]> {
    const { user_location, search_radius, limit = 50, annotation_types } = params;
    
    let typeFilter = '';
    if (annotation_types && annotation_types.length > 0) {
      const typeList = annotation_types.map(t => `'${t}'`).join(', ');
      typeFilter = `AND a.smell_category IN (${typeList})`;
    }

    // PostGIS spatial query with ST_DWithin for optimal performance
    const result = await this.db.sql`
      SELECT 
        a.id,
        a.location->>'latitude' as latitude,
        a.location->>'longitude' as longitude,
        a.smell_category as annotation_type,
        COALESCE(gfc.reward_radius, ${DEFAULT_REWARD_RADIUS.standard}) as reward_radius,
        ST_Distance(
          ST_Point(${user_location.longitude}, ${user_location.latitude})::geography,
          ST_Point((a.location->>'longitude')::float, (a.location->>'latitude')::float)::geography
        ) as distance_meters
      FROM annotations a
      LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
      WHERE a.status = 'active'
        AND a.visibility = 'public'
        ${typeFilter}
        AND ST_DWithin(
          ST_Point(${user_location.longitude}, ${user_location.latitude})::geography,
          ST_Point((a.location->>'longitude')::float, (a.location->>'latitude')::float)::geography,
          ${search_radius}
        )
      ORDER BY distance_meters
      LIMIT ${limit}
    `;

    return result.map(row => ({
      is_within_geofence: parseFloat(row.distance_meters) <= parseFloat(row.reward_radius),
      distance_meters: parseFloat(row.distance_meters),
      reward_eligible: parseFloat(row.distance_meters) <= parseFloat(row.reward_radius),
      reward_radius: parseFloat(row.reward_radius),
      annotation: {
        id: row.id,
        location: {
          latitude: parseFloat(row.latitude),
          longitude: parseFloat(row.longitude)
        },
        reward_type: row.annotation_type
      }
    }));
  }

  /**
   * Fallback method using manual Haversine calculations
   */
  private async findNearbyAnnotationsFallback(params: {
    user_location: { latitude: number; longitude: number };
    search_radius: number;
    limit?: number;
    annotation_types?: string[];
  }): Promise<GeofenceResult[]> {
    const { user_location, search_radius, limit = 50, annotation_types } = params;

    // Get annotations with basic filtering
    const radius_deg = search_radius / 111320; // Convert meters to approximate degrees
    
    let typeFilter = '';
    if (annotation_types && annotation_types.length > 0) {
      const typeList = annotation_types.map(t => `'${t}'`).join(', ');
      typeFilter = `AND a.smell_category IN (${typeList})`;
    }

    const result = await this.db.sql`
      SELECT 
        a.id,
        a.location->>'latitude' as latitude,
        a.location->>'longitude' as longitude,
        a.smell_category as annotation_type,
        COALESCE(gfc.reward_radius, ${DEFAULT_REWARD_RADIUS.standard}) as reward_radius
      FROM annotations a
      LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
      WHERE a.status = 'active'
        AND a.visibility = 'public'
        ${typeFilter}
        AND (a.location->>'latitude')::float BETWEEN ${user_location.latitude - radius_deg} AND ${user_location.latitude + radius_deg}
        AND (a.location->>'longitude')::float BETWEEN ${user_location.longitude - radius_deg} AND ${user_location.longitude + radius_deg}
      LIMIT ${limit * 2}
    `;

    // Calculate precise distances and filter
    const annotationsWithDistance = result
      .map(row => {
        const annotationLat = parseFloat(row.latitude);
        const annotationLng = parseFloat(row.longitude);
        const distance = calculateVincentyDistance(
          user_location.latitude,
          user_location.longitude,
          annotationLat,
          annotationLng
        );

        return {
          is_within_geofence: distance <= parseFloat(row.reward_radius),
          distance_meters: distance,
          reward_eligible: distance <= parseFloat(row.reward_radius),
          reward_radius: parseFloat(row.reward_radius),
          annotation: {
            id: row.id,
            location: {
              latitude: annotationLat,
              longitude: annotationLng
            },
            reward_type: row.annotation_type
          }
        };
      })
      .filter(item => item.distance_meters <= search_radius)
      .sort((a, b) => a.distance_meters - b.distance_meters)
      .slice(0, limit);

    return annotationsWithDistance;
  }

  /**
   * Configure geofencing radius for an annotation
   */
  async configureGeofenceRadius(params: {
    annotation_id: string;
    reward_radius: number;
    annotation_type?: string;
    created_by: string;
  }): Promise<GeofenceConfiguration> {
    try {
      const validatedParams = radiusConfigSchema.parse(params);

      // Check if configuration exists
      const existingConfig = await this.db.sql`
        SELECT * FROM geofence_configs 
        WHERE annotation_id = ${validatedParams.annotation_id}
      `;

      let result;
      if (existingConfig.length > 0) {
        // Update existing configuration
        result = await this.db.sql`
          UPDATE geofence_configs 
          SET reward_radius = ${validatedParams.reward_radius},
              annotation_type = ${validatedParams.annotation_type || existingConfig[0].annotation_type},
              updated_at = NOW()
          WHERE annotation_id = ${validatedParams.annotation_id}
          RETURNING *
        `;
      } else {
        // Create new configuration
        result = await this.db.sql`
          INSERT INTO geofence_configs (annotation_id, reward_radius, annotation_type, created_by, created_at, updated_at)
          VALUES (${validatedParams.annotation_id}, ${validatedParams.reward_radius}, ${validatedParams.annotation_type || 'standard'}, ${validatedParams.created_by}, NOW(), NOW())
          RETURNING *
        `;
      }

      // Clear cache for this annotation
      this.locationCache.delete(validatedParams.annotation_id);

      return {
        annotation_id: result[0].annotation_id,
        reward_radius: result[0].reward_radius,
        annotation_type: result[0].annotation_type,
        created_at: result[0].created_at,
        updated_at: result[0].updated_at
      };

    } catch (error) {
      console.error('Configure geofence radius error:', error);
      throw new Error(`Failed to configure geofence radius: ${error.message}`);
    }
  }

  /**
   * Get annotation location and configuration from database or cache
   */
  private async getAnnotationLocationAndConfig(annotationId: string): Promise<{
    location: { latitude: number; longitude: number };
    radius: number;
    type: string;
  } | null> {
    try {
      // Check cache first
      const cached = this.locationCache.get(annotationId);
      if (cached && (Date.now() - cached.cached_at) < this.CACHE_TTL) {
        return {
          location: cached.location,
          radius: cached.radius,
          type: cached.type
        };
      }

      // Query database
      const result = await this.db.sql`
        SELECT 
          a.id,
          a.location->>'latitude' as latitude,
          a.location->>'longitude' as longitude,
          a.smell_category as annotation_type,
          COALESCE(gfc.reward_radius, ${DEFAULT_REWARD_RADIUS.standard}) as reward_radius
        FROM annotations a
        LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
        WHERE a.id = ${annotationId} AND a.status = 'active'
      `;

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      const data = {
        location: {
          latitude: parseFloat(row.latitude),
          longitude: parseFloat(row.longitude)
        },
        radius: parseFloat(row.reward_radius),
        type: row.annotation_type || 'standard'
      };

      // Cache the result
      this.locationCache.set(annotationId, {
        ...data,
        cached_at: Date.now()
      });

      return data;

    } catch (error) {
      console.error('Get annotation location error:', error);
      return null;
    }
  }

  /**
   * Initialize geofencing tables if they don't exist
   */
  async initializeGeofencingTables(): Promise<boolean> {
    try {
      // Create geofence configurations table
      await this.db.sql`
        CREATE TABLE IF NOT EXISTS geofence_configs (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
          reward_radius INTEGER NOT NULL DEFAULT ${DEFAULT_REWARD_RADIUS.standard},
          annotation_type VARCHAR(50) NOT NULL DEFAULT 'standard',
          created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          UNIQUE(annotation_id)
        )
      `;

      // Create index for performance
      await this.db.sql`
        CREATE INDEX IF NOT EXISTS idx_geofence_configs_annotation_id 
        ON geofence_configs(annotation_id)
      `;

      // Create spatial index on annotations if PostGIS is available
      try {
        await this.db.sql`CREATE EXTENSION IF NOT EXISTS postgis`;
        
        // Create spatial index for location queries
        await this.db.sql`
          CREATE INDEX IF NOT EXISTS idx_annotations_location_gist 
          ON annotations USING GIST(
            ST_Point((location->>'longitude')::float, (location->>'latitude')::float)
          )
        `;
        
        console.log('PostGIS spatial indexing enabled');
      } catch (error) {
        console.log('PostGIS not available, using standard indexing');
      }

      console.log('Geofencing tables initialized successfully');
      return true;

    } catch (error) {
      console.error('Initialize geofencing tables error:', error);
      return false;
    }
  }

  /**
   * Clear location cache (useful for testing or memory management)
   */
  clearCache(): void {
    this.locationCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; entries: string[] } {
    return {
      size: this.locationCache.size,
      entries: Array.from(this.locationCache.keys())
    };
  }
}

// Export utility functions for external use
export { calculateHaversineDistance, calculateVincentyDistance };