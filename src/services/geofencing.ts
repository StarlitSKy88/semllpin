import { Pool, PoolClient } from 'pg';
import { z } from 'zod';

// Validation schemas
const coordinatesSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180)
});

const geofenceCheckSchema = z.object({
  user_location: coordinatesSchema,
  annotation_id: z.string().uuid(),
  custom_radius: z.number().min(50).max(1000).optional()
});

const radiusConfigSchema = z.object({
  annotation_id: z.string().uuid(),
  reward_radius: z.number().min(50).max(1000),
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
 */
export function calculateHaversineDistance(
  lat1: number, 
  lon1: number, 
  lat2: number, 
  lon2: number
): number {
  const lat1Rad = (lat1 * Math.PI) / 180;
  const lon1Rad = (lon1 * Math.PI) / 180;
  const lat2Rad = (lat2 * Math.PI) / 180;
  const lon2Rad = (lon2 * Math.PI) / 180;

  const deltaLat = lat2Rad - lat1Rad;
  const deltaLon = lon2Rad - lon1Rad;

  const a = 
    Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) * 
    Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distanceMeters = EARTH_RADIUS_M * c;
  
  return Math.round(distanceMeters * 100) / 100;
}

/**
 * Advanced Vincenty's formula for higher precision distance calculation
 */
export function calculateVincentyDistance(
  lat1: number, 
  lon1: number, 
  lat2: number, 
  lon2: number
): number {
  const a = 6378137;
  const b = 6356752.314245;
  const f = 1 / 298.257223563;

  const L = ((lon2 - lon1) * Math.PI) / 180;
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

    if (sinSigma === 0) return 0;

    cosSigma = sinU1 * sinU2 + cosU1 * cosU2 * cosLambda;
    sigma = Math.atan2(sinSigma, cosSigma);

    const sinAlpha = (cosU1 * cosU2 * sinLambda) / sinSigma;
    cosSqAlpha = 1 - sinAlpha * sinAlpha;
    cos2SigmaM = cosSigma - (2 * sinU1 * sinU2) / cosSqAlpha;

    if (isNaN(cos2SigmaM)) cos2SigmaM = 0;

    const C = (f / 16) * cosSqAlpha * (4 + f * (4 - 3 * cosSqAlpha));
    lambdaP = lambda;
    lambda = L + (1 - C) * f * sinAlpha *
      (sigma + C * sinSigma * (cos2SigmaM + C * cosSigma * (-1 + 2 * cos2SigmaM * cos2SigmaM)));
  } while (Math.abs(lambda - lambdaP) > 1e-12 && --iterLimit > 0);

  if (iterLimit === 0) {
    return calculateHaversineDistance(lat1, lon1, lat2, lon2);
  }

  const uSq = (cosSqAlpha * (a * a - b * b)) / (b * b);
  const A = 1 + (uSq / 16384) * (4096 + uSq * (-768 + uSq * (320 - 175 * uSq)));
  const B = (uSq / 1024) * (256 + uSq * (-128 + uSq * (74 - 47 * uSq)));
  const deltaSigma = B * sinSigma * (cos2SigmaM + (B / 4) * (cosSigma * (-1 + 2 * cos2SigmaM * cos2SigmaM) -
    (B / 6) * cos2SigmaM * (-3 + 4 * sinSigma * sinSigma) * (-3 + 4 * cos2SigmaM * cos2SigmaM)));

  const s = b * A * (sigma - deltaSigma);
  
  return Math.round(s * 100) / 100;
}

export class BackendGeofencingService {
  private pool: Pool;
  
  // Cache for annotation locations and configurations
  private locationCache = new Map<string, {
    location: { latitude: number; longitude: number };
    radius: number;
    type: string;
    cached_at: number;
  }>();
  
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /**
   * Check if user is within geofence of an annotation with timeout protection
   */
  async checkGeofence(params: {
    user_location: { latitude: number; longitude: number };
    annotation_id: string;
    custom_radius?: number;
    timeout?: number;
  }): Promise<GeofenceResult> {
    const timeout = params.timeout || 5000; // 5秒默认超时
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Geofence check timeout after ${timeout}ms`));
      }, timeout);
    });

    return Promise.race([
      this._performGeofenceCheck(params),
      timeoutPromise
    ]);
  }

  private async _performGeofenceCheck(params: {
    user_location: { latitude: number; longitude: number };
    annotation_id: string;
    custom_radius?: number;
  }): Promise<GeofenceResult> {
    const client = await this.pool.connect();
    
    try {
      const validatedParams = geofenceCheckSchema.parse(params);
      
      const annotationData = await this.getAnnotationLocationAndConfig(
        validatedParams.annotation_id, 
        client
      );
      
      if (!annotationData) {
        throw new Error(`Annotation not found: ${validatedParams.annotation_id}`);
      }

      const { location, radius: configuredRadius, type } = annotationData;
      const effectiveRadius = validatedParams.custom_radius || configuredRadius;

      // Use more efficient Haversine for initial distance check
      const roughDistance = calculateHaversineDistance(
        validatedParams.user_location.latitude,
        validatedParams.user_location.longitude,
        location.latitude,
        location.longitude
      );

      // Only use precise Vincenty if roughly within range
      let distance = roughDistance;
      if (Math.abs(roughDistance - effectiveRadius) < 50) {
        distance = calculateVincentyDistance(
          validatedParams.user_location.latitude,
          validatedParams.user_location.longitude,
          location.latitude,
          location.longitude
        );
      }

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
      console.error('Backend geofence check error:', error);
      throw new Error(`Failed to check geofence: ${(error as Error).message}`);
    } finally {
      client.release();
    }
  }

  /**
   * Batch check multiple annotations for geofencing
   */
  async checkMultipleGeofences(params: {
    user_location: { latitude: number; longitude: number };
    annotation_ids: string[];
    max_distance?: number;
  }): Promise<GeofenceResult[]> {
    const client = await this.pool.connect();
    
    try {
      const { user_location, annotation_ids, max_distance = 2000 } = params;
      
      coordinatesSchema.parse(user_location);
      
      if (annotation_ids.length === 0) {
        return [];
      }

      const annotationDataMap = new Map<string, any>();
      
      for (const annotationId of annotation_ids) {
        const data = await this.getAnnotationLocationAndConfig(annotationId, client);
        if (data) {
          annotationDataMap.set(annotationId, data);
        }
      }

      const results: GeofenceResult[] = [];
      
      for (const [annotationId, annotationData] of annotationDataMap) {
        const { location, radius, type } = annotationData;
        
        const roughDistance = calculateHaversineDistance(
          user_location.latitude,
          user_location.longitude,
          location.latitude,
          location.longitude
        );

        if (roughDistance > max_distance) {
          continue;
        }

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

      results.sort((a, b) => a.distance_meters - b.distance_meters);
      return results;

    } catch (error) {
      console.error('Backend multiple geofence check error:', error);
      throw new Error(`Failed to check multiple geofences: ${(error as Error).message}`);
    } finally {
      client.release();
    }
  }

  /**
   * Find all nearby annotations within a given radius using PostGIS
   */
  async findNearbyAnnotations(params: {
    user_location: { latitude: number; longitude: number };
    search_radius: number;
    limit?: number;
    annotation_types?: string[];
  }): Promise<GeofenceResult[]> {
    const client = await this.pool.connect();
    
    try {
      const { user_location, search_radius, limit = 50, annotation_types } = params;
      
      coordinatesSchema.parse(user_location);
      
      try {
        return await this.findNearbyAnnotationsPostGIS(params, client);
      } catch (error) {
        console.log('PostGIS not available, falling back to manual calculation');
        return await this.findNearbyAnnotationsFallback(params, client);
      }

    } catch (error) {
      console.error('Backend find nearby annotations error:', error);
      throw new Error(`Failed to find nearby annotations: ${(error as Error).message}`);
    } finally {
      client.release();
    }
  }

  /**
   * PostGIS-powered spatial query for high performance with timeout protection
   */
  private async findNearbyAnnotationsPostGIS(
    params: {
      user_location: { latitude: number; longitude: number };
      search_radius: number;
      limit?: number;
      annotation_types?: string[];
    },
    client: PoolClient
  ): Promise<GeofenceResult[]> {
    const { user_location, search_radius, limit = 50, annotation_types } = params;
    
    // Add spatial query timeout
    const queryTimeout = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`PostGIS spatial query timeout`));
      }, 8000); // 8秒空间查询超时
    });
    
    let typeFilter = '';
    let queryParams: any[] = [user_location.longitude, user_location.latitude, search_radius, Math.min(limit, 100)];
    
    if (annotation_types && annotation_types.length > 0) {
      typeFilter = `AND a.smell_category = ANY($5)`;
      queryParams.push(annotation_types);
    }

    // Optimized query with proper indexing hints
    const query = `
      SELECT 
        a.id,
        (a.location->>'latitude')::float as latitude,
        (a.location->>'longitude')::float as longitude,
        a.smell_intensity as annotation_type,
        COALESCE(gfc.reward_radius, $6) as reward_radius,
        ST_Distance(
          ST_Point($1, $2)::geography,
          ST_Point((a.location->>'longitude')::float, (a.location->>'latitude')::float)::geography
        ) as distance_meters
      FROM annotations a
      LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
      WHERE a.status = 'active'
        ${typeFilter}
        AND ST_DWithin(
          ST_Point($1, $2)::geography,
          ST_Point((a.location->>'longitude')::float, (a.location->>'latitude')::float)::geography,
          $3
        )
      ORDER BY distance_meters
      LIMIT $4
    `;

    queryParams.push(DEFAULT_REWARD_RADIUS.standard);

    const queryPromise = client.query(query, queryParams);
    const result = await Promise.race([queryPromise, queryTimeout]);

    return result.rows.map(row => ({
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
   * Fallback method using manual calculations
   */
  private async findNearbyAnnotationsFallback(
    params: {
      user_location: { latitude: number; longitude: number };
      search_radius: number;
      limit?: number;
      annotation_types?: string[];
    },
    client: PoolClient
  ): Promise<GeofenceResult[]> {
    const { user_location, search_radius, limit = 50, annotation_types } = params;

    const radius_deg = search_radius / 111320;
    
    let typeFilter = '';
    let queryParams: any[] = [
      user_location.latitude - radius_deg,
      user_location.latitude + radius_deg,
      user_location.longitude - radius_deg,
      user_location.longitude + radius_deg,
      limit * 2,
      DEFAULT_REWARD_RADIUS.standard
    ];
    
    if (annotation_types && annotation_types.length > 0) {
      typeFilter = `AND a.smell_category = ANY($7)`;
      queryParams.push(annotation_types);
    }

    const query = `
      SELECT 
        a.id,
        (a.location->>'latitude')::float as latitude,
        (a.location->>'longitude')::float as longitude,
        a.smell_category as annotation_type,
        COALESCE(gfc.reward_radius, $6) as reward_radius
      FROM annotations a
      LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
      WHERE a.status = 'active'
        AND a.visibility = 'public'
        ${typeFilter}
        AND (a.location->>'latitude')::float BETWEEN $1 AND $2
        AND (a.location->>'longitude')::float BETWEEN $3 AND $4
      LIMIT $5
    `;

    const result = await client.query(query, queryParams);

    const annotationsWithDistance = result.rows
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
    const client = await this.pool.connect();
    
    try {
      const validatedParams = radiusConfigSchema.parse(params);

      const existingQuery = `
        SELECT * FROM geofence_configs 
        WHERE annotation_id = $1
      `;
      const existingResult = await client.query(existingQuery, [validatedParams.annotation_id]);

      let result;
      if (existingResult.rows.length > 0) {
        const updateQuery = `
          UPDATE geofence_configs 
          SET reward_radius = $2,
              annotation_type = $3,
              updated_at = NOW()
          WHERE annotation_id = $1
          RETURNING *
        `;
        result = await client.query(updateQuery, [
          validatedParams.annotation_id,
          validatedParams.reward_radius,
          validatedParams.annotation_type || existingResult.rows[0].annotation_type
        ]);
      } else {
        const insertQuery = `
          INSERT INTO geofence_configs (annotation_id, reward_radius, annotation_type, created_by, created_at, updated_at)
          VALUES ($1, $2, $3, $4, NOW(), NOW())
          RETURNING *
        `;
        result = await client.query(insertQuery, [
          validatedParams.annotation_id,
          validatedParams.reward_radius,
          validatedParams.annotation_type || 'standard',
          validatedParams.created_by
        ]);
      }

      // Clear cache for this annotation
      this.locationCache.delete(validatedParams.annotation_id);

      return {
        annotation_id: result.rows[0].annotation_id,
        reward_radius: result.rows[0].reward_radius,
        annotation_type: result.rows[0].annotation_type,
        created_at: result.rows[0].created_at,
        updated_at: result.rows[0].updated_at
      };

    } catch (error) {
      console.error('Backend configure geofence radius error:', error);
      throw new Error(`Failed to configure geofence radius: ${(error as Error).message}`);
    } finally {
      client.release();
    }
  }

  /**
   * Get annotation location and configuration from database or cache with timeout protection
   */
  private async getAnnotationLocationAndConfig(
    annotationId: string, 
    client: PoolClient
  ): Promise<{
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

      // Add query timeout
      const queryTimeout = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Database query timeout for annotation ${annotationId}`));
        }, 3000); // 3秒数据库查询超时
      });

      const queryPromise = client.query(
        `
        SELECT 
          a.id,
          (a.location->>'latitude')::float as latitude,
          (a.location->>'longitude')::float as longitude,
          a.smell_category as annotation_type,
          COALESCE(gfc.reward_radius, $2) as reward_radius
        FROM annotations a
        LEFT JOIN geofence_configs gfc ON a.id = gfc.annotation_id
        WHERE a.id = $1 AND a.status = 'active'
        LIMIT 1
        `,
        [annotationId, DEFAULT_REWARD_RADIUS.standard]
      );

      const result = await Promise.race([queryPromise, queryTimeout]);

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];
      const data = {
        location: {
          latitude: parseFloat(row.latitude),
          longitude: parseFloat(row.longitude)
        },
        radius: parseFloat(row.reward_radius),
        type: row.annotation_type || 'standard'
      };

      // Cache the result with extended TTL for frequently accessed annotations
      this.locationCache.set(annotationId, {
        ...data,
        cached_at: Date.now()
      });

      return data;

    } catch (error) {
      console.error('Backend get annotation location error:', error);
      // Return cached data as fallback even if expired
      const cached = this.locationCache.get(annotationId);
      if (cached) {
        console.warn(`Using expired cache for annotation ${annotationId}`);
        return {
          location: cached.location,
          radius: cached.radius,
          type: cached.type
        };
      }
      return null;
    }
  }

  /**
   * Initialize geofencing tables if they don't exist
   */
  async initializeGeofencingTables(): Promise<boolean> {
    const client = await this.pool.connect();
    
    try {
      await client.query(`
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
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_geofence_configs_annotation_id 
        ON geofence_configs(annotation_id)
      `);

      // Try to enable PostGIS and create spatial index
      try {
        await client.query('CREATE EXTENSION IF NOT EXISTS postgis');
        
        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_annotations_location_gist 
          ON annotations USING GIST(
            ST_Point((location->>'longitude')::float, (location->>'latitude')::float)
          )
        `);
        
        console.log('Backend PostGIS spatial indexing enabled');
      } catch (error) {
        console.log('Backend PostGIS not available, using standard indexing');
      }

      console.log('Backend geofencing tables initialized successfully');
      return true;

    } catch (error) {
      console.error('Backend initialize geofencing tables error:', error);
      return false;
    } finally {
      client.release();
    }
  }

  /**
   * Clear location cache
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