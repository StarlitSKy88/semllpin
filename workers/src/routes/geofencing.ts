import { GeofencingService, GeofenceResult } from '../services/geofencing';
import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

// Validation schemas
const checkGeofenceSchema = z.object({
  user_location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180)
  }),
  annotation_id: z.string().uuid(),
  custom_radius: z.number().min(50).max(1000).optional()
});

const batchGeofenceSchema = z.object({
  user_location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180)
  }),
  annotation_ids: z.array(z.string().uuid()).max(100),
  max_distance: z.number().min(100).max(5000).optional()
});

const nearbyAnnotationsSchema = z.object({
  user_location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180)
  }),
  search_radius: z.number().min(50).max(2000),
  limit: z.number().min(1).max(100).optional(),
  annotation_types: z.array(z.string()).optional()
});

const configureRadiusSchema = z.object({
  annotation_id: z.string().uuid(),
  reward_radius: z.number().min(50).max(1000),
  annotation_type: z.string().optional()
});

/**
 * Initialize geofencing tables
 */
export const initializeGeofencingTables: RouteHandler = async (request, env) => {
  try {
    const geofencingService = new GeofencingService(env);
    const success = await geofencingService.initializeGeofencingTables();

    if (success) {
      return new Response(JSON.stringify({
        success: true,
        message: 'Geofencing tables initialized successfully'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({
        error: 'Initialization failed',
        message: 'Failed to initialize geofencing tables'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

  } catch (error) {
    console.error('Initialize geofencing tables error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to initialize geofencing tables: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Check if user is within geofence of a specific annotation
 */
export const checkAnnotationGeofence: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const validatedData = checkGeofenceSchema.parse(body);

    const geofencingService = new GeofencingService(env);
    const result: GeofenceResult = await geofencingService.checkGeofence({
      user_location: validatedData.user_location,
      annotation_id: validatedData.annotation_id,
      custom_radius: validatedData.custom_radius
    });

    return new Response(JSON.stringify({
      success: true,
      data: result,
      message: result.is_within_geofence 
        ? `User is within ${result.reward_radius}m geofence (${result.distance_meters.toFixed(1)}m away)`
        : `User is outside geofence (${result.distance_meters.toFixed(1)}m away, ${result.reward_radius}m required)`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Check annotation geofence error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to check geofence: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Batch check multiple annotations for geofencing
 */
export const checkBatchGeofences: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const validatedData = batchGeofenceSchema.parse(body);

    const geofencingService = new GeofencingService(env);
    const results: GeofenceResult[] = await geofencingService.checkMultipleGeofences({
      user_location: validatedData.user_location,
      annotation_ids: validatedData.annotation_ids,
      max_distance: validatedData.max_distance
    });

    // Calculate summary statistics
    const withinGeofence = results.filter(r => r.is_within_geofence);
    const rewardEligible = results.filter(r => r.reward_eligible);
    const averageDistance = results.length > 0 
      ? results.reduce((sum, r) => sum + r.distance_meters, 0) / results.length 
      : 0;

    return new Response(JSON.stringify({
      success: true,
      data: results,
      summary: {
        total_checked: validatedData.annotation_ids.length,
        results_returned: results.length,
        within_geofence: withinGeofence.length,
        reward_eligible: rewardEligible.length,
        average_distance_meters: Math.round(averageDistance * 100) / 100
      },
      message: `Checked ${results.length} annotations, ${withinGeofence.length} within geofence`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Check batch geofences error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to check batch geofences: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Find all nearby annotations within a radius
 */
export const findNearbyAnnotations: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const validatedData = nearbyAnnotationsSchema.parse(body);

    const geofencingService = new GeofencingService(env);
    const results: GeofenceResult[] = await geofencingService.findNearbyAnnotations({
      user_location: validatedData.user_location,
      search_radius: validatedData.search_radius,
      limit: validatedData.limit,
      annotation_types: validatedData.annotation_types
    });

    // Group results by reward eligibility
    const rewardEligible = results.filter(r => r.reward_eligible);
    const nearbyOnly = results.filter(r => !r.reward_eligible);

    return new Response(JSON.stringify({
      success: true,
      data: {
        reward_eligible: rewardEligible,
        nearby_annotations: nearbyOnly,
        all_results: results
      },
      summary: {
        total_found: results.length,
        reward_eligible: rewardEligible.length,
        nearby_only: nearbyOnly.length,
        search_radius_meters: validatedData.search_radius,
        closest_distance_meters: results.length > 0 ? results[0].distance_meters : null
      },
      message: `Found ${results.length} annotations within ${validatedData.search_radius}m, ${rewardEligible.length} eligible for rewards`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Find nearby annotations error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to find nearby annotations: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Configure geofence radius for an annotation
 */
export const configureAnnotationRadius: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const validatedData = configureRadiusSchema.parse(body);

    const geofencingService = new GeofencingService(env);
    const configuration = await geofencingService.configureGeofenceRadius({
      annotation_id: validatedData.annotation_id,
      reward_radius: validatedData.reward_radius,
      annotation_type: validatedData.annotation_type,
      created_by: user.id
    });

    return new Response(JSON.stringify({
      success: true,
      data: configuration,
      message: `Geofence radius configured to ${validatedData.reward_radius}m for annotation ${validatedData.annotation_id}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Configure annotation radius error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to configure geofence radius: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Get geofencing service statistics and health check
 */
export const getGeofencingStats: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const geofencingService = new GeofencingService(env);
    const cacheStats = geofencingService.getCacheStats();

    // Get database statistics
    const db = geofencingService['db']; // Access private property for stats
    
    const configStats = await db.sql`
      SELECT 
        COUNT(*) as total_configs,
        AVG(reward_radius) as avg_radius,
        MIN(reward_radius) as min_radius,
        MAX(reward_radius) as max_radius
      FROM geofence_configs
    `;

    const annotationStats = await db.sql`
      SELECT 
        COUNT(*) as total_annotations,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_annotations
      FROM annotations
      WHERE location IS NOT NULL
    `;

    return new Response(JSON.stringify({
      success: true,
      data: {
        cache: cacheStats,
        configurations: configStats[0] || {
          total_configs: 0,
          avg_radius: 0,
          min_radius: 0,
          max_radius: 0
        },
        annotations: annotationStats[0] || {
          total_annotations: 0,
          active_annotations: 0
        },
        service_status: 'healthy',
        timestamp: new Date().toISOString()
      },
      message: 'Geofencing service statistics retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get geofencing stats error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to get geofencing statistics: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

/**
 * Clear geofencing cache (admin only)
 */
export const clearGeofencingCache: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user || user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'Admin access required'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const geofencingService = new GeofencingService(env);
    const beforeStats = geofencingService.getCacheStats();
    
    geofencingService.clearCache();
    
    const afterStats = geofencingService.getCacheStats();

    return new Response(JSON.stringify({
      success: true,
      data: {
        before: beforeStats,
        after: afterStats,
        cleared_entries: beforeStats.size
      },
      message: `Cleared ${beforeStats.size} cache entries`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Clear geofencing cache error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: `Failed to clear geofencing cache: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};