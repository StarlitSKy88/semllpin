import { Request, Response } from 'express';
import { BackendGeofencingService, GeofenceResult } from '../services/geofencing';
import { getDatabase } from '../config/database';
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

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    username: string;
    email: string;
    role: string;
  };
}

export class GeofencingController {
  private geofencingService: BackendGeofencingService;

  constructor() {
    const pool = getDatabase();
    this.geofencingService = new BackendGeofencingService(pool);
  }

  /**
   * Initialize geofencing tables
   */
  public initializeTables = async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('Initializing geofencing tables...');
      const success = await this.geofencingService.initializeGeofencingTables();

      if (success) {
        res.status(200).json({
          success: true,
          message: 'Geofencing tables initialized successfully',
          timestamp: new Date().toISOString()
        });
      } else {
        res.status(500).json({
          error: 'Initialization failed',
          message: 'Failed to initialize geofencing tables',
          timestamp: new Date().toISOString()
        });
      }

    } catch (error) {
      console.error('Initialize geofencing tables error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to initialize geofencing tables: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Check if user is within geofence of a specific annotation
   */
  public checkAnnotationGeofence = async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('Checking annotation geofence with data:', req.body);
      const validatedData = checkGeofenceSchema.parse(req.body);

      const result: GeofenceResult = await this.geofencingService.checkGeofence({
        user_location: validatedData.user_location,
        annotation_id: validatedData.annotation_id,
        custom_radius: validatedData.custom_radius
      });

      console.log('Geofence check result:', result);

      res.status(200).json({
        success: true,
        data: result,
        message: result.is_within_geofence 
          ? `User is within ${result.reward_radius}m geofence (${result.distance_meters.toFixed(1)}m away)`
          : `User is outside geofence (${result.distance_meters.toFixed(1)}m away, ${result.reward_radius}m required)`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Check annotation geofence error:', error);
      
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
        return;
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to check geofence: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Batch check multiple annotations for geofencing
   */
  public checkBatchGeofences = async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('Checking batch geofences with data:', req.body);
      const validatedData = batchGeofenceSchema.parse(req.body);

      const results: GeofenceResult[] = await this.geofencingService.checkMultipleGeofences({
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

      console.log(`Batch geofence check completed: ${results.length} results, ${withinGeofence.length} within geofence`);

      res.status(200).json({
        success: true,
        data: results,
        summary: {
          total_checked: validatedData.annotation_ids.length,
          results_returned: results.length,
          within_geofence: withinGeofence.length,
          reward_eligible: rewardEligible.length,
          average_distance_meters: Math.round(averageDistance * 100) / 100
        },
        message: `Checked ${results.length} annotations, ${withinGeofence.length} within geofence`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Check batch geofences error:', error);
      
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
        return;
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to check batch geofences: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Find all nearby annotations within a radius
   */
  public findNearbyAnnotations = async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('Finding nearby annotations with data:', req.body);
      const validatedData = nearbyAnnotationsSchema.parse(req.body);

      const results: GeofenceResult[] = await this.geofencingService.findNearbyAnnotations({
        user_location: validatedData.user_location,
        search_radius: validatedData.search_radius,
        limit: validatedData.limit,
        annotation_types: validatedData.annotation_types
      });

      // Group results by reward eligibility
      const rewardEligible = results.filter(r => r.reward_eligible);
      const nearbyOnly = results.filter(r => !r.reward_eligible);

      console.log(`Found ${results.length} nearby annotations, ${rewardEligible.length} eligible for rewards`);

      res.status(200).json({
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
        message: `Found ${results.length} annotations within ${validatedData.search_radius}m, ${rewardEligible.length} eligible for rewards`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Find nearby annotations error:', error);
      
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
        return;
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to find nearby annotations: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Configure geofence radius for an annotation
   */
  public configureAnnotationRadius = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      console.log('Configuring annotation radius with data:', req.body);
      const validatedData = configureRadiusSchema.parse(req.body);

      const configuration = await this.geofencingService.configureGeofenceRadius({
        annotation_id: validatedData.annotation_id,
        reward_radius: validatedData.reward_radius,
        annotation_type: validatedData.annotation_type,
        created_by: req.user.id
      });

      console.log(`Configured geofence radius: ${validatedData.reward_radius}m for annotation ${validatedData.annotation_id}`);

      res.status(200).json({
        success: true,
        data: configuration,
        message: `Geofence radius configured to ${validatedData.reward_radius}m for annotation ${validatedData.annotation_id}`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Configure annotation radius error:', error);
      
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
        return;
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to configure geofence radius: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Get geofencing service statistics and health check
   */
  public getGeofencingStats = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      console.log('Getting geofencing statistics...');
      const cacheStats = this.geofencingService.getCacheStats();

      // Get database statistics
      const pool = getDatabase();
      const client = await pool.connect();
      
      try {
        const configStatsResult = await client.query(`
          SELECT 
            COUNT(*) as total_configs,
            AVG(reward_radius) as avg_radius,
            MIN(reward_radius) as min_radius,
            MAX(reward_radius) as max_radius
          FROM geofence_configs
        `);

        const annotationStatsResult = await client.query(`
          SELECT 
            COUNT(*) as total_annotations,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_annotations
          FROM annotations
          WHERE location IS NOT NULL
        `);

        res.status(200).json({
          success: true,
          data: {
            cache: cacheStats,
            configurations: configStatsResult.rows[0] || {
              total_configs: 0,
              avg_radius: 0,
              min_radius: 0,
              max_radius: 0
            },
            annotations: annotationStatsResult.rows[0] || {
              total_annotations: 0,
              active_annotations: 0
            },
            service_status: 'healthy',
            timestamp: new Date().toISOString()
          },
          message: 'Geofencing service statistics retrieved successfully',
          timestamp: new Date().toISOString()
        });

      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Get geofencing stats error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to get geofencing statistics: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Clear geofencing cache (admin only)
   */
  public clearGeofencingCache = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.user || req.user.role !== 'admin') {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Admin access required',
          timestamp: new Date().toISOString()
        });
        return;
      }

      console.log('Clearing geofencing cache...');
      const beforeStats = this.geofencingService.getCacheStats();
      
      this.geofencingService.clearCache();
      
      const afterStats = this.geofencingService.getCacheStats();

      console.log(`Cleared ${beforeStats.size} cache entries`);

      res.status(200).json({
        success: true,
        data: {
          before: beforeStats,
          after: afterStats,
          cleared_entries: beforeStats.size
        },
        message: `Cleared ${beforeStats.size} cache entries`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Clear geofencing cache error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to clear geofencing cache: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Health check endpoint for geofencing service
   */
  public healthCheck = async (req: Request, res: Response): Promise<void> => {
    try {
      const cacheStats = this.geofencingService.getCacheStats();
      
      res.status(200).json({
        success: true,
        data: {
          service: 'geofencing',
          status: 'healthy',
          cache_size: cacheStats.size,
          algorithms: ['haversine', 'vincenty'],
          features: ['postgis_fallback', 'batch_processing', 'configurable_radius'],
          timestamp: new Date().toISOString()
        },
        message: 'Geofencing service is healthy',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Geofencing health check error:', error);
      res.status(500).json({
        error: 'Service Unhealthy',
        message: `Geofencing service health check failed: ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
  };
}