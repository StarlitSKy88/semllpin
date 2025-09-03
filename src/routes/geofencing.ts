import { Router } from 'express';
import { GeofencingController } from '../controllers/geofencing';
import { authenticateToken, requireAuth } from '../middleware/auth';
import { requireAdmin } from '../middleware/adminAuth';
import { rateLimiter } from '../middleware/rateLimiter';
import { validateRequest } from '../middleware/validation';
import { z } from 'zod';

// Create router instance
const router = Router();
const geofencingController = new GeofencingController();

// Validation schemas for request validation middleware
const checkGeofenceSchema = z.object({
  body: z.object({
    user_location: z.object({
      latitude: z.number().min(-90).max(90),
      longitude: z.number().min(-180).max(180)
    }),
    annotation_id: z.string().uuid(),
    custom_radius: z.number().min(50).max(1000).optional()
  })
});

const batchGeofenceSchema = z.object({
  body: z.object({
    user_location: z.object({
      latitude: z.number().min(-90).max(90),
      longitude: z.number().min(-180).max(180)
    }),
    annotation_ids: z.array(z.string().uuid()).max(100),
    max_distance: z.number().min(100).max(5000).optional()
  })
});

const nearbyAnnotationsSchema = z.object({
  body: z.object({
    user_location: z.object({
      latitude: z.number().min(-90).max(90),
      longitude: z.number().min(-180).max(180)
    }),
    search_radius: z.number().min(50).max(2000),
    limit: z.number().min(1).max(100).optional(),
    annotation_types: z.array(z.string()).optional()
  })
});

const configureRadiusSchema = z.object({
  body: z.object({
    annotation_id: z.string().uuid(),
    reward_radius: z.number().min(50).max(1000),
    annotation_type: z.string().optional()
  })
});

/**
 * @route POST /api/geofencing/init-tables
 * @desc Initialize geofencing tables in the database
 * @access Public (for setup)
 */
router.post(
  '/init-tables',
  rateLimiter({ windowMs: 15 * 60 * 1000, max: 5 }), // 5 requests per 15 minutes
  geofencingController.initializeTables
);

/**
 * @route POST /api/geofencing/check
 * @desc Check if user is within geofence of a specific annotation
 * @access Public
 * @body { user_location: { latitude, longitude }, annotation_id, custom_radius? }
 */
router.post(
  '/check',
  rateLimiter({ windowMs: 1 * 60 * 1000, max: 100 }), // 100 requests per minute
  validateRequest(checkGeofenceSchema),
  geofencingController.checkAnnotationGeofence
);

/**
 * @route POST /api/geofencing/check-batch
 * @desc Batch check multiple annotations for geofencing
 * @access Public
 * @body { user_location: { latitude, longitude }, annotation_ids: [], max_distance? }
 */
router.post(
  '/check-batch',
  rateLimiter({ windowMs: 1 * 60 * 1000, max: 50 }), // 50 requests per minute (more intensive)
  validateRequest(batchGeofenceSchema),
  geofencingController.checkBatchGeofences
);

/**
 * @route POST /api/geofencing/nearby
 * @desc Find all nearby annotations within a radius
 * @access Public
 * @body { user_location: { latitude, longitude }, search_radius, limit?, annotation_types? }
 */
router.post(
  '/nearby',
  rateLimiter({ windowMs: 1 * 60 * 1000, max: 60 }), // 60 requests per minute
  validateRequest(nearbyAnnotationsSchema),
  geofencingController.findNearbyAnnotations
);

/**
 * @route POST /api/geofencing/configure-radius
 * @desc Configure geofence radius for an annotation
 * @access Private (authenticated users)
 * @body { annotation_id, reward_radius, annotation_type? }
 */
router.post(
  '/configure-radius',
  rateLimiter({ windowMs: 5 * 60 * 1000, max: 20 }), // 20 requests per 5 minutes
  authenticateToken,
  requireAuth,
  validateRequest(configureRadiusSchema),
  geofencingController.configureAnnotationRadius
);

/**
 * @route GET /api/geofencing/stats
 * @desc Get geofencing service statistics and health check
 * @access Private (authenticated users)
 */
router.get(
  '/stats',
  rateLimiter({ windowMs: 1 * 60 * 1000, max: 10 }), // 10 requests per minute
  authenticateToken,
  requireAuth,
  geofencingController.getGeofencingStats
);

/**
 * @route DELETE /api/geofencing/cache
 * @desc Clear geofencing cache (admin only)
 * @access Private (admin only)
 */
router.delete(
  '/cache',
  rateLimiter({ windowMs: 5 * 60 * 1000, max: 5 }), // 5 requests per 5 minutes
  authenticateToken,
  requireAuth,
  requireAdmin,
  geofencingController.clearGeofencingCache
);

/**
 * @route GET /api/geofencing/health
 * @desc Health check endpoint for geofencing service
 * @access Public
 */
router.get(
  '/health',
  rateLimiter({ windowMs: 1 * 60 * 1000, max: 30 }), // 30 requests per minute
  geofencingController.healthCheck
);

/**
 * @route GET /api/geofencing
 * @desc Get geofencing service information and available endpoints
 * @access Public
 */
router.get('/', (req, res) => {
  res.json({
    service: 'SmellPin Geofencing API',
    version: '1.0.0',
    description: 'Advanced geofencing system for LBS rewards with PostGIS integration',
    features: [
      'High-precision distance calculations (Haversine & Vincenty)',
      'PostGIS spatial queries with fallback support',
      'Configurable reward radius per annotation',
      'Batch processing for multiple annotations',
      'In-memory caching for performance optimization',
      'Real-time geofence detection',
      'Administrative monitoring and statistics'
    ],
    algorithms: {
      haversine: 'Fast spherical distance calculation for initial filtering',
      vincenty: 'High-precision ellipsoidal distance for reward eligibility'
    },
    endpoints: {
      'POST /init-tables': 'Initialize database tables',
      'POST /check': 'Check single annotation geofence',
      'POST /check-batch': 'Check multiple annotations geofence',
      'POST /nearby': 'Find nearby annotations within radius',
      'POST /configure-radius': 'Configure annotation reward radius (auth required)',
      'GET /stats': 'Get service statistics (auth required)',
      'DELETE /cache': 'Clear cache (admin only)',
      'GET /health': 'Service health check'
    },
    default_radius: {
      standard: 100,
      premium: 200,
      event: 500,
      historical: 150
    },
    limits: {
      max_radius: 1000, // meters
      min_radius: 50,   // meters
      max_batch_size: 100,
      max_search_radius: 2000 // meters
    },
    timestamp: new Date().toISOString()
  });
});

export default router;