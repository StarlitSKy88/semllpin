import { Router } from 'express';
import { GeofencingController } from '../controllers/geofencing';
import { authMiddleware, requireAdmin } from '../middleware/auth';
import { rateLimiter } from '../middleware/performance';
import { validateRequest } from '../middleware/validation';
import Joi from 'joi';

// Create router instance
const router = Router();
const geofencingController = new GeofencingController();

// Validation schemas for request validation middleware
const checkGeofenceSchema = {
  body: Joi.object({
    user_location: Joi.object({
      latitude: Joi.number().min(-90).max(90).required(),
      longitude: Joi.number().min(-180).max(180).required()
    }).required(),
    annotation_id: Joi.string().uuid().required(),
    custom_radius: Joi.number().min(50).max(1000).optional()
  })
};

const batchGeofenceSchema = {
  body: Joi.object({
    user_location: Joi.object({
      latitude: Joi.number().min(-90).max(90).required(),
      longitude: Joi.number().min(-180).max(180).required()
    }).required(),
    annotation_ids: Joi.array().items(Joi.string().uuid()).max(100).required(),
    max_distance: Joi.number().min(100).max(5000).optional()
  })
};

const nearbyAnnotationsSchema = {
  body: Joi.object({
    user_location: Joi.object({
      latitude: Joi.number().min(-90).max(90).required(),
      longitude: Joi.number().min(-180).max(180).required()
    }).required(),
    search_radius: Joi.number().min(50).max(2000).required(),
    limit: Joi.number().min(1).max(100).optional(),
    annotation_types: Joi.array().items(Joi.string()).optional()
  })
};

const configureRadiusSchema = {
  body: Joi.object({
    annotation_id: Joi.string().uuid().required(),
    reward_radius: Joi.number().min(50).max(1000).required(),
    annotation_type: Joi.string().optional()
  })
};

/**
 * @route POST /api/geofencing/init-tables
 * @desc Initialize geofencing tables in the database
 * @access Public (for setup)
 */
router.post(
  '/init-tables',
  rateLimiter(5, 15 * 60 * 1000), // 5 requests per 15 minutes
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
  rateLimiter(100, 1 * 60 * 1000), // 100 requests per minute
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
  rateLimiter(50, 1 * 60 * 1000), // 50 requests per minute (more intensive)
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
  rateLimiter(60, 1 * 60 * 1000), // 60 requests per minute
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
  rateLimiter(20, 5 * 60 * 1000), // 20 requests per 5 minutes
  authMiddleware,
  requireAdmin,
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
  rateLimiter(10, 1 * 60 * 1000), // 10 requests per minute
  authMiddleware,
  requireAdmin,
  geofencingController.getGeofencingStats
);

/**
 * @route DELETE /api/geofencing/cache
 * @desc Clear geofencing cache (admin only)
 * @access Private (admin only)
 */
router.delete(
  '/cache',
  rateLimiter(5, 5 * 60 * 1000), // 5 requests per 5 minutes
  authMiddleware,
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
  rateLimiter(30, 1 * 60 * 1000), // 30 requests per minute
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