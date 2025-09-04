/**
 * SmellPin LBS Reward System - New Advanced API Routes
 * Complete API endpoints for the enhanced LBS reward system
 */

import express, { Request, Response, NextFunction } from 'express';
import { body, query, param, validationResult } from 'express-validator';
import { authMiddleware } from '../middleware/auth';
import { logger } from '../utils/logger';
import { RedisService } from '../services/RedisService';
import { LBSMasterSystem } from '../services/lbs/LBSMasterSystem';

const router = express.Router();

// Initialize LBS Master System
let lbsSystem: LBSMasterSystem;

// Initialize LBS system
export const initializeLBSSystem = (redis: RedisService): void => {
  lbsSystem = new LBSMasterSystem(redis);
  
  // Initialize the system
  lbsSystem.initialize().catch(error => {
    logger.error('Failed to initialize LBS Master System', { error });
    process.exit(1);
  });

  logger.info('LBS Master System initialized and ready');
};

// Validation middleware
const validateCheckInRequest = [
  body('location.latitude')
    .isFloat({ min: -90, max: 90 })
    .withMessage('Latitude must be between -90 and 90'),
  body('location.longitude')
    .isFloat({ min: -180, max: 180 })
    .withMessage('Longitude must be between -180 and 180'),
  body('location.accuracy')
    .optional()
    .isFloat({ min: 0, max: 1000 })
    .withMessage('Accuracy must be between 0 and 1000 meters'),
  body('deviceInfo.userAgent')
    .notEmpty()
    .withMessage('User agent is required'),
  body('deviceInfo.platform')
    .notEmpty()
    .withMessage('Platform is required'),
  body('sessionData.duration')
    .isInt({ min: 1, max: 3600 })
    .withMessage('Session duration must be between 1 and 3600 seconds'),
  body('sessionData.interactionCount')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Interaction count must be at least 1'),
  body('sessionData.features')
    .isArray()
    .withMessage('Features must be an array'),
  (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request parameters',
          details: errors.array()
        },
        timestamp: new Date().toISOString()
      });
    }
    return next();
  }
];

const validateAnalyticsRequest = [
  query('timeRange.startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('timeRange.endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('location.latitude')
    .optional()
    .isFloat({ min: -90, max: 90 })
    .withMessage('Latitude must be between -90 and 90'),
  query('location.longitude')
    .optional()
    .isFloat({ min: -180, max: 180 })
    .withMessage('Longitude must be between -180 and 180'),
  query('location.radius')
    .optional()
    .isInt({ min: 1, max: 100000 })
    .withMessage('Radius must be between 1 and 100000 meters'),
  query('groupBy')
    .optional()
    .isIn(['hour', 'day', 'week', 'month'])
    .withMessage('GroupBy must be one of: hour, day, week, month'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Limit must be between 1 and 1000'),
  (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request parameters',
          details: errors.array()
        },
        timestamp: new Date().toISOString()
      });
    }
    return next();
  }
];

/**
 * @route   POST /api/v1/lbs-rewards/checkin
 * @desc    Process advanced location check-in with comprehensive reward calculation
 * @access  Private
 * @rateLimit 10 requests per minute
 */
router.post('/checkin', 
  authMiddleware,
  validateCheckInRequest,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      return await lbsSystem.processCheckIn(req, res, next);
    } catch (error) {
      logger.error('Advanced LBS check-in route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/status
 * @desc    Get comprehensive system health status
 * @access  Private (Admin only)
 */
router.get('/status',
  authMiddleware,
  async (req: Request, res: Response) => {
    try {
      // Check if user has admin privileges
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Admin access required'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      return await lbsSystem.getSystemStatus(req, res);
    } catch (error) {
      logger.error('Advanced LBS status route error', { error });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve system status'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/analytics/user
 * @desc    Get comprehensive user-specific analytics
 * @access  Private
 * @rateLimit 100 requests per hour
 */
router.get('/analytics/user',
  authMiddleware,
  validateAnalyticsRequest,
  async (req: Request, res: Response) => {
    try {
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      return await lbsSystem.getAnalytics(req, res);
    } catch (error) {
      logger.error('Advanced LBS analytics route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve analytics'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/analytics/location
 * @desc    Get location-specific analytics with comprehensive insights
 * @access  Private
 */
router.get('/analytics/location',
  authMiddleware,
  [
    query('latitude')
      .isFloat({ min: -90, max: 90 })
      .withMessage('Latitude must be between -90 and 90'),
    query('longitude')
      .isFloat({ min: -180, max: 180 })
      .withMessage('Longitude must be between -180 and 180'),
    query('radius')
      .optional()
      .isInt({ min: 10, max: 10000 })
      .withMessage('Radius must be between 10 and 10000 meters'),
    (req: Request, res: Response, next: NextFunction) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request parameters',
            details: errors.array()
          },
          timestamp: new Date().toISOString()
        });
      }
      return next();
    }
  ],
  async (req: Request, res: Response) => {
    try {
      const { latitude, longitude, radius } = req.query;
      
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      const location = {
        latitude: parseFloat(latitude as string),
        longitude: parseFloat(longitude as string)
      };

      const locationRadius = radius ? parseInt(radius as string) : 500;

      // Get location analytics using the advanced system
      const analytics = await lbsSystem['rewardEngine'].analytics.generateLocationAnalytics(
        location,
        locationRadius
      );

      return res.json({
        success: true,
        data: {
          location,
          radius: locationRadius,
          analytics
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Advanced location analytics route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve location analytics'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/user/history
 * @desc    Get comprehensive user reward history with analytics
 * @access  Private
 */
router.get('/user/history',
  authMiddleware,
  async (req: Request, res: Response) => {
    try {
      const userId = req.user!.id;
      
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      const history = await lbsSystem['rewardEngine'].distribution.getUserRewardHistory(userId);
      
      if (!history) {
        return res.json({
          success: true,
          data: {
            userId,
            totalEarned: 0,
            totalDistributions: 0,
            averageReward: 0,
            bestReward: 0,
            currentStreak: 0,
            longestStreak: 0,
            rewardsByLocation: {},
            rewardsByTimeOfDay: {},
            monthlyEarnings: [],
            levelProgress: {
              currentLevel: 1,
              currentXP: 0,
              nextLevelXP: 100,
              levelBenefits: []
            }
          },
          timestamp: new Date().toISOString()
        });
      }

      return res.json({
        success: true,
        data: history,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Advanced user history route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve user history'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/rewards/distribution/:id
 * @desc    Get detailed reward distribution status
 * @access  Private
 */
router.get('/rewards/distribution/:id',
  authMiddleware,
  param('id')
    .matches(/^dist_\d+_[a-z0-9]+$/)
    .withMessage('Invalid distribution ID format'),
  async (req: Request, res: Response) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid distribution ID',
            details: errors.array()
          },
          timestamp: new Date().toISOString()
        });
      }

      const distributionId = req.params['id'];
      
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      const distribution = await lbsSystem['rewardEngine'].distribution.getDistributionStatus(distributionId);
      
      if (!distribution) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'DISTRIBUTION_NOT_FOUND',
            message: 'Distribution not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Ensure user can only access their own distributions
      if (distribution.userId !== req.user!.id && req.user!.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Access denied'
          },
          timestamp: new Date().toISOString()
        });
      }

      return res.json({
        success: true,
        data: distribution,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Advanced distribution status route error', { 
        userId: req.user?.id,
        distributionId: req.params['id'],
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve distribution status'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   POST /api/v1/lbs-rewards/geofence
 * @desc    Create advanced geofence zone with multi-layer support
 * @access  Private (Admin only)
 */
router.post('/geofence',
  authMiddleware,
  [
    body('name')
      .notEmpty()
      .withMessage('Geofence name is required'),
    body('center.latitude')
      .isFloat({ min: -90, max: 90 })
      .withMessage('Center latitude must be between -90 and 90'),
    body('center.longitude')
      .isFloat({ min: -180, max: 180 })
      .withMessage('Center longitude must be between -180 and 180'),
    body('radius')
      .isInt({ min: 1, max: 50000 })
      .withMessage('Radius must be between 1 and 50000 meters'),
    body('shape')
      .isIn(['circle', 'polygon'])
      .withMessage('Shape must be either circle or polygon'),
    body('vertices')
      .optional()
      .isArray()
      .withMessage('Vertices must be an array'),
    (req: Request, res: Response, next: NextFunction) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request parameters',
            details: errors.array()
          },
          timestamp: new Date().toISOString()
        });
      }
      return next();
    }
  ],
  async (req: Request, res: Response) => {
    try {
      // Check if user has admin privileges
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Admin access required'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      const { name, center, radius, shape, vertices, metadata } = req.body;

      const geofenceId = await lbsSystem['geographicSystem'].geofencing.addGeofence({
        name,
        center,
        radius,
        shape,
        vertices,
        metadata,
        active: true
      });

      return res.status(201).json({
        success: true,
        data: {
          geofenceId,
          message: 'Advanced geofence created successfully'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Create advanced geofence route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to create geofence'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/test
 * @desc    Run comprehensive system tests (development/staging only)
 * @access  Private (Admin only)
 */
router.get('/test',
  authMiddleware,
  query('quick')
    .optional()
    .isBoolean()
    .withMessage('Quick parameter must be boolean'),
  async (req: Request, res: Response) => {
    try {
      // Check if user has admin privileges
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Admin access required'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Only allow in non-production environments
      if (process.env['NODE_ENV'] === 'production') {
        return res.status(404).json({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Testing endpoints not available in production'
          },
          timestamp: new Date().toISOString()
        });
      }

      return await lbsSystem.runTests(req, res);

    } catch (error) {
      logger.error('Advanced test route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to run tests'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/metrics
 * @desc    Get comprehensive system performance metrics
 * @access  Private (Admin only)
 */
router.get('/metrics',
  authMiddleware,
  async (req: Request, res: Response) => {
    try {
      // Check if user has admin privileges
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Admin access required'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      const [systemHealth, performanceMetrics] = await Promise.all([
        lbsSystem['healthMonitor'].performHealthCheck(),
        lbsSystem['rewardEngine'].getPerformanceMetrics()
      ]);

      return res.json({
        success: true,
        data: {
          systemHealth,
          performanceMetrics,
          optimizerMetrics: lbsSystem['optimizer'].getMetrics()
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Advanced metrics route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve metrics'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * @route   GET /api/v1/lbs-rewards/leaderboard
 * @desc    Get reward leaderboard with multiple categories
 * @access  Private
 */
router.get('/leaderboard',
  authMiddleware,
  [
    query('period')
      .optional()
      .isIn(['daily', 'weekly', 'monthly', 'all-time'])
      .withMessage('Period must be one of: daily, weekly, monthly, all-time'),
    query('category')
      .optional()
      .isIn(['total-rewards', 'streak', 'locations', 'level'])
      .withMessage('Category must be one of: total-rewards, streak, locations, level'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    (req: Request, res: Response, next: NextFunction) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request parameters',
            details: errors.array()
          },
          timestamp: new Date().toISOString()
        });
      }
      return next();
    }
  ],
  async (req: Request, res: Response) => {
    try {
      const { period = 'monthly', category = 'total-rewards', limit = 50 } = req.query;
      
      if (!lbsSystem) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Advanced LBS system is not initialized'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Get comprehensive analytics for leaderboard
      const analytics = await lbsSystem['rewardEngine'].analytics.generateAnalytics();
      
      // Mock leaderboard data - in production would be calculated from actual data
      const leaderboard = {
        period,
        category,
        entries: analytics.topEarningUsers.slice(0, parseInt(limit as string)).map((user, index) => ({
          rank: index + 1,
          userId: user.userId,
          username: `User${user.userId}`, // Would get from user service
          value: user.totalEarned,
          change: Math.floor(Math.random() * 10) - 5 // Mock change from previous period
        })),
        userRank: Math.floor(Math.random() * 100) + 1,
        userValue: Math.floor(Math.random() * 1000)
      };

      return res.json({
        success: true,
        data: leaderboard,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Leaderboard route error', { 
        userId: req.user?.id, 
        error 
      });
      
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to retrieve leaderboard'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
);

// Error handling middleware specifically for advanced LBS routes
router.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Advanced LBS route error', {
    path: req.path,
    method: req.method,
    userId: req.user?.id,
    error: error.message,
    stack: error.stack
  });

  res.status(500).json({
    success: false,
    error: {
      code: 'ADVANCED_LBS_SYSTEM_ERROR',
      message: 'Advanced LBS system encountered an error',
      requestId: req.id
    },
    timestamp: new Date().toISOString()
  });
});

export default router;
export { lbsSystem };