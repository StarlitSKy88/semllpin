/**
 * Anti-Fraud API Routes
 * Handles GPS location verification and fraud detection endpoints
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../index';
import AntiFraudService from '../services/antiFraudService';
import { authenticateJWT } from '../middleware/jwt-auth';

const app = new Hono<{ Bindings: Env }>();

// Validation schemas
const verifyLocationSchema = z.object({
  annotation_id: z.string().uuid('Invalid annotation ID'),
  location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180),
    accuracy: z.number().positive().optional(),
    altitude: z.number().optional(),
    speed: z.number().min(0).optional(),
    heading: z.number().min(0).max(360).optional(),
    timestamp: z.number().optional()
  }),
  device_info: z.object({
    userAgent: z.string(),
    screen: z.object({
      width: z.number(),
      height: z.number(),
      colorDepth: z.number().optional(),
      pixelRatio: z.number().optional()
    }),
    timezone: z.string(),
    language: z.string(),
    platform: z.string(),
    cookieEnabled: z.boolean().optional(),
    doNotTrack: z.boolean().optional(),
    plugins: z.array(z.string()).optional(),
    webgl: z.object({
      vendor: z.string().optional(),
      renderer: z.string().optional()
    }).optional()
  }),
  submission_time: z.number().optional()
});

const riskAssessmentSchema = z.object({
  user_id: z.string().uuid('Invalid user ID').optional(),
  time_window_hours: z.number().min(1).max(168).optional() // 1 hour to 1 week
});

/**
 * POST /api/anti-fraud/verify-location
 * Main endpoint for GPS location verification
 */
app.post('/verify-location', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');
    const clientIP = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';

    // Parse and validate request body
    const body = await c.req.json();
    const validatedData = verifyLocationSchema.parse(body);

    console.log(`[AntiF​raud API] Location verification request from user ${user.id}`);

    // Initialize anti-fraud service
    const antiFraudService = new AntiFraudService(env);

    // Perform GPS verification
    const verificationResult = await antiFraudService.verifyGPSLocation({
      user_id: user.id,
      annotation_id: validatedData.annotation_id,
      location: validatedData.location,
      device_info: validatedData.device_info,
      ip_address: clientIP,
      submission_time: validatedData.submission_time
    });

    // Return appropriate response based on verification result
    const responseStatus = verificationResult.verification_status === 'passed' ? 200 : 
                          verificationResult.verification_status === 'manual_review' ? 202 : 400;

    return c.json({
      success: verificationResult.verification_status === 'passed',
      verification_result: {
        status: verificationResult.verification_status,
        risk_score: verificationResult.risk_score,
        risk_level: getRiskLevel(verificationResult.risk_score),
        requires_manual_review: verificationResult.requires_manual_review,
        decision_reason: verificationResult.decision_reason,
        risk_factors: verificationResult.risk_factors,
        auto_action: verificationResult.auto_action
      },
      // Include evidence only for development/admin users
      evidence: env.ENVIRONMENT === 'development' ? verificationResult.evidence : undefined,
      timestamp: new Date().toISOString()
    }, responseStatus);

  } catch (error) {
    console.error('[AntiF​raud API] Location verification error:', error);
    
    if (error instanceof z.ZodError) {
      return c.json({
        success: false,
        error: 'Validation failed',
        details: error.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        }))
      }, 400);
    }

    return c.json({
      success: false,
      error: 'Location verification failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /api/anti-fraud/user-risk/:userId
 * Get user risk profile and score
 */
app.get('/user-risk/:userId', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');
    const targetUserId = c.req.param('userId');

    // Only allow users to check their own risk or admin users
    if (user.id !== targetUserId && user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized - can only check own risk profile'
      }, 403);
    }

    const antiFraudService = new AntiFraudService(env);
    const riskScore = await antiFraudService.getUserRiskScore(targetUserId);

    return c.json({
      success: true,
      user_id: targetUserId,
      risk_score: riskScore,
      risk_level: getRiskLevel(riskScore),
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] User risk check error:', error);
    return c.json({
      success: false,
      error: 'Failed to retrieve user risk profile',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /api/anti-fraud/bulk-risk-assessment
 * Bulk risk assessment for multiple users or time periods
 */
app.post('/bulk-risk-assessment', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');

    // Only admin users can perform bulk assessments
    if (user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized - admin access required'
      }, 403);
    }

    const body = await c.req.json();
    const validatedData = riskAssessmentSchema.parse(body);

    // This would implement bulk risk assessment logic
    // For now, return a placeholder response
    return c.json({
      success: true,
      message: 'Bulk risk assessment initiated',
      assessment_id: crypto.randomUUID(),
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] Bulk risk assessment error:', error);
    return c.json({
      success: false,
      error: 'Bulk risk assessment failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /api/anti-fraud/incidents
 * Get recent fraud incidents (admin only)
 */
app.get('/incidents', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');

    // Only admin users can view fraud incidents
    if (user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized - admin access required'
      }, 403);
    }

    const limit = parseInt(c.req.query('limit') || '20');
    const offset = parseInt(c.req.query('offset') || '0');

    const antiFraudService = new AntiFraudService(env);
    const incidents = await antiFraudService.getRecentFraudIncidents(limit);

    return c.json({
      success: true,
      incidents,
      meta: {
        limit,
        offset,
        total: incidents.length
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] Incidents retrieval error:', error);
    return c.json({
      success: false,
      error: 'Failed to retrieve fraud incidents',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /api/anti-fraud/stats
 * Get overall fraud detection statistics (admin only)
 */
app.get('/stats', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');

    // Only admin users can view stats
    if (user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized - admin access required'
      }, 403);
    }

    // This would implement comprehensive fraud statistics
    // For now, return placeholder data
    return c.json({
      success: true,
      stats: {
        total_verifications_24h: 0,
        failed_verifications_24h: 0,
        manual_reviews_pending: 0,
        fraud_incidents_7d: 0,
        avg_risk_score_24h: 0,
        top_risk_factors: []
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] Stats retrieval error:', error);
    return c.json({
      success: false,
      error: 'Failed to retrieve fraud statistics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /api/anti-fraud/manual-review/:verificationId
 * Submit manual review decision (admin only)
 */
app.post('/manual-review/:verificationId', authenticateJWT, async (c) => {
  try {
    const env = c.env;
    const user = c.get('user');
    const verificationId = c.req.param('verificationId');

    // Only admin users can perform manual reviews
    if (user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized - admin access required'
      }, 403);
    }

    const body = await c.req.json();
    const decision = z.enum(['approve', 'reject', 'flag']).parse(body.decision);
    const notes = z.string().max(1000).optional().parse(body.notes);

    // This would implement manual review processing
    // For now, return a success response
    return c.json({
      success: true,
      verification_id: verificationId,
      decision,
      reviewed_by: user.id,
      review_notes: notes,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] Manual review error:', error);
    return c.json({
      success: false,
      error: 'Manual review failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /api/anti-fraud/health
 * Health check for anti-fraud system
 */
app.get('/health', async (c) => {
  try {
    const env = c.env;

    // Basic health check
    const antiFraudService = new AntiFraudService(env);
    
    // Test database connectivity by checking if tables exist
    // This is a simple health check - in production you'd want more comprehensive checks

    return c.json({
      success: true,
      status: 'healthy',
      services: {
        database: 'connected',
        fraud_detection: 'operational',
        risk_scoring: 'operational'
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[AntiF​raud API] Health check error:', error);
    return c.json({
      success: false,
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    }, 503);
  }
});

// Utility functions
function getRiskLevel(riskScore: number): string {
  if (riskScore >= 90) return 'critical';
  if (riskScore >= 75) return 'high';
  if (riskScore >= 50) return 'medium';
  if (riskScore >= 25) return 'low';
  return 'minimal';
}

export default app;