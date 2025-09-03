import { Router } from './utils/router';
import { corsHeaders, handleCORS, addCorsHeaders } from './middleware/cors';
import { rateLimitMiddleware } from './middleware/rateLimit';
import { authMiddleware, adminMiddleware } from './middleware/auth';
import { errorHandler } from './middleware/errorHandler';
import { createDatabaseClient, getDatabaseInfo } from './utils/database';

// Extend Request interface to include database client
declare global {
  interface Request {
    database?: any; // Unified database client
    user?: any;
  }
}

// Import route handlers
import { signUp, signIn, signOut, resetPassword, updatePassword } from './routes/auth';
import { signUp as neonSignUp, signIn as neonSignIn, getCurrentUser as neonGetCurrentUser } from './routes/neon-auth';
import { getCurrentUser, getUserById, updateProfile, updatePrivacySettings, toggleFollow, getFollowers, getFollowing } from './routes/users';
import { createAnnotation, getAnnotations, getAnnotationById, updateAnnotation, deleteAnnotation, toggleLike } from './routes/annotations';
import { createComment, getCommentsByAnnotation, updateComment, deleteComment } from './routes/comments';
import {
  createPayment,
  createPaymentTest,
  confirmPayment,
  refundPayment,
  getPaymentHistory,
  getPaymentStatus,
  createPaymentIntent,
  getWallet,
  transferFunds,
  getTransactionHistory,
  initPaymentTables
} from './routes/payments';
import { checkIn, getNearbyRewards, getCheckInHistory, getAreaLeaderboard, initializeLbsTables } from './routes/lbs';
import { getUploadUrl, uploadFile, deleteFile, getUserFiles, uploadMultipleFiles, getUserStorageStats } from './routes/upload';
import { geocode, reverseGeocode, getCacheStats, clearCache } from './routes/geocoding';
import { 
  initializeGeofencingTables, 
  checkAnnotationGeofence, 
  checkBatchGeofences, 
  findNearbyAnnotations, 
  configureAnnotationRadius, 
  getGeofencingStats, 
  clearGeofencingCache 
} from './routes/geofencing';
import antiFraudRoutes from './routes/anti-fraud';
import {
  initializeRewardTables,
  distributeReward,
  createRewardPool,
  getRewardPoolStatus,
  depositToRewardPool,
  withdrawFromRewardPool,
  getRewardHistory,
  getRewardStatistics,
  configureReward,
  getPoolAnalytics,
  getPoolOperationHistory,
  clearRewardCaches,
  getRewardSystemHealth
} from './routes/rewards';

export interface Env {
  // Database configuration
  DATABASE_URL?: string; // PostgreSQL connection string (Neon, etc.)
  JWT_SECRET?: string;
  STRIPE_SECRET_KEY?: string;
  FRONTEND_URL?: string;
  ENVIRONMENT?: string;
  CORS_ORIGINS: string;
  CORS_METHODS: string;
  CORS_HEADERS: string;
  RATE_LIMIT_REQUESTS: string;
  RATE_LIMIT_WINDOW: string;
  MAX_FILE_SIZE: string;
  ALLOWED_FILE_TYPES: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      // Handle simple health check first (before any initialization)
      const url = new URL(request.url);
      if (url.pathname === '/health' && request.method === 'GET') {
        const response = new Response(JSON.stringify({ 
          status: 'healthy', 
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          environment: env.ENVIRONMENT || 'development'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
        return addCorsHeaders(response, env);
      }

      // Handle CORS preflight requests
      if (request.method === 'OPTIONS') {
        return handleCORS(request, env);
      }

      // Initialize database client
      const database = createDatabaseClient(env);

      // Create router
      const router = new Router();

      // Apply global middleware
      router.use(rateLimitMiddleware);
      router.use((req, env, ctx, next) => {
        req.database = database;
        return next();
      });

      // Auth routes (public) - Using Neon database
      router.post('/auth/signup', neonSignUp);
      router.post('/auth/signin', neonSignIn);
      // Auth route aliases for compatibility
      router.post('/auth/register', neonSignUp);
      router.post('/auth/login', neonSignIn);
      router.post('/auth/signout', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await signOut(req, env, ctx, params);
        });
      });
      router.post('/auth/reset-password', resetPassword);
      router.post('/auth/update-password', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await updatePassword(req, env, ctx, params);
        });
      });

      // User routes
      router.get('/users/me', neonGetCurrentUser);
      router.get('/users/:id', getUserById);
      router.put('/users/profile', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await updateProfile(req, env, ctx, params);
        });
      });
      router.put('/users/privacy', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await updatePrivacySettings(req, env, ctx, params);
        });
      });
      router.post('/users/:id/follow', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await toggleFollow(req, env, ctx, params);
        });
      });
      router.get('/users/:id/followers', getFollowers);
      router.get('/users/:id/following', getFollowing);

      // Annotation routes
      router.post('/annotations', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await createAnnotation(req, env, ctx, params);
        });
      });
      router.get('/annotations', getAnnotations);
      router.get('/annotations/:id', getAnnotationById);
      router.put('/annotations/:id', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await updateAnnotation(req, env, ctx, params);
        });
      });
      router.delete('/annotations/:id', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await deleteAnnotation(req, env, ctx, params);
        });
      });
      router.post('/annotations/:id/like', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await toggleLike(req, env, ctx, params);
        });
      });
      
      // Comment routes
      router.post('/comments', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await createComment(req, env, ctx, params);
        });
      });
      router.get('/annotations/:annotation_id/comments', getCommentsByAnnotation);
      router.put('/comments/:id', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await updateComment(req, env, ctx, params);
        });
      });
      router.delete('/comments/:id', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await deleteComment(req, env, ctx, params);
        });
      });

      // Payment routes
      router.post('/payments/create', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await createPayment(req, env, ctx, params);
        });
      });
      
      // Test payment route without auth for debugging
      router.post('/payments/test-create', async (req, env, ctx, params) => {
        return await createPaymentTest(req, env, ctx, params);
      });
      
      // Initialize payment tables
      router.post('/payments/init-tables', async (req, env, ctx, params) => {
        return await initPaymentTables(req, env, ctx, params);
      });
      router.post('/payments/confirm', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await confirmPayment(req, env, ctx, params);
        });
      });
      router.post('/payments/refund', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await refundPayment(req, env, ctx, params);
        });
      });
      router.get('/payments/history', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getPaymentHistory(req, env, ctx, params);
        });
      });
      router.get('/payments/status/:id', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getPaymentStatus(req, env, ctx, params);
        });
      });
      
      // Legacy payment routes for backward compatibility
      router.post('/payments/intent', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await createPaymentIntent(req, env, ctx, params);
        });
      });
      router.get('/payments/wallet', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getWallet(req, env, ctx, params);
        });
      });
      router.post('/payments/transfer', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await transferFunds(req, env, ctx, params);
        });
      });
      router.get('/payments/transactions', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getTransactionHistory(req, env, ctx, params);
        });
      });
      // PayPal webhook endpoint removed - using PayPal instead of Stripe

      // LBS routes
      // Initialize LBS tables
      router.post('/lbs/init-tables', async (req, env, ctx, params) => {
        return await initializeLbsTables(req, env, ctx, params);
      });
      router.post('/lbs/checkin', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await checkIn(req, env, ctx, params);
        });
      });
      router.get('/lbs/nearby', getNearbyRewards);
      router.get('/lbs/history', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getCheckInHistory(req, env, ctx, params);
        });
      });
      router.get('/lbs/leaderboard', getAreaLeaderboard);

      // Upload routes
      router.get('/upload', async (req, env, ctx, params) => {
        return new Response(JSON.stringify({
          message: 'Upload endpoint is available',
          methods: ['POST'],
          endpoints: {
            'POST /upload': 'Upload single file',
            'POST /upload/multiple': 'Upload multiple files',
            'GET /upload/files': 'Get user files',
            'GET /upload/stats': 'Get storage stats',
            'GET /upload/url': 'Get upload URL'
          }
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      });
      router.get('/upload/url', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getUploadUrl(req, env, ctx, params);
        });
      });
      router.post('/upload', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await uploadFile(req, env, ctx, params);
        });
      });
      router.post('/upload/multiple', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await uploadMultipleFiles(req, env, ctx, params);
        });
      });
      router.delete('/upload/:bucket/:file_path', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await deleteFile(req, env, ctx, params);
        });
      });
      router.get('/upload/files', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getUserFiles(req, env, ctx, params);
        });
      });
      router.get('/upload/stats', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getUserStorageStats(req, env, ctx, params);
        });
      });

      // Geocoding routes
      router.post('/geocoding/geocode', geocode);
      router.post('/geocoding/reverse', reverseGeocode);
      router.get('/geocoding/cache/stats', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getCacheStats(req, env, ctx, params);
        });
      });
      router.delete('/geocoding/cache', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await clearCache(req, env, ctx, params);
        });
      });

      // Geofencing routes
      router.post('/geofencing/init-tables', initializeGeofencingTables);
      router.post('/geofencing/check', checkAnnotationGeofence);
      router.post('/geofencing/check-batch', checkBatchGeofences);
      router.post('/geofencing/nearby', findNearbyAnnotations);
      router.post('/geofencing/configure-radius', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await configureAnnotationRadius(req, env, ctx, params);
        });
      });
      router.get('/geofencing/stats', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getGeofencingStats(req, env, ctx, params);
        });
      });
      router.delete('/geofencing/cache', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await clearGeofencingCache(req, env, ctx, params);
        });
      });

      // Anti-Fraud routes - GPS location verification and fraud detection
      router.route('/anti-fraud/*', async (req, env, ctx, params) => {
        // Create a new request with the adjusted path for the subrouter
        const url = new URL(req.url);
        const adjustedPath = url.pathname.replace('/anti-fraud', '');
        url.pathname = adjustedPath;
        
        const adjustedRequest = new Request(url.toString(), {
          method: req.method,
          headers: req.headers,
          body: req.body
        });
        
        // Set environment context for the anti-fraud routes
        return await antiFraudRoutes.fetch(adjustedRequest, env, ctx);
      });

      // Reward system routes
      router.post('/admin/rewards/initialize', async (req, env, ctx, params) => {
        return await adminMiddleware(req, env, ctx, async () => {
          return await initializeRewardTables(req, env, ctx, params);
        });
      });
      
      router.post('/rewards/distribute', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await distributeReward(req, env, ctx, params);
        });
      });
      
      router.post('/rewards/pools', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await createRewardPool(req, env, ctx, params);
        });
      });
      
      router.get('/rewards/pools/status', getRewardPoolStatus);
      
      router.post('/rewards/pools/deposit', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await depositToRewardPool(req, env, ctx, params);
        });
      });
      
      router.post('/rewards/pools/withdraw', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await withdrawFromRewardPool(req, env, ctx, params);
        });
      });
      
      router.get('/rewards/history', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getRewardHistory(req, env, ctx, params);
        });
      });
      
      router.get('/rewards/statistics', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getRewardStatistics(req, env, ctx, params);
        });
      });
      
      router.post('/rewards/configure', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await configureReward(req, env, ctx, params);
        });
      });
      
      router.get('/rewards/pools/analytics', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getPoolAnalytics(req, env, ctx, params);
        });
      });
      
      router.get('/rewards/pools/operations', async (req, env, ctx, params) => {
        return await authMiddleware(req, env, ctx, async () => {
          return await getPoolOperationHistory(req, env, ctx, params);
        });
      });
      
      router.delete('/admin/rewards/cache', async (req, env, ctx, params) => {
        return await adminMiddleware(req, env, ctx, async () => {
          return await clearRewardCaches(req, env, ctx, params);
        });
      });
      
      router.get('/admin/rewards/health', async (req, env, ctx, params) => {
        return await adminMiddleware(req, env, ctx, async () => {
          return await getRewardSystemHealth(req, env, ctx, params);
        });
      });

      // Root endpoint
      router.get('/', async (req, env, ctx, params) => {
        return new Response(JSON.stringify({ 
          message: 'SmellPin Workers API',
          status: 'ok', 
          timestamp: new Date().toISOString(),
          version: '1.0.0'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      });

      // Health check endpoint (simplified, no middleware)
      router.get('/health', async (req, env, ctx, params) => {
        try {
          return new Response(JSON.stringify({ 
            status: 'healthy', 
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            environment: env.ENVIRONMENT || 'development'
          }), {
            headers: { 'Content-Type': 'application/json' }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            status: 'error',
            message: error.message,
            timestamp: new Date().toISOString()
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      });

      // Database info debug endpoint
      router.get('/api/debug/database-info', async (req, env, ctx, params) => {
        try {
          const database = createDatabaseClient(env);
          const dbInfo = getDatabaseInfo(env);
          
          return new Response(JSON.stringify({
            status: 'ok',
            timestamp: new Date().toISOString(),
            database: {
              type: 'PostgreSQL (Neon)',
              connection: 'Direct PostgreSQL',
              url_configured: !!env.DATABASE_URL,
              info: dbInfo
            }
          }), {
            headers: { 'Content-Type': 'application/json' }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            status: 'error',
            message: error.message,
            timestamp: new Date().toISOString(),
            database: {
              type: 'PostgreSQL (Neon)',
              connection: 'Failed to connect',
              url_configured: !!env.DATABASE_URL
            }
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      });

      // Handle the request
      const response = await router.handle(request, env, ctx);
      
      // Add CORS headers to response
      return addCorsHeaders(response, env);
    } catch (error) {
      // Use centralized error handler
      const errorResponse = errorHandler(error as Error, request, env);
      return addCorsHeaders(errorResponse, env);
    }
  },
};