import { Env } from '../index';
import { Middleware } from '../utils/router';

// Simple in-memory rate limiting (for production, consider using Durable Objects or external storage)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

export const rateLimitMiddleware: Middleware = async (request, env, ctx, next) => {
  try {
    const clientIP = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    'unknown';
    
    const maxRequests = parseInt(env.RATE_LIMIT_REQUESTS || '100');
    const windowMs = parseInt(env.RATE_LIMIT_WINDOW || '60') * 1000; // Convert to milliseconds
    
    const now = Date.now();
    const key = `rate_limit:${clientIP}`;
    
    // Get current rate limit data
    let rateLimitData = rateLimitStore.get(key);
    
    // Reset if window has expired
    if (!rateLimitData || now > rateLimitData.resetTime) {
      rateLimitData = {
        count: 0,
        resetTime: now + windowMs
      };
    }
    
    // Increment request count
    rateLimitData.count++;
    rateLimitStore.set(key, rateLimitData);
    
    // Check if rate limit exceeded
    if (rateLimitData.count > maxRequests) {
      const retryAfter = Math.ceil((rateLimitData.resetTime - now) / 1000);
      
      return new Response(JSON.stringify({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded',
        retryAfter
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': retryAfter.toString(),
          'X-RateLimit-Limit': maxRequests.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': rateLimitData.resetTime.toString()
        }
      });
    }
    
    // Add rate limit headers to response
    const response = await next();
    const remaining = Math.max(0, maxRequests - rateLimitData.count);
    
    // Clone response to add headers
    const newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...Object.fromEntries(response.headers.entries()),
        'X-RateLimit-Limit': maxRequests.toString(),
        'X-RateLimit-Remaining': remaining.toString(),
        'X-RateLimit-Reset': rateLimitData.resetTime.toString()
      }
    });
    
    return newResponse;
    
  } catch (error) {
    console.error('Rate limit middleware error:', error);
    // If rate limiting fails, continue with the request
    return await next();
  }
};

// Note: Periodic cleanup is not available in Cloudflare Workers global scope
// Cleanup will happen naturally when entries are accessed and found to be expired