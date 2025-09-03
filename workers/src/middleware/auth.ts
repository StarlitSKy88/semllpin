import { jwtVerify, importSPKI } from 'jose';
import { Env } from '../index';
import { Middleware } from '../utils/router';
import { verifyToken } from '../routes/neon-auth';
import { createNeonDatabase } from '../utils/neon-database';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export const authMiddleware: Middleware = async (request, env, ctx, next) => {
  try {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify JWT token using our custom verifyToken function
    try {
      const payload = await verifyToken(token, env);
      
      if (!payload) {
        return new Response(JSON.stringify({
          error: 'Unauthorized',
          message: 'Invalid or expired token'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Get user details from database
      const db = createNeonDatabase(env);
      const userResult = await db.getUserById(payload.sub);
      
      if (!userResult) {
        return new Response(JSON.stringify({
          error: 'Unauthorized',
          message: 'User not found'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Add user to request object
      (request as AuthenticatedRequest).user = {
        id: userResult.id,
        email: userResult.email,
        role: 'user' // Default role, can be extended later
      };

      return await next();
    } catch (jwtError) {
      console.error('JWT verification error:', jwtError);
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Token verification failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Authentication failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Optional: Admin role check middleware
export const adminMiddleware: Middleware = async (request, env, ctx, next) => {
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

  return await next();
};