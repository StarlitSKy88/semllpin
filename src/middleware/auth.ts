import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { AppError, createAuthError, createForbiddenError } from './errorHandler';
import { logger } from '../utils/logger';
import { cacheService } from '../config/redis';

// JWT payload interface
interface JWTPayload {
  sub: string; // user id
  email: string;
  username: string;
  role: string;
  iat: number;
  exp: number;
}

// Extract token from request
const extractToken = (req: Request): string | null => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Also check for token in cookies (for web app)
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }

  return null;
};

// Verify JWT token
const verifyToken = (token: string): Promise<JWTPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, config.jwt.secret, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded as JWTPayload);
      }
    });
  });
};

// Check if token is blacklisted
const isTokenBlacklisted = async (token: string): Promise<boolean> => {
  try {
    const blacklisted = await cacheService.get(`blacklist:${token}`);
    return blacklisted === 'true';
  } catch (error) {
    logger.error('检查令牌黑名单失败:', error);
    return false; // Fail open
  }
};

// Authentication middleware
export const authMiddleware = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const token = extractToken(req);

    if (!token) {
      throw createAuthError('访问令牌缺失');
    }

    // Check if token is blacklisted
    if (await isTokenBlacklisted(token)) {
      throw createAuthError('访问令牌已失效');
    }

    // Verify token
    const payload = await verifyToken(token);

    // Check if user still exists and is active
    const userKey = `user:${payload.sub}`;
    const cachedUser = await cacheService.get(userKey);

    if (!cachedUser) {
      // User not in cache, would need to check database
      // For now, we'll trust the token if it's valid
      logger.warn(`用户 ${payload.sub} 不在缓存中`);
    }

    // Attach user info to request
    req.user = {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      role: payload.role,
    };

    next();
  } catch (error) {
    next(error);
  }
};

// Optional authentication middleware (doesn't throw error if no token)
export const optionalAuthMiddleware = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const token = extractToken(req);

    if (!token) {
      return next();
    }

    // Check if token is blacklisted
    if (await isTokenBlacklisted(token)) {
      return next();
    }

    // Verify token
    const payload = await verifyToken(token);

    // Attach user info to request
    req.user = {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      role: payload.role,
    };

    next();
  } catch (error) {
    // Don't throw error for optional auth
    next();
  }
};

// Role-based authorization middleware
export const requireRole = (roles: string | string[]) => {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw createAuthError('用户未认证');
    }

    const userRole = req.user.role;
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    if (!allowedRoles.includes(userRole)) {
      throw createForbiddenError('权限不足');
    }

    next();
  };
};

// Admin only middleware
export const requireAdmin = requireRole('admin');

// Moderator or admin middleware
export const requireModerator = requireRole(['moderator', 'admin']);

// Check if user owns resource
export const requireOwnership = (getResourceUserId: (req: Request) => string | Promise<string>) => {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw createAuthError('用户未认证');
      }

      const resourceUserId = await getResourceUserId(req);

      // Admin can access any resource
      if (req.user.role === 'admin') {
        return next();
      }

      // Check ownership
      if (req.user.id !== resourceUserId) {
        throw createForbiddenError('只能访问自己的资源');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Generate JWT token
export const generateToken = (payload: Omit<JWTPayload, 'iat' | 'exp'>): string => {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  } as jwt.SignOptions);
};

// Generate refresh token
export const generateRefreshToken = (userId: string): string => {
  return jwt.sign({ sub: userId }, config.jwt.refreshSecret, {
    expiresIn: config.jwt.refreshExpiresIn,
  } as jwt.SignOptions);
};

// Verify refresh token
export const verifyRefreshToken = (token: string): Promise<{ sub: string }> => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, config.jwt.refreshSecret, (err: jwt.VerifyErrors | null, decoded: any) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded as { sub: string });
      }
    });
  });
};

// Blacklist token
export const blacklistToken = async (token: string): Promise<void> => {
  try {
    // Decode token to get expiration time
    const decoded = jwt.decode(token) as JWTPayload;
    if (decoded && decoded.exp) {
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await cacheService.set(`blacklist:${token}`, 'true', ttl);
      }
    }
  } catch (error) {
    logger.error('令牌加入黑名单失败:', error);
    throw error;
  }
};

// Rate limiting by user
export const rateLimitByUser = (maxRequests: number, windowMs: number) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const userId = req.user?.id || req.ip;
      const key = `rate_limit:user:${userId}`;

      const current = await cacheService.incr(key);

      if (current === 1) {
        await cacheService.expire(key, Math.ceil(windowMs / 1000));
      }

      if (current > maxRequests) {
        throw new AppError(
          '请求过于频繁，请稍后再试',
          429,
          'RATE_LIMIT_EXCEEDED',
        );
      }

      // Add rate limit headers
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - current));
      res.setHeader('X-RateLimit-Reset', new Date(Date.now() + windowMs).toISOString());

      next();
    } catch (error) {
      next(error);
    }
  };
};

export default authMiddleware;
