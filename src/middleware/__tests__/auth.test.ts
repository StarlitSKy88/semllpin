import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authenticateToken, requireRole, rateLimiter } from '../auth';
import { jest } from '@jest/globals';

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../config/redis');

const mockJwt = jwt as jest.Mocked<typeof jwt>;

describe('Auth Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      ip: '127.0.0.1',
      user: undefined
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis()
    } as any;
    
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('authenticateToken', () => {
    it('should authenticate valid token successfully', () => {
      const validToken = 'valid.jwt.token';
      const decodedUser = {
        id: 'user123',
        phone: '13800138000',
        role: 'user',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      
      mockRequest.headers = {
        authorization: `Bearer ${validToken}`
      };
      
      (mockJwt.verify as jest.MockedFunction<any>).mockReturnValue(decodedUser);

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockJwt.verify).toHaveBeenCalledWith(
        validToken,
        process.env['JWT_SECRET'] || 'default-secret'
      );
      expect(mockRequest.user).toEqual(decodedUser);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject request without authorization header', () => {
      mockRequest.headers = {};

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '未提供认证令牌'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject request with malformed authorization header', () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token'
      };

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '认证令牌格式错误'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject request with invalid token', () => {
      const invalidToken = 'invalid.jwt.token';
      
      mockRequest.headers = {
        authorization: `Bearer ${invalidToken}`
      };
      
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '认证令牌无效'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject expired token', () => {
      const expiredToken = 'expired.jwt.token';
      
      mockRequest.headers = {
        authorization: `Bearer ${expiredToken}`
      };
      
      const tokenExpiredError = new Error('Token expired');
      tokenExpiredError.name = 'TokenExpiredError';
      
      mockJwt.verify.mockImplementation(() => {
        throw tokenExpiredError;
      });

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '认证令牌已过期'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle JsonWebTokenError', () => {
      const malformedToken = 'malformed.token';
      
      mockRequest.headers = {
        authorization: `Bearer ${malformedToken}`
      };
      
      const jwtError = new Error('Malformed token');
      jwtError.name = 'JsonWebTokenError';
      
      mockJwt.verify.mockImplementation(() => {
        throw jwtError;
      });

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '认证令牌格式错误'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should extract token from different authorization formats', () => {
      const token = 'valid.jwt.token';
      const decodedUser = { id: 'user123', role: 'user' };
      
      // Test with 'Bearer ' prefix
      mockRequest.headers = {
        authorization: `Bearer ${token}`
      };
      
      (mockJwt.verify as jest.MockedFunction<any>).mockReturnValue(decodedUser);

      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockJwt.verify).toHaveBeenCalledWith(token, expect.any(String));
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should allow access for user with required role', () => {
      (mockRequest as any).user = {
        id: 'admin123',
        email: 'admin@example.com',
        username: 'admin',
        role: 'admin'
      };

      const adminMiddleware = requireRole('admin');
      adminMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny access for user without required role', () => {
      (mockRequest as any).user = {
        id: 'user123',
        email: 'user@example.com',
        username: 'testuser',
        role: 'user'
      };

      const adminMiddleware = requireRole('admin');
      adminMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 403,
        message: '权限不足'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should deny access for unauthenticated user', () => {
      (mockRequest as any).user = undefined;

      const adminMiddleware = requireRole('admin');
      adminMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '未认证用户'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should allow access for multiple valid roles', () => {
      mockRequest.user = {
        id: 'moderator123',
        email: 'moderator@example.com',
        username: 'moderator',
        role: 'moderator'
      };

      const multiRoleMiddleware = requireRole(['admin', 'moderator']);
      multiRoleMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny access when user role not in allowed roles', () => {
      mockRequest.user = {
        id: 'user123',
        email: 'user@example.com',
        username: 'user',
        role: 'user'
      };

      const multiRoleMiddleware = requireRole(['admin', 'moderator']);
      multiRoleMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 403,
        message: '权限不足'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('rateLimiter', () => {
    let mockRedisClient: any;

    beforeEach(() => {
      mockRedisClient = {
        get: jest.fn(),
        setex: jest.fn(),
        incr: jest.fn(),
        expire: jest.fn()
      };
      
      // Mock Redis client
      jest.doMock('../../config/redis', () => ({
        redisClient: mockRedisClient
      }));
    });

    it('should allow request within rate limit', async () => {
      const clientIp = '127.0.0.1';
      (mockRequest as any).ip = clientIp;
      
      // Mock Redis to return current count below limit
      mockRedisClient.get.mockResolvedValue('5'); // 5 requests in current window
      mockRedisClient.incr.mockResolvedValue(6);

      const limiter = rateLimiter({ windowMs: 60000, max: 10 });
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockRedisClient.get).toHaveBeenCalledWith(`rate_limit:${clientIp}`);
      expect(mockRedisClient.incr).toHaveBeenCalledWith(`rate_limit:${clientIp}`);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should block request when rate limit exceeded', async () => {
      const clientIp = '127.0.0.1';
      (mockRequest as any).ip = clientIp;
      
      // Mock Redis to return count at limit
      mockRedisClient.get.mockResolvedValue('10'); // Already at limit
      mockRedisClient.incr.mockResolvedValue(11);

      const limiter = rateLimiter({ windowMs: 60000, max: 10 });
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 429,
        message: '请求过于频繁，请稍后再试',
        retryAfter: expect.any(Number)
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should initialize counter for new IP', async () => {
      const clientIp = '192.168.1.1';
      (mockRequest as any).ip = clientIp;
      
      // Mock Redis to return null for new IP
      mockRedisClient.get.mockResolvedValue(null);
      mockRedisClient.incr.mockResolvedValue(1);

      const limiter = rateLimiter({ windowMs: 60000, max: 10 });
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockRedisClient.incr).toHaveBeenCalledWith(`rate_limit:${clientIp}`);
      expect(mockRedisClient.expire).toHaveBeenCalledWith(
        `rate_limit:${clientIp}`,
        60 // 60 seconds
      );
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should set appropriate headers', async () => {
      const clientIp = '127.0.0.1';
      (mockRequest as any).ip = clientIp;
      
      mockRedisClient.get.mockResolvedValue('3');
      mockRedisClient.incr.mockResolvedValue(4);

      const limiter = rateLimiter({ windowMs: 60000, max: 10 });
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', 10);
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 6);
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Reset',
        expect.any(Number)
      );
    });

    it('should handle Redis errors gracefully', async () => {
      const clientIp = '127.0.0.1';
      (mockRequest as any).ip = clientIp;
      
      // Mock Redis to throw error
      mockRedisClient.get.mockRejectedValue(new Error('Redis connection failed'));

      const limiter = rateLimiter({ windowMs: 60000, max: 10 });
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      // Should allow request when Redis fails (fail open)
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should use custom key generator', async () => {
      const userId = 'user123';
      (mockRequest as any).user = { 
        id: userId,
        email: 'user@example.com',
        username: 'testuser',
        role: 'user'
      };
      
      const customKeyGen = (req: Request) => `user:${req.user?.id}`;
      
      mockRedisClient.get.mockResolvedValue('2');
      mockRedisClient.incr.mockResolvedValue(3);

      const limiter = rateLimiter({
        windowMs: 60000,
        max: 5,
        keyGenerator: customKeyGen
      });
      
      await limiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockRedisClient.get).toHaveBeenCalledWith(`rate_limit:user:${userId}`);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should apply different limits for different endpoints', async () => {
      const clientIp = '127.0.0.1';
      (mockRequest as any).ip = clientIp;
      (mockRequest as any).path = '/api/auth/login';
      
      mockRedisClient.get.mockResolvedValue('4');
      mockRedisClient.incr.mockResolvedValue(5);

      // Stricter limit for auth endpoints
      const authLimiter = rateLimiter({ windowMs: 300000, max: 5 }); // 5 per 5 minutes
      await authLimiter(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockRedisClient.get).toHaveBeenCalledWith(`rate_limit:${clientIp}`);
      expect(mockNext).toHaveBeenCalledWith();
    });
  });

  describe('integration scenarios', () => {
    it('should handle authentication and role check together', () => {
      const validToken = 'valid.admin.token';
      const adminUser = {
        id: 'admin123',
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      
      mockRequest.headers = {
        authorization: `Bearer ${validToken}`
      };
      
      (mockJwt.verify as jest.MockedFunction<any>).mockReturnValue(adminUser);

      // First apply authentication
      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);
      
      expect(mockRequest.user).toEqual(adminUser);
      expect(mockNext).toHaveBeenCalledWith();
      
      // Reset mock
      (mockNext as jest.MockedFunction<any>).mockClear();
      
      // Then apply role check
      const adminMiddleware = requireRole('admin');
      adminMiddleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject user with valid token but insufficient role', () => {
      const validToken = 'valid.user.token';
      const regularUser = {
        id: 'user123',
        role: 'user',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      
      mockRequest.headers = {
        authorization: `Bearer ${validToken}`
      };
      
      (mockJwt.verify as jest.MockedFunction<any>).mockReturnValue(regularUser);

      // First apply authentication
      authenticateToken(mockRequest as Request, mockResponse as Response, mockNext);
      
      expect(mockRequest.user).toEqual(regularUser);
      expect(mockNext).toHaveBeenCalledWith();
      
      // Reset mocks
      (mockNext as jest.MockedFunction<any>).mockClear();
      (mockResponse.status as jest.Mock).mockClear();
      (mockResponse.json as jest.Mock).mockClear();
      
      // Then apply admin role check
      const adminMiddleware = requireRole('admin');
      adminMiddleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 403,
        message: '权限不足'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});