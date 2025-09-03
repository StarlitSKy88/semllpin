import { Request, Response } from 'express';
import { UserController } from '../userController';
import { jest } from '@jest/globals';

// Mock dependencies
jest.mock('../../config/database');
jest.mock('../../services/userService');
jest.mock('../../middleware/auth');

describe('UserController', () => {
  let userController: UserController;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.Mock;

  beforeEach(() => {
    userController = new UserController();
    
    mockRequest = {
      body: {},
      params: {},
      query: {},
      user: { id: 'user123', email: 'test@example.com', username: 'testuser', role: 'user' }
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis()
    };
    
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register new user successfully', async () => {
      const userData = {
        phone: '13800138000',
        verificationCode: '123456',
        nickname: 'TestUser',
        avatar: 'https://example.com/avatar.jpg'
      };
      
      mockRequest.body = userData;

      // Mock user service
      const mockUserService = {
        verifyCode: jest.fn().mockResolvedValue(true),
        createUser: jest.fn().mockResolvedValue({
          id: 'user123',
          phone: userData.phone,
          nickname: userData.nickname,
          avatar: userData.avatar,
          createdAt: new Date()
        }),
        generateToken: jest.fn().mockReturnValue('jwt_token_123')
      };
      
      (userController as any).userService = mockUserService;

      await userController.register(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.verifyCode).toHaveBeenCalledWith(
        userData.phone,
        userData.verificationCode
      );
      expect(mockUserService.createUser).toHaveBeenCalledWith({
        phone: userData.phone,
        nickname: userData.nickname,
        avatar: userData.avatar
      });
      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '注册成功',
        data: {
          user: expect.objectContaining({
            id: 'user123',
            phone: userData.phone
          }),
          token: 'jwt_token_123'
        }
      });
    });

    it('should reject registration with invalid verification code', async () => {
      const userData = {
        phone: '13800138000',
        verificationCode: 'wrong_code',
        nickname: 'TestUser'
      };
      
      mockRequest.body = userData;

      const mockUserService = {
        verifyCode: jest.fn().mockResolvedValue(false)
      };
      
      (userController as any).userService = mockUserService;

      await userController.register(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 400,
        message: '验证码错误或已过期'
      });
    });

    it('should handle duplicate phone number', async () => {
      const userData = {
        phone: '13800138000',
        verificationCode: '123456',
        nickname: 'TestUser'
      };
      
      mockRequest.body = userData;

      const mockUserService = {
        verifyCode: jest.fn().mockResolvedValue(true),
        createUser: jest.fn().mockRejectedValue(new Error('Phone number already exists'))
      };
      
      (userController as any).userService = mockUserService;

      await userController.register(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 409,
        message: '手机号已注册'
      });
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      const loginData = {
        phone: '13800138000',
        verificationCode: '123456'
      };
      
      mockRequest.body = loginData;

      const mockUser = {
        id: 'user123',
        phone: loginData.phone,
        nickname: 'TestUser',
        avatar: 'https://example.com/avatar.jpg',
        level: 1,
        points: 100
      };

      const mockUserService = {
        verifyCode: jest.fn().mockResolvedValue(true),
        findByPhone: jest.fn().mockResolvedValue(mockUser),
        updateLastLogin: jest.fn().mockResolvedValue(undefined),
        generateToken: jest.fn().mockReturnValue('jwt_token_123')
      };
      
      (userController as any).userService = mockUserService;

      await userController.login(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.verifyCode).toHaveBeenCalledWith(
        loginData.phone,
        loginData.verificationCode
      );
      expect(mockUserService.findByPhone).toHaveBeenCalledWith(loginData.phone);
      expect(mockUserService.updateLastLogin).toHaveBeenCalledWith(mockUser.id);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '登录成功',
        data: {
          user: mockUser,
          token: 'jwt_token_123'
        }
      });
    });

    it('should reject login with non-existent user', async () => {
      const loginData = {
        phone: '13800138000',
        verificationCode: '123456'
      };
      
      mockRequest.body = loginData;

      const mockUserService = {
        verifyCode: jest.fn().mockResolvedValue(true),
        findByPhone: jest.fn().mockResolvedValue(null)
      };
      
      (userController as any).userService = mockUserService;

      await userController.login(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 404,
        message: '用户不存在，请先注册'
      });
    });
  });

  describe('getProfile', () => {
    it('should get user profile successfully', async () => {
      const userId = 'user123';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };

      const mockUserProfile = {
        id: userId,
        phone: '13800138000',
        nickname: 'TestUser',
        avatar: 'https://example.com/avatar.jpg',
        level: 2,
        points: 250,
        totalRewards: 150.5,
        annotationsCount: 5,
        discoveredCount: 12,
        createdAt: new Date(),
        lastLoginAt: new Date()
      };

      const mockUserService = {
        getUserProfile: jest.fn().mockResolvedValue(mockUserProfile)
      };
      
      (userController as any).userService = mockUserService;

      await userController.getProfile(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.getUserProfile).toHaveBeenCalledWith(userId);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取用户信息成功',
        data: mockUserProfile
      });
    });

    it('should handle user not found', async () => {
      const userId = 'nonexistent';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };

      const mockUserService = {
        getUserProfile: jest.fn().mockResolvedValue(null)
      };
      
      (userController as any).userService = mockUserService;

      await userController.getProfile(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 404,
        message: '用户不存在'
      });
    });
  });

  describe('updateProfile', () => {
    it('should update user profile successfully', async () => {
      const userId = 'user123';
      const updateData = {
        nickname: 'NewNickname',
        avatar: 'https://example.com/new-avatar.jpg',
        bio: 'Updated bio'
      };
      
      mockRequest.user = { id: userId };
      mockRequest.body = updateData;

      const updatedUser = {
        id: userId,
        ...updateData,
        updatedAt: new Date()
      };

      const mockUserService = {
        updateProfile: jest.fn().mockResolvedValue(updatedUser)
      };
      
      (userController as any).userService = mockUserService;

      await userController.updateProfile(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.updateProfile).toHaveBeenCalledWith(userId, updateData);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '更新用户信息成功',
        data: updatedUser
      });
    });

    it('should validate profile update data', async () => {
      const userId = 'user123';
      const invalidData = {
        nickname: '', // Empty nickname
        avatar: 'invalid-url'
      };
      
      mockRequest.user = { id: userId };
      mockRequest.body = invalidData;

      await userController.updateProfile(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 400,
        message: expect.stringContaining('验证失败')
      });
    });
  });

  describe('getUserStats', () => {
    it('should get user statistics successfully', async () => {
      const userId = 'user123';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };

      const mockStats = {
        totalAnnotations: 8,
        totalDiscoveries: 15,
        totalRewards: 245.5,
        currentStreak: 5,
        longestStreak: 12,
        level: 3,
        points: 450,
        rankPosition: 25,
        monthlyStats: {
          annotations: 3,
          discoveries: 7,
          rewards: 85.0
        }
      };

      const mockUserService = {
        getUserStats: jest.fn().mockResolvedValue(mockStats)
      };
      
      (userController as any).userService = mockUserService;

      await userController.getUserStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.getUserStats).toHaveBeenCalledWith(userId);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取用户统计成功',
        data: mockStats
      });
    });
  });

  describe('getRewardHistory', () => {
    it('should get user reward history successfully', async () => {
      const userId = 'user123';
      const page = 1;
      const limit = 20;
      
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.query = { page: page.toString(), limit: limit.toString() };

      const mockRewardHistory = {
        rewards: [
          {
            id: 'reward1',
            amount: 25.5,
            annotationTitle: 'Funny smell here',
            location: 'Central Park',
            earnedAt: new Date(),
            type: 'discovery'
          },
          {
            id: 'reward2',
            amount: 15.0,
            annotationTitle: 'Stinky spot',
            location: 'Times Square',
            earnedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
            type: 'first_discovery'
          }
        ],
        pagination: {
          page: 1,
          limit: 20,
          total: 2,
          totalPages: 1
        }
      };

      const mockUserService = {
        getRewardHistory: jest.fn().mockResolvedValue(mockRewardHistory)
      };
      
      (userController as any).userService = mockUserService;

      await userController.getRewardHistory(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.getRewardHistory).toHaveBeenCalledWith(
        userId,
        page,
        limit
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取奖励历史成功',
        data: mockRewardHistory
      });
    });
  });

  describe('sendVerificationCode', () => {
    it('should send verification code successfully', async () => {
      const phone = '13800138000';
      mockRequest.body = { phone };

      const mockUserService = {
        sendVerificationCode: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue({
          success: true,
          expiresAt: new Date(Date.now() + 5 * 60 * 1000)
        })
      };
      
      (userController as any).userService = mockUserService;

      await userController.sendVerificationCode(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.sendVerificationCode).toHaveBeenCalledWith(phone);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '验证码发送成功',
        data: {
          expiresAt: expect.any(Date)
        }
      });
    });

    it('should handle rate limiting', async () => {
      const phone = '13800138000';
      mockRequest.body = { phone };

      const mockUserService = {
        sendVerificationCode: (jest.fn() as jest.MockedFunction<any>).mockRejectedValue(
          new Error('Rate limit exceeded')
        )
      };
      
      (userController as any).userService = mockUserService;

      await userController.sendVerificationCode(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 429,
        message: '发送频率过快，请稍后再试'
      });
    });
  });

  describe('deleteAccount', () => {
    it('should delete user account successfully', async () => {
      const userId = 'user123';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = { confirmPassword: 'user_password' };

      const mockUserService = {
        deleteAccount: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue({ success: true })
      };
      
      (userController as any).userService = mockUserService;

      await userController.deleteAccount(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockUserService.deleteAccount).toHaveBeenCalledWith(
        userId,
        'user_password'
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '账户删除成功'
      });
    });

    it('should reject deletion with wrong password', async () => {
      const userId = 'user123';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = { confirmPassword: 'wrong_password' };

      const mockUserService = {
        deleteAccount: (jest.fn() as jest.MockedFunction<any>).mockRejectedValue(
          new Error('Invalid password')
        )
      };
      
      (userController as any).userService = mockUserService;

      await userController.deleteAccount(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 401,
        message: '密码验证失败'
      });
    });
  });

  describe('error handling', () => {
    it('should handle unexpected errors', async () => {
      const userId = 'user123';
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };

      const mockUserService = {
        getUserProfile: (jest.fn() as jest.MockedFunction<any>).mockRejectedValue(
          new Error('Database connection failed')
        )
      };
      
      (userController as any).userService = mockUserService;

      await userController.getProfile(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Database connection failed'
        })
      );
    });
  });
});