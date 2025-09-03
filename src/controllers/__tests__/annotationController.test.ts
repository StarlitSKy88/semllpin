import { Request, Response } from 'express';
import { AnnotationController } from '../annotationController';
import { jest } from '@jest/globals';

// Mock dependencies
jest.mock('../../config/database');
jest.mock('../../services/annotationService');
jest.mock('../../services/geofenceService');
jest.mock('../../services/paymentService');
jest.mock('../../middleware/auth');

describe('AnnotationController', () => {
  let annotationController: AnnotationController;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.Mock;

  beforeEach(() => {
    annotationController = new AnnotationController();
    
    mockRequest = {
      body: {},
      params: {},
      query: {},
      user: { id: 'user123', role: 'user' }
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis()
    };
    
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('createAnnotation', () => {
    it('should create annotation successfully', async () => {
      const annotationData = {
        title: 'Funny smell here!',
        description: 'There is a weird smell coming from this area',
        latitude: 40.7128,
        longitude: -74.0060,
        category: 'smell',
        tags: ['funny', 'weird'],
        rewardAmount: 50.0,
        duration: 24 // hours
      };
      
      mockRequest.body = annotationData;
      mockRequest.user = { id: 'user123' };

      const mockCreatedAnnotation = {
        id: 'annotation123',
        ...annotationData,
        userId: 'user123',
        status: 'active',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
      };

      const mockAnnotationService = {
        validateAnnotationData: jest.fn().mockReturnValue({ isValid: true }),
        checkLocationAvailability: jest.fn().mockResolvedValue(true),
        createAnnotation: jest.fn().mockResolvedValue(mockCreatedAnnotation)
      };
      
      const mockPaymentService = {
        processPayment: jest.fn().mockResolvedValue({
          success: true,
          transactionId: 'txn_123',
          amount: 50
        })
      };
      
      const mockGeofenceService = {
        createGeofence: jest.fn().mockResolvedValue({
          id: 'geofence_123',
          radius: 100
        })
      };
      
      (annotationController as any).annotationService = mockAnnotationService;
      (annotationController as any).paymentService = mockPaymentService;
      (annotationController as any).geofenceService = mockGeofenceService;

      await annotationController.createAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.validateAnnotationData).toHaveBeenCalledWith(annotationData);
      expect(mockAnnotationService.checkLocationAvailability).toHaveBeenCalledWith(
        annotationData.latitude,
        annotationData.longitude
      );
      expect(mockPaymentService.processPayment).toHaveBeenCalledWith(
        'user123',
        annotationData.rewardAmount
      );
      expect(mockGeofenceService.createGeofence).toHaveBeenCalled();
      expect(mockAnnotationService.createAnnotation).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '标注创建成功',
        data: mockCreatedAnnotation
      });
    });

    it('should reject annotation with invalid data', async () => {
      const invalidData = {
        title: '', // Empty title
        latitude: 200, // Invalid latitude
        longitude: -200, // Invalid longitude
        rewardAmount: -10 // Negative amount
      };
      
      mockRequest.body = invalidData;

      const mockAnnotationService = {
        validateAnnotationData: jest.fn().mockReturnValue({
          isValid: false,
          errors: ['标题不能为空', '经纬度无效', '奖励金额必须大于0']
        })
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.createAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 400,
        message: '数据验证失败',
        errors: expect.arrayContaining(['标题不能为空', '经纬度无效'])
      });
    });

    it('should handle location unavailability', async () => {
      const annotationData = {
        title: 'Test annotation',
        latitude: 40.7128,
        longitude: -74.0060,
        rewardAmount: 25.0
      };
      
      mockRequest.body = annotationData;

      const mockAnnotationService = {
        validateAnnotationData: jest.fn().mockReturnValue({ isValid: true }),
        checkLocationAvailability: jest.fn().mockResolvedValue(false)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.createAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 409,
        message: '该位置已存在标注，请选择其他位置'
      });
    });

    it('should handle payment failure', async () => {
      const annotationData = {
        title: 'Test annotation',
        latitude: 40.7128,
        longitude: -74.0060,
        rewardAmount: 100.0
      };
      
      mockRequest.body = annotationData;

      const mockAnnotationService = {
        validateAnnotationData: jest.fn().mockReturnValue({ isValid: true }),
        checkLocationAvailability: jest.fn().mockResolvedValue(true)
      };
      
      const mockPaymentService = {
        processPayment: jest.fn().mockResolvedValue({
          success: false,
          error: 'Insufficient balance'
        })
      };
      
      (annotationController as any).annotationService = mockAnnotationService;
      (annotationController as any).paymentService = mockPaymentService;

      await annotationController.createAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(402);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 402,
        message: '支付失败，余额不足'
      });
    });
  });

  describe('getNearbyAnnotations', () => {
    it('should get nearby annotations successfully', async () => {
      const queryParams = {
        latitude: '40.7128',
        longitude: '-74.0060',
        radius: '1000',
        limit: '20'
      };
      
      mockRequest.query = queryParams;

      const mockNearbyAnnotations = [
        {
          id: 'annotation1',
          title: 'Funny smell',
          description: 'Weird smell here',
          latitude: 40.7130,
          longitude: -74.0058,
          category: 'smell',
          rewardAmount: 25.0,
          distance: 150,
          status: 'active',
          createdAt: new Date()
        },
        {
          id: 'annotation2',
          title: 'Strange odor',
          description: 'Something smells off',
          latitude: 40.7125,
          longitude: -74.0065,
          category: 'smell',
          rewardAmount: 30.0,
          distance: 200,
          status: 'active',
          createdAt: new Date()
        }
      ];

      const mockAnnotationService = {
        getNearbyAnnotations: jest.fn().mockResolvedValue(mockNearbyAnnotations)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.getNearbyAnnotations(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.getNearbyAnnotations).toHaveBeenCalledWith(
        parseFloat(queryParams.latitude),
        parseFloat(queryParams.longitude),
        parseInt(queryParams.radius),
        parseInt(queryParams.limit)
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取附近标注成功',
        data: {
          annotations: mockNearbyAnnotations,
          count: mockNearbyAnnotations.length
        }
      });
    });

    it('should validate location parameters', async () => {
      const invalidParams = {
        latitude: 'invalid',
        longitude: '200', // Invalid longitude
        radius: '-100' // Negative radius
      };
      
      mockRequest.query = invalidParams;

      await annotationController.getNearbyAnnotations(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 400,
        message: '位置参数无效'
      });
    });
  });

  describe('getAnnotationDetails', () => {
    it('should get annotation details successfully', async () => {
      const annotationId = 'annotation123';
      mockRequest.params = { id: annotationId };

      const mockAnnotationDetails = {
        id: annotationId,
        title: 'Funny smell here',
        description: 'Detailed description of the smell',
        latitude: 40.7128,
        longitude: -74.0060,
        category: 'smell',
        tags: ['funny', 'weird'],
        rewardAmount: 50.0,
        status: 'active',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        creator: {
          id: 'user456',
          nickname: 'Creator',
          avatar: 'https://example.com/avatar.jpg'
        },
        discoveryCount: 3,
        totalRewardsPaid: 75.0,
        comments: [
          {
            id: 'comment1',
            content: 'I found this too!',
            user: { nickname: 'Discoverer1' },
            createdAt: new Date()
          }
        ]
      };

      const mockAnnotationService = {
        getAnnotationDetails: jest.fn().mockResolvedValue(mockAnnotationDetails)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.getAnnotationDetails(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.getAnnotationDetails).toHaveBeenCalledWith(annotationId);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取标注详情成功',
        data: mockAnnotationDetails
      });
    });

    it('should handle annotation not found', async () => {
      const annotationId = 'nonexistent';
      mockRequest.params = { id: annotationId };

      const mockAnnotationService = {
        getAnnotationDetails: jest.fn().mockResolvedValue(null)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.getAnnotationDetails(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 404,
        message: '标注不存在'
      });
    });
  });

  describe('claimReward', () => {
    it('should claim reward successfully', async () => {
      const annotationId = 'annotation123';
      const userId = 'user123';
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 5.0
      };

      const mockRewardResult = {
        success: true,
        rewardAmount: 25.0,
        bonusMultiplier: 1.2,
        totalReward: 30.0,
        isFirstDiscovery: false,
        streakBonus: 5.0,
        transactionId: 'txn456'
      };

      const mockAnnotationService = {
        claimReward: jest.fn().mockResolvedValue(mockRewardResult)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.claimReward(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.claimReward).toHaveBeenCalledWith(
        annotationId,
        userId,
        {
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 5.0
        }
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '奖励领取成功',
        data: mockRewardResult
      });
    });

    it('should reject reward claim for invalid location', async () => {
      const annotationId = 'annotation123';
      const userId = 'user123';
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = {
        latitude: 41.0000, // Too far from annotation
        longitude: -75.0000,
        accuracy: 10.0
      };

      const mockAnnotationService = {
        claimReward: jest.fn().mockRejectedValue(
          new Error('Location too far from annotation')
        )
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.claimReward(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 400,
        message: '位置距离标注太远，无法领取奖励'
      });
    });

    it('should reject duplicate reward claims', async () => {
      const annotationId = 'annotation123';
      const userId = 'user123';
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 5.0
      };

      const mockAnnotationService = {
        claimReward: jest.fn().mockRejectedValue(
          new Error('Reward already claimed by this user')
        )
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.claimReward(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 409,
        message: '您已经领取过该标注的奖励'
      });
    });
  });

  describe('updateAnnotation', () => {
    it('should update annotation successfully', async () => {
      const annotationId = 'annotation123';
      const userId = 'user123';
      const updateData = {
        title: 'Updated title',
        description: 'Updated description',
        tags: ['updated', 'modified']
      };
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = updateData;

      const mockUpdatedAnnotation = {
        id: annotationId,
        ...updateData,
        updatedAt: new Date()
      };

      const mockAnnotationService = {
        updateAnnotation: jest.fn().mockResolvedValue(mockUpdatedAnnotation),
        checkOwnership: jest.fn().mockResolvedValue(true)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.updateAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.checkOwnership).toHaveBeenCalledWith(
        annotationId,
        userId
      );
      expect(mockAnnotationService.updateAnnotation).toHaveBeenCalledWith(
        annotationId,
        updateData
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '标注更新成功',
        data: mockUpdatedAnnotation
      });
    });

    it('should reject update from non-owner', async () => {
      const annotationId = 'annotation123';
      const userId = 'user456'; // Different user
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.body = { title: 'Hacked title' };

      const mockAnnotationService = {
        checkOwnership: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue(false)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.updateAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 403,
        message: '无权限修改此标注'
      });
    });
  });

  describe('deleteAnnotation', () => {
    it('should delete annotation successfully', async () => {
      const annotationId = 'annotation123';
      const userId = 'user123';
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };

      const mockAnnotationService = {
        checkOwnership: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue(true),
        deleteAnnotation: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue({ success: true })
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.deleteAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.checkOwnership).toHaveBeenCalledWith(
        annotationId,
        userId
      );
      expect(mockAnnotationService.deleteAnnotation).toHaveBeenCalledWith(annotationId);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '标注删除成功'
      });
    });

    it('should reject deletion from non-owner', async () => {
      const annotationId = 'annotation123';
      const userId = 'user456';
      
      mockRequest.params = { id: annotationId };
      mockRequest.user = { 
        id: userId,
        email: 'test@example.com',
        username: 'testuser',
        role: 'user'
      };

      const mockAnnotationService = {
        checkOwnership: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue(false)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.deleteAnnotation(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 403,
        message: '无权限删除此标注'
      });
    });
  });

  describe('getUserAnnotations', () => {
    it('should get user annotations successfully', async () => {
      const userId = 'user123';
      const page = 1;
      const limit = 10;
      
      mockRequest.user = { id: userId, email: 'test@example.com', username: 'testuser', role: 'user' };
      mockRequest.query = { page: page.toString(), limit: limit.toString() };

      const mockUserAnnotations = {
        annotations: [
          {
            id: 'annotation1',
            title: 'My first annotation',
            status: 'active',
            rewardAmount: 25.0,
            discoveryCount: 2,
            createdAt: new Date()
          },
          {
            id: 'annotation2',
            title: 'My second annotation',
            status: 'expired',
            rewardAmount: 30.0,
            discoveryCount: 5,
            createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000)
          }
        ],
        pagination: {
          page: 1,
          limit: 10,
          total: 2,
          totalPages: 1
        }
      };

      const mockAnnotationService = {
        getUserAnnotations: (jest.fn() as jest.MockedFunction<any>).mockResolvedValue(mockUserAnnotations)
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.getUserAnnotations(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockAnnotationService.getUserAnnotations).toHaveBeenCalledWith(
        userId,
        page,
        limit
      );
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 200,
        message: '获取用户标注成功',
        data: mockUserAnnotations
      });
    });
  });

  describe('error handling', () => {
    it('should handle service errors gracefully', async () => {
      mockRequest.query = {
        latitude: '40.7128',
        longitude: '-74.0060'
      };

      const mockAnnotationService = {
        getNearbyAnnotations: (jest.fn() as jest.MockedFunction<any>).mockRejectedValue(
          new Error('Database connection failed')
        )
      };
      
      (annotationController as any).annotationService = mockAnnotationService;

      await annotationController.getNearbyAnnotations(
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