import request from 'supertest';
import { Express } from 'express';
import Server from '../../server';
import { db } from '../../config/database';
import jwt from 'jsonwebtoken';

describe('API Integration Tests', () => {
  let app: Express;
  let authToken: string;
  let testUserId: string;
  let testAnnotationId: string;

  beforeAll(async () => {
    // 创建应用实例
    const server = new Server();
    app = server.getApp();
    
    // 创建测试用户和认证token
    const testUser = {
      id: 'test-user-123',
      phone: '13800138000',
      role: 'user'
    };
    
    authToken = jwt.sign(testUser, process.env['JWT_SECRET'] || 'test-secret', {
      expiresIn: '1h'
    });
    
    testUserId = testUser.id;
  });

  afterAll(async () => {
    // 清理测试数据
    // Clean up database connections if needed
    // await db.destroy();
  });

  describe('Authentication Endpoints', () => {
    describe('POST /api/v1/auth/login', () => {
      it('should login with valid credentials', async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: '13800138000',
            verificationCode: '123456'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('token');
        expect(response.body.data).toHaveProperty('user');
      });

      it('should reject invalid phone number', async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: 'invalid-phone',
            verificationCode: '123456'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });

      it('should reject missing verification code', async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: '13800138000'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });

    describe('POST /api/v1/auth/send-code', () => {
      it('should send verification code', async () => {
        const response = await request(app)
          .post('/api/v1/auth/send-code')
          .send({
            phone: '13800138000'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('message');
      });

      it('should reject invalid phone number', async () => {
        const response = await request(app)
          .post('/api/v1/auth/send-code')
          .send({
            phone: 'invalid'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });
  });

  describe('User Endpoints', () => {
    describe('GET /api/v1/users/profile', () => {
      it('should get user profile with valid token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${authToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('id');
        expect(response.body.data).toHaveProperty('phone');
      });

      it('should reject request without token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });

      it('should reject request with invalid token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', 'Bearer invalid-token');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });
    });

    describe('PUT /api/v1/users/profile', () => {
      it('should update user profile', async () => {
        const updateData = {
          nickname: 'Updated Nickname',
          avatar: 'https://example.com/avatar.jpg'
        };

        const response = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${authToken}`)
          .send(updateData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
      });

      it('should validate profile data', async () => {
        const invalidData = {
          nickname: '', // 空昵称应该被拒绝
          avatar: 'invalid-url'
        };

        const response = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });
  });

  describe('Annotation Endpoints', () => {
    describe('POST /api/v1/annotations', () => {
      it('should create annotation with valid data', async () => {
        const annotationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'Test Smell',
          description: 'This is a test smell annotation',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: 10.00
        };

        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send(annotationData);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('code', 201);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('id');
        
        testAnnotationId = response.body.data.id;
      });

      it('should reject annotation with invalid coordinates', async () => {
        const invalidData = {
          latitude: 91, // 无效纬度
          longitude: -74.0060,
          title: 'Test Smell',
          description: 'Test description',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: 10.00
        };

        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });

      it('should reject annotation with negative reward amount', async () => {
        const invalidData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'Test Smell',
          description: 'Test description',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: -5.00 // 负数奖励
        };

        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });

    describe('GET /api/v1/annotations', () => {
      it('should get annotations with location filter', async () => {
        const response = await request(app)
          .get('/api/v1/annotations')
          .query({
            latitude: 40.7128,
            longitude: -74.0060,
            radius: 1000
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(Array.isArray(response.body.data)).toBe(true);
      });

      it('should support pagination', async () => {
        const response = await request(app)
          .get('/api/v1/annotations')
          .query({
            page: 1,
            limit: 10
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body).toHaveProperty('pagination');
      });
    });

    describe('GET /api/v1/annotations/:id', () => {
      it('should get annotation by id', async () => {
        if (!testAnnotationId) {
          // 如果没有测试标注ID，跳过此测试
          return;
        }

        const response = await request(app)
          .get(`/api/v1/annotations/${testAnnotationId}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('id', testAnnotationId);
      });

      it('should return 404 for non-existent annotation', async () => {
        const response = await request(app)
          .get('/api/v1/annotations/non-existent-id');

        expect(response.status).toBe(404);
        expect(response.body).toHaveProperty('code', 404);
      });
    });
  });

  describe('LBS Endpoints', () => {
    describe('POST /api/v1/lbs/check-rewards', () => {
      it('should check for rewards at location', async () => {
        const locationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 10
        };

        const response = await request(app)
          .post('/api/v1/lbs/check-rewards')
          .set('Authorization', `Bearer ${authToken}`)
          .send(locationData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('rewards');
        expect(Array.isArray(response.body.data.rewards)).toBe(true);
      });

      it('should reject invalid GPS coordinates', async () => {
        const invalidData = {
          latitude: 'invalid',
          longitude: -74.0060,
          accuracy: 10
        };

        const response = await request(app)
          .post('/api/v1/lbs/check-rewards')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });

      it('should require authentication', async () => {
        const locationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 10
        };

        const response = await request(app)
          .post('/api/v1/lbs/check-rewards')
          .send(locationData);

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });
    });

    describe('POST /api/v1/lbs/claim-reward', () => {
      it('should claim reward with valid data', async () => {
        const claimData = {
          annotationId: testAnnotationId || 'test-annotation-id',
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 5
        };

        const response = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${authToken}`)
          .send(claimData);

        // 可能返回200（成功）或400（已领取/不符合条件）
        expect([200, 400]).toContain(response.status);
        expect(response.body).toHaveProperty('code');
      });

      it('should reject claim without annotation id', async () => {
        const invalidData = {
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 5
        };

        const response = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });
  });

  describe('Payment Endpoints', () => {
    describe('POST /api/v1/payments/create', () => {
      it('should create payment with valid data', async () => {
        const paymentData = {
          amount: 50.00,
          currency: 'CNY',
          paymentMethod: 'alipay',
          description: 'Test payment for annotation'
        };

        const response = await request(app)
          .post('/api/v1/payments/create')
          .set('Authorization', `Bearer ${authToken}`)
          .send(paymentData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('paymentId');
      });

      it('should reject invalid payment amount', async () => {
        const invalidData = {
          amount: -10.00, // 负数金额
          currency: 'CNY',
          paymentMethod: 'alipay'
        };

        const response = await request(app)
          .post('/api/v1/payments/create')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidData);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('code', 400);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 for non-existent routes', async () => {
      const response = await request(app)
        .get('/api/v1/non-existent-route');

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('code', 404);
      expect(response.body).toHaveProperty('message');
    });

    it('should handle malformed JSON', async () => {
      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');

      expect(response.status).toBe(400);
    });

    it('should include proper CORS headers', async () => {
      const response = await request(app)
        .options('/api/v1/annotations')
        .set('Origin', 'http://localhost:3000');

      expect(response.headers).toHaveProperty('access-control-allow-origin');
      expect(response.headers).toHaveProperty('access-control-allow-methods');
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to sensitive endpoints', async () => {
      // 快速发送多个请求测试限流
      const requests = Array(10).fill(null).map(() => 
        request(app)
          .post('/api/v1/auth/send-code')
          .send({ phone: '13800138000' })
      );

      const responses = await Promise.all(requests);
      
      // 应该有一些请求被限流（返回429状态码）
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('Security Headers', () => {
    it('should include security headers', async () => {
      const response = await request(app)
        .get('/api/v1/annotations');

      expect(response.headers).toHaveProperty('x-content-type-options');
      expect(response.headers).toHaveProperty('x-frame-options');
      expect(response.headers).toHaveProperty('x-xss-protection');
    });
  });
});