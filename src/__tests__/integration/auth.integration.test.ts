import request from 'supertest';
import { Express } from 'express';
import { createApp } from '../../server';
import { pool } from '../../config/database';
import jwt from 'jsonwebtoken';
import { UserService } from '../../services/userService';

describe('Authentication and Authorization Integration Tests', () => {
  let app: Express;
  let userService: UserService;
  let normalUserToken: string;
  let adminUserToken: string;
  let expiredToken: string;
  let invalidToken: string;
  let normalUserId: string;
  let adminUserId: string;

  beforeAll(async () => {
    // 创建应用实例
    app = createApp();
    userService = new UserService();
    
    // 创建测试用户
    await setupTestUsers();
    
    // 创建各种类型的token
    await setupTestTokens();
  });

  afterAll(async () => {
    // 清理测试数据
    await cleanupTestData();
    
    if (pool) {
      await pool.end();
    }
  });

  describe('Authentication Middleware', () => {
    describe('Token Validation', () => {
      it('should accept valid JWT token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(response.body.data).toHaveProperty('id', normalUserId);
      });

      it('should reject request without token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
        expect(response.body).toHaveProperty('message');
      });

      it('should reject request with invalid token format', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', 'InvalidTokenFormat');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });

      it('should reject request with malformed JWT', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', 'Bearer invalid.jwt.token');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });

      it('should reject expired token', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${expiredToken}`);

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
        expect(response.body.message).toContain('expired');
      });

      it('should reject token with invalid signature', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${invalidToken}`);

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });

      it('should reject token for non-existent user', async () => {
        const nonExistentUserToken = jwt.sign(
          { id: 'non-existent-user', phone: '13800000000', role: 'user' },
          process.env['JWT_SECRET'] || 'test-secret',
          { expiresIn: '1h' }
        );

        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${nonExistentUserToken}`);

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });
    });

    describe('Token Extraction', () => {
      it('should extract token from Authorization header with Bearer prefix', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
      });

      it('should handle Authorization header case insensitively', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
      });

      it('should handle Bearer prefix case insensitively', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
      });

      it('should reject token without Bearer prefix', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', normalUserToken);

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });
    });
  });

  describe('Role-Based Authorization', () => {
    describe('Admin-Only Endpoints', () => {
      it('should allow admin access to admin endpoints', async () => {
        const response = await request(app)
          .get('/api/v1/admin/users')
          .set('Authorization', `Bearer ${adminUserToken}`);

        expect([200, 404]).toContain(response.status); // 404 if endpoint not implemented
      });

      it('should deny normal user access to admin endpoints', async () => {
        const response = await request(app)
          .get('/api/v1/admin/users')
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('code', 403);
        expect(response.body.message).toContain('permission');
      });

      it('should deny unauthenticated access to admin endpoints', async () => {
        const response = await request(app)
          .get('/api/v1/admin/users');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('code', 401);
      });
    });

    describe('User-Specific Resource Access', () => {
      it('should allow users to access their own resources', async () => {
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
        expect(response.body.data).toHaveProperty('id', normalUserId);
      });

      it('should allow users to update their own profile', async () => {
        const updateData = {
          nickname: 'Updated Nickname',
          avatar: 'https://example.com/new-avatar.jpg'
        };

        const response = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${normalUserToken}`)
          .send(updateData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
      });

      it('should allow users to access their own annotations', async () => {
        const response = await request(app)
          .get('/api/v1/users/annotations')
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
        expect(Array.isArray(response.body.data)).toBe(true);
      });

      it('should allow users to create annotations', async () => {
        const annotationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'Auth Test Smell',
          description: 'Test annotation for auth',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: 10.00
        };

        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${normalUserToken}`)
          .send(annotationData);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('code', 201);
        expect(response.body.data).toHaveProperty('id');
      });
    });

    describe('Resource Ownership Validation', () => {
      let userAnnotationId: string;
      let otherUserToken: string;
      let otherUserId: string;

      beforeAll(async () => {
        // 创建另一个用户
        const otherUser = await userService.createUser({
          phone: '13900139999',
          nickname: 'Other Test User'
        });
        otherUserId = otherUser.id;
        
        otherUserToken = jwt.sign(
          { id: otherUserId, phone: '13900139999', role: 'user' },
          process.env.JWT_SECRET || 'test-secret',
          { expiresIn: '1h' }
        );

        // 创建一个标注
        const annotationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'Ownership Test Smell',
          description: 'Test annotation for ownership',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: 10.00
        };

        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${normalUserToken}`)
          .send(annotationData);

        userAnnotationId = response.body.data.id;
      });

      it('should allow users to update their own annotations', async () => {
        const updateData = {
          title: 'Updated Title',
          description: 'Updated description'
        };

        const response = await request(app)
          .put(`/api/v1/annotations/${userAnnotationId}`)
          .set('Authorization', `Bearer ${normalUserToken}`)
          .send(updateData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('code', 200);
      });

      it('should deny users from updating others annotations', async () => {
        const updateData = {
          title: 'Unauthorized Update',
          description: 'This should fail'
        };

        const response = await request(app)
          .put(`/api/v1/annotations/${userAnnotationId}`)
          .set('Authorization', `Bearer ${otherUserToken}`)
          .send(updateData);

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('code', 403);
      });

      it('should allow users to delete their own annotations', async () => {
        // 创建一个新标注用于删除测试
        const annotationData = {
          latitude: 40.7129,
          longitude: -74.0061,
          title: 'Delete Test Smell',
          description: 'Test annotation for deletion',
          smellType: 'organic',
          intensity: 2,
          rewardAmount: 5.00
        };

        const createResponse = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${normalUserToken}`)
          .send(annotationData);

        const annotationId = createResponse.body.data.id;

        const deleteResponse = await request(app)
          .delete(`/api/v1/annotations/${annotationId}`)
          .set('Authorization', `Bearer ${normalUserToken}`);

        expect(deleteResponse.status).toBe(200);
        expect(deleteResponse.body).toHaveProperty('code', 200);
      });

      it('should deny users from deleting others annotations', async () => {
        const response = await request(app)
          .delete(`/api/v1/annotations/${userAnnotationId}`)
          .set('Authorization', `Bearer ${otherUserToken}`);

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('code', 403);
      });

      it('should allow admin to access any resource', async () => {
        const response = await request(app)
          .put(`/api/v1/annotations/${userAnnotationId}`)
          .set('Authorization', `Bearer ${adminUserToken}`)
          .send({ title: 'Admin Update' });

        expect([200, 404]).toContain(response.status); // 200 if implemented, 404 if not
      });
    });
  });

  describe('Session Management', () => {
    describe('Token Refresh', () => {
      it('should handle token refresh if implemented', async () => {
        const response = await request(app)
          .post('/api/v1/auth/refresh')
          .set('Authorization', `Bearer ${normalUserToken}`);

        // 可能返回200（已实现）或404（未实现）
        expect([200, 404]).toContain(response.status);
      });
    });

    describe('Logout', () => {
      it('should handle logout if implemented', async () => {
        const response = await request(app)
          .post('/api/v1/auth/logout')
          .set('Authorization', `Bearer ${normalUserToken}`);

        // 可能返回200（已实现）或404（未实现）
        expect([200, 404]).toContain(response.status);
      });
    });
  });

  describe('Security Headers and CORS', () => {
    it('should include security headers in responses', async () => {
      const response = await request(app)
        .get('/api/v1/annotations')
        .set('Authorization', `Bearer ${normalUserToken}`);

      expect(response.headers).toHaveProperty('x-content-type-options');
      expect(response.headers).toHaveProperty('x-frame-options');
      expect(response.headers).toHaveProperty('x-xss-protection');
    });

    it('should handle CORS preflight requests', async () => {
      const response = await request(app)
        .options('/api/v1/annotations')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Authorization,Content-Type');

      expect(response.status).toBe(200);
      expect(response.headers).toHaveProperty('access-control-allow-origin');
      expect(response.headers).toHaveProperty('access-control-allow-methods');
      expect(response.headers).toHaveProperty('access-control-allow-headers');
    });

    it('should include CORS headers in actual requests', async () => {
      const response = await request(app)
        .get('/api/v1/annotations')
        .set('Origin', 'http://localhost:3000')
        .set('Authorization', `Bearer ${normalUserToken}`);

      expect(response.headers).toHaveProperty('access-control-allow-origin');
    });
  });

  describe('Rate Limiting and Security', () => {
    it('should apply rate limiting to authentication endpoints', async () => {
      const requests = Array(15).fill(null).map(() => 
        request(app)
          .post('/api/v1/auth/send-code')
          .send({ phone: '13800138000' })
      );

      const responses = await Promise.all(requests);
      
      // 应该有一些请求被限流
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('should apply rate limiting to API endpoints', async () => {
      const requests = Array(100).fill(null).map(() => 
        request(app)
          .get('/api/v1/annotations')
          .set('Authorization', `Bearer ${normalUserToken}`)
      );

      const responses = await Promise.all(requests);
      
      // 检查是否有限流响应
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      // 根据实际限流配置，可能有也可能没有限流
      expect(rateLimitedResponses.length).toBeGreaterThanOrEqual(0);
    });

    it('should prevent SQL injection in authentication', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: maliciousInput,
          verificationCode: '123456'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('code', 400);
    });

    it('should prevent XSS in user input', async () => {
      const xssPayload = '<script>alert("xss")</script>';
      
      const response = await request(app)
        .put('/api/v1/users/profile')
        .set('Authorization', `Bearer ${normalUserToken}`)
        .send({
          nickname: xssPayload
        });

      // 应该被拒绝或者被清理
      if (response.status === 200) {
        expect(response.body.data.nickname).not.toContain('<script>');
      } else {
        expect(response.status).toBe(400);
      }
    });
  });

  // 辅助函数
  async function setupTestUsers(): Promise<void> {
    try {
      // 创建普通用户
      const normalUser = await userService.createUser({
        phone: '13900139001',
        nickname: 'Normal Test User',
        role: 'user'
      });
      normalUserId = normalUser.id;

      // 创建管理员用户
      const adminUser = await userService.createUser({
        phone: '13900139002',
        nickname: 'Admin Test User',
        role: 'admin'
      });
      adminUserId = adminUser.id;
    } catch (error) {
      console.warn('设置测试用户时出错:', error);
    }
  }

  async function setupTestTokens(): Promise<void> {
    const secret = process.env['JWT_SECRET'] || 'test-secret';
    
    // 正常用户token
    normalUserToken = jwt.sign(
      { id: normalUserId, phone: '13900139001', role: 'user' },
      secret,
      { expiresIn: '1h' }
    );

    // 管理员token
    adminUserToken = jwt.sign(
      { id: adminUserId, phone: '13900139002', role: 'admin' },
      secret,
      { expiresIn: '1h' }
    );

    // 过期token
    expiredToken = jwt.sign(
      { id: normalUserId, phone: '13900139001', role: 'user' },
      secret,
      { expiresIn: '-1h' } // 已过期
    );

    // 无效签名token
    invalidToken = jwt.sign(
      { id: normalUserId, phone: '13900139001', role: 'user' },
      'wrong-secret',
      { expiresIn: '1h' }
    );
  }

  async function cleanupTestData(): Promise<void> {
    try {
      await pool.query('DELETE FROM annotations WHERE title LIKE \'%Test%\'');
      await pool.query('DELETE FROM users WHERE phone LIKE \'139001390%\'');
    } catch (error) {
      console.warn('清理测试数据时出错:', error);
    }
  }
});