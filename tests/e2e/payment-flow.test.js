const request = require('supertest');
const app = require('../setup/testServer');
const { db } = require('../setup/testDatabase');

describe('Payment Flow E2E Tests', () => {
  let authToken;
  let userId;
  let annotationId;

  beforeAll(async () => {
    // 创建测试用户并获取认证令牌
    const userResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'testuser_payment@example.com',
        password: 'Test123!@#',
        username: 'testuser_payment'
      });
    
    console.log('User registration response:', JSON.stringify(userResponse.body, null, 2));
    console.log('User registration status:', userResponse.status);
    console.log('User registration headers:', userResponse.headers);
    
    if (!userResponse.body.data) {
      console.error('Registration failed with response:', userResponse.body);
      throw new Error(`Registration failed: ${userResponse.body.message || 'Unknown error'}`);
    }
    
    userId = userResponse.body.data.user.id;
    authToken = userResponse.body.data.tokens.accessToken;

    // 创建测试标注
    const annotationResponse = await request(app)
      .post('/api/v1/annotations')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        content: 'Test annotation for payment',
        latitude: 39.9042,
        longitude: 116.4074,
        price: 10.00
      });
    
    annotationId = annotationResponse.body.data.id;
  });

  afterAll(async () => {
    // 清理测试数据
    await db('payments').where('user_id', userId).del();
    await db('annotations').where('id', annotationId).del();
    await db('users').where('id', userId).del();
  });

  describe('Payment Session Creation', () => {
    test('should create payment session successfully', async () => {
      const response = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          amount: 10.00,
          currency: 'CNY'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('sessionId');
      expect(response.body.data).toHaveProperty('clientSecret');
      expect(response.body.data.amount).toBe(10.00);
    });

    test('should fail with invalid annotation ID', async () => {
      const response = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: 'invalid-id',
          amount: 10.00,
          currency: 'CNY'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid annotation');
    });

    test('should fail with invalid amount', async () => {
      const response = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          amount: -5.00,
          currency: 'CNY'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid amount');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .post('/api/v1/payments/create-session')
        .send({
          annotationId: annotationId,
          amount: 10.00,
          currency: 'CNY'
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Payment Status Verification', () => {
    let sessionId;

    beforeEach(async () => {
      // 创建支付会话
      const sessionResponse = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          amount: 10.00,
          currency: 'CNY'
        });
      
      sessionId = sessionResponse.body.data.sessionId;
    });

    test('should get payment session status', async () => {
      const response = await request(app)
        .get(`/api/v1/payments/session/${sessionId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('status');
      expect(response.body.data).toHaveProperty('amount');
      expect(response.body.data.amount).toBe(10.00);
    });

    test('should fail with invalid session ID', async () => {
      const response = await request(app)
        .get('/api/v1/payments/session/invalid-session-id')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Payment History', () => {
    test('should get user payment history', async () => {
      const response = await request(app)
        .get('/api/v1/payments/history')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    test('should get payment history with pagination', async () => {
      const response = await request(app)
        .get('/api/v1/payments/history?page=1&limit=10')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('payments');
      expect(response.body.data).toHaveProperty('pagination');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/payments/history');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Payment Statistics', () => {
    test('should get payment statistics', async () => {
      const response = await request(app)
        .get('/api/v1/payments/stats')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalAmount');
      expect(response.body.data).toHaveProperty('totalTransactions');
      expect(response.body.data).toHaveProperty('averageAmount');
    });

    test('should get payment statistics with date range', async () => {
      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date().toISOString();
      
      const response = await request(app)
        .get(`/api/v1/payments/stats?startDate=${startDate}&endDate=${endDate}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalAmount');
    });
  });

  describe('Database Integration', () => {
    test('should verify payment record in database', async () => {
      // 创建支付会话
      const sessionResponse = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          amount: 15.00,
          currency: 'CNY'
        });

      const sessionId = sessionResponse.body.data.sessionId;

      // 验证数据库中的记录
      const dbResult = await db('payments')
        .where('session_id', sessionId)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].user_id).toBe(userId);
      expect(dbResult[0].annotation_id).toBe(annotationId);
      expect(parseFloat(dbResult[0].amount)).toBe(15.00);
      expect(dbResult[0].status).toBe('pending');
    });

    test('should verify payment history query from database', async () => {
      const response = await request(app)
        .get('/api/v1/payments/history')
        .set('Authorization', `Bearer ${authToken}`);

      // 验证返回的数据与数据库一致
      const dbResult = await db('payments')
        .where('user_id', userId)
        .count('* as count')
        .first();

      expect(response.body.data.length).toBe(dbResult.count);
    });
  });

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      // 模拟数据库连接错误的情况
      const originalSelect = db.select;
      db.select = jest.fn().mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .get('/api/v1/payments/history')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Internal server error');

      // 恢复原始函数
      db.select = originalSelect;
    });

    test('should handle invalid payment data', async () => {
      const response = await request(app)
        .post('/api/v1/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          amount: 'invalid-amount',
          currency: 'INVALID'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');
    });
  });
});