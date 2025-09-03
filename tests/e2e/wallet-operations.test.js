const request = require('supertest');
const app = require('../setup/testServer');
const { db } = require('../setup/testDatabase');

describe('Wallet Operations E2E Tests', () => {
  let authToken;
  let userId;
  let walletId;

  beforeAll(async () => {
    // 创建测试用户并获取认证令牌
    const userResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'testuser_wallet@example.com',
        password: 'test123456',
        username: 'testuser_wallet'
      });
    
    userId = userResponse.body.data.user.id;
    authToken = userResponse.body.data.tokens.accessToken;
  });

  afterAll(async () => {
    // 清理测试数据
    await db('wallet_transactions').where('wallet_id', walletId).del();
    await db('wallets').where('user_id', userId).del();
    await db('users').where('id', userId).del();
  });

  describe('Wallet Creation', () => {
    test('should create wallet successfully', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/create')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          currency: 'CNY'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('walletId');
      expect(response.body.data).toHaveProperty('balance');
      expect(response.body.data.balance).toBe(0);
      
      walletId = response.body.data.walletId;
    });

    test('should not create duplicate wallet', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/create')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          currency: 'CNY'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Wallet already exists');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/create')
        .send({
          currency: 'CNY'
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Wallet Balance Operations', () => {
    test('should get wallet balance', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('balance');
      expect(response.body.data).toHaveProperty('currency');
      expect(response.body.data.currency).toBe('CNY');
    });

    test('should fail to get balance without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/balance');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Wallet Recharge Operations', () => {
    test('should create recharge order successfully', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/recharge')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 100.00,
          paymentMethod: 'alipay'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('orderId');
      expect(response.body.data).toHaveProperty('paymentUrl');
      expect(response.body.data.amount).toBe(100.00);
    });

    test('should fail with invalid amount', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/recharge')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: -50.00,
          paymentMethod: 'alipay'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid amount');
    });

    test('should fail with unsupported payment method', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/recharge')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 100.00,
          paymentMethod: 'bitcoin'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unsupported payment method');
    });
  });

  describe('Transaction History', () => {
    beforeEach(async () => {
      // 创建一些测试交易记录
      await db('wallet_transactions').insert({
        wallet_id: walletId,
        type: 'recharge',
        amount: 50.00,
        description: 'Test recharge',
        status: 'completed'
      });
      await db('wallet_transactions').insert({
        wallet_id: walletId,
        type: 'payment',
        amount: -10.00,
        description: 'Test payment',
        status: 'completed'
      });
    });

    test('should get transaction history', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/transactions')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBeGreaterThan(0);
    });

    test('should get transaction history with pagination', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/transactions?page=1&limit=5')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('transactions');
      expect(response.body.data).toHaveProperty('pagination');
      expect(response.body.data.pagination).toHaveProperty('page');
      expect(response.body.data.pagination).toHaveProperty('limit');
    });

    test('should filter transactions by type', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/transactions?type=recharge')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      
      // 验证所有返回的交易都是充值类型
      response.body.data.forEach(transaction => {
        expect(transaction.type).toBe('recharge');
      });
    });
  });

  describe('Wallet Statistics', () => {
    test('should get wallet statistics', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/stats')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalRecharge');
      expect(response.body.data).toHaveProperty('totalSpent');
      expect(response.body.data).toHaveProperty('transactionCount');
      expect(response.body.data).toHaveProperty('currentBalance');
    });

    test('should get monthly statistics', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/stats/monthly')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe('LBS Reward Integration', () => {
    let annotationId;

    beforeEach(async () => {
      // 创建测试标注
      const annotationResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          content: 'Test annotation for LBS reward',
          latitude: 39.9042,
          longitude: 116.4074,
          price: 20.00
        });
      
      annotationId = annotationResponse.body.data.id;
    });

    afterEach(async () => {
      await db('annotations').where('id', annotationId).del();
    });

    test('should process LBS reward successfully', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/lbs-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('rewardAmount');
      expect(response.body.data).toHaveProperty('newBalance');
      expect(response.body.data.rewardAmount).toBeGreaterThan(0);
    });

    test('should fail LBS reward for same user twice', async () => {
      // 第一次获取奖励
      await request(app)
        .post('/api/v1/wallet/lbs-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      // 第二次尝试获取奖励
      const response = await request(app)
        .post('/api/v1/wallet/lbs-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Already claimed');
    });

    test('should fail LBS reward for invalid location', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/lbs-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: annotationId,
          latitude: 40.0000, // 距离太远
          longitude: 117.0000
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Too far from annotation');
    });
  });

  describe('Database Integration', () => {
    test('should verify wallet creation in database', async () => {
      const dbResult = await db('wallets')
        .where('user_id', userId)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].user_id).toBe(userId);
      expect(dbResult[0].currency).toBe('CNY');
      expect(parseFloat(dbResult[0].balance)).toBe(0);
    });

    test('should verify transaction records in database', async () => {
      const dbResult = await db('wallet_transactions')
        .where('wallet_id', walletId)
        .count('* as count')
        .first();

      const apiResponse = await request(app)
        .get('/api/v1/wallet/transactions')
        .set('Authorization', `Bearer ${authToken}`);

      expect(apiResponse.body.data.length).toBe(dbResult.count);
    });

    test('should verify balance calculation consistency', async () => {
      // 获取API返回的余额
      const balanceResponse = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${authToken}`);

      // 从数据库计算余额
      const dbResult = await db('wallet_transactions')
        .where('wallet_id', walletId)
        .where('status', 'completed')
        .sum('amount as calculated_balance')
        .first();

      const calculatedBalance = dbResult.calculated_balance || 0;
      expect(balanceResponse.body.data.balance).toBe(calculatedBalance);
    });
  });

  describe('Error Handling', () => {
    test('should handle insufficient balance', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/transfer')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 1000.00,
          targetUserId: 'some-user-id'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Insufficient balance');
    });

    test('should handle database transaction failures', async () => {
      // 模拟数据库事务失败
      const originalInsert = db.insert;
      db.insert = jest.fn().mockRejectedValue(new Error('Transaction failed'));

      const response = await request(app)
        .post('/api/v1/wallet/recharge')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 100.00,
          paymentMethod: 'alipay'
        });

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);

      // 恢复原始函数
      db.insert = originalInsert;
    });

    test('should handle invalid wallet operations', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/recharge')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 'invalid-amount',
          paymentMethod: 'alipay'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');
    });
  });
});}}}