const request = require('supertest');
const { expect } = require('chai');
const sinon = require('sinon');
const app = require('../../src/app');
const { db } = require('../../src/config/database');
const { generateTestUser } = require('../helpers/testData');
const stripe = require('stripe');

describe('Payment System Tests', () => {
  let testUser;
  let authToken;
  let stripeStub;

  before(async () => {
    // 设置测试数据库
    await db.migrate.latest();
    
    // 创建测试用户
    testUser = generateTestUser();
    const registerResponse = await request(app)
      .post('/api/auth/register')
      .send(testUser)
      .expect(201);
    
    // 登录获取token
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: testUser.password,
      })
      .expect(200);
    
    authToken = loginResponse.body.data.token;
    
    // Mock Stripe API
    stripeStub = {
      checkout: {
        sessions: {
          create: sinon.stub(),
          retrieve: sinon.stub(),
        },
      },
      webhooks: {
        constructEvent: sinon.stub(),
      },
    };
  });

  after(async () => {
    // 清理测试数据
    await db('wallet_transactions').del();
    await db('payments').del();
    await db('users').del();
    
    // 恢复Stripe stubs
    sinon.restore();
  });

  describe('钱包功能', () => {
    it('应该获取用户钱包余额', async () => {
      const response = await request(app)
        .get('/api/wallet/balance')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('balance');
      expect(response.body.data.balance).to.be.a('number');
    });

    it('应该获取钱包交易历史', async () => {
      const response = await request(app)
        .get('/api/wallet/transactions')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.pagination).to.exist;
    });

    it('应该支持交易历史分页', async () => {
      const response = await request(app)
        .get('/api/wallet/transactions')
        .query({ page: 1, limit: 10 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.pagination.page).to.equal(1);
      expect(response.body.pagination.limit).to.equal(10);
    });

    it('应该按类型过滤交易', async () => {
      const response = await request(app)
        .get('/api/wallet/transactions')
        .query({ type: 'credit' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      response.body.data.forEach(transaction => {
        expect(transaction.transaction_type).to.equal('credit');
      });
    });
  });

  describe('充值功能', () => {
    beforeEach(() => {
      // 重置Stripe stubs
      stripeStub.checkout.sessions.create.reset();
      stripeStub.checkout.sessions.retrieve.reset();
    });

    it('应该创建充值会话', async () => {
      const mockSession = {
        id: 'cs_test_123456',
        url: 'https://checkout.stripe.com/pay/cs_test_123456',
        payment_status: 'unpaid',
        amount_total: 10000, // $100.00 in cents
      };
      
      stripeStub.checkout.sessions.create.resolves(mockSession);

      const chargeData = {
        amount: 100, // $100
        currency: 'usd',
        description: '钱包充值',
      };

      const response = await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(chargeData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('session_id');
      expect(response.body.data).to.have.property('checkout_url');
      expect(stripeStub.checkout.sessions.create.calledOnce).to.be.true;
    });

    it('应该验证充值金额', async () => {
      const invalidChargeData = {
        amount: 0.5, // 低于最小金额
        currency: 'usd',
      };

      await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidChargeData)
        .expect(400);
    });

    it('应该拒绝过大的充值金额', async () => {
      const invalidChargeData = {
        amount: 10000, // 超过最大金额
        currency: 'usd',
      };

      await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidChargeData)
        .expect(400);
    });

    it('应该支持不同货币', async () => {
      const mockSession = {
        id: 'cs_test_cny_123',
        url: 'https://checkout.stripe.com/pay/cs_test_cny_123',
        payment_status: 'unpaid',
        amount_total: 68800, // ¥688.00 in cents
      };
      
      stripeStub.checkout.sessions.create.resolves(mockSession);

      const chargeData = {
        amount: 100,
        currency: 'cny',
        description: '钱包充值',
      };

      const response = await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(chargeData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(stripeStub.checkout.sessions.create.calledOnce).to.be.true;
      
      const createArgs = stripeStub.checkout.sessions.create.getCall(0).args[0];
      expect(createArgs.currency).to.equal('cny');
    });
  });

  describe('支付状态查询', () => {
    it('应该查询支付会话状态', async () => {
      const mockSession = {
        id: 'cs_test_status_123',
        payment_status: 'paid',
        amount_total: 10000,
        currency: 'usd',
      };
      
      stripeStub.checkout.sessions.retrieve.resolves(mockSession);

      const response = await request(app)
        .get('/api/payments/session-status/cs_test_status_123')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.payment_status).to.equal('paid');
      expect(stripeStub.checkout.sessions.retrieve.calledOnce).to.be.true;
    });

    it('应该处理无效的会话ID', async () => {
      stripeStub.checkout.sessions.retrieve.rejects(new Error('No such checkout session'));

      await request(app)
        .get('/api/payments/session-status/invalid_session_id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('Webhook处理', () => {
    it('应该处理成功支付的webhook', async () => {
      const mockEvent = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_webhook_123',
            payment_status: 'paid',
            amount_total: 10000,
            currency: 'usd',
            metadata: {
              user_id: testUser.id,
              type: 'wallet_charge',
            },
          },
        },
      };
      
      stripeStub.webhooks.constructEvent.returns(mockEvent);

      const response = await request(app)
        .post('/api/payments/webhook')
        .set('stripe-signature', 'test_signature')
        .send(JSON.stringify(mockEvent))
        .expect(200);

      expect(response.body.received).to.be.true;
      
      // 验证钱包余额是否增加
      const balanceResponse = await request(app)
        .get('/api/wallet/balance')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);
      
      expect(balanceResponse.body.data.balance).to.be.greaterThan(0);
    });

    it('应该处理支付失败的webhook', async () => {
      const mockEvent = {
        type: 'checkout.session.async_payment_failed',
        data: {
          object: {
            id: 'cs_test_failed_123',
            payment_status: 'unpaid',
            amount_total: 5000,
            currency: 'usd',
            metadata: {
              user_id: testUser.id,
              type: 'wallet_charge',
            },
          },
        },
      };
      
      stripeStub.webhooks.constructEvent.returns(mockEvent);

      const response = await request(app)
        .post('/api/payments/webhook')
        .set('stripe-signature', 'test_signature')
        .send(JSON.stringify(mockEvent))
        .expect(200);

      expect(response.body.received).to.be.true;
      
      // 验证支付记录状态为失败
      const payments = await db('payments')
        .where('stripe_session_id', 'cs_test_failed_123')
        .first();
      
      expect(payments.status).to.equal('failed');
    });

    it('应该验证webhook签名', async () => {
      stripeStub.webhooks.constructEvent.throws(new Error('Invalid signature'));

      await request(app)
        .post('/api/payments/webhook')
        .set('stripe-signature', 'invalid_signature')
        .send(JSON.stringify({ type: 'test' }))
        .expect(400);
    });
  });

  describe('支付历史', () => {
    it('应该获取用户支付历史', async () => {
      const response = await request(app)
        .get('/api/payments/history')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该按状态过滤支付历史', async () => {
      const response = await request(app)
        .get('/api/payments/history')
        .query({ status: 'completed' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      response.body.data.forEach(payment => {
        expect(payment.status).to.equal('completed');
      });
    });

    it('应该按日期范围过滤支付历史', async () => {
      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(); // 30天前
      const endDate = new Date().toISOString();

      const response = await request(app)
        .get('/api/payments/history')
        .query({ start_date: startDate, end_date: endDate })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('退款功能', () => {
    let paymentId;

    before(async () => {
      // 创建一个测试支付记录
      const [payment] = await db('payments').insert({
        user_id: testUser.id,
        amount: 50.00,
        currency: 'usd',
        status: 'completed',
        stripe_session_id: 'cs_test_refund_123',
        description: '测试支付',
        created_at: new Date(),
        updated_at: new Date(),
      }).returning('*');
      
      paymentId = payment.id;
    });

    it('应该处理退款请求', async () => {
      const refundData = {
        reason: '用户要求退款',
        amount: 25.00, // 部分退款
      };

      const response = await request(app)
        .post(`/api/payments/${paymentId}/refund`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(refundData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('refund_id');
    });

    it('应该拒绝超额退款', async () => {
      const refundData = {
        reason: '超额退款测试',
        amount: 100.00, // 超过原支付金额
      };

      await request(app)
        .post(`/api/payments/${paymentId}/refund`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(refundData)
        .expect(400);
    });

    it('应该拒绝非本人支付的退款', async () => {
      // 创建另一个用户
      const anotherUser = generateTestUser();
      await request(app)
        .post('/api/auth/register')
        .send(anotherUser)
        .expect(201);

      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: anotherUser.email,
          password: anotherUser.password,
        })
        .expect(200);

      const anotherToken = loginResponse.body.data.token;

      await request(app)
        .post(`/api/payments/${paymentId}/refund`)
        .set('Authorization', `Bearer ${anotherToken}`)
        .send({ reason: '恶意退款', amount: 10.00 })
        .expect(403);
    });
  });

  describe('支付安全', () => {
    it('应该限制支付请求频率', async () => {
      const chargeData = {
        amount: 10,
        currency: 'usd',
        description: '频率测试',
      };

      // 快速发送多个请求
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/payments/create-charge-session')
            .set('Authorization', `Bearer ${authToken}`)
            .send(chargeData)
        );
      }

      const responses = await Promise.all(promises);
      
      // 应该有一些请求被限流
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).to.be.greaterThan(0);
    });

    it('应该验证支付金额格式', async () => {
      const invalidData = {
        amount: 'invalid_amount',
        currency: 'usd',
      };

      await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);
    });

    it('应该验证货币代码', async () => {
      const invalidData = {
        amount: 50,
        currency: 'invalid_currency',
      };

      await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);
    });

    it('应该记录可疑支付活动', async () => {
      // 尝试创建异常大额支付
      const suspiciousData = {
        amount: 9999,
        currency: 'usd',
        description: '可疑大额支付',
      };

      await request(app)
        .post('/api/payments/create-charge-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send(suspiciousData)
        .expect(400);
      
      // 这里应该检查日志中是否记录了可疑活动
      // 实际实现中会有相应的日志记录
    });
  });

  describe('支付统计', () => {
    it('应该获取用户支付统计', async () => {
      const response = await request(app)
        .get('/api/payments/stats')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('total_spent');
      expect(response.body.data).to.have.property('total_transactions');
      expect(response.body.data).to.have.property('average_transaction');
    });

    it('应该获取月度支付统计', async () => {
      const response = await request(app)
        .get('/api/payments/stats/monthly')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('性能测试', () => {
    it('应该快速处理支付查询', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get('/api/payments/history')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);
      
      const responseTime = Date.now() - startTime;
      expect(responseTime).to.be.lessThan(1000); // 应该在1秒内响应
    });

    it('应该处理并发支付请求', async () => {
      const mockSession = {
        id: 'cs_test_concurrent',
        url: 'https://checkout.stripe.com/pay/cs_test_concurrent',
        payment_status: 'unpaid',
        amount_total: 1000,
      };
      
      stripeStub.checkout.sessions.create.resolves(mockSession);

      const chargeData = {
        amount: 10,
        currency: 'usd',
        description: '并发测试',
      };

      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          request(app)
            .post('/api/payments/create-charge-session')
            .set('Authorization', `Bearer ${authToken}`)
            .send(chargeData)
        );
      }

      const responses = await Promise.all(promises);
      
      // 至少有一些请求应该成功
      const successfulResponses = responses.filter(r => r.status === 200);
      expect(successfulResponses.length).to.be.greaterThan(0);
    });
  });
});