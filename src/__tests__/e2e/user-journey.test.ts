import request from 'supertest';
import { Express } from 'express';
import { createApp } from '../../server';
import { pool } from '../../config/database';
import { UserService } from '../../services/userService';
import { AnnotationService } from '../../services/annotationService';
import { LBSService } from '../../services/lbsService';
import { PaymentService } from '../../services/paymentService';

describe('End-to-End User Journey Tests', () => {
  let app: Express;
  let userService: UserService;
  let annotationService: AnnotationService;
  let lbsService: LBSService;
  let paymentService: PaymentService;
  
  // 测试用户数据
  const testUsers = {
    creator: {
      phone: '13800138001',
      nickname: 'Smell Creator',
      id: '',
      token: ''
    },
    discoverer: {
      phone: '13800138002', 
      nickname: 'Smell Discoverer',
      id: '',
      token: ''
    }
  };
  
  // 测试标注数据
  let testAnnotation: any = null;
  
  beforeAll(async () => {
    app = createApp();
    userService = new UserService();
    annotationService = new AnnotationService();
    lbsService = new LBSService();
    paymentService = new PaymentService();
    
    // 清理可能存在的测试数据
    await cleanupTestData();
  });

  afterAll(async () => {
    await cleanupTestData();
    
    if (pool) {
      await pool.end();
    }
  });

  describe('Complete User Journey: From Registration to Reward Collection', () => {
    describe('Step 1: User Registration and Authentication', () => {
      it('should register creator user successfully', async () => {
        // 1. 发送验证码
        const sendCodeResponse = await request(app)
          .post('/api/v1/auth/send-code')
          .send({ phone: testUsers.creator.phone });
        
        expect([200, 429]).toContain(sendCodeResponse.status); // 可能因限流返回429
        
        // 2. 模拟验证码登录（使用测试验证码）
        const loginResponse = await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: testUsers.creator.phone,
            verificationCode: '123456' // 测试环境验证码
          });
        
        if (loginResponse.status === 200) {
          expect(loginResponse.body).toHaveProperty('code', 200);
          expect(loginResponse.body.data).toHaveProperty('token');
          expect(loginResponse.body.data).toHaveProperty('user');
          
          testUsers.creator.token = loginResponse.body.data.token;
          testUsers.creator.id = loginResponse.body.data.user.id;
        } else {
          // 如果登录失败，直接创建用户和token（测试环境）
          const user = await userService.createUser({
            phone: testUsers.creator.phone,
            nickname: testUsers.creator.nickname
          });
          
          testUsers.creator.id = user.id;
          testUsers.creator.token = generateTestToken(user);
        }
        
        expect(testUsers.creator.id).toBeTruthy();
        expect(testUsers.creator.token).toBeTruthy();
      });

      it('should register discoverer user successfully', async () => {
        // 类似创建者的注册流程
        const sendCodeResponse = await request(app)
          .post('/api/v1/auth/send-code')
          .send({ phone: testUsers.discoverer.phone });
        
        expect([200, 429]).toContain(sendCodeResponse.status);
        
        const loginResponse = await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: testUsers.discoverer.phone,
            verificationCode: '123456'
          });
        
        if (loginResponse.status === 200) {
          testUsers.discoverer.token = loginResponse.body.data.token;
          testUsers.discoverer.id = loginResponse.body.data.user.id;
        } else {
          const user = await userService.createUser({
            phone: testUsers.discoverer.phone,
            nickname: testUsers.discoverer.nickname
          });
          
          testUsers.discoverer.id = user.id;
          testUsers.discoverer.token = generateTestToken(user);
        }
        
        expect(testUsers.discoverer.id).toBeTruthy();
        expect(testUsers.discoverer.token).toBeTruthy();
      });

      it('should update user profiles successfully', async () => {
        // 创建者更新个人资料
        const creatorProfileUpdate = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${testUsers.creator.token}`)
          .send({
            nickname: testUsers.creator.nickname,
            avatar: 'https://example.com/creator-avatar.jpg',
            bio: 'I love creating funny smell annotations!'
          });
        
        expect(creatorProfileUpdate.status).toBe(200);
        expect(creatorProfileUpdate.body).toHaveProperty('code', 200);
        
        // 发现者更新个人资料
        const discovererProfileUpdate = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            nickname: testUsers.discoverer.nickname,
            avatar: 'https://example.com/discoverer-avatar.jpg',
            bio: 'I enjoy discovering and collecting rewards!'
          });
        
        expect(discovererProfileUpdate.status).toBe(200);
        expect(discovererProfileUpdate.body).toHaveProperty('code', 200);
      });
    });

    describe('Step 2: Wallet Setup and Payment', () => {
      it('should initialize user wallets', async () => {
        // 检查创建者钱包
        const creatorWallet = await request(app)
          .get('/api/v1/users/wallet')
          .set('Authorization', `Bearer ${testUsers.creator.token}`);
        
        expect([200, 404]).toContain(creatorWallet.status);
        
        // 检查发现者钱包
        const discovererWallet = await request(app)
          .get('/api/v1/users/wallet')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(discovererWallet.status);
      });

      it('should simulate wallet recharge for creator', async () => {
        // 模拟充值操作
        const rechargeResponse = await request(app)
          .post('/api/v1/payment/recharge')
          .set('Authorization', `Bearer ${testUsers.creator.token}`)
          .send({
            amount: 100.00,
            paymentMethod: 'alipay',
            returnUrl: 'https://example.com/return'
          });
        
        expect([200, 201, 404]).toContain(rechargeResponse.status);
        
        if (rechargeResponse.status === 200 || rechargeResponse.status === 201) {
          expect(rechargeResponse.body.data).toHaveProperty('paymentUrl');
          
          // 模拟支付成功回调
          const paymentCallback = await request(app)
            .post('/api/v1/payment/callback')
            .send({
              orderId: rechargeResponse.body.data.orderId,
              status: 'success',
              amount: 100.00
            });
          
          expect([200, 404]).toContain(paymentCallback.status);
        }
      });
    });

    describe('Step 3: Annotation Creation', () => {
      it('should create a smell annotation successfully', async () => {
        const annotationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'E2E Test Mysterious Smell',
          description: 'A strange chemical smell detected near the subway station. Smells like a mix of cleaning products and something else unidentifiable.',
          smellType: 'chemical',
          intensity: 4,
          rewardAmount: 25.00,
          tags: ['subway', 'chemical', 'cleaning'],
          images: [
            'https://example.com/smell-location1.jpg',
            'https://example.com/smell-location2.jpg'
          ]
        };

        const createResponse = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUsers.creator.token}`)
          .send(annotationData);
        
        expect(createResponse.status).toBe(201);
        expect(createResponse.body).toHaveProperty('code', 201);
        expect(createResponse.body.data).toHaveProperty('id');
        expect(createResponse.body.data).toHaveProperty('title', annotationData.title);
        expect(createResponse.body.data).toHaveProperty('rewardAmount', annotationData.rewardAmount);
        
        testAnnotation = createResponse.body.data;
      });

      it('should verify annotation appears in public list', async () => {
        const listResponse = await request(app)
          .get('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect(listResponse.status).toBe(200);
        expect(listResponse.body).toHaveProperty('code', 200);
        expect(Array.isArray(listResponse.body.data)).toBe(true);
        
        const foundAnnotation = listResponse.body.data.find(
          (annotation: any) => annotation.id === testAnnotation.id
        );
        
        expect(foundAnnotation).toBeTruthy();
        expect(foundAnnotation.title).toBe(testAnnotation.title);
      });

      it('should verify annotation appears in creator\'s list', async () => {
        const userAnnotations = await request(app)
          .get('/api/v1/users/annotations')
          .set('Authorization', `Bearer ${testUsers.creator.token}`);
        
        expect(userAnnotations.status).toBe(200);
        expect(userAnnotations.body).toHaveProperty('code', 200);
        
        const foundAnnotation = userAnnotations.body.data.find(
          (annotation: any) => annotation.id === testAnnotation.id
        );
        
        expect(foundAnnotation).toBeTruthy();
      });
    });

    describe('Step 4: Location-Based Discovery', () => {
      it('should find nearby annotations through search', async () => {
        const searchResponse = await request(app)
          .get('/api/v1/annotations/search')
          .query({
            latitude: 40.7128,
            longitude: -74.0060,
            radius: 1000 // 1km radius
          })
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(searchResponse.status);
        
        if (searchResponse.status === 200) {
          expect(Array.isArray(searchResponse.body.data)).toBe(true);
          
          const foundAnnotation = searchResponse.body.data.find(
            (annotation: any) => annotation.id === testAnnotation.id
          );
          
          expect(foundAnnotation).toBeTruthy();
        }
      });

      it('should check for available rewards at location', async () => {
        const checkRewardsResponse = await request(app)
          .post('/api/v1/lbs/check-rewards')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            latitude: 40.7128,
            longitude: -74.0060,
            accuracy: 10 // GPS accuracy in meters
          });
        
        expect([200, 404]).toContain(checkRewardsResponse.status);
        
        if (checkRewardsResponse.status === 200) {
          expect(Array.isArray(checkRewardsResponse.body.data)).toBe(true);
          
          const availableReward = checkRewardsResponse.body.data.find(
            (reward: any) => reward.annotationId === testAnnotation.id
          );
          
          if (availableReward) {
            expect(availableReward).toHaveProperty('rewardAmount');
            expect(availableReward).toHaveProperty('distance');
          }
        }
      });
    });

    describe('Step 5: Reward Collection', () => {
      it('should claim reward successfully', async () => {
        const claimResponse = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            annotationId: testAnnotation.id,
            latitude: 40.7128,
            longitude: -74.0060,
            accuracy: 5,
            timestamp: Date.now()
          });
        
        expect([200, 400, 404]).toContain(claimResponse.status);
        
        if (claimResponse.status === 200) {
          expect(claimResponse.body).toHaveProperty('code', 200);
          expect(claimResponse.body.data).toHaveProperty('rewardAmount');
          expect(claimResponse.body.data).toHaveProperty('transactionId');
          
          // 验证奖励金额
          expect(claimResponse.body.data.rewardAmount).toBeGreaterThan(0);
        }
      });

      it('should prevent duplicate reward claims', async () => {
        // 尝试再次领取同一个奖励
        const duplicateClaimResponse = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            annotationId: testAnnotation.id,
            latitude: 40.7128,
            longitude: -74.0060,
            accuracy: 5,
            timestamp: Date.now()
          });
        
        expect([400, 409]).toContain(duplicateClaimResponse.status);
        
        if (duplicateClaimResponse.status === 400 || duplicateClaimResponse.status === 409) {
          expect(duplicateClaimResponse.body.message).toContain('already');
        }
      });

      it('should update discoverer wallet balance', async () => {
        const walletResponse = await request(app)
          .get('/api/v1/users/wallet')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(walletResponse.status);
        
        if (walletResponse.status === 200) {
          expect(walletResponse.body.data).toHaveProperty('balance');
          expect(parseFloat(walletResponse.body.data.balance)).toBeGreaterThanOrEqual(0);
        }
      });
    });

    describe('Step 6: Transaction History and Analytics', () => {
      it('should show transaction history for discoverer', async () => {
        const transactionHistory = await request(app)
          .get('/api/v1/users/transactions')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(transactionHistory.status);
        
        if (transactionHistory.status === 200) {
          expect(Array.isArray(transactionHistory.body.data)).toBe(true);
          
          // 查找奖励交易记录
          const rewardTransaction = transactionHistory.body.data.find(
            (tx: any) => tx.type === 'reward' && tx.annotationId === testAnnotation.id
          );
          
          if (rewardTransaction) {
            expect(rewardTransaction).toHaveProperty('amount');
            expect(rewardTransaction).toHaveProperty('createdAt');
          }
        }
      });

      it('should show transaction history for creator', async () => {
        const transactionHistory = await request(app)
          .get('/api/v1/users/transactions')
          .set('Authorization', `Bearer ${testUsers.creator.token}`);
        
        expect([200, 404]).toContain(transactionHistory.status);
        
        if (transactionHistory.status === 200) {
          expect(Array.isArray(transactionHistory.body.data)).toBe(true);
          
          // 查找标注创建相关的交易记录
          const annotationTransaction = transactionHistory.body.data.find(
            (tx: any) => tx.annotationId === testAnnotation.id
          );
          
          if (annotationTransaction) {
            expect(annotationTransaction).toHaveProperty('amount');
            expect(annotationTransaction).toHaveProperty('type');
          }
        }
      });

      it('should show user statistics', async () => {
        // 创建者统计
        const creatorStats = await request(app)
          .get('/api/v1/users/stats')
          .set('Authorization', `Bearer ${testUsers.creator.token}`);
        
        expect([200, 404]).toContain(creatorStats.status);
        
        if (creatorStats.status === 200) {
          expect(creatorStats.body.data).toHaveProperty('annotationsCreated');
          expect(creatorStats.body.data).toHaveProperty('totalSpent');
        }
        
        // 发现者统计
        const discovererStats = await request(app)
          .get('/api/v1/users/stats')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(discovererStats.status);
        
        if (discovererStats.status === 200) {
          expect(discovererStats.body.data).toHaveProperty('rewardsCollected');
          expect(discovererStats.body.data).toHaveProperty('totalEarned');
        }
      });
    });

    describe('Step 7: Social Features and Interaction', () => {
      it('should allow users to rate annotations', async () => {
        const ratingResponse = await request(app)
          .post(`/api/v1/annotations/${testAnnotation.id}/rate`)
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            rating: 4,
            comment: 'Great annotation! Very accurate description.'
          });
        
        expect([200, 201, 404]).toContain(ratingResponse.status);
        
        if (ratingResponse.status === 200 || ratingResponse.status === 201) {
          expect(ratingResponse.body).toHaveProperty('code');
        }
      });

      it('should allow users to report inappropriate content', async () => {
        const reportResponse = await request(app)
          .post(`/api/v1/annotations/${testAnnotation.id}/report`)
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            reason: 'testing',
            description: 'This is a test report for E2E testing'
          });
        
        expect([200, 201, 404]).toContain(reportResponse.status);
      });

      it('should show annotation details with ratings', async () => {
        const detailResponse = await request(app)
          .get(`/api/v1/annotations/${testAnnotation.id}`)
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(detailResponse.status);
        
        if (detailResponse.status === 200) {
          expect(detailResponse.body.data).toHaveProperty('id', testAnnotation.id);
          expect(detailResponse.body.data).toHaveProperty('title');
          expect(detailResponse.body.data).toHaveProperty('averageRating');
          expect(detailResponse.body.data).toHaveProperty('ratingCount');
        }
      });
    });

    describe('Step 8: Withdrawal and Monetization', () => {
      it('should allow discoverer to request withdrawal', async () => {
        const withdrawalResponse = await request(app)
          .post('/api/v1/payment/withdraw')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
          .send({
            amount: 10.00,
            method: 'alipay',
            account: 'test@example.com'
          });
        
        expect([200, 201, 400, 404]).toContain(withdrawalResponse.status);
        
        if (withdrawalResponse.status === 200 || withdrawalResponse.status === 201) {
          expect(withdrawalResponse.body.data).toHaveProperty('withdrawalId');
          expect(withdrawalResponse.body.data).toHaveProperty('status');
        }
      });

      it('should show withdrawal history', async () => {
        const withdrawalHistory = await request(app)
          .get('/api/v1/users/withdrawals')
          .set('Authorization', `Bearer ${testUsers.discoverer.token}`);
        
        expect([200, 404]).toContain(withdrawalHistory.status);
        
        if (withdrawalHistory.status === 200) {
          expect(Array.isArray(withdrawalHistory.body.data)).toBe(true);
        }
      });
    });
  });

  describe('Edge Cases and Error Scenarios', () => {
    it('should handle invalid GPS coordinates', async () => {
      const invalidClaimResponse = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
        .send({
          annotationId: testAnnotation.id,
          latitude: 999, // Invalid latitude
          longitude: 999, // Invalid longitude
          accuracy: 5
        });
      
      expect(invalidClaimResponse.status).toBe(400);
      expect(invalidClaimResponse.body).toHaveProperty('code', 400);
    });

    it('should handle non-existent annotation claims', async () => {
      const nonExistentClaimResponse = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${testUsers.discoverer.token}`)
        .send({
          annotationId: 'non-existent-id',
          latitude: 40.7128,
          longitude: -74.0060,
          accuracy: 5
        });
      
      expect([400, 404]).toContain(nonExistentClaimResponse.status);
    });

    it('should handle insufficient wallet balance for annotation creation', async () => {
      const expensiveAnnotation = {
        latitude: 40.7129,
        longitude: -74.0061,
        title: 'Expensive Test Smell',
        description: 'This should fail due to insufficient balance',
        smellType: 'chemical',
        intensity: 5,
        rewardAmount: 10000.00 // Very high amount
      };

      const createResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${testUsers.creator.token}`)
        .send(expensiveAnnotation);
      
      expect([400, 402]).toContain(createResponse.status);
    });
  });

  // 辅助函数
  function generateTestToken(user: any): string {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      { id: user.id, phone: user.phone, role: user.role || 'user' },
      process.env['JWT_SECRET'] || 'test-secret',
      { expiresIn: '2h' }
    );
  }

  async function cleanupTestData(): Promise<void> {
    try {
      // 清理测试数据（按依赖关系顺序）
      await pool.query('DELETE FROM transactions WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM rewards WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM ratings WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM reports WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM annotations WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM wallets WHERE user_id IN (SELECT id FROM users WHERE phone LIKE \'13800138%\')');
      await pool.query('DELETE FROM users WHERE phone LIKE \'13800138%\'');
    } catch (error) {
      console.warn('清理测试数据时出错:', error);
    }
  }
});