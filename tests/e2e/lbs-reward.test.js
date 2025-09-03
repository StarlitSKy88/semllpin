const request = require('supertest');
const app = require('../setup/testServer');
const { db } = require('../setup/testDatabase');

describe('LBS Reward System E2E Tests', () => {
  let creatorToken, discovererToken;
  let creatorId, discovererId;
  let annotationId;
  let creatorWalletId, discovererWalletId;

  beforeAll(async () => {
    // 创建标注创建者用户
    const creatorResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'creator@example.com',
        password: 'test123456',
        username: 'creator_user'
      });
    
    creatorId = creatorResponse.body.data.user.id;
    creatorToken = creatorResponse.body.data.tokens.accessToken;

    // 创建标注发现者用户
    const discovererResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'discoverer@example.com',
        password: 'test123456',
        username: 'discoverer_user'
      });
    
    discovererId = discovererResponse.body.data.user.id;
    discovererToken = discovererResponse.body.data.tokens.accessToken;

    // 为两个用户创建钱包
    const creatorWalletResponse = await request(app)
      .post('/api/v1/wallet/create')
      .set('Authorization', `Bearer ${creatorToken}`)
      .send({ currency: 'CNY' });
    
    creatorWalletId = creatorWalletResponse.body.data.walletId;

    const discovererWalletResponse = await request(app)
      .post('/api/v1/wallet/create')
      .set('Authorization', `Bearer ${discovererToken}`)
      .send({ currency: 'CNY' });
    
    discovererWalletId = discovererWalletResponse.body.data.walletId;
  });

  afterAll(async () => {
    // 清理测试数据
    await db('lbs_rewards').where('annotation_id', annotationId).del();
    await db('wallet_transactions').whereIn('wallet_id', [creatorWalletId, discovererWalletId]).del();
    await db('annotations').where('id', annotationId).del();
    await db('wallets').whereIn('user_id', [creatorId, discovererId]).del();
    await db('users').whereIn('id', [creatorId, discovererId]).del();
  });

  describe('Annotation Creation for LBS', () => {
    test('should create annotation with reward pool', async () => {
      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${creatorToken}`)
        .send({
          content: 'Test LBS annotation with reward',
          latitude: 39.9042,
          longitude: 116.4074,
          price: 50.00,
          rewardPercentage: 30 // 30% 作为奖励池
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data).toHaveProperty('rewardPool');
      expect(response.body.data.rewardPool).toBe(15.00); // 50 * 0.3
      
      annotationId = response.body.data.id;
    });

    test('should verify annotation in database', async () => {
      const dbResult = await db('annotations').where('id', annotationId).select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].creator_id).toBe(creatorId);
      expect(parseFloat(dbResult[0].price)).toBe(50.00);
      expect(parseFloat(dbResult[0].reward_pool)).toBe(15.00);
    });
  });

  describe('LBS Discovery and Reward Distribution', () => {
    test('should trigger LBS reward when user enters geofence', async () => {
      const response = await request(app)
        .post('/api/v1/lbs/discover')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          latitude: 39.9042,
          longitude: 116.4074,
          accuracy: 10 // 10米精度
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('discoveredAnnotations');
      expect(response.body.data.discoveredAnnotations.length).toBeGreaterThan(0);
      
      const discoveredAnnotation = response.body.data.discoveredAnnotations.find(
        ann => ann.id === annotationId
      );
      expect(discoveredAnnotation).toBeDefined();
      expect(discoveredAnnotation).toHaveProperty('rewardAmount');
      expect(discoveredAnnotation.rewardAmount).toBeGreaterThan(0);
    });

    test('should distribute reward to discoverer wallet', async () => {
      const beforeBalance = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${discovererToken}`);

      const response = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('rewardAmount');
      expect(response.body.data).toHaveProperty('newBalance');

      const afterBalance = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${discovererToken}`);

      expect(afterBalance.body.data.balance).toBeGreaterThan(beforeBalance.body.data.balance);
      expect(afterBalance.body.data.balance).toBe(response.body.data.newBalance);
    });

    test('should record reward transaction in database', async () => {
      const dbResult = await db('lbs_rewards')
        .where('annotation_id', annotationId)
        .where('discoverer_id', discovererId)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].annotation_id).toBe(annotationId);
      expect(dbResult[0].discoverer_id).toBe(discovererId);
      expect(parseFloat(dbResult[0].reward_amount)).toBeGreaterThan(0);
      expect(dbResult[0].status).toBe('completed');
    });

    test('should create wallet transaction for reward', async () => {
      const dbResult = await db('wallet_transactions')
        .where('wallet_id', discovererWalletId)
        .where('type', 'lbs_reward')
        .select('*');

      expect(dbResult.length).toBeGreaterThan(0);
      const rewardTransaction = dbResult[0];
      expect(parseFloat(rewardTransaction.amount)).toBeGreaterThan(0);
      expect(rewardTransaction.status).toBe('completed');
      expect(rewardTransaction.description).toContain('LBS reward');
    });
  });

  describe('Geofence Validation', () => {
    test('should fail reward claim when too far from annotation', async () => {
      const response = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          annotationId: annotationId,
          latitude: 40.0000, // 距离太远
          longitude: 117.0000
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('outside geofence');
    });

    test('should validate GPS accuracy requirements', async () => {
      const response = await request(app)
        .post('/api/v1/lbs/discover')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          latitude: 39.9042,
          longitude: 116.4074,
          accuracy: 1000 // 精度太低
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('GPS accuracy');
    });

    test('should calculate distance correctly', async () => {
      // 测试边界情况：刚好在地理围栏边缘
      const response = await request(app)
        .post('/api/v1/lbs/discover')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          latitude: 39.9043, // 略微偏移
          longitude: 116.4075,
          accuracy: 5
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('Anti-Fraud Mechanisms', () => {
    test('should prevent same user from claiming reward twice', async () => {
      // 第二次尝试领取奖励
      const response = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already claimed');
    });

    test('should prevent creator from claiming own annotation reward', async () => {
      const response = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${creatorToken}`)
        .send({
          annotationId: annotationId,
          latitude: 39.9042,
          longitude: 116.4074
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('cannot claim own annotation');
    });

    test('should detect suspicious location patterns', async () => {
      // 模拟快速连续的位置变化
      const locations = [
        { lat: 39.9042, lng: 116.4074 },
        { lat: 40.0042, lng: 117.4074 },
        { lat: 41.0042, lng: 118.4074 }
      ];

      for (const location of locations) {
        await request(app)
          .post('/api/v1/lbs/discover')
          .set('Authorization', `Bearer ${discovererToken}`)
          .send({
            latitude: location.lat,
            longitude: location.lng,
            accuracy: 5
          });
      }

      // 检查是否触发了反作弊机制
      const response = await request(app)
        .get('/api/v1/user/fraud-status')
        .set('Authorization', `Bearer ${discovererToken}`);

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty('suspiciousActivity');
    });
  });

  describe('Reward Pool Management', () => {
    test('should update annotation reward pool after distribution', async () => {
      const dbResult = await db('annotations')
        .where('id', annotationId)
        .select('reward_pool', 'total_rewards_distributed');

      expect(dbResult.length).toBe(1);
      const annotation = dbResult[0];
      expect(parseFloat(annotation.total_rewards_distributed)).toBeGreaterThan(0);
      expect(parseFloat(annotation.reward_pool)).toBeLessThan(15.00); // 原始奖励池减少
    });

    test('should handle reward pool depletion', async () => {
      // 创建一个小奖励池的标注
      const smallRewardResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${creatorToken}`)
        .send({
          content: 'Small reward annotation',
          latitude: 39.9050,
          longitude: 116.4080,
          price: 1.00,
          rewardPercentage: 50 // 0.5元奖励池
        });

      const smallAnnotationId = smallRewardResponse.body.data.id;

      // 尝试多次领取奖励直到池子耗尽
      let rewardResponse;
      let attempts = 0;
      do {
        attempts++;
        rewardResponse = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${discovererToken}`)
          .send({
            annotationId: smallAnnotationId,
            latitude: 39.9050,
            longitude: 116.4080
          });
      } while (rewardResponse.status === 200 && attempts < 10);

      expect(rewardResponse.status).toBe(400);
      expect(rewardResponse.body.message).toContain('reward pool depleted');

      // 清理
      await db('annotations').where('id', smallAnnotationId).del();
    });
  });

  describe('Real-time Notifications', () => {
    test('should send notification when reward is claimed', async () => {
      // 创建新标注用于测试通知
      const notificationTestResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${creatorToken}`)
        .send({
          content: 'Notification test annotation',
          latitude: 39.9060,
          longitude: 116.4090,
          price: 20.00,
          rewardPercentage: 25
        });

      const testAnnotationId = notificationTestResponse.body.data.id;

      // 领取奖励
      const rewardResponse = await request(app)
        .post('/api/v1/lbs/claim-reward')
        .set('Authorization', `Bearer ${discovererToken}`)
        .send({
          annotationId: testAnnotationId,
          latitude: 39.9060,
          longitude: 116.4090
        });

      expect(rewardResponse.status).toBe(200);

      // 检查通知记录
      const notificationResult = await db('notifications')
        .where('user_id', creatorId)
        .where('type', 'reward_claimed')
        .select('*');

      expect(notificationResult.length).toBeGreaterThan(0);
      expect(notificationResult[0].content).toContain('reward claimed');

      // 清理
      await db('notifications').where('user_id', creatorId).del();
      await db('annotations').where('id', testAnnotationId).del();
    });
  });

  describe('Analytics and Reporting', () => {
    test('should track LBS reward statistics', async () => {
      const response = await request(app)
        .get('/api/v1/analytics/lbs-rewards')
        .set('Authorization', `Bearer ${creatorToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalRewardsDistributed');
      expect(response.body.data).toHaveProperty('totalDiscoveries');
      expect(response.body.data).toHaveProperty('averageRewardAmount');
    });

    test('should provide user-specific LBS statistics', async () => {
      const response = await request(app)
        .get('/api/v1/user/lbs-stats')
        .set('Authorization', `Bearer ${discovererToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalRewardsEarned');
      expect(response.body.data).toHaveProperty('annotationsDiscovered');
      expect(response.body.data).toHaveProperty('discoveryRate');
    });
  });

  describe('Database Consistency', () => {
    test('should maintain referential integrity', async () => {
      // 验证所有相关表的数据一致性
      const rewardResult = await db('lbs_rewards')
        .where('annotation_id', annotationId)
        .count('* as count')
        .first();

      const transactionResult = await db('wallet_transactions')
        .where('description', 'like', '%LBS reward%')
        .where('wallet_id', discovererWalletId)
        .count('* as count')
        .first();

      expect(rewardResult.count).toBe(transactionResult.count);
    });

    test('should verify balance calculations', async () => {
      // 计算数据库中的实际余额
      const dbBalance = await db('wallet_transactions')
        .where('wallet_id', discovererWalletId)
        .where('status', 'completed')
        .sum('amount as balance')
        .first();

      // 获取API返回的余额
      const apiBalance = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${discovererToken}`);

      expect(apiBalance.body.data.balance).toBe(dbBalance.balance || 0);
    });
  });
});