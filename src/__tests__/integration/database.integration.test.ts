import { pool } from '../../config/database';
import { AnnotationService } from '../../services/annotationService';
import { UserService } from '../../services/userService';
import { LBSService } from '../../services/lbsService';
import { PaymentService } from '../../services/paymentService';
import { Annotation, User, LBSReward, Payment } from '../../types';

describe('Database Integration Tests', () => {
  let annotationService: AnnotationService;
  let userService: UserService;
  let lbsService: LBSService;
  let paymentService: PaymentService;
  
  let testUserId: string;
  let testAnnotationId: string;
  let testPaymentId: string;

  beforeAll(async () => {
    // 初始化服务
    annotationService = new AnnotationService();
    userService = new UserService();
    lbsService = new LBSService();
    paymentService = new PaymentService();
  });

  beforeEach(async () => {
    // 清理测试数据
    await cleanupTestData();
    
    // 创建测试用户
    const testUser = await createTestUser();
    testUserId = testUser.id;
  });

  afterEach(async () => {
    // 清理测试数据
    await cleanupTestData();
  });

  afterAll(async () => {
    // 关闭数据库连接
    if (pool) {
      await pool.end();
    }
  });

  describe('User Service Database Operations', () => {
    it('should create user with valid data', async () => {
      const userData = {
        phone: '13900139001',
        nickname: 'Test User',
        avatar: 'https://example.com/avatar.jpg'
      };

      const user = await userService.createUser(userData);
      
      expect(user).toBeDefined();
      expect(user.id).toBeDefined();
      expect(user.phone).toBe(userData.phone);
      expect(user.nickname).toBe(userData.nickname);
      expect(user.createdAt).toBeDefined();
    });

    it('should update user profile', async () => {
      const updateData = {
        nickname: 'Updated Nickname',
        avatar: 'https://example.com/new-avatar.jpg'
      };

      const updatedUser = await userService.updateUser(testUserId, updateData);
      
      expect(updatedUser).toBeDefined();
      expect(updatedUser.nickname).toBe(updateData.nickname);
      expect(updatedUser.avatar).toBe(updateData.avatar);
      expect(updatedUser.updatedAt).toBeDefined();
    });

    it('should get user by id', async () => {
      const user = await userService.getUserById(testUserId);
      
      expect(user).toBeDefined();
      expect(user!.id).toBe(testUserId);
      expect(user!.phone).toBeDefined();
    });

    it('should get user by phone', async () => {
      const testUser = await userService.getUserById(testUserId);
      const user = await userService.getUserByPhone(testUser!.phone);
      
      expect(user).toBeDefined();
      expect(user!.id).toBe(testUserId);
      expect(user!.phone).toBe(testUser!.phone);
    });

    it('should handle user not found', async () => {
      const user = await userService.getUserById('non-existent-id');
      expect(user).toBeNull();
    });

    it('should prevent duplicate phone numbers', async () => {
      const userData = {
        phone: '13900139002',
        nickname: 'Test User 1'
      };

      await userService.createUser(userData);
      
      // 尝试创建相同手机号的用户
      await expect(userService.createUser(userData))
        .rejects.toThrow();
    });
  });

  describe('Annotation Service Database Operations', () => {
    it('should create annotation with valid data', async () => {
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'This is a test smell annotation',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const annotation = await annotationService.createAnnotation(annotationData);
      testAnnotationId = annotation.id;
      
      expect(annotation).toBeDefined();
      expect(annotation.id).toBeDefined();
      expect(annotation.userId).toBe(testUserId);
      expect(annotation.latitude).toBe(annotationData.latitude);
      expect(annotation.longitude).toBe(annotationData.longitude);
      expect(annotation.title).toBe(annotationData.title);
      expect(annotation.smellType).toBe(annotationData.smellType);
      expect(annotation.status).toBe('active');
      expect(annotation.createdAt).toBeDefined();
    });

    it('should get annotations by location', async () => {
      // 创建测试标注
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      await annotationService.createAnnotation(annotationData);

      const annotations = await annotationService.getAnnotationsByLocation(
        40.7128,
        -74.0060,
        1000 // 1km radius
      );
      
      expect(annotations).toBeDefined();
      expect(Array.isArray(annotations)).toBe(true);
      expect(annotations.length).toBeGreaterThan(0);
      expect(annotations[0]).toHaveProperty('id');
      expect(annotations[0]).toHaveProperty('latitude');
      expect(annotations[0]).toHaveProperty('longitude');
    });

    it('should get annotation by id', async () => {
      // 创建测试标注
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const createdAnnotation = await annotationService.createAnnotation(annotationData);
      const annotation = await annotationService.getAnnotationById(createdAnnotation.id);
      
      expect(annotation).toBeDefined();
      expect(annotation!.id).toBe(createdAnnotation.id);
      expect(annotation!.title).toBe(annotationData.title);
    });

    it('should update annotation', async () => {
      // 创建测试标注
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const createdAnnotation = await annotationService.createAnnotation(annotationData);
      
      const updateData = {
        title: 'Updated Title',
        description: 'Updated description',
        intensity: 4
      };

      const updatedAnnotation = await annotationService.updateAnnotation(
        createdAnnotation.id,
        updateData
      );
      
      expect(updatedAnnotation).toBeDefined();
      expect(updatedAnnotation.title).toBe(updateData.title);
      expect(updatedAnnotation.description).toBe(updateData.description);
      expect(updatedAnnotation.intensity).toBe(updateData.intensity);
      expect(updatedAnnotation.updatedAt).toBeDefined();
    });

    it('should delete annotation', async () => {
      // 创建测试标注
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const createdAnnotation = await annotationService.createAnnotation(annotationData);
      
      await annotationService.deleteAnnotation(createdAnnotation.id);
      
      const deletedAnnotation = await annotationService.getAnnotationById(createdAnnotation.id);
      expect(deletedAnnotation).toBeNull();
    });

    it('should get user annotations', async () => {
      // 创建多个测试标注
      const annotationData1 = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell 1',
        description: 'Test description 1',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const annotationData2 = {
        userId: testUserId,
        latitude: 40.7129,
        longitude: -74.0061,
        title: 'Test Smell 2',
        description: 'Test description 2',
        smellType: 'organic' as const,
        intensity: 2,
        rewardAmount: 15.00
      };

      await annotationService.createAnnotation(annotationData1);
      await annotationService.createAnnotation(annotationData2);

      const userAnnotations = await annotationService.getUserAnnotations(testUserId);
      
      expect(userAnnotations).toBeDefined();
      expect(Array.isArray(userAnnotations)).toBe(true);
      expect(userAnnotations.length).toBe(2);
      expect(userAnnotations.every(a => a.userId === testUserId)).toBe(true);
    });
  });

  describe('LBS Service Database Operations', () => {
    beforeEach(async () => {
      // 创建测试标注
      const annotationData = {
        userId: testUserId,
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical' as const,
        intensity: 3,
        rewardAmount: 10.00
      };

      const annotation = await annotationService.createAnnotation(annotationData);
      testAnnotationId = annotation.id;
    });

    it('should check rewards at location', async () => {
      const rewards = await lbsService.checkRewardsAtLocation(
        testUserId,
        40.7128,
        -74.0060,
        100 // 100m radius
      );
      
      expect(rewards).toBeDefined();
      expect(Array.isArray(rewards)).toBe(true);
      expect(rewards.length).toBeGreaterThan(0);
      expect(rewards[0]).toHaveProperty('annotationId');
      expect(rewards[0]).toHaveProperty('rewardAmount');
    });

    it('should claim reward successfully', async () => {
      // 创建另一个用户来领取奖励
      const anotherUser = await createTestUser('13900139003');
      
      const result = await lbsService.claimReward(
        anotherUser.id,
        testAnnotationId,
        40.7128,
        -74.0060,
        5 // 5m accuracy
      );
      
      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.rewardAmount).toBeGreaterThan(0);
      expect(result.transactionId).toBeDefined();
    });

    it('should prevent duplicate reward claims', async () => {
      // 创建另一个用户
      const anotherUser = await createTestUser('13900139004');
      
      // 第一次领取
      await lbsService.claimReward(
        anotherUser.id,
        testAnnotationId,
        40.7128,
        -74.0060,
        5
      );
      
      // 第二次领取应该失败
      await expect(lbsService.claimReward(
        anotherUser.id,
        testAnnotationId,
        40.7128,
        -74.0060,
        5
      )).rejects.toThrow();
    });

    it('should prevent creator from claiming own reward', async () => {
      await expect(lbsService.claimReward(
        testUserId, // 创建者尝试领取自己的奖励
        testAnnotationId,
        40.7128,
        -74.0060,
        5
      )).rejects.toThrow();
    });

    it('should validate GPS accuracy', async () => {
      const anotherUser = await createTestUser('13900139005');
      
      // 精度太低应该失败
      await expect(lbsService.claimReward(
        anotherUser.id,
        testAnnotationId,
        40.7128,
        -74.0060,
        100 // 100m accuracy，太低
      )).rejects.toThrow();
    });

    it('should validate distance from annotation', async () => {
      const anotherUser = await createTestUser('13900139006');
      
      // 距离太远应该失败
      await expect(lbsService.claimReward(
        anotherUser.id,
        testAnnotationId,
        40.8128, // 距离原位置约11km
        -74.0060,
        5
      )).rejects.toThrow();
    });
  });

  describe('Payment Service Database Operations', () => {
    it('should create payment record', async () => {
      const paymentData = {
        userId: testUserId,
        amount: 50.00,
        currency: 'CNY',
        paymentMethod: 'alipay',
        description: 'Test payment'
      };

      const payment = await paymentService.createPayment(paymentData);
      testPaymentId = payment.id;
      
      expect(payment).toBeDefined();
      expect(payment.id).toBeDefined();
      expect(payment.userId).toBe(testUserId);
      expect(payment.amount).toBe(paymentData.amount);
      expect(payment.currency).toBe(paymentData.currency);
      expect(payment.status).toBe('pending');
      expect(payment.createdAt).toBeDefined();
    });

    it('should update payment status', async () => {
      const paymentData = {
        userId: testUserId,
        amount: 50.00,
        currency: 'CNY',
        paymentMethod: 'alipay',
        description: 'Test payment'
      };

      const payment = await paymentService.createPayment(paymentData);
      
      const updatedPayment = await paymentService.updatePaymentStatus(
        payment.id,
        'completed',
        'external-transaction-id'
      );
      
      expect(updatedPayment).toBeDefined();
      expect(updatedPayment.status).toBe('completed');
      expect(updatedPayment.externalTransactionId).toBe('external-transaction-id');
      expect(updatedPayment.updatedAt).toBeDefined();
    });

    it('should get user payments', async () => {
      // 创建多个支付记录
      const paymentData1 = {
        userId: testUserId,
        amount: 30.00,
        currency: 'CNY',
        paymentMethod: 'alipay',
        description: 'Test payment 1'
      };

      const paymentData2 = {
        userId: testUserId,
        amount: 40.00,
        currency: 'CNY',
        paymentMethod: 'wechat',
        description: 'Test payment 2'
      };

      await paymentService.createPayment(paymentData1);
      await paymentService.createPayment(paymentData2);

      const userPayments = await paymentService.getUserPayments(testUserId);
      
      expect(userPayments).toBeDefined();
      expect(Array.isArray(userPayments)).toBe(true);
      expect(userPayments.length).toBe(2);
      expect(userPayments.every(p => p.userId === testUserId)).toBe(true);
    });
  });

  describe('Transaction Handling', () => {
    it('should handle database transactions correctly', async () => {
      const client = await pool.connect();
      
      try {
        await client.query('BEGIN');
        
        // 创建用户
        const userResult = await client.query(
          'INSERT INTO users (phone, nickname) VALUES ($1, $2) RETURNING *',
          ['13900139007', 'Transaction Test User']
        );
        
        const userId = userResult.rows[0].id;
        
        // 创建标注
        const annotationResult = await client.query(
          `INSERT INTO annotations (user_id, latitude, longitude, title, description, smell_type, intensity, reward_amount) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
          [userId, 40.7128, -74.0060, 'Transaction Test', 'Test description', 'chemical', 3, 10.00]
        );
        
        await client.query('COMMIT');
        
        // 验证数据已保存
        const savedUser = await userService.getUserById(userId);
        const savedAnnotation = await annotationService.getAnnotationById(annotationResult.rows[0].id);
        
        expect(savedUser).toBeDefined();
        expect(savedAnnotation).toBeDefined();
        
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    });

    it('should rollback on transaction failure', async () => {
      const client = await pool.connect();
      
      try {
        await client.query('BEGIN');
        
        // 创建用户
        const userResult = await client.query(
          'INSERT INTO users (phone, nickname) VALUES ($1, $2) RETURNING *',
          ['13900139008', 'Rollback Test User']
        );
        
        const userId = userResult.rows[0].id;
        
        // 故意创建一个会失败的查询
        await client.query(
          'INSERT INTO non_existent_table (id) VALUES ($1)',
          [userId]
        );
        
        await client.query('COMMIT');
        
      } catch (error) {
        await client.query('ROLLBACK');
        
        // 验证用户没有被保存（事务已回滚）
        const users = await pool.query(
          'SELECT * FROM users WHERE phone = $1',
          ['13900139008']
        );
        
        expect(users.rows.length).toBe(0);
      } finally {
        client.release();
      }
    });
  });

  describe('Database Constraints and Validation', () => {
    it('should enforce foreign key constraints', async () => {
      // 尝试创建引用不存在用户的标注
      await expect(annotationService.createAnnotation({
        userId: 'non-existent-user-id',
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical',
        intensity: 3,
        rewardAmount: 10.00
      })).rejects.toThrow();
    });

    it('should enforce unique constraints', async () => {
      const userData = {
        phone: '13900139009',
        nickname: 'Unique Test User'
      };

      await userService.createUser(userData);
      
      // 尝试创建相同手机号的用户
      await expect(userService.createUser(userData))
        .rejects.toThrow();
    });

    it('should enforce check constraints', async () => {
      // 尝试创建无效坐标的标注
      await expect(annotationService.createAnnotation({
        userId: testUserId,
        latitude: 91, // 无效纬度
        longitude: -74.0060,
        title: 'Test Smell',
        description: 'Test description',
        smellType: 'chemical',
        intensity: 3,
        rewardAmount: 10.00
      })).rejects.toThrow();
    });
  });

  // 辅助函数
  async function createTestUser(phone: string = '13900139000'): Promise<User> {
    const userData = {
      phone,
      nickname: `Test User ${phone}`,
      avatar: 'https://example.com/avatar.jpg'
    };

    return await userService.createUser(userData);
  }

  async function cleanupTestData(): Promise<void> {
    try {
      // 删除测试数据（按依赖关系顺序）
      await pool.query('DELETE FROM lbs_rewards WHERE 1=1');
      await pool.query('DELETE FROM payments WHERE 1=1');
      await pool.query('DELETE FROM annotations WHERE 1=1');
      await pool.query('DELETE FROM users WHERE phone LIKE \'139001390%\'');
    } catch (error) {
      console.warn('清理测试数据时出错:', error);
    }
  }
});