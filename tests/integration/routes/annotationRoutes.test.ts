// 标注路由集成测试 - SmellPin自动化测试方案2.0
import request from 'supertest';
import { Express } from 'express';
import { Server } from '../../../src/server';
import { UserFactory } from '../../factories/userFactory';
import { AnnotationFactory } from '../../factories/annotationFactory';
import { getTestDb, setupTestDatabase, cleanupTestDatabase, teardownTestDatabase } from '../../setup/databaseSetup';
import jwt from 'jsonwebtoken';
import { config } from '../../../src/config/config';

describe('Annotation Routes Integration', () => {
  let app: Express;
  let server: Server;
  let db: any;
  let testUser: any;
  let authToken: string;

  beforeAll(async () => {
    await setupTestDatabase();
    db = getTestDb();
    server = new Server();
    app = server.getApp();
    
    // 创建测试用户
    const userData = UserFactory.create({
      username: 'annotationtest',
      email: 'annotationtest@smellpin.test',
    });

    // 模拟用户创建过程
    testUser = {
      id: 'test-user-1',
      username: userData.username,
      email: userData.email,
      status: 'active',
    };

    // 生成JWT令牌
    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      config.JWT_SECRET!,
      { expiresIn: '1h' }
    );
  });

  afterEach(async () => {
    await cleanupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
    if (server) {
      await server.close();
    }
  });

  describe('POST /api/v1/annotations', () => {
    it('should create a new annotation successfully', async () => {
      const annotationData = AnnotationFactory.create({
        userId: testUser.id,
        title: '测试标注创建',
        description: '这是一个集成测试创建的标注',
        smellType: '食物香味',
        intensity: 3,
        latitude: 39.9042,
        longitude: 116.4074,
      });

      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: annotationData.title,
          description: annotationData.description,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
          locationName: annotationData.locationName,
          tags: annotationData.tags,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.title).toBe(annotationData.title);
      expect(response.body.data.smellType).toBe(annotationData.smellType);
      expect(response.body.data.intensity).toBe(annotationData.intensity);
      expect(response.body.data.latitude).toBe(annotationData.latitude);
      expect(response.body.data.longitude).toBe(annotationData.longitude);
      expect(response.body.data.status).toBe('published');
    });

    it('should reject annotation creation without authentication', async () => {
      const annotationData = AnnotationFactory.create();

      const response = await request(app)
        .post('/api/v1/annotations')
        .send({
          title: annotationData.title,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('unauthorized');
    });

    it('should reject annotation with invalid data', async () => {
      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: '', // 空标题
          smellType: '食物香味',
          intensity: 10, // 超出范围
          latitude: 'invalid', // 无效纬度
          longitude: 116.4074,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('validation');
    });

    it('should reject annotation with invalid coordinates', async () => {
      const annotationData = AnnotationFactory.create({
        latitude: 200, // 超出范围
        longitude: 300, // 超出范围
      });

      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: annotationData.title,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/v1/annotations/list', () => {
    beforeEach(async () => {
      // 创建多个测试标注
      const annotations = AnnotationFactory.createMultiple(10, {
        userId: testUser.id,
      });

      // 模拟数据库插入（实际应该通过API创建）
      for (const annotation of annotations) {
        await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            title: annotation.title,
            description: annotation.description,
            smellType: annotation.smellType,
            intensity: annotation.intensity,
            latitude: annotation.latitude,
            longitude: annotation.longitude,
          });
      }
    });

    it('should get paginated list of annotations', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/list')
        .query({ page: 1, limit: 5 })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.annotations).toBeDefined();
      expect(Array.isArray(response.body.data.annotations)).toBe(true);
      expect(response.body.data.annotations.length).toBeLessThanOrEqual(5);
      expect(response.body.data.pagination).toBeDefined();
      expect(response.body.data.pagination.page).toBe(1);
      expect(response.body.data.pagination.limit).toBe(5);
    });

    it('should filter annotations by smell type', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/list')
        .query({ smellType: '食物香味' })
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.annotations.forEach((annotation: any) => {
        expect(annotation.smellType).toBe('食物香味');
      });
    });

    it('should filter annotations by intensity range', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/list')
        .query({ minIntensity: 3, maxIntensity: 5 })
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.annotations.forEach((annotation: any) => {
        expect(annotation.intensity).toBeGreaterThanOrEqual(3);
        expect(annotation.intensity).toBeLessThanOrEqual(5);
      });
    });

    it('should sort annotations by creation date', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/list')
        .query({ sortBy: 'created_at', sortOrder: 'desc' })
        .expect(200);

      expect(response.body.success).toBe(true);
      
      const annotations = response.body.data.annotations;
      if (annotations.length > 1) {
        for (let i = 0; i < annotations.length - 1; i++) {
          const current = new Date(annotations[i].createdAt);
          const next = new Date(annotations[i + 1].createdAt);
          expect(current.getTime()).toBeGreaterThanOrEqual(next.getTime());
        }
      }
    });
  });

  describe('GET /api/v1/annotations/nearby', () => {
    beforeEach(async () => {
      // 创建不同位置的测试标注
      const beijingAnnotations = AnnotationFactory.createClusteredAnnotations(
        39.9042, 116.4074, 5, 0.01 // 北京周围
      );
      
      const shanghaiAnnotations = AnnotationFactory.createClusteredAnnotations(
        31.2304, 121.4737, 3, 0.01 // 上海周围
      );

      const allAnnotations = [...beijingAnnotations, ...shanghaiAnnotations];
      
      for (const annotation of allAnnotations) {
        await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            title: annotation.title,
            description: annotation.description,
            smellType: annotation.smellType,
            intensity: annotation.intensity,
            latitude: annotation.latitude,
            longitude: annotation.longitude,
          });
      }
    });

    it('should find nearby annotations within radius', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/nearby')
        .query({
          latitude: 39.9042,  // 天安门
          longitude: 116.4074,
          radius: 2000, // 2公里
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(Array.isArray(response.body.data.annotations)).toBe(true);
      
      // 所有返回的标注都应该在指定范围内
      response.body.data.annotations.forEach((annotation: any) => {
        const distance = calculateDistance(
          39.9042, 116.4074,
          annotation.latitude, annotation.longitude
        );
        expect(distance).toBeLessThanOrEqual(2000);
      });
    });

    it('should limit nearby annotations count', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/nearby')
        .query({
          latitude: 39.9042,
          longitude: 116.4074,
          radius: 5000,
          limit: 3,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.annotations.length).toBeLessThanOrEqual(3);
    });

    it('should reject invalid coordinates for nearby search', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/nearby')
        .query({
          latitude: 'invalid',
          longitude: 116.4074,
          radius: 1000,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/v1/annotations/:id', () => {
    let testAnnotation: any;

    beforeEach(async () => {
      const annotationData = AnnotationFactory.create({
        userId: testUser.id,
      });

      const createResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: annotationData.title,
          description: annotationData.description,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
        });

      testAnnotation = createResponse.body.data;
    });

    it('should get annotation by ID successfully', async () => {
      const response = await request(app)
        .get(`/api/v1/annotations/${testAnnotation.id}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.id).toBe(testAnnotation.id);
      expect(response.body.data.title).toBe(testAnnotation.title);
      expect(response.body.data.user).toBeDefined(); // 应该包含用户信息
    });

    it('should return 404 for non-existent annotation', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/non-existent-id')
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('not found');
    });
  });

  describe('PUT /api/v1/annotations/:id', () => {
    let testAnnotation: any;

    beforeEach(async () => {
      const annotationData = AnnotationFactory.create({
        userId: testUser.id,
      });

      const createResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: annotationData.title,
          description: annotationData.description,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
        });

      testAnnotation = createResponse.body.data;
    });

    it('should update annotation successfully by owner', async () => {
      const updateData = {
        title: '更新后的标注标题',
        description: '更新后的标注描述',
        intensity: 4,
        tags: ['更新', '测试'],
      };

      const response = await request(app)
        .put(`/api/v1/annotations/${testAnnotation.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(updateData.title);
      expect(response.body.data.description).toBe(updateData.description);
      expect(response.body.data.intensity).toBe(updateData.intensity);
      expect(response.body.data.updatedAt).toBeDefined();
    });

    it('should reject update without authentication', async () => {
      const updateData = {
        title: '未授权的更新',
      };

      const response = await request(app)
        .put(`/api/v1/annotations/${testAnnotation.id}`)
        .send(updateData)
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject update by non-owner', async () => {
      // 创建另一个用户的令牌
      const otherUserToken = jwt.sign(
        { userId: 'other-user', email: 'other@smellpin.test' },
        config.JWT_SECRET!,
        { expiresIn: '1h' }
      );

      const updateData = {
        title: '他人尝试更新',
      };

      const response = await request(app)
        .put(`/api/v1/annotations/${testAnnotation.id}`)
        .set('Authorization', `Bearer ${otherUserToken}`)
        .send(updateData)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('permission');
    });
  });

  describe('POST /api/v1/annotations/:id/like', () => {
    let testAnnotation: any;

    beforeEach(async () => {
      const annotationData = AnnotationFactory.create({
        userId: testUser.id,
      });

      const createResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: annotationData.title,
          description: annotationData.description,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
        });

      testAnnotation = createResponse.body.data;
    });

    it('should like annotation successfully', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.liked).toBe(true);
      expect(response.body.data.likeCount).toBeGreaterThan(0);
    });

    it('should unlike annotation if already liked', async () => {
      // 先点赞
      await request(app)
        .post(`/api/v1/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      // 再次点赞应该取消
      const response = await request(app)
        .post(`/api/v1/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.liked).toBe(false);
    });

    it('should reject like without authentication', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${testAnnotation.id}/like`)
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits on annotation creation', async () => {
      const annotationData = AnnotationFactory.create({
        userId: testUser.id,
      });

      // 尝试快速创建多个标注
      const requests = [];
      for (let i = 0; i < 15; i++) { // 超过预期的速率限制
        requests.push(
          request(app)
            .post('/api/v1/annotations')
            .set('Authorization', `Bearer ${authToken}`)
            .send({
              ...annotationData,
              title: `Rate limit test ${i}`,
            })
        );
      }

      const responses = await Promise.all(requests.map(req => 
        req.then(res => res.status, err => err.status)
      ));

      // 应该有一些请求被限制
      const rateLimitedCount = responses.filter(status => status === 429).length;
      expect(rateLimitedCount).toBeGreaterThan(0);
    }, 30000); // 增加超时时间
  });

  // 辅助函数：计算两点间距离（米）
  function calculateDistance(lat1: number, lng1: number, lat2: number, lng2: number): number {
    const R = 6371e3; // 地球半径（米）
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lng2 - lng1) * Math.PI / 180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    return R * c;
  }
});