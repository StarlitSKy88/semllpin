import request from 'supertest';
import { Express } from 'express';
import { createApp } from '../../server';
import { pool } from '../../config/database';
import jwt from 'jsonwebtoken';
import { UserService } from '../../services/userService';
import { performance } from 'perf_hooks';

describe('Performance and Load Tests', () => {
  let app: Express;
  let userService: UserService;
  let testUserToken: string;
  let testUserId: string;
  
  // 性能基准
  const PERFORMANCE_THRESHOLDS = {
    API_RESPONSE_TIME: 200, // ms
    DATABASE_QUERY_TIME: 100, // ms
    CONCURRENT_USERS: 100,
    REQUESTS_PER_SECOND: 50
  };

  beforeAll(async () => {
    app = createApp();
    userService = new UserService();
    
    // 创建测试用户
    await setupTestUser();
    
    // 预热应用
    await warmupApplication();
  });

  afterAll(async () => {
    await cleanupTestData();
    
    if (pool) {
      await pool.end();
    }
  });

  describe('API Response Time Tests', () => {
    describe('Authentication Endpoints', () => {
      it('should respond to login within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .post('/api/v1/auth/send-code')
          .send({ phone: '13800138000' });
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect([200, 400, 429]).toContain(response.status); // 可能因为限流返回429
      });

      it('should validate token within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .get('/api/v1/users/profile')
          .set('Authorization', `Bearer ${testUserToken}`);
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect(response.status).toBe(200);
      });
    });

    describe('Annotation Endpoints', () => {
      it('should list annotations within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .get('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`);
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect(response.status).toBe(200);
      });

      it('should create annotation within 200ms', async () => {
        const annotationData = {
          latitude: 40.7128,
          longitude: -74.0060,
          title: 'Performance Test Smell',
          description: 'Test annotation for performance',
          smellType: 'chemical',
          intensity: 3,
          rewardAmount: 10.00
        };

        const startTime = performance.now();
        
        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`)
          .send(annotationData);
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect(response.status).toBe(201);
      });

      it('should search annotations within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .get('/api/v1/annotations/search')
          .query({
            latitude: 40.7128,
            longitude: -74.0060,
            radius: 1000
          })
          .set('Authorization', `Bearer ${testUserToken}`);
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect([200, 404]).toContain(response.status);
      });
    });

    describe('LBS Endpoints', () => {
      it('should check rewards within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .post('/api/v1/lbs/check-rewards')
          .set('Authorization', `Bearer ${testUserToken}`)
          .send({
            latitude: 40.7128,
            longitude: -74.0060
          });
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect([200, 404]).toContain(response.status);
      });

      it('should claim rewards within 200ms', async () => {
        const startTime = performance.now();
        
        const response = await request(app)
          .post('/api/v1/lbs/claim-reward')
          .set('Authorization', `Bearer ${testUserToken}`)
          .send({
            annotationId: 'test-annotation-id',
            latitude: 40.7128,
            longitude: -74.0060
          });
        
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
        expect([200, 400, 404]).toContain(response.status);
      });
    });
  });

  describe('Concurrent User Tests', () => {
    it('should handle 50 concurrent read requests', async () => {
      const concurrentRequests = Array(50).fill(null).map(() => 
        request(app)
          .get('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`)
      );

      const startTime = performance.now();
      const responses = await Promise.all(concurrentRequests);
      const endTime = performance.now();
      
      const totalTime = endTime - startTime;
      const avgResponseTime = totalTime / responses.length;
      
      // 所有请求都应该成功
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
      
      // 平均响应时间应该在合理范围内
      expect(avgResponseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME * 2);
      
      console.log(`50个并发读取请求 - 总时间: ${totalTime.toFixed(2)}ms, 平均响应时间: ${avgResponseTime.toFixed(2)}ms`);
    });

    it('should handle 20 concurrent write requests', async () => {
      const concurrentRequests = Array(20).fill(null).map((_, index) => 
        request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`)
          .send({
            latitude: 40.7128 + (index * 0.001),
            longitude: -74.0060 + (index * 0.001),
            title: `Concurrent Test Smell ${index}`,
            description: `Test annotation ${index} for concurrency`,
            smellType: 'chemical',
            intensity: 3,
            rewardAmount: 5.00
          })
      );

      const startTime = performance.now();
      const responses = await Promise.all(concurrentRequests);
      const endTime = performance.now();
      
      const totalTime = endTime - startTime;
      const avgResponseTime = totalTime / responses.length;
      
      // 大部分请求应该成功
      const successfulResponses = responses.filter(res => res.status === 201);
      expect(successfulResponses.length).toBeGreaterThan(15); // 至少75%成功
      
      // 平均响应时间应该在合理范围内
      expect(avgResponseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME * 3);
      
      console.log(`20个并发写入请求 - 总时间: ${totalTime.toFixed(2)}ms, 平均响应时间: ${avgResponseTime.toFixed(2)}ms, 成功率: ${(successfulResponses.length/20*100).toFixed(1)}%`);
    });

    it('should handle mixed read/write concurrent requests', async () => {
      const readRequests = Array(30).fill(null).map(() => 
        request(app)
          .get('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`)
      );
      
      const writeRequests = Array(10).fill(null).map((_, index) => 
        request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${testUserToken}`)
          .send({
            latitude: 40.7130 + (index * 0.001),
            longitude: -74.0062 + (index * 0.001),
            title: `Mixed Test Smell ${index}`,
            description: `Mixed test annotation ${index}`,
            smellType: 'organic',
            intensity: 2,
            rewardAmount: 3.00
          })
      );

      const allRequests = [...readRequests, ...writeRequests];
      
      const startTime = performance.now();
      const responses = await Promise.all(allRequests);
      const endTime = performance.now();
      
      const totalTime = endTime - startTime;
      const avgResponseTime = totalTime / responses.length;
      
      // 读取请求应该全部成功
      const readResponses = responses.slice(0, 30);
      readResponses.forEach(response => {
        expect(response.status).toBe(200);
      });
      
      // 写入请求大部分应该成功
      const writeResponses = responses.slice(30);
      const successfulWrites = writeResponses.filter(res => res.status === 201);
      expect(successfulWrites.length).toBeGreaterThan(7); // 至少70%成功
      
      console.log(`混合并发请求 - 总时间: ${totalTime.toFixed(2)}ms, 平均响应时间: ${avgResponseTime.toFixed(2)}ms`);
    });
  });

  describe('Database Performance Tests', () => {
    it('should execute user queries within 100ms', async () => {
      const startTime = performance.now();
      
      const result = await pool.query(
        'SELECT id, phone, nickname, created_at FROM users WHERE id = $1',
        [testUserId]
      );
      
      const endTime = performance.now();
      const queryTime = endTime - startTime;
      
      expect(queryTime).toBeLessThan(PERFORMANCE_THRESHOLDS.DATABASE_QUERY_TIME);
      expect(result.rows.length).toBe(1);
      
      console.log(`用户查询时间: ${queryTime.toFixed(2)}ms`);
    });

    it('should execute annotation queries within 100ms', async () => {
      const startTime = performance.now();
      
      const result = await pool.query(
        'SELECT id, title, latitude, longitude, created_at FROM annotations LIMIT 10'
      );
      
      const endTime = performance.now();
      const queryTime = endTime - startTime;
      
      expect(queryTime).toBeLessThan(PERFORMANCE_THRESHOLDS.DATABASE_QUERY_TIME);
      
      console.log(`标注查询时间: ${queryTime.toFixed(2)}ms, 返回记录数: ${result.rows.length}`);
    });

    it('should execute geospatial queries within 100ms', async () => {
      const startTime = performance.now();
      
      const result = await pool.query(`
        SELECT id, title, latitude, longitude,
               ST_Distance(
                 ST_Point(longitude, latitude)::geography,
                 ST_Point($1, $2)::geography
               ) as distance
        FROM annotations
        WHERE ST_DWithin(
          ST_Point(longitude, latitude)::geography,
          ST_Point($1, $2)::geography,
          $3
        )
        ORDER BY distance
        LIMIT 10
      `, [-74.0060, 40.7128, 1000]);
      
      const endTime = performance.now();
      const queryTime = endTime - startTime;
      
      expect(queryTime).toBeLessThan(PERFORMANCE_THRESHOLDS.DATABASE_QUERY_TIME * 2); // 地理查询允许更长时间
      
      console.log(`地理空间查询时间: ${queryTime.toFixed(2)}ms, 返回记录数: ${result.rows.length}`);
    });

    it('should handle concurrent database connections', async () => {
      const concurrentQueries = Array(20).fill(null).map(() => 
        pool.query('SELECT COUNT(*) FROM annotations')
      );

      const startTime = performance.now();
      const results = await Promise.all(concurrentQueries);
      const endTime = performance.now();
      
      const totalTime = endTime - startTime;
      const avgQueryTime = totalTime / results.length;
      
      // 所有查询都应该成功
      results.forEach(result => {
        expect(result.rows.length).toBe(1);
        expect(typeof result.rows[0].count).toBe('string');
      });
      
      expect(avgQueryTime).toBeLessThan(PERFORMANCE_THRESHOLDS.DATABASE_QUERY_TIME);
      
      console.log(`20个并发数据库查询 - 总时间: ${totalTime.toFixed(2)}ms, 平均查询时间: ${avgQueryTime.toFixed(2)}ms`);
    });
  });

  describe('Memory and Resource Usage Tests', () => {
    it('should not have memory leaks during sustained load', async () => {
      const initialMemory = process.memoryUsage();
      
      // 执行1000个请求
      for (let i = 0; i < 100; i++) {
        const batch = Array(10).fill(null).map(() => 
          request(app)
            .get('/api/v1/annotations')
            .set('Authorization', `Bearer ${testUserToken}`)
        );
        
        await Promise.all(batch);
        
        // 每100个请求检查一次内存
        if (i % 20 === 0) {
          global.gc && global.gc(); // 强制垃圾回收（如果可用）
        }
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // 内存增长应该在合理范围内（小于50MB）
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
      
      console.log(`内存使用情况 - 初始: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB, 最终: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB, 增长: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
    });

    it('should handle large payload requests efficiently', async () => {
      const largeDescription = 'A'.repeat(1000); // 1KB描述
      
      const annotationData = {
        latitude: 40.7128,
        longitude: -74.0060,
        title: 'Large Payload Test',
        description: largeDescription,
        smellType: 'chemical',
        intensity: 5,
        rewardAmount: 20.00
      };

      const startTime = performance.now();
      
      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send(annotationData);
      
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME * 2);
      expect(response.status).toBe(201);
      
      console.log(`大负载请求响应时间: ${responseTime.toFixed(2)}ms`);
    });
  });

  describe('Stress Tests', () => {
    it('should maintain performance under high load', async () => {
      const STRESS_DURATION = 10000; // 10秒
      const REQUEST_INTERVAL = 100; // 每100ms发送一个请求
      
      const startTime = performance.now();
      const responses: any[] = [];
      const errors: any[] = [];
      
      const stressTest = async () => {
        while (performance.now() - startTime < STRESS_DURATION) {
          try {
            const response = await request(app)
              .get('/api/v1/annotations')
              .set('Authorization', `Bearer ${testUserToken}`);
            
            responses.push({
              status: response.status,
              time: performance.now() - startTime
            });
          } catch (error) {
            errors.push({
              error: error,
              time: performance.now() - startTime
            });
          }
          
          await new Promise(resolve => setTimeout(resolve, REQUEST_INTERVAL));
        }
      };
      
      await stressTest();
      
      const successRate = responses.length / (responses.length + errors.length);
      const avgResponseTime = responses.reduce((sum, res) => sum + res.time, 0) / responses.length;
      
      // 成功率应该大于95%
      expect(successRate).toBeGreaterThan(0.95);
      
      // 大部分响应应该是成功的
      const successfulResponses = responses.filter(res => res.status === 200);
      expect(successfulResponses.length / responses.length).toBeGreaterThan(0.9);
      
      console.log(`压力测试结果 - 总请求: ${responses.length + errors.length}, 成功率: ${(successRate * 100).toFixed(1)}%, 错误数: ${errors.length}`);
    }, 15000); // 15秒超时
  });

  // 辅助函数
  async function setupTestUser(): Promise<void> {
    try {
      const testUser = await userService.createUser({
        phone: '13900139999',
        nickname: 'Performance Test User'
      });
      testUserId = testUser.id;
      
      testUserToken = jwt.sign(
        { id: testUserId, phone: '13900139999', role: 'user' },
        process.env['JWT_SECRET'] || 'test-secret',
        { expiresIn: '2h' }
      );
    } catch (error) {
      console.warn('设置测试用户时出错:', error);
    }
  }

  async function warmupApplication(): Promise<void> {
    // 预热应用，确保所有模块都已加载
    try {
      await request(app).get('/api/v1/health');
      await request(app)
        .get('/api/v1/annotations')
        .set('Authorization', `Bearer ${testUserToken}`);
    } catch (error) {
      console.warn('应用预热时出错:', error);
    }
  }

  async function cleanupTestData(): Promise<void> {
    try {
      await pool.query('DELETE FROM annotations WHERE title LIKE \'%Test%\'');
      await pool.query('DELETE FROM users WHERE phone = \'13900139999\'');
    } catch (error) {
      console.warn('清理测试数据时出错:', error);
    }
  }
});