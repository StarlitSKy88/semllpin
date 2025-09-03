const request = require('supertest');
const { expect } = require('chai');
const app = require('../../src/app');
const { db } = require('../../src/config/database');
const { generateTestUser, generateTestAnnotation } = require('../helpers/testData');

describe('Annotation Functionality Tests', () => {
  let testUser;
  let authToken;
  let testAnnotation;

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
  });

  after(async () => {
    // 清理测试数据
    await db('annotations').del();
    await db('users').del();
  });

  describe('创建标注功能', () => {
    it('应该成功创建一个新的气味标注', async () => {
      testAnnotation = generateTestAnnotation();
      
      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(testAnnotation)
        .expect(201);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('id');
      expect(response.body.data.latitude).to.equal(testAnnotation.latitude);
      expect(response.body.data.longitude).to.equal(testAnnotation.longitude);
      expect(response.body.data.smell_intensity).to.equal(testAnnotation.smell_intensity);
      expect(response.body.data.description).to.equal(testAnnotation.description);
      expect(response.body.data.category).to.equal(testAnnotation.category);
      
      testAnnotation.id = response.body.data.id;
    });

    it('应该拒绝无效的坐标', async () => {
      const invalidAnnotation = {
        ...generateTestAnnotation(),
        latitude: 200, // 无效纬度
        longitude: 200, // 无效经度
      };

      await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidAnnotation)
        .expect(400);
    });

    it('应该拒绝无效的气味强度', async () => {
      const invalidAnnotation = {
        ...generateTestAnnotation(),
        smell_intensity: 15, // 超出范围 (1-10)
      };

      await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidAnnotation)
        .expect(400);
    });

    it('应该拒绝未认证的请求', async () => {
      await request(app)
        .post('/api/annotations')
        .send(generateTestAnnotation())
        .expect(401);
    });
  });

  describe('获取标注功能', () => {
    it('应该获取所有标注列表', async () => {
      const response = await request(app)
        .get('/api/annotations')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.data.length).to.be.greaterThan(0);
    });

    it('应该根据地理位置过滤标注', async () => {
      const response = await request(app)
        .get('/api/annotations')
        .query({
          latitude: testAnnotation.latitude,
          longitude: testAnnotation.longitude,
          radius: 1000, // 1km半径
        })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该根据气味强度过滤标注', async () => {
      const response = await request(app)
        .get('/api/annotations')
        .query({
          min_intensity: 5,
          max_intensity: 10,
        })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该根据类别过滤标注', async () => {
      const response = await request(app)
        .get('/api/annotations')
        .query({
          category: testAnnotation.category,
        })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该支持分页', async () => {
      const response = await request(app)
        .get('/api/annotations')
        .query({
          page: 1,
          limit: 5,
        })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.pagination).to.have.property('page');
      expect(response.body.pagination).to.have.property('limit');
      expect(response.body.pagination).to.have.property('total');
    });
  });

  describe('更新标注功能', () => {
    it('应该允许作者更新自己的标注', async () => {
      const updateData = {
        description: '更新后的描述',
        smell_intensity: 8,
      };

      const response = await request(app)
        .put(`/api/annotations/${testAnnotation.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.description).to.equal(updateData.description);
      expect(response.body.data.smell_intensity).to.equal(updateData.smell_intensity);
    });

    it('应该拒绝非作者更新标注', async () => {
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
        .put(`/api/annotations/${testAnnotation.id}`)
        .set('Authorization', `Bearer ${anotherToken}`)
        .send({ description: '恶意更新' })
        .expect(403);
    });
  });

  describe('删除标注功能', () => {
    it('应该允许作者删除自己的标注', async () => {
      const response = await request(app)
        .delete(`/api/annotations/${testAnnotation.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;

      // 验证标注已被删除
      await request(app)
        .get(`/api/annotations/${testAnnotation.id}`)
        .expect(404);
    });
  });

  describe('搞笑功能测试', () => {
    beforeEach(async () => {
      // 为每个搞笑功能测试创建新的标注
      testAnnotation = generateTestAnnotation();
      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(testAnnotation)
        .expect(201);
      testAnnotation.id = response.body.data.id;
    });

    it('应该支持添加搞笑评论', async () => {
      const funnyComment = {
        content: '这里的味道比我袜子还臭！😂',
        is_funny: true,
      };

      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(funnyComment)
        .expect(201);

      expect(response.body.success).to.be.true;
      expect(response.body.data.content).to.equal(funnyComment.content);
      expect(response.body.data.is_funny).to.be.true;
    });

    it('应该支持给标注点赞', async () => {
      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.liked).to.be.true;
    });

    it('应该支持取消点赞', async () => {
      // 先点赞
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // 再取消点赞
      const response = await request(app)
        .delete(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.liked).to.be.false;
    });

    it('应该支持分享标注', async () => {
      const shareData = {
        platform: 'wechat',
        message: '快来看看这个搞笑的气味标注！',
      };

      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/share`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(shareData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('share_url');
      expect(response.body.data).to.have.property('share_count');
    });

    it('应该获取热门搞笑标注', async () => {
      const response = await request(app)
        .get('/api/annotations/funny/popular')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该获取最新搞笑标注', async () => {
      const response = await request(app)
        .get('/api/annotations/funny/latest')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('媒体文件功能', () => {
    it('应该支持上传图片', async () => {
      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/media`)
        .set('Authorization', `Bearer ${authToken}`)
        .attach('file', Buffer.from('fake image data'), 'test.jpg')
        .expect(201);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('file_url');
      expect(response.body.data.file_type).to.equal('image');
    });

    it('应该拒绝不支持的文件类型', async () => {
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/media`)
        .set('Authorization', `Bearer ${authToken}`)
        .attach('file', Buffer.from('fake exe data'), 'virus.exe')
        .expect(400);
    });
  });

  describe('性能测试', () => {
    it('应该在合理时间内响应大量标注请求', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/annotations')
        .query({ limit: 100 })
        .expect(200);
      
      const responseTime = Date.now() - startTime;
      
      expect(responseTime).to.be.lessThan(1000); // 应该在1秒内响应
      expect(response.body.success).to.be.true;
    });

    it('应该正确处理并发请求', async () => {
      const promises = [];
      
      // 创建10个并发请求
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .get('/api/annotations')
            .expect(200)
        );
      }
      
      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body.success).to.be.true;
      });
    });
  });

  describe('边界条件测试', () => {
    it('应该处理极端坐标值', async () => {
      const extremeAnnotation = {
        ...generateTestAnnotation(),
        latitude: 90, // 北极
        longitude: 180, // 国际日期变更线
      };

      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(extremeAnnotation)
        .expect(201);

      expect(response.body.success).to.be.true;
    });

    it('应该处理超长描述', async () => {
      const longDescription = 'a'.repeat(1000); // 1000字符
      
      const longAnnotation = {
        ...generateTestAnnotation(),
        description: longDescription,
      };

      await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(longAnnotation)
        .expect(400); // 应该拒绝过长的描述
    });

    it('应该处理特殊字符', async () => {
      const specialAnnotation = {
        ...generateTestAnnotation(),
        description: '这里有特殊字符：<script>alert("XSS")</script> & 中文 🤢',
      };

      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(specialAnnotation)
        .expect(201);

      expect(response.body.success).to.be.true;
      // 验证XSS已被过滤
      expect(response.body.data.description).to.not.include('<script>');
    });
  });
});