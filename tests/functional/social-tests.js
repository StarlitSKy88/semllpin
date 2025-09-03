const request = require('supertest');
const { expect } = require('chai');
const app = require('../../src/app');
const { db } = require('../../src/config/database');
const { generateTestUser, generateTestAnnotation } = require('../helpers/testData');

describe('Social Interaction Tests', () => {
  let user1, user2, user3;
  let token1, token2, token3;
  let testAnnotation;

  before(async () => {
    // 设置测试数据库
    await db.migrate.latest();
    
    // 创建三个测试用户
    user1 = generateTestUser();
    user2 = generateTestUser();
    user3 = generateTestUser();
    
    // 注册用户
    await request(app).post('/api/auth/register').send(user1).expect(201);
    await request(app).post('/api/auth/register').send(user2).expect(201);
    await request(app).post('/api/auth/register').send(user3).expect(201);
    
    // 获取认证token
    const login1 = await request(app).post('/api/auth/login').send({
      email: user1.email,
      password: user1.password,
    }).expect(200);
    token1 = login1.body.data.token;
    
    const login2 = await request(app).post('/api/auth/login').send({
      email: user2.email,
      password: user2.password,
    }).expect(200);
    token2 = login2.body.data.token;
    
    const login3 = await request(app).post('/api/auth/login').send({
      email: user3.email,
      password: user3.password,
    }).expect(200);
    token3 = login3.body.data.token;
    
    // 创建测试标注
    const annotationResponse = await request(app)
      .post('/api/annotations')
      .set('Authorization', `Bearer ${token1}`)
      .send(generateTestAnnotation())
      .expect(201);
    testAnnotation = annotationResponse.body.data;
  });

  after(async () => {
    // 清理测试数据
    await db('user_follows').del();
    await db('comments').del();
    await db('annotation_likes').del();
    await db('annotations').del();
    await db('users').del();
  });

  describe('用户关注功能', () => {
    it('应该允许用户关注其他用户', async () => {
      const response = await request(app)
        .post(`/api/users/${user2.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.following).to.be.true;
    });

    it('应该防止用户关注自己', async () => {
      await request(app)
        .post(`/api/users/${user1.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(400);
    });

    it('应该防止重复关注', async () => {
      // 第一次关注
      await request(app)
        .post(`/api/users/${user3.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      // 第二次关注应该失败
      await request(app)
        .post(`/api/users/${user3.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(400);
    });

    it('应该允许用户取消关注', async () => {
      const response = await request(app)
        .delete(`/api/users/${user2.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.following).to.be.false;
    });

    it('应该获取用户的关注列表', async () => {
      // 重新关注user2
      await request(app)
        .post(`/api/users/${user2.id}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      const response = await request(app)
        .get(`/api/users/${user1.id}/following`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.data.length).to.be.greaterThan(0);
    });

    it('应该获取用户的粉丝列表', async () => {
      const response = await request(app)
        .get(`/api/users/${user2.id}/followers`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.data.length).to.be.greaterThan(0);
    });
  });

  describe('评论功能', () => {
    let testComment;

    it('应该允许用户添加评论', async () => {
      const commentData = {
        content: '这个地方我也去过，确实很臭！😷',
      };

      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/comments`)
        .set('Authorization', `Bearer ${token2}`)
        .send(commentData)
        .expect(201);

      expect(response.body.success).to.be.true;
      expect(response.body.data.content).to.equal(commentData.content);
      expect(response.body.data.user_id).to.equal(user2.id);
      
      testComment = response.body.data;
    });

    it('应该支持回复评论', async () => {
      const replyData = {
        content: '我觉得还好啊，可能是风向的问题',
        parent_id: testComment.id,
      };

      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/comments`)
        .set('Authorization', `Bearer ${token3}`)
        .send(replyData)
        .expect(201);

      expect(response.body.success).to.be.true;
      expect(response.body.data.parent_id).to.equal(testComment.id);
    });

    it('应该获取标注的所有评论', async () => {
      const response = await request(app)
        .get(`/api/annotations/${testAnnotation.id}/comments`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      expect(response.body.data.length).to.be.greaterThan(0);
    });

    it('应该支持评论分页', async () => {
      const response = await request(app)
        .get(`/api/annotations/${testAnnotation.id}/comments`)
        .query({ page: 1, limit: 5 })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.pagination).to.have.property('page');
      expect(response.body.pagination).to.have.property('limit');
    });

    it('应该允许作者删除自己的评论', async () => {
      const response = await request(app)
        .delete(`/api/comments/${testComment.id}`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      expect(response.body.success).to.be.true;
    });

    it('应该拒绝非作者删除评论', async () => {
      // 创建新评论
      const commentResponse = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/comments`)
        .set('Authorization', `Bearer ${token2}`)
        .send({ content: '测试评论' })
        .expect(201);

      // 尝试用其他用户删除
      await request(app)
        .delete(`/api/comments/${commentResponse.body.data.id}`)
        .set('Authorization', `Bearer ${token3}`)
        .expect(403);
    });
  });

  describe('点赞功能', () => {
    it('应该允许用户给标注点赞', async () => {
      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.liked).to.be.true;
    });

    it('应该防止重复点赞', async () => {
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(400);
    });

    it('应该允许用户取消点赞', async () => {
      const response = await request(app)
        .delete(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.liked).to.be.false;
    });

    it('应该获取标注的点赞数', async () => {
      // 多个用户点赞
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token3}`)
        .expect(200);

      const response = await request(app)
        .get(`/api/annotations/${testAnnotation.id}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.like_count).to.be.greaterThan(0);
    });
  });

  describe('分享功能', () => {
    it('应该生成分享链接', async () => {
      const shareData = {
        platform: 'wechat',
        message: '快来看看这个搞笑的气味标注！',
      };

      const response = await request(app)
        .post(`/api/annotations/${testAnnotation.id}/share`)
        .set('Authorization', `Bearer ${token2}`)
        .send(shareData)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('share_url');
      expect(response.body.data).to.have.property('share_count');
      expect(response.body.data.share_url).to.include(testAnnotation.id);
    });

    it('应该记录分享统计', async () => {
      // 多次分享
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/share`)
        .set('Authorization', `Bearer ${token3}`)
        .send({ platform: 'weibo' })
        .expect(200);

      const response = await request(app)
        .get(`/api/annotations/${testAnnotation.id}`)
        .expect(200);

      expect(response.body.data.share_count).to.be.greaterThan(0);
    });

    it('应该获取热门分享', async () => {
      const response = await request(app)
        .get('/api/annotations/popular-shares')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('用户互动历史', () => {
    it('应该获取用户的互动历史', async () => {
      const response = await request(app)
        .get('/api/users/interaction-history')
        .set('Authorization', `Bearer ${token2}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('likes');
      expect(response.body.data).to.have.property('comments');
      expect(response.body.data).to.have.property('shares');
    });

    it('应该获取用户的关注动态', async () => {
      const response = await request(app)
        .get('/api/users/following-activities')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('社交统计', () => {
    it('应该获取用户的社交统计', async () => {
      const response = await request(app)
        .get(`/api/users/${user1.id}/stats`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('annotation_count');
      expect(response.body.data).to.have.property('follower_count');
      expect(response.body.data).to.have.property('following_count');
      expect(response.body.data).to.have.property('total_likes_received');
    });

    it('应该获取平台整体统计', async () => {
      const response = await request(app)
        .get('/api/stats/social')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('total_users');
      expect(response.body.data).to.have.property('total_annotations');
      expect(response.body.data).to.have.property('total_comments');
      expect(response.body.data).to.have.property('total_likes');
    });
  });

  describe('通知功能', () => {
    it('应该在被关注时发送通知', async () => {
      // user3关注user1
      await request(app)
        .post(`/api/users/${user1.id}/follow`)
        .set('Authorization', `Bearer ${token3}`)
        .expect(200);

      // 检查user1的通知
      const response = await request(app)
        .get('/api/notifications')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
      
      const followNotification = response.body.data.find(
        n => n.type === 'follow' && n.from_user_id === user3.id
      );
      expect(followNotification).to.exist;
    });

    it('应该在标注被评论时发送通知', async () => {
      // user3评论user1的标注
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/comments`)
        .set('Authorization', `Bearer ${token3}`)
        .send({ content: '有趣的标注！' })
        .expect(201);

      // 检查user1的通知
      const response = await request(app)
        .get('/api/notifications')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      const commentNotification = response.body.data.find(
        n => n.type === 'comment' && n.from_user_id === user3.id
      );
      expect(commentNotification).to.exist;
    });

    it('应该在标注被点赞时发送通知', async () => {
      // user3点赞user1的标注
      await request(app)
        .post(`/api/annotations/${testAnnotation.id}/like`)
        .set('Authorization', `Bearer ${token3}`)
        .expect(200);

      // 检查user1的通知
      const response = await request(app)
        .get('/api/notifications')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      const likeNotification = response.body.data.find(
        n => n.type === 'like' && n.from_user_id === user3.id
      );
      expect(likeNotification).to.exist;
    });

    it('应该支持标记通知为已读', async () => {
      const notificationsResponse = await request(app)
        .get('/api/notifications')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      const notification = notificationsResponse.body.data[0];
      
      const response = await request(app)
        .put(`/api/notifications/${notification.id}/read`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data.is_read).to.be.true;
    });

    it('应该获取未读通知数量', async () => {
      const response = await request(app)
        .get('/api/notifications/unread-count')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.have.property('count');
      expect(response.body.data.count).to.be.a('number');
    });
  });

  describe('搞笑内容推荐', () => {
    it('应该基于用户兴趣推荐内容', async () => {
      const response = await request(app)
        .get('/api/recommendations/funny')
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该获取趋势标注', async () => {
      const response = await request(app)
        .get('/api/annotations/trending')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });

    it('应该获取本周最搞笑的标注', async () => {
      const response = await request(app)
        .get('/api/annotations/funniest-this-week')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.be.an('array');
    });
  });

  describe('性能测试', () => {
    it('应该快速处理社交查询', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get(`/api/users/${user1.id}/following`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);
      
      const responseTime = Date.now() - startTime;
      expect(responseTime).to.be.lessThan(500); // 应该在500ms内响应
    });

    it('应该处理大量通知查询', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get('/api/notifications')
        .query({ limit: 50 })
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);
      
      const responseTime = Date.now() - startTime;
      expect(responseTime).to.be.lessThan(1000); // 应该在1秒内响应
    });
  });
});