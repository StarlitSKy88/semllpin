const request = require('supertest');
const app = require('../setup/testServer');
const { db } = require('../setup/testDatabase');

describe('User Interactions E2E Tests', () => {
  let user1Token, user2Token;
  let user1Id, user2Id;
  let annotationId, commentId;

  beforeAll(async () => {
    // 创建第一个测试用户
    const user1Response = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'testuser1@example.com',
        password: 'test123456',
        username: 'interaction_user1'
      });
    
    user1Id = user1Response.body.data.user.id;
    user1Token = user1Response.body.data.tokens.accessToken;

    // 创建第二个测试用户
    const user2Response = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'testuser2@example.com',
        password: 'test123456',
        username: 'interaction_user2'
      });
    
    user2Id = user2Response.body.data.user.id;
    user2Token = user2Response.body.data.tokens.accessToken;

    // 创建测试标注
    const annotationResponse = await request(app)
      .post('/api/v1/annotations')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({
        content: 'Test annotation for interactions',
        latitude: 39.9042,
        longitude: 116.4074,
        price: 10.00
      });
    
    annotationId = annotationResponse.body.data.id;
  });

  afterAll(async () => {
    // 清理测试数据
    await db('comments').where('annotation_id', annotationId).del();
    await db('favorites').where('annotation_id', annotationId).del();
    await db('likes').where('annotation_id', annotationId).del();
    await db('annotations').where('id', annotationId).del();
    await db('users').whereIn('id', [user1Id, user2Id]).del();
  });

  describe('Like System', () => {
    test('should like annotation successfully', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('liked');
      expect(response.body.data.liked).toBe(true);
      expect(response.body.data).toHaveProperty('likeCount');
      expect(response.body.data.likeCount).toBe(1);
    });

    test('should verify like in database', async () => {
      const dbResult = await db('likes')
        .where('annotation_id', annotationId)
        .where('user_id', user2Id)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].annotation_id).toBe(annotationId);
      expect(dbResult[0].user_id).toBe(user2Id);
      expect(dbResult[0].created_at).toBeDefined();
    });

    test('should get annotation with like status', async () => {
      const response = await request(app)
        .get(`/api/v1/annotations/${annotationId}`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('isLiked');
      expect(response.body.data.isLiked).toBe(true);
      expect(response.body.data).toHaveProperty('likeCount');
      expect(response.body.data.likeCount).toBe(1);
    });

    test('should unlike annotation successfully', async () => {
      const response = await request(app)
        .delete(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('liked');
      expect(response.body.data.liked).toBe(false);
      expect(response.body.data).toHaveProperty('likeCount');
      expect(response.body.data.likeCount).toBe(0);
    });

    test('should verify unlike in database', async () => {
      const dbResult = await db('likes')
        .where('annotation_id', annotationId)
        .where('user_id', user2Id)
        .select('*');

      expect(dbResult.length).toBe(0);
    });

    test('should prevent double like', async () => {
      // 先点赞
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      // 再次点赞
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already liked');
    });

    test('should fail like without authentication', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Favorite System', () => {
    test('should favorite annotation successfully', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/favorite`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('favorited');
      expect(response.body.data.favorited).toBe(true);
      expect(response.body.data).toHaveProperty('favoriteCount');
      expect(response.body.data.favoriteCount).toBe(1);
    });

    test('should verify favorite in database', async () => {
      const dbResult = await db('favorites')
        .where('annotation_id', annotationId)
        .where('user_id', user2Id)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].annotation_id).toBe(annotationId);
      expect(dbResult[0].user_id).toBe(user2Id);
      expect(dbResult[0].created_at).toBeDefined();
    });

    test('should get user favorites list', async () => {
      const response = await request(app)
        .get('/api/v1/user/favorites')
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBe(1);
      expect(response.body.data[0]).toHaveProperty('id');
      expect(response.body.data[0].id).toBe(annotationId);
    });

    test('should unfavorite annotation successfully', async () => {
      const response = await request(app)
        .delete(`/api/v1/annotations/${annotationId}/favorite`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('favorited');
      expect(response.body.data.favorited).toBe(false);
      expect(response.body.data).toHaveProperty('favoriteCount');
      expect(response.body.data.favoriteCount).toBe(0);
    });

    test('should prevent double favorite', async () => {
      // 先收藏
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/favorite`)
        .set('Authorization', `Bearer ${user2Token}`);

      // 再次收藏
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/favorite`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already favorited');
    });
  });

  describe('Comment System', () => {
    test('should create comment successfully', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({
          content: 'This is a test comment',
          parentId: null
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data).toHaveProperty('content');
      expect(response.body.data.content).toBe('This is a test comment');
      expect(response.body.data).toHaveProperty('authorId');
      expect(response.body.data.authorId).toBe(user2Id);
      
      commentId = response.body.data.id;
    });

    test('should verify comment in database', async () => {
      const dbResult = await db('comments')
        .where('id', commentId)
        .select('*');

      expect(dbResult.length).toBe(1);
      expect(dbResult[0].annotation_id).toBe(annotationId);
      expect(dbResult[0].user_id).toBe(user2Id);
      expect(dbResult[0].content).toBe('This is a test comment');
      expect(dbResult[0].parent_id).toBeNull();
    });

    test('should get annotation comments', async () => {
      const response = await request(app)
        .get(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBe(1);
      expect(response.body.data[0]).toHaveProperty('id');
      expect(response.body.data[0].id).toBe(commentId);
      expect(response.body.data[0]).toHaveProperty('author');
      expect(response.body.data[0].author).toHaveProperty('username');
    });

    test('should create reply comment successfully', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({
          content: 'This is a reply to the comment',
          parentId: commentId
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('parentId');
      expect(response.body.data.parentId).toBe(commentId);
    });

    test('should get comments with replies', async () => {
      const response = await request(app)
        .get(`/api/v1/annotations/${annotationId}/comments?includeReplies=true`)
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.length).toBeGreaterThan(1);
      
      const parentComment = response.body.data.find(c => c.id === commentId);
      expect(parentComment).toHaveProperty('replies');
      expect(Array.isArray(parentComment.replies)).toBe(true);
      expect(parentComment.replies.length).toBe(1);
    });

    test('should update comment successfully', async () => {
      const response = await request(app)
        .put(`/api/v1/comments/${commentId}`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({
          content: 'Updated comment content'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('content');
      expect(response.body.data.content).toBe('Updated comment content');
    });

    test('should fail to update comment by non-author', async () => {
      const response = await request(app)
        .put(`/api/v1/comments/${commentId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({
          content: 'Unauthorized update attempt'
        });

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('permission');
    });

    test('should delete comment successfully', async () => {
      const response = await request(app)
        .delete(`/api/v1/comments/${commentId}`)
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should verify comment deletion in database', async () => {
      const dbResult = await db('comments')
        .where('id', commentId)
        .select('*');

      expect(dbResult.length).toBe(0);
    });

    test('should validate comment content', async () => {
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({
          content: '', // 空内容
          parentId: null
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Content is required');
    });

    test('should limit comment length', async () => {
      const longContent = 'a'.repeat(1001); // 超过1000字符限制
      
      const response = await request(app)
        .post(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({
          content: longContent,
          parentId: null
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('too long');
    });
  });

  describe('Interaction Statistics', () => {
    beforeEach(async () => {
      // 创建一些交互数据
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);
      
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/favorite`)
        .set('Authorization', `Bearer ${user2Token}`);
    });

    test('should get annotation interaction stats', async () => {
      const response = await request(app)
        .get(`/api/v1/annotations/${annotationId}/stats`)
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('likeCount');
      expect(response.body.data).toHaveProperty('favoriteCount');
      expect(response.body.data).toHaveProperty('commentCount');
      expect(response.body.data.likeCount).toBe(1);
      expect(response.body.data.favoriteCount).toBe(1);
    });

    test('should get user interaction history', async () => {
      const response = await request(app)
        .get('/api/v1/user/interactions')
        .set('Authorization', `Bearer ${user2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('likes');
      expect(response.body.data).toHaveProperty('favorites');
      expect(response.body.data).toHaveProperty('comments');
      expect(Array.isArray(response.body.data.likes)).toBe(true);
      expect(Array.isArray(response.body.data.favorites)).toBe(true);
    });

    test('should get trending annotations based on interactions', async () => {
      const response = await request(app)
        .get('/api/v1/annotations/trending')
        .query({ timeframe: '24h' });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      
      if (response.body.data.length > 0) {
        expect(response.body.data[0]).toHaveProperty('interactionScore');
        expect(response.body.data[0]).toHaveProperty('likeCount');
        expect(response.body.data[0]).toHaveProperty('favoriteCount');
      }
    });
  });

  describe('Notification System', () => {
    test('should create notification when annotation is liked', async () => {
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      // 检查通知是否创建
      const notificationResult = await db('notifications')
        .where('user_id', user1Id)
        .where('type', 'like')
        .orderBy('created_at', 'desc')
        .limit(1)
        .select('*');

      expect(notificationResult.length).toBe(1);
      expect(notificationResult[0].content).toContain('liked your annotation');
      expect(notificationResult[0].is_read).toBe(false);
    });

    test('should create notification when annotation is commented', async () => {
      await request(app)
        .post(`/api/v1/annotations/${annotationId}/comments`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({
          content: 'Notification test comment',
          parentId: null
        });

      // 检查通知是否创建
      const notificationResult = await db('notifications')
        .where('user_id', user1Id)
        .where('type', 'comment')
        .orderBy('created_at', 'desc')
        .limit(1)
        .select('*');

      expect(notificationResult.length).toBe(1);
      expect(notificationResult[0].content).toContain('commented on your annotation');
    });

    test('should get user notifications', async () => {
      const response = await request(app)
        .get('/api/v1/user/notifications')
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBeGreaterThan(0);
    });

    test('should mark notifications as read', async () => {
      const response = await request(app)
        .put('/api/v1/user/notifications/mark-read')
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);

      // 验证数据库中的通知已标记为已读
      const dbResult = await db('notifications')
        .where('user_id', user1Id)
        .where('is_read', false)
        .count('* as unread_count')
        .first();

      expect(dbResult.unread_count).toBe(0);
    });
  });

  describe('Database Consistency', () => {
    test('should maintain referential integrity for interactions', async () => {
      // 验证点赞数据一致性
      const likeCountAPI = await request(app)
        .get(`/api/v1/annotations/${annotationId}`)
        .set('Authorization', `Bearer ${user1Token}`);

      const likeCountDB = await db('likes')
        .where('annotation_id', annotationId)
        .count('* as count')
        .first();

      expect(likeCountAPI.body.data.likeCount).toBe(likeCountDB.count);
    });

    test('should handle cascade deletion properly', async () => {
      // 创建临时标注和交互
      const tempAnnotationResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${user1Token}`)
        .send({
          content: 'Temp annotation for deletion test',
          latitude: 39.9050,
          longitude: 116.4080,
          price: 5.00
        });

      const tempAnnotationId = tempAnnotationResponse.body.data.id;

      // 添加交互
      await request(app)
        .post(`/api/v1/annotations/${tempAnnotationId}/like`)
        .set('Authorization', `Bearer ${user2Token}`);

      await request(app)
        .post(`/api/v1/annotations/${tempAnnotationId}/comments`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ content: 'Test comment', parentId: null });

      // 删除标注
      await request(app)
        .delete(`/api/v1/annotations/${tempAnnotationId}`)
        .set('Authorization', `Bearer ${user1Token}`);

      // 验证相关交互数据也被删除
      const likesResult = await db('likes')
        .where('annotation_id', tempAnnotationId)
        .count('* as count')
        .first();

      const commentsResult = await db('comments')
        .where('annotation_id', tempAnnotationId)
        .count('* as count')
        .first();

      expect(likesResult.count).toBe(0);
      expect(commentsResult.count).toBe(0);
    });
  });
});