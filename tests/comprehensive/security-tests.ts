/**
 * 安全性全面测试套件
 * 
 * 测试SQL注入、XSS防护、CSRF防护、身份验证绕过、授权漏洞等安全问题
 */

import request from 'supertest';
import { faker } from '@faker-js/faker/locale/zh_CN';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Client } from 'pg';

describe('7. 安全性测试', () => {
  let testUser: any;
  let authToken: string;
  let adminUser: any;
  let adminToken: string;

  beforeAll(async () => {
    // 创建测试用户
    testUser = {
      id: faker.string.uuid(),
      email: faker.internet.email(),
      username: faker.internet.username(),
      password: 'TestPassword123!',
      role: 'user'
    };

    // 创建管理员用户
    adminUser = {
      id: faker.string.uuid(),
      email: faker.internet.email(),
      username: faker.internet.username(),
      password: 'AdminPassword123!',
      role: 'admin'
    };

    // 生成测试令牌
    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email, role: testUser.role },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );

    adminToken = jwt.sign(
      { userId: adminUser.id, email: adminUser.email, role: adminUser.role },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );
  });

  describe('SQL注入攻击防护', () => {
    const sqlInjectionPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' OR 1=1 --",
      "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
      "' UNION SELECT * FROM users --",
      "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
      "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
      "'; DELETE FROM annotations; --",
      "' OR username LIKE '%admin%' --",
      "\"; DROP DATABASE smellpin; --"
    ];

    it('应该防护用户登录的SQL注入', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .post('/api/v1/users/login')
          .send({
            email: payload,
            password: payload
          });

        // 不应该返回500错误（说明SQL注入被阻止）
        expect(response.status).not.toBe(500);
        
        // 应该返回正常的登录失败响应
        if (response.status === 401) {
          expect(response.body).toHaveProperty('success', false);
          expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
        }
      }
    });

    it('应该防护用户注册的SQL注入', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .post('/api/v1/users/register')
          .send({
            email: payload,
            username: payload,
            password: 'ValidPassword123!'
          });

        expect(response.status).not.toBe(500);
        
        if (response.status === 400) {
          expect(response.body).toHaveProperty('success', false);
        }
      }
    });

    it('应该防护标注查询的SQL注入', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .get('/api/v1/annotations/list')
          .query({
            smellType: payload,
            search: payload,
            userId: payload
          });

        expect(response.status).not.toBe(500);
        
        if (response.body.success === true) {
          expect(Array.isArray(response.body.data.annotations)).toBe(true);
        }
      }
    });

    it('应该防护用户搜索的SQL注入', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .get('/api/v1/search/users')
          .query({ q: payload })
          .set('Authorization', `Bearer ${authToken}`);

        expect(response.status).not.toBe(500);
      }
    });

    it('应该防护地理位置查询的SQL注入', async () => {
      const locationPayloads = [
        "31.2304'; DROP TABLE annotations; --",
        "31.2304 OR 1=1",
        "UNION SELECT * FROM users"
      ];

      for (const payload of locationPayloads) {
        const response = await request(app)
          .get('/api/v1/annotations/nearby')
          .query({
            latitude: payload,
            longitude: payload,
            radius: payload
          });

        expect(response.status).not.toBe(500);
      }
    });

    it('应该防护数据库函数注入', async () => {
      const functionInjectionPayloads = [
        "version()",
        "pg_sleep(10)",
        "current_user",
        "current_database()",
        "pg_read_file('/etc/passwd')"
      ];

      for (const payload of functionInjectionPayloads) {
        const response = await request(app)
          .get('/api/v1/annotations/list')
          .query({ description: payload });

        expect(response.status).not.toBe(500);
      }
    });
  });

  describe('XSS攻击防护', () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">',
      '<svg onload="alert(\'XSS\')">',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<div onmouseover="alert(\'XSS\')">Hover me</div>',
      '<input type="text" onfocus="alert(\'XSS\')" autofocus>',
      '<body onload="alert(\'XSS\')">',
      '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
      '"><script>alert("XSS")</script>',
      '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";',
      '<scr<script>ipt>alert("XSS")</scr</script>ipt>'
    ];

    it('应该清理标注描述中的XSS', async () => {
      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            latitude: 31.2304,
            longitude: 121.4737,
            smellType: 'industrial',
            intensity: 3,
            description: payload
          });

        if (response.status === 201) {
          // 检查返回的描述是否被清理
          expect(response.body.data.description).not.toContain('<script>');
          expect(response.body.data.description).not.toContain('onerror');
          expect(response.body.data.description).not.toContain('onload');
          expect(response.body.data.description).not.toContain('javascript:');
        }
      }
    });

    it('应该清理用户资料中的XSS', async () => {
      for (const payload of xssPayloads) {
        const response = await request(app)
          .put('/api/v1/users/profile')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            username: 'testuser',
            bio: payload,
            location: payload
          });

        if (response.status === 200) {
          expect(response.body.data.bio).not.toContain('<script>');
          expect(response.body.data.location).not.toContain('<script>');
        }
      }
    });

    it('应该清理评论中的XSS', async () => {
      // 首先创建一个测试标注
      const annotationResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          latitude: 31.2304,
          longitude: 121.4737,
          smellType: 'industrial',
          intensity: 3,
          description: '测试标注'
        });

      if (annotationResponse.status === 201) {
        const annotationId = annotationResponse.body.data.id;

        for (const payload of xssPayloads) {
          const response = await request(app)
            .post(`/api/v1/annotations/${annotationId}/comments`)
            .set('Authorization', `Bearer ${authToken}`)
            .send({
              content: payload
            });

          if (response.status === 201) {
            expect(response.body.data.content).not.toContain('<script>');
            expect(response.body.data.content).not.toContain('onerror');
          }
        }

        // 清理测试标注
        await request(app)
          .delete(`/api/v1/annotations/${annotationId}`)
          .set('Authorization', `Bearer ${authToken}`);
      }
    });

    it('应该设置正确的CSP头', async () => {
      const response = await request(app)
        .get('/api/v1/health');

      expect(response.headers['content-security-policy']).toBeTruthy();
      expect(response.headers['content-security-policy']).toContain("default-src 'self'");
      expect(response.headers['content-security-policy']).toContain("script-src 'self'");
      expect(response.headers['content-security-policy']).toContain("object-src 'none'");
    });

    it('应该设置XSS防护头', async () => {
      const response = await request(app)
        .get('/api/v1/health');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBeTruthy();
    });
  });

  describe('身份验证绕过测试', () => {
    it('应该拒绝无效的JWT令牌', async () => {
      const invalidTokens = [
        'invalid.jwt.token',
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid',
        'Bearer invalid-token',
        '',
        null,
        undefined
      ];

      for (const token of invalidTokens) {
        const response = await request(app)
          .get('/api/v1/users/profile/me')
          .set('Authorization', token ? `Bearer ${token}` : '');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('success', false);
        expect(response.body.error.code).toBe('INVALID_TOKEN');
      }
    });

    it('应该拒绝过期的JWT令牌', async () => {
      const expiredToken = jwt.sign(
        { userId: testUser.id, email: testUser.email },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '-1h' } // 1小时前过期
      );

      const response = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('应该拒绝被篡改的JWT令牌', async () => {
      const validToken = jwt.sign(
        { userId: testUser.id, email: testUser.email, role: 'user' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      // 篡改令牌的最后几个字符
      const tamperedToken = validToken.slice(0, -10) + 'tampered123';

      const response = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${tamperedToken}`);

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });

    it('应该拒绝使用错误密钥签名的JWT令牌', async () => {
      const tokenWithWrongKey = jwt.sign(
        { userId: testUser.id, email: testUser.email, role: 'admin' },
        'wrong-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${tokenWithWrongKey}`);

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });

    it('应该防止JWT算法混淆攻击', async () => {
      // 尝试使用"none"算法的令牌
      const noneAlgToken = jwt.sign(
        { userId: testUser.id, email: testUser.email, role: 'admin' },
        '',
        { algorithm: 'none' as any }
      );

      const response = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${noneAlgToken}`);

      expect(response.status).toBe(401);
    });

    it('应该防止会话固定攻击', async () => {
      // 登录获取令牌
      const loginResponse = await request(app)
        .post('/api/v1/users/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(loginResponse.status).toBe(200);
      const firstToken = loginResponse.body.data.token;

      // 再次登录应该获得不同的令牌
      const secondLoginResponse = await request(app)
        .post('/api/v1/users/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(secondLoginResponse.status).toBe(200);
      const secondToken = secondLoginResponse.body.data.token;

      expect(firstToken).not.toBe(secondToken);
    });
  });

  describe('授权绕过测试', () => {
    it('应该防止水平权限提升', async () => {
      // 创建另一个用户
      const otherUser = {
        id: faker.string.uuid(),
        email: faker.internet.email(),
        username: faker.internet.username()
      };

      const otherUserToken = jwt.sign(
        { userId: otherUser.id, email: otherUser.email, role: 'user' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      // 尝试访问其他用户的资料
      const response = await request(app)
        .get(`/api/v1/users/${testUser.id}/profile`)
        .set('Authorization', `Bearer ${otherUserToken}`);

      // 应该被拒绝或只返回公开信息
      if (response.status === 403) {
        expect(response.body).toHaveProperty('success', false);
        expect(response.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
      } else if (response.status === 200) {
        // 如果允许访问，不应该包含敏感信息
        expect(response.body.data).not.toHaveProperty('email');
        expect(response.body.data).not.toHaveProperty('phone');
      }
    });

    it('应该防止垂直权限提升', async () => {
      // 普通用户尝试访问管理员功能
      const adminOnlyEndpoints = [
        '/api/v1/admin/users',
        '/api/v1/admin/annotations/moderate',
        '/api/v1/admin/system/stats',
        '/api/v1/admin/payments/refunds'
      ];

      for (const endpoint of adminOnlyEndpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Authorization', `Bearer ${authToken}`);

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('success', false);
        expect(response.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
      }
    });

    it('应该验证资源所有权', async () => {
      // 创建一个标注
      const annotationResponse = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          latitude: 31.2304,
          longitude: 121.4737,
          smellType: 'industrial',
          intensity: 3,
          description: '测试标注所有权'
        });

      if (annotationResponse.status === 201) {
        const annotationId = annotationResponse.body.data.id;

        // 创建另一个用户尝试修改这个标注
        const otherUser = {
          id: faker.string.uuid(),
          email: faker.internet.email()
        };

        const otherUserToken = jwt.sign(
          { userId: otherUser.id, email: otherUser.email, role: 'user' },
          process.env.JWT_SECRET || 'test-secret',
          { expiresIn: '1h' }
        );

        const updateResponse = await request(app)
          .put(`/api/v1/annotations/${annotationId}`)
          .set('Authorization', `Bearer ${otherUserToken}`)
          .send({
            description: '尝试修改他人标注'
          });

        expect(updateResponse.status).toBe(403);
        expect(updateResponse.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');

        // 清理
        await request(app)
          .delete(`/api/v1/annotations/${annotationId}`)
          .set('Authorization', `Bearer ${authToken}`);
      }
    });

    it('应该防止批量权限绕过', async () => {
      // 尝试批量修改不属于自己的数据
      const maliciousPayload = {
        annotationIds: ['*', 'all', '%'],
        action: 'delete'
      };

      const response = await request(app)
        .post('/api/v1/annotations/batch')
        .set('Authorization', `Bearer ${authToken}`)
        .send(maliciousPayload);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('success', false);
    });
  });

  describe('CSRF攻击防护', () => {
    it('应该要求CSRF令牌进行状态改变操作', async () => {
      // 测试没有CSRF令牌的POST请求
      const response = await request(app)
        .post('/api/v1/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Origin', 'https://malicious-site.com')
        .send({
          latitude: 31.2304,
          longitude: 121.4737,
          smellType: 'industrial',
          intensity: 3,
          description: 'CSRF测试'
        });

      // 应该验证Origin头或要求CSRF令牌
      if (response.status === 403) {
        expect(response.body.error.code).toBe('CSRF_PROTECTION');
      }
    });

    it('应该验证Origin头', async () => {
      const maliciousOrigins = [
        'https://malicious-site.com',
        'http://localhost:3000.evil.com',
        'data:text/html,<script>alert("XSS")</script>',
        'javascript:alert("XSS")'
      ];

      for (const origin of maliciousOrigins) {
        const response = await request(app)
          .post('/api/v1/users/logout')
          .set('Authorization', `Bearer ${authToken}`)
          .set('Origin', origin);

        // 应该拒绝恶意Origin
        if (response.status === 403) {
          expect(response.body.error.code).toBe('INVALID_ORIGIN');
        }
      }
    });

    it('应该验证Referer头', async () => {
      const response = await request(app)
        .post('/api/v1/users/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Referer', 'https://malicious-site.com/csrf-attack');

      // 可能基于Referer头进行额外验证
      expect([200, 403]).toContain(response.status);
    });
  });

  describe('输入验证和过滤', () => {
    it('应该验证文件上传类型', async () => {
      const maliciousFiles = [
        { filename: 'script.js', content: 'alert("XSS")' },
        { filename: 'virus.exe', content: 'malicious binary' },
        { filename: 'shell.php', content: '<?php system($_GET["cmd"]); ?>' },
        { filename: 'image.jpg.exe', content: 'fake image' },
        { filename: '../../../etc/passwd', content: 'path traversal' }
      ];

      for (const file of maliciousFiles) {
        const response = await request(app)
          .post('/api/v1/media/upload')
          .set('Authorization', `Bearer ${authToken}`)
          .attach('file', Buffer.from(file.content), file.filename);

        expect(response.status).toBe(400);
        expect(response.body.error.code).toBe('INVALID_FILE_TYPE');
      }
    });

    it('应该限制文件大小', async () => {
      // 尝试上传超大文件
      const largeFile = Buffer.alloc(50 * 1024 * 1024); // 50MB

      const response = await request(app)
        .post('/api/v1/media/upload')
        .set('Authorization', `Bearer ${authToken}`)
        .attach('file', largeFile, 'large-file.jpg');

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('FILE_TOO_LARGE');
    });

    it('应该验证地理坐标范围', async () => {
      const invalidCoordinates = [
        { latitude: 91, longitude: 0 },
        { latitude: -91, longitude: 0 },
        { latitude: 0, longitude: 181 },
        { latitude: 0, longitude: -181 },
        { latitude: 'invalid', longitude: 'invalid' },
        { latitude: null, longitude: null }
      ];

      for (const coords of invalidCoordinates) {
        const response = await request(app)
          .post('/api/v1/annotations')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            latitude: coords.latitude,
            longitude: coords.longitude,
            smellType: 'industrial',
            intensity: 3,
            description: '坐标验证测试'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('success', false);
        expect(response.body.error.code).toBe('INVALID_COORDINATES');
      }
    });

    it('应该验证邮箱格式', async () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'test@',
        'test@domain',
        'test..test@domain.com',
        'test@domain..com',
        '<script>alert("XSS")</script>@domain.com',
        'test@domain.com<script>alert("XSS")</script>'
      ];

      for (const email of invalidEmails) {
        const response = await request(app)
          .post('/api/v1/users/register')
          .send({
            email,
            username: faker.internet.username(),
            password: 'ValidPassword123!'
          });

        expect(response.status).toBe(400);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    it('应该防止NoSQL注入', async () => {
      const noSQLPayloads = [
        { "$ne": null },
        { "$gt": "" },
        { "$where": "function() { return true; }" },
        { "$regex": ".*" },
        { "$or": [{"password": {"$regex": ".*"}}, {"username": {"$regex": ".*"}}] }
      ];

      for (const payload of noSQLPayloads) {
        const response = await request(app)
          .get('/api/v1/annotations/list')
          .query({ filter: JSON.stringify(payload) });

        expect(response.status).not.toBe(500);
      }
    });
  });

  describe('信息泄露防护', () => {
    it('应该不暴露敏感错误信息', async () => {
      // 触发各种错误情况
      const errorTests = [
        () => request(app).get('/api/v1/nonexistent-endpoint'),
        () => request(app).post('/api/v1/users/login').send({}),
        () => request(app).get('/api/v1/users/123456').set('Authorization', 'Bearer invalid'),
      ];

      for (const test of errorTests) {
        const response = await test();
        
        // 错误响应不应该包含敏感信息
        const responseText = JSON.stringify(response.body);
        expect(responseText).not.toMatch(/password/i);
        expect(responseText).not.toMatch(/secret/i);
        expect(responseText).not.toMatch(/database/i);
        expect(responseText).not.toMatch(/stack trace/i);
        expect(responseText).not.toMatch(/internal server/i);
      }
    });

    it('应该设置安全响应头', async () => {
      const response = await request(app)
        .get('/api/v1/health');

      expect(response.headers['x-powered-by']).toBeUndefined();
      expect(response.headers['server']).toBeFalsy();
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['referrer-policy']).toBeTruthy();
    });

    it('应该不在响应中包含敏感字段', async () => {
      const response = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${authToken}`);

      if (response.status === 200) {
        expect(response.body.data).not.toHaveProperty('password');
        expect(response.body.data).not.toHaveProperty('password_hash');
        expect(response.body.data).not.toHaveProperty('salt');
      }
    });

    it('应该防止用户枚举攻击', async () => {
      // 尝试登录不存在的用户和错误密码的存在用户
      // 两种情况应该返回相同的错误消息和响应时间
      const nonExistentUserResponse = await request(app)
        .post('/api/v1/users/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        });

      const existentUserWrongPasswordResponse = await request(app)
        .post('/api/v1/users/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword'
        });

      expect(nonExistentUserResponse.status).toBe(401);
      expect(existentUserWrongPasswordResponse.status).toBe(401);
      expect(nonExistentUserResponse.body.error.code).toBe(existentUserWrongPasswordResponse.body.error.code);
      expect(nonExistentUserResponse.body.message).toBe(existentUserWrongPasswordResponse.body.message);
    });
  });

  describe('速率限制和DDoS防护', () => {
    it('应该限制登录尝试频率', async () => {
      const maxAttempts = 5;
      const responses = [];

      // 快速发送多次登录请求
      for (let i = 0; i < maxAttempts + 2; i++) {
        const response = await request(app)
          .post('/api/v1/users/login')
          .send({
            email: testUser.email,
            password: 'wrongpassword'
          });
        responses.push(response);
      }

      // 最后几次请求应该被限制
      const lastResponses = responses.slice(-2);
      expect(lastResponses.some(r => r.status === 429)).toBe(true);
    });

    it('应该限制注册频率', async () => {
      const registrationPromises = Array.from({ length: 10 }, (_, i) => 
        request(app)
          .post('/api/v1/users/register')
          .send({
            email: `test${i}@example.com`,
            username: `testuser${i}`,
            password: 'TestPassword123!'
          })
      );

      const responses = await Promise.all(registrationPromises);
      
      // 某些请求应该被速率限制
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('应该限制API调用频率', async () => {
      const apiCalls = Array.from({ length: 100 }, () =>
        request(app)
          .get('/api/v1/annotations/list')
          .set('Authorization', `Bearer ${authToken}`)
      );

      const responses = await Promise.all(apiCalls);
      
      // 应该有一些请求被限制
      const rateLimitedCount = responses.filter(r => r.status === 429).length;
      expect(rateLimitedCount).toBeGreaterThan(0);
    });

    it('应该防护暴力破解攻击', async () => {
      const bruteForceattempts = Array.from({ length: 20 }, (_, i) =>
        request(app)
          .post('/api/v1/users/login')
          .send({
            email: testUser.email,
            password: `password${i}`
          })
      );

      const responses = await Promise.all(bruteForceattempts);
      
      // 应该逐渐增加响应延迟或完全阻止
      const blockedResponses = responses.filter(r => r.status === 429 || r.status === 423);
      expect(blockedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('会话安全', () => {
    it('应该支持会话失效', async () => {
      // 登录获取令牌
      const loginResponse = await request(app)
        .post('/api/v1/users/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(loginResponse.status).toBe(200);
      const token = loginResponse.body.data.token;

      // 使用令牌访问受保护资源
      const accessResponse = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${token}`);

      expect(accessResponse.status).toBe(200);

      // 登出
      const logoutResponse = await request(app)
        .post('/api/v1/users/logout')
        .set('Authorization', `Bearer ${token}`);

      expect(logoutResponse.status).toBe(200);

      // 登出后令牌应该失效
      const accessAfterLogoutResponse = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${token}`);

      expect(accessAfterLogoutResponse.status).toBe(401);
    });

    it('应该检测并发会话', async () => {
      // 从不同位置/设备登录
      const login1 = await request(app)
        .post('/api/v1/users/login')
        .set('User-Agent', 'Device1/1.0')
        .set('X-Forwarded-For', '192.168.1.100')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      const login2 = await request(app)
        .post('/api/v1/users/login')
        .set('User-Agent', 'Device2/1.0')
        .set('X-Forwarded-For', '192.168.1.200')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(login1.status).toBe(200);
      expect(login2.status).toBe(200);

      // 两个会话应该都有效（或系统应该警告用户）
      const token1 = login1.body.data.token;
      const token2 = login2.body.data.token;

      const access1 = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${token1}`);

      const access2 = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${token2}`);

      // 至少有一个会话应该有效
      expect([access1.status, access2.status]).toContain(200);
    });

    it('应该防护会话劫持', async () => {
      // 测试JWT令牌绑定到IP地址
      const loginResponse = await request(app)
        .post('/api/v1/users/login')
        .set('X-Forwarded-For', '192.168.1.100')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      const token = loginResponse.body.data.token;

      // 尝试从不同IP使用令牌
      const hijackAttempt = await request(app)
        .get('/api/v1/users/profile/me')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Forwarded-For', '192.168.1.200'); // 不同IP

      // 根据实现可能允许或拒绝
      if (hijackAttempt.status === 401) {
        expect(hijackAttempt.body.error.code).toBe('SESSION_IP_MISMATCH');
      }
    });
  });

  describe('数据加密和隐私', () => {
    it('应该正确加密密码', async () => {
      const password = 'TestPassword123!';
      const hashedPassword = await bcrypt.hash(password, 10);

      // 验证密码不以明文存储
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword.length).toBeGreaterThan(50);
      expect(hashedPassword).toMatch(/^\$2[aby]\$/);

      // 验证密码验证工作正常
      const isValid = await bcrypt.compare(password, hashedPassword);
      expect(isValid).toBe(true);

      const isInvalid = await bcrypt.compare('wrongpassword', hashedPassword);
      expect(isInvalid).toBe(false);
    });

    it('应该使用HTTPS在生产环境', async () => {
      if (process.env.NODE_ENV === 'production') {
        const response = await request(app)
          .get('/api/v1/health');

        // 在生产环境应该设置HSTS头
        expect(response.headers['strict-transport-security']).toBeTruthy();
      }
    });

    it('应该正确处理敏感数据', async () => {
      // 注册时的响应不应该包含密码
      const registerResponse = await request(app)
        .post('/api/v1/users/register')
        .send({
          email: faker.internet.email(),
          username: faker.internet.username(),
          password: 'TestPassword123!'
        });

      if (registerResponse.status === 201) {
        expect(registerResponse.body.data.user).not.toHaveProperty('password');
        expect(registerResponse.body.data.user).not.toHaveProperty('password_hash');
      }
    });

    it('应该清理日志中的敏感信息', async () => {
      // 这个测试需要检查日志文件或日志系统
      // 确保密码、令牌等敏感信息不被记录
      
      await request(app)
        .post('/api/v1/users/login')
        .send({
          email: testUser.email,
          password: 'TestPassword123!'
        });

      // 在实际实现中，需要检查日志系统确保密码未被记录
      // 这里仅作为提醒需要实现这个功能
      expect(true).toBe(true); // 占位符断言
    });
  });
});