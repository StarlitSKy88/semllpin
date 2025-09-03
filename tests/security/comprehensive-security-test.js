#!/usr/bin/env node

/**
 * SmellPin 综合安全测试套件
 * 测试SQL注入、XSS、CSRF、认证安全、数据传输安全等
 * 
 * 运行方式: node tests/security/comprehensive-security-test.js
 */

const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 安全测试配置
const SECURITY_CONFIG = {
  baseURL: 'http://localhost:3003',
  testTimeout: 30000,
  
  // 测试payloads
  payloads: {
    sqlInjection: [
      "' OR '1'='1",
      "'; DROP TABLE users;--",
      "' UNION SELECT * FROM users--",
      "1' OR 1=1#",
      "admin'--",
      "' OR 1=1 LIMIT 1--",
    ],
    xss: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>",
      "';alert('XSS');//",
      "<iframe src=javascript:alert('XSS')></iframe>",
    ],
    csrf: [
      // CSRF攻击模拟
      "maliciousToken123",
      "",
      "null",
      "undefined",
    ],
    pathTraversal: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    commandInjection: [
      "; ls -la",
      "| cat /etc/passwd",
      "&& whoami",
      "`id`",
      "$(whoami)",
    ]
  }
};

// 安全测试结果存储
const securityResults = {
  timestamp: new Date().toISOString(),
  config: SECURITY_CONFIG,
  tests: [],
  summary: {},
  vulnerabilities: [],
  recommendations: []
};

class SecurityTestSuite {
  constructor() {
    this.testToken = null;
    this.testUser = null;
  }

  // 生成测试用户令牌
  async generateTestToken() {
    try {
      const response = await axios.post(`${SECURITY_CONFIG.baseURL}/api/v1/users/login`, {
        email: 'test@example.com',
        password: 'testpassword123'
      }, { timeout: SECURITY_CONFIG.testTimeout });
      
      if (response.data.success && response.data.data.accessToken) {
        this.testToken = response.data.data.accessToken;
        this.testUser = response.data.data.user;
        console.log('✓ 安全测试令牌生成成功');
        return true;
      }
    } catch (error) {
      console.warn('⚠ 测试用户不存在，部分安全测试将跳过');
      return false;
    }
  }

  // 1. SQL注入漏洞测试
  async testSQLInjection() {
    console.log('\n💉 执行SQL注入漏洞测试...');
    
    const testResult = {
      name: 'SQL Injection Vulnerability Test',
      category: 'Input Validation',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    // 测试不同的端点
    const endpoints = [
      { method: 'GET', path: '/api/v1/annotations/list', param: 'search' },
      { method: 'GET', path: '/api/v1/users', param: 'email' },
      { method: 'POST', path: '/api/v1/users/login', body: 'email' },
    ];

    for (const endpoint of endpoints) {
      console.log(`  测试端点: ${endpoint.method} ${endpoint.path}`);
      
      for (const payload of SECURITY_CONFIG.payloads.sqlInjection) {
        try {
          let response;
          
          if (endpoint.method === 'GET' && endpoint.param) {
            const url = `${SECURITY_CONFIG.baseURL}${endpoint.path}?${endpoint.param}=${encodeURIComponent(payload)}`;
            response = await axios.get(url, { 
              timeout: SECURITY_CONFIG.testTimeout,
              validateStatus: () => true // 不抛出错误
            });
          } else if (endpoint.method === 'POST' && endpoint.body) {
            const data = {};
            data[endpoint.body] = payload;
            data.password = 'test123';
            response = await axios.post(`${SECURITY_CONFIG.baseURL}${endpoint.path}`, data, {
              timeout: SECURITY_CONFIG.testTimeout,
              validateStatus: () => true
            });
          }

          const testCase = {
            endpoint: endpoint.path,
            method: endpoint.method,
            payload,
            statusCode: response?.status,
            responseTime: response?.headers?.['x-response-time'],
            vulnerable: this.detectSQLInjectionVulnerability(response)
          };

          testResult.tests.push(testCase);

          if (testCase.vulnerable) {
            const vulnerability = {
              type: 'SQL Injection',
              severity: 'Critical',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              description: 'API端点可能存在SQL注入漏洞',
              evidence: response?.data
            };
            
            testResult.vulnerabilities.push(vulnerability);
            securityResults.vulnerabilities.push(vulnerability);
            testResult.passed = false;
            
            console.log(`    ❌ 检测到潜在SQL注入漏洞: ${payload.substring(0, 30)}...`);
          }

        } catch (error) {
          // 网络错误不计为漏洞
          if (!error.code || !error.code.includes('NETWORK')) {
            console.log(`    ⚠ 测试异常: ${error.message}`);
          }
        }
      }
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('SQL Injection', testResult);
    return testResult;
  }

  // 2. XSS跨站脚本攻击测试
  async testXSS() {
    console.log('\n🔗 执行XSS跨站脚本攻击测试...');
    
    const testResult = {
      name: 'Cross-Site Scripting (XSS) Test',
      category: 'Input Validation',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    // 测试可能返回用户输入的端点
    const endpoints = [
      { method: 'POST', path: '/api/v1/annotations', field: 'title' },
      { method: 'POST', path: '/api/v1/annotations', field: 'description' },
      { method: 'PUT', path: '/api/v1/users/profile', field: 'username' },
    ];

    if (!this.testToken) {
      console.log('  ⚠ 跳过XSS测试（需要认证令牌）');
      testResult.skipped = true;
      securityResults.tests.push(testResult);
      return testResult;
    }

    for (const endpoint of endpoints) {
      console.log(`  测试端点: ${endpoint.method} ${endpoint.path}`);
      
      for (const payload of SECURITY_CONFIG.payloads.xss) {
        try {
          const data = {
            [endpoint.field]: payload
          };

          // 为不同端点添加必要字段
          if (endpoint.path.includes('annotations')) {
            Object.assign(data, {
              category: 'test',
              intensity: 5,
              location: { lat: 39.9042, lng: 116.4074 },
              address: 'Test Address'
            });
          }

          const response = await axios({
            method: endpoint.method,
            url: `${SECURITY_CONFIG.baseURL}${endpoint.path}`,
            data,
            headers: { 
              'Authorization': `Bearer ${this.testToken}`,
              'Content-Type': 'application/json'
            },
            timeout: SECURITY_CONFIG.testTimeout,
            validateStatus: () => true
          });

          const testCase = {
            endpoint: endpoint.path,
            method: endpoint.method,
            field: endpoint.field,
            payload,
            statusCode: response.status,
            vulnerable: this.detectXSSVulnerability(response, payload)
          };

          testResult.tests.push(testCase);

          if (testCase.vulnerable) {
            const vulnerability = {
              type: 'Cross-Site Scripting (XSS)',
              severity: 'High',
              endpoint: endpoint.path,
              method: endpoint.method,
              field: endpoint.field,
              payload,
              description: 'API未正确过滤或编码用户输入，可能导致XSS攻击',
              evidence: response.data
            };
            
            testResult.vulnerabilities.push(vulnerability);
            securityResults.vulnerabilities.push(vulnerability);
            testResult.passed = false;
            
            console.log(`    ❌ 检测到潜在XSS漏洞: ${payload.substring(0, 30)}...`);
          }

        } catch (error) {
          console.log(`    ⚠ 测试异常: ${error.message}`);
        }
      }
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('XSS', testResult);
    return testResult;
  }

  // 3. CSRF跨站请求伪造测试
  async testCSRF() {
    console.log('\n🎭 执行CSRF跨站请求伪造测试...');
    
    const testResult = {
      name: 'Cross-Site Request Forgery (CSRF) Test',
      category: 'Authentication',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    if (!this.testToken) {
      console.log('  ⚠ 跳过CSRF测试（需要认证令牌）');
      testResult.skipped = true;
      securityResults.tests.push(testResult);
      return testResult;
    }

    // 测试状态改变的端点
    const endpoints = [
      { method: 'POST', path: '/api/v1/annotations' },
      { method: 'PUT', path: '/api/v1/users/profile' },
      { method: 'DELETE', path: '/api/v1/annotations/1' },
    ];

    for (const endpoint of endpoints) {
      console.log(`  测试端点: ${endpoint.method} ${endpoint.path}`);
      
      try {
        // 测试1: 没有CSRF token的请求
        const requestWithoutCSRF = {
          method: endpoint.method,
          url: `${SECURITY_CONFIG.baseURL}${endpoint.path}`,
          headers: { 
            'Authorization': `Bearer ${this.testToken}`,
            'Content-Type': 'application/json'
          },
          data: endpoint.method !== 'DELETE' ? {
            title: 'CSRF Test',
            description: 'Testing CSRF protection'
          } : undefined,
          timeout: SECURITY_CONFIG.testTimeout,
          validateStatus: () => true
        };

        const response = await axios(requestWithoutCSRF);

        // 测试2: 来自不同Origin的请求
        const crossOriginRequest = {
          ...requestWithoutCSRF,
          headers: {
            ...requestWithoutCSRF.headers,
            'Origin': 'https://malicious-site.com',
            'Referer': 'https://malicious-site.com/attack.html'
          }
        };

        const crossOriginResponse = await axios(crossOriginRequest);

        const testCase = {
          endpoint: endpoint.path,
          method: endpoint.method,
          normalRequestStatus: response.status,
          crossOriginRequestStatus: crossOriginResponse.status,
          vulnerable: this.detectCSRFVulnerability(response, crossOriginResponse)
        };

        testResult.tests.push(testCase);

        if (testCase.vulnerable) {
          const vulnerability = {
            type: 'Cross-Site Request Forgery (CSRF)',
            severity: 'Medium',
            endpoint: endpoint.path,
            method: endpoint.method,
            description: 'API端点缺少CSRF保护，可能被恶意网站利用',
            evidence: {
              normalStatus: response.status,
              crossOriginStatus: crossOriginResponse.status
            }
          };
          
          testResult.vulnerabilities.push(vulnerability);
          securityResults.vulnerabilities.push(vulnerability);
          testResult.passed = false;
          
          console.log(`    ❌ 检测到CSRF漏洞: ${endpoint.path}`);
        }

      } catch (error) {
        console.log(`    ⚠ 测试异常: ${error.message}`);
      }
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('CSRF', testResult);
    return testResult;
  }

  // 4. 认证和授权安全测试
  async testAuthentication() {
    console.log('\n🔐 执行认证和授权安全测试...');
    
    const testResult = {
      name: 'Authentication & Authorization Security Test',
      category: 'Authentication',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    // 测试认证相关的端点
    const protectedEndpoints = [
      { method: 'GET', path: '/api/v1/users/profile/me' },
      { method: 'POST', path: '/api/v1/annotations' },
      { method: 'PUT', path: '/api/v1/users/profile' },
    ];

    for (const endpoint of protectedEndpoints) {
      console.log(`  测试端点: ${endpoint.method} ${endpoint.path}`);
      
      try {
        // 测试1: 没有认证令牌
        const noAuthResponse = await axios({
          method: endpoint.method,
          url: `${SECURITY_CONFIG.baseURL}${endpoint.path}`,
          data: endpoint.method !== 'GET' ? { test: 'data' } : undefined,
          timeout: SECURITY_CONFIG.testTimeout,
          validateStatus: () => true
        });

        // 测试2: 无效的认证令牌
        const invalidTokenResponse = await axios({
          method: endpoint.method,
          url: `${SECURITY_CONFIG.baseURL}${endpoint.path}`,
          headers: { 'Authorization': 'Bearer invalid_token_123' },
          data: endpoint.method !== 'GET' ? { test: 'data' } : undefined,
          timeout: SECURITY_CONFIG.testTimeout,
          validateStatus: () => true
        });

        // 测试3: 过期的认证令牌（模拟）
        const expiredTokenResponse = await axios({
          method: endpoint.method,
          url: `${SECURITY_CONFIG.baseURL}${endpoint.path}`,
          headers: { 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJleHAiOjE1NDYzMDA4MDB9.invalid' },
          data: endpoint.method !== 'GET' ? { test: 'data' } : undefined,
          timeout: SECURITY_CONFIG.testTimeout,
          validateStatus: () => true
        });

        const testCase = {
          endpoint: endpoint.path,
          method: endpoint.method,
          noAuthStatus: noAuthResponse.status,
          invalidTokenStatus: invalidTokenResponse.status,
          expiredTokenStatus: expiredTokenResponse.status,
          vulnerable: this.detectAuthVulnerability(noAuthResponse, invalidTokenResponse, expiredTokenResponse)
        };

        testResult.tests.push(testCase);

        if (testCase.vulnerable) {
          const vulnerability = {
            type: 'Authentication Bypass',
            severity: 'Critical',
            endpoint: endpoint.path,
            method: endpoint.method,
            description: '受保护的端点可能存在认证绕过漏洞',
            evidence: {
              noAuthStatus: noAuthResponse.status,
              invalidTokenStatus: invalidTokenResponse.status,
              expiredTokenStatus: expiredTokenResponse.status
            }
          };
          
          testResult.vulnerabilities.push(vulnerability);
          securityResults.vulnerabilities.push(vulnerability);
          testResult.passed = false;
          
          console.log(`    ❌ 检测到认证漏洞: ${endpoint.path}`);
        }

      } catch (error) {
        console.log(`    ⚠ 测试异常: ${error.message}`);
      }
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('Authentication', testResult);
    return testResult;
  }

  // 5. 路径遍历攻击测试
  async testPathTraversal() {
    console.log('\n📁 执行路径遍历攻击测试...');
    
    const testResult = {
      name: 'Path Traversal Attack Test',
      category: 'Input Validation',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    // 测试文件访问端点
    const endpoints = [
      { method: 'GET', path: '/uploads/' },
      { method: 'GET', path: '/api/v1/media/' },
    ];

    for (const endpoint of endpoints) {
      console.log(`  测试端点: ${endpoint.method} ${endpoint.path}`);
      
      for (const payload of SECURITY_CONFIG.payloads.pathTraversal) {
        try {
          const url = `${SECURITY_CONFIG.baseURL}${endpoint.path}${payload}`;
          const response = await axios.get(url, {
            timeout: SECURITY_CONFIG.testTimeout,
            validateStatus: () => true
          });

          const testCase = {
            endpoint: endpoint.path,
            payload,
            statusCode: response.status,
            contentLength: response.headers['content-length'],
            vulnerable: this.detectPathTraversalVulnerability(response, payload)
          };

          testResult.tests.push(testCase);

          if (testCase.vulnerable) {
            const vulnerability = {
              type: 'Path Traversal',
              severity: 'High',
              endpoint: endpoint.path,
              payload,
              description: '服务器可能允许访问系统文件，存在路径遍历漏洞',
              evidence: {
                statusCode: response.status,
                contentLength: response.headers['content-length'],
                response: response.data ? response.data.toString().substring(0, 200) : null
              }
            };
            
            testResult.vulnerabilities.push(vulnerability);
            securityResults.vulnerabilities.push(vulnerability);
            testResult.passed = false;
            
            console.log(`    ❌ 检测到路径遍历漏洞: ${payload}`);
          }

        } catch (error) {
          // 网络错误不计为漏洞
        }
      }
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('Path Traversal', testResult);
    return testResult;
  }

  // 6. HTTP头部安全测试
  async testSecurityHeaders() {
    console.log('\n🛡️ 执行HTTP安全头部测试...');
    
    const testResult = {
      name: 'HTTP Security Headers Test',
      category: 'Security Configuration',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    try {
      const response = await axios.get(`${SECURITY_CONFIG.baseURL}/health`, {
        timeout: SECURITY_CONFIG.testTimeout
      });

      const headers = response.headers;
      const requiredHeaders = {
        'x-frame-options': 'Clickjacking protection',
        'x-content-type-options': 'MIME type sniffing protection',
        'x-xss-protection': 'XSS protection',
        'strict-transport-security': 'HTTPS enforcement',
        'content-security-policy': 'CSP protection',
        'referrer-policy': 'Referrer information control',
        'permissions-policy': 'Feature policy'
      };

      const testCase = {
        endpoint: '/health',
        headers: headers,
        missingHeaders: [],
        insecureHeaders: []
      };

      for (const [headerName, description] of Object.entries(requiredHeaders)) {
        if (!headers[headerName]) {
          testCase.missingHeaders.push({ header: headerName, description });
          
          const vulnerability = {
            type: 'Missing Security Header',
            severity: 'Medium',
            header: headerName,
            description: `缺少 ${headerName} 安全头部: ${description}`,
            recommendation: `添加 ${headerName} 头部以增强安全性`
          };
          
          testResult.vulnerabilities.push(vulnerability);
          securityResults.vulnerabilities.push(vulnerability);
          testResult.passed = false;
        }
      }

      // 检查不安全的头部值
      if (headers['x-powered-by']) {
        testCase.insecureHeaders.push({
          header: 'x-powered-by',
          value: headers['x-powered-by'],
          issue: 'Information disclosure'
        });

        const vulnerability = {
          type: 'Information Disclosure',
          severity: 'Low',
          header: 'x-powered-by',
          value: headers['x-powered-by'],
          description: 'X-Powered-By头部泄露服务器技术信息',
          recommendation: '移除或隐藏X-Powered-By头部'
        };
        
        testResult.vulnerabilities.push(vulnerability);
        securityResults.vulnerabilities.push(vulnerability);
        testResult.passed = false;
      }

      testResult.tests.push(testCase);

    } catch (error) {
      console.log(`    ⚠ 测试异常: ${error.message}`);
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('Security Headers', testResult);
    return testResult;
  }

  // 7. 速率限制测试
  async testRateLimit() {
    console.log('\n⏱️ 执行速率限制测试...');
    
    const testResult = {
      name: 'Rate Limiting Test',
      category: 'Security Configuration',
      vulnerabilities: [],
      passed: true,
      tests: []
    };

    const endpoint = '/api/v1/users/login';
    const requestData = {
      email: 'nonexistent@example.com',
      password: 'wrongpassword'
    };

    console.log(`  测试端点: POST ${endpoint}`);

    try {
      const requests = [];
      const startTime = Date.now();
      
      // 发送快速连续请求测试速率限制
      for (let i = 0; i < 20; i++) {
        requests.push(
          axios.post(`${SECURITY_CONFIG.baseURL}${endpoint}`, requestData, {
            timeout: SECURITY_CONFIG.testTimeout,
            validateStatus: () => true
          }).then(response => ({
            request: i + 1,
            status: response.status,
            headers: response.headers,
            timestamp: Date.now()
          })).catch(error => ({
            request: i + 1,
            error: error.message,
            timestamp: Date.now()
          }))
        );
      }

      const results = await Promise.all(requests);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // 分析结果
      const rateLimitedRequests = results.filter(r => 
        r.status === 429 || 
        (r.headers && (r.headers['x-ratelimit-remaining'] === '0' || r.headers['retry-after']))
      );

      const testCase = {
        endpoint,
        totalRequests: 20,
        rateLimitedRequests: rateLimitedRequests.length,
        duration,
        results,
        vulnerable: rateLimitedRequests.length === 0 // 如果没有被限制，则存在漏洞
      };

      testResult.tests.push(testCase);

      if (testCase.vulnerable) {
        const vulnerability = {
          type: 'Missing Rate Limiting',
          severity: 'Medium',
          endpoint,
          description: 'API端点缺少速率限制，可能被滥用进行暴力攻击',
          evidence: {
            totalRequests: 20,
            rateLimitedRequests: rateLimitedRequests.length,
            duration
          },
          recommendation: '实施适当的速率限制策略'
        };
        
        testResult.vulnerabilities.push(vulnerability);
        securityResults.vulnerabilities.push(vulnerability);
        testResult.passed = false;
        
        console.log(`    ❌ 检测到缺少速率限制: ${endpoint}`);
      } else {
        console.log(`    ✅ 速率限制正常工作: ${rateLimitedRequests.length}/${20} 请求被限制`);
      }

    } catch (error) {
      console.log(`    ⚠ 测试异常: ${error.message}`);
    }

    securityResults.tests.push(testResult);
    this.logSecurityResult('Rate Limiting', testResult);
    return testResult;
  }

  // 漏洞检测方法

  detectSQLInjectionVulnerability(response) {
    if (!response || !response.data) return false;
    
    const data = JSON.stringify(response.data).toLowerCase();
    const sqlErrorPatterns = [
      'sql syntax',
      'mysql_fetch',
      'ora-',
      'microsoft ole db',
      'sqlite_',
      'postgresql',
      'syntax error'
    ];
    
    return sqlErrorPatterns.some(pattern => data.includes(pattern)) || 
           (response.status === 200 && data.includes('users') && data.includes('password'));
  }

  detectXSSVulnerability(response, payload) {
    if (!response || !response.data) return false;
    
    const responseText = JSON.stringify(response.data);
    // 检查payload是否未经处理直接返回
    return responseText.includes(payload) && !responseText.includes('&lt;') && !responseText.includes('&gt;');
  }

  detectCSRFVulnerability(normalResponse, crossOriginResponse) {
    // 如果跨域请求也成功，可能存在CSRF漏洞
    return normalResponse.status === crossOriginResponse.status && 
           [200, 201, 204].includes(crossOriginResponse.status);
  }

  detectAuthVulnerability(noAuthResponse, invalidTokenResponse, expiredTokenResponse) {
    // 受保护的端点应该返回401或403
    return [200, 201, 204].includes(noAuthResponse.status) ||
           [200, 201, 204].includes(invalidTokenResponse.status) ||
           [200, 201, 204].includes(expiredTokenResponse.status);
  }

  detectPathTraversalVulnerability(response, payload) {
    if (!response || response.status !== 200) return false;
    
    const responseText = response.data ? response.data.toString() : '';
    const systemFilePatterns = [
      'root:x:0:0',  // /etc/passwd
      '[boot loader]', // Windows boot.ini
      'HKEY_LOCAL_MACHINE', // Windows registry
    ];
    
    return systemFilePatterns.some(pattern => responseText.includes(pattern));
  }

  // 记录安全测试结果
  logSecurityResult(testName, result) {
    const status = result.passed ? '✅ PASSED' : '❌ FAILED';
    const vulnerabilityCount = result.vulnerabilities.length;
    
    console.log(`\n${status} ${testName}:`);
    console.log(`  测试数量: ${result.tests.length}`);
    console.log(`  发现漏洞: ${vulnerabilityCount}`);
    
    if (vulnerabilityCount > 0) {
      console.log(`  漏洞详情:`);
      result.vulnerabilities.forEach((vuln, index) => {
        console.log(`    ${index + 1}. [${vuln.severity}] ${vuln.type}: ${vuln.description}`);
      });
    }
  }

  // 生成安全报告
  generateSecurityReport() {
    console.log('\n🛡️ 生成安全测试报告...');
    
    const passedTests = securityResults.tests.filter(test => test.passed).length;
    const totalTests = securityResults.tests.length;
    const totalVulnerabilities = securityResults.vulnerabilities.length;
    
    const severityCounts = {
      Critical: securityResults.vulnerabilities.filter(v => v.severity === 'Critical').length,
      High: securityResults.vulnerabilities.filter(v => v.severity === 'High').length,
      Medium: securityResults.vulnerabilities.filter(v => v.severity === 'Medium').length,
      Low: securityResults.vulnerabilities.filter(v => v.severity === 'Low').length,
    };

    const securityScore = totalVulnerabilities === 0 ? 100 : 
      Math.max(0, 100 - (severityCounts.Critical * 25 + severityCounts.High * 15 + severityCounts.Medium * 10 + severityCounts.Low * 5));

    securityResults.summary = {
      securityScore,
      passedTests,
      totalTests,
      totalVulnerabilities,
      severityCounts,
      riskLevel: this.calculateRiskLevel(severityCounts)
    };

    // 生成安全建议
    this.generateSecurityRecommendations();

    // 输出结果到文件
    const reportPath = path.join(__dirname, `../test-results/security-report-${Date.now()}.json`);
    
    // 确保目录存在
    const reportDir = path.dirname(reportPath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(securityResults, null, 2));

    console.log(`\n🎯 安全评分: ${securityScore.toFixed(1)}/100`);
    console.log(`🛡️ 风险等级: ${securityResults.summary.riskLevel}`);
    console.log(`📊 测试通过率: ${passedTests}/${totalTests}`);
    console.log(`🚨 发现漏洞: ${totalVulnerabilities} 个`);
    
    if (totalVulnerabilities > 0) {
      console.log(`   严重: ${severityCounts.Critical} | 高危: ${severityCounts.High} | 中危: ${severityCounts.Medium} | 低危: ${severityCounts.Low}`);
    }
    
    console.log(`📄 详细报告: ${reportPath}`);

    return securityResults;
  }

  calculateRiskLevel(severityCounts) {
    if (severityCounts.Critical > 0) return 'Critical';
    if (severityCounts.High > 0) return 'High';
    if (severityCounts.Medium > 2) return 'High';
    if (severityCounts.Medium > 0 || severityCounts.Low > 3) return 'Medium';
    if (severityCounts.Low > 0) return 'Low';
    return 'Minimal';
  }

  generateSecurityRecommendations() {
    const recommendations = [];

    // 基于发现的漏洞生成建议
    const vulnTypes = [...new Set(securityResults.vulnerabilities.map(v => v.type))];
    
    vulnTypes.forEach(vulnType => {
      switch (vulnType) {
        case 'SQL Injection':
          recommendations.push({
            priority: 'Critical',
            category: '输入验证',
            title: '修复SQL注入漏洞',
            description: '使用参数化查询、输入验证和转义来防止SQL注入攻击',
            actions: [
              '实施参数化查询/准备语句',
              '添加严格的输入验证',
              '使用最小权限数据库账户',
              '实施WAF规则'
            ]
          });
          break;
        
        case 'Cross-Site Scripting (XSS)':
          recommendations.push({
            priority: 'High',
            category: '输出编码',
            title: '修复XSS漏洞',
            description: '对所有用户输入进行适当的编码和过滤',
            actions: [
              '实施输出编码',
              '使用CSP头部',
              '验证和过滤用户输入',
              '使用安全的模板引擎'
            ]
          });
          break;
        
        case 'Missing Security Header':
          recommendations.push({
            priority: 'Medium',
            category: '安全配置',
            title: '添加安全HTTP头部',
            description: '配置所有必要的安全HTTP头部',
            actions: [
              '添加X-Frame-Options头部',
              '配置Content-Security-Policy',
              '设置X-Content-Type-Options',
              '添加Strict-Transport-Security'
            ]
          });
          break;
      }
    });

    // 通用安全建议
    recommendations.push({
      priority: 'High',
      category: '监控和日志',
      title: '增强安全监控',
      description: '实施全面的安全监控和日志记录',
      actions: [
        '配置详细的安全日志',
        '实施实时威胁检测',
        '设置异常行为告警',
        '定期安全审计'
      ]
    });

    securityResults.recommendations = recommendations;
  }

  // 执行所有安全测试
  async runAllTests() {
    console.log('🛡️ 开始SmellPin安全测试套件');
    console.log(`🎯 目标服务: ${SECURITY_CONFIG.baseURL}`);
    console.log(`⏱️ 请求超时: ${SECURITY_CONFIG.testTimeout}ms`);
    
    try {
      // 生成测试令牌
      await this.generateTestToken();

      // 执行所有安全测试
      await this.testSQLInjection();
      await this.testXSS();
      await this.testCSRF();
      await this.testAuthentication();
      await this.testPathTraversal();
      await this.testSecurityHeaders();
      await this.testRateLimit();

      // 生成报告
      return this.generateSecurityReport();

    } catch (error) {
      console.error('❌ 安全测试执行失败:', error);
      throw error;
    }
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const testSuite = new SecurityTestSuite();
  
  testSuite.runAllTests()
    .then(results => {
      console.log('\n✅ 所有安全测试完成');
      process.exit(results.summary.securityScore >= 80 ? 0 : 1);
    })
    .catch(error => {
      console.error('❌ 安全测试失败:', error);
      process.exit(1);
    });
}

module.exports = SecurityTestSuite;