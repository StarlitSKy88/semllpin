#!/usr/bin/env node

/**
 * SmellPin 后端API认证功能测试
 * 测试范围：Cloudflare Workers API
 * 数据库：Neon PostgreSQL
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// 测试配置
const API_BASE_URL = 'https://smellpin-workers.dev-small-1.workers.dev';
const TEST_RESULTS = [];
let failCount = 0;

// 测试用户数据
const TEST_USER = {
  email: `test_${Date.now()}@example.com`,
  password: 'TestPassword123!',
  username: `testuser_${Date.now()}`
};

// HTTP请求工具函数
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SmellPin-Test-Client/1.0',
        ...options.headers
      }
    };

    const req = client.request(requestOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const jsonData = data ? JSON.parse(data) : {};
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: jsonData
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data
          });
        }
      });
    });

    req.on('error', reject);
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

// 测试结果记录
function recordTest(name, success, details, duration) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`
  };
  
  TEST_RESULTS.push(result);
  
  if (!success) {
    failCount++;
    console.log(`[FAIL] ${name}`);
    console.log(`   详情: ${details}`);
  } else {
    console.log(`[PASS] ${name}`);
    console.log(`   详情: ${details}`);
  }
  console.log(`   耗时: ${duration}ms\n`);
}

// 测试1: API健康检查
async function testAPIHealth() {
  console.log('=== 测试1: API健康检查 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/health`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('API健康检查', true, `状态码: ${response.status}, 响应: ${JSON.stringify(response.data)}`, duration);
    } else {
      recordTest('API健康检查', false, `状态码: ${response.status}, 响应: ${JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('API健康检查', false, `请求失败: ${error.message}`, duration);
  }
}

// 测试2: 用户注册
async function testUserRegistration() {
  console.log('=== 测试2: 用户注册 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/auth/register`, {
      method: 'POST',
      body: {
        email: TEST_USER.email,
        password: TEST_USER.password,
        username: TEST_USER.username
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201 || response.status === 200) {
      recordTest('用户注册', true, `状态码: ${response.status}, 用户ID: ${response.data.user?.id || 'N/A'}`, duration);
      return response.data;
    } else {
      recordTest('用户注册', false, `状态码: ${response.status}, 错误: ${response.data.error || JSON.stringify(response.data)}`, duration);
      return null;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册', false, `请求失败: ${error.message}`, duration);
    return null;
  }
}

// 测试3: 用户登录
async function testUserLogin() {
  console.log('=== 测试3: 用户登录 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/auth/login`, {
      method: 'POST',
      body: {
        email: TEST_USER.email,
        password: TEST_USER.password
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 && response.data.token) {
      recordTest('用户登录', true, `状态码: ${response.status}, Token获取成功`, duration);
      return response.data.token;
    } else {
      recordTest('用户登录', false, `状态码: ${response.status}, 错误: ${response.data.error || JSON.stringify(response.data)}`, duration);
      return null;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户登录', false, `请求失败: ${error.message}`, duration);
    return null;
  }
}

// 测试4: JWT Token验证
async function testJWTVerification(token) {
  console.log('=== 测试4: JWT Token验证 ===\n');
  
  if (!token) {
    recordTest('JWT Token验证', false, '没有可用的Token进行验证', 0);
    return;
  }
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/auth/verify`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('JWT Token验证', true, `状态码: ${response.status}, 用户验证成功`, duration);
    } else {
      recordTest('JWT Token验证', false, `状态码: ${response.status}, 验证失败: ${response.data.error || JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('JWT Token验证', false, `请求失败: ${error.message}`, duration);
  }
}

// 测试5: 获取用户信息
async function testGetUserProfile(token) {
  console.log('=== 测试5: 获取用户信息 ===\n');
  
  if (!token) {
    recordTest('获取用户信息', false, '没有可用的Token进行请求', 0);
    return;
  }
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/user/profile`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('获取用户信息', true, `状态码: ${response.status}, 用户信息获取成功`, duration);
    } else {
      recordTest('获取用户信息', false, `状态码: ${response.status}, 获取失败: ${response.data.error || JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('获取用户信息', false, `请求失败: ${error.message}`, duration);
  }
}

// 生成测试报告
function generateReport() {
  const totalTests = TEST_RESULTS.length;
  const passedTests = totalTests - failCount;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;
  
  console.log('============================================================');
  console.log('📊 后端API认证功能测试报告');
  console.log('============================================================');
  console.log(`✅ 通过: ${passedTests}`);
  console.log(`❌ 失败: ${failCount}`);
  console.log(`📈 成功率: ${successRate}%`);
  console.log('');
  
  console.log('📋 详细测试结果:');
  TEST_RESULTS.forEach((result, index) => {
    const status = result.success ? '[PASS]' : '[FAIL]';
    console.log(`${index + 1}. ${status} ${result.name} (${result.duration})`);
    if (!result.success) {
      console.log(`   ❌ ${result.details}`);
    }
  });
  
  console.log('');
  console.log('✨ 后端API认证功能测试完成!');
  
  // 如果有失败的测试，返回非零退出码
  if (failCount > 0) {
    process.exit(1);
  }
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin后端API认证功能测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}`);
  console.log('');
  
  try {
    // 执行所有测试
    await testAPIHealth();
    const registrationResult = await testUserRegistration();
    const token = await testUserLogin();
    await testJWTVerification(token);
    await testGetUserProfile(token);
    
    // 生成报告
    generateReport();
    
  } catch (error) {
    console.error('❌ 测试执行过程中发生错误:', error.message);
    process.exit(1);
  }
}

// 运行测试
if (require.main === module) {
  runTests();
}

module.exports = { runTests, TEST_RESULTS };