#!/usr/bin/env node

/**
 * SmellPin 本地后端API测试
 * 测试范围：本地Cloudflare Workers (localhost:8787)
 * 数据库：Neon PostgreSQL
 */

const http = require('http');
const { URL } = require('url');

// 测试配置
const API_BASE_URL = 'http://localhost:8787';
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
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || 80,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SmellPin-Test-Client/1.0',
        ...options.headers
      },
      timeout: 10000 // 10秒超时
    };

    const req = http.request(requestOptions, (res) => {
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
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
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

// 测试1: 基础连接测试
async function testBasicConnection() {
  console.log('=== 测试1: 基础连接测试 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 404) {
      recordTest('基础连接', true, `状态码: ${response.status}, 服务器响应正常`, duration);
    } else {
      recordTest('基础连接', false, `状态码: ${response.status}, 响应: ${JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('基础连接', false, `连接失败: ${error.message}`, duration);
  }
}

// 测试2: 数据库连接测试
async function testDatabaseConnection() {
  console.log('=== 测试2: 数据库连接测试 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/debug/database-info`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('数据库连接', true, `状态码: ${response.status}, 数据库连接正常`, duration);
    } else {
      recordTest('数据库连接', false, `状态码: ${response.status}, 响应: ${JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库连接', false, `请求失败: ${error.message}`, duration);
  }
}

// 测试3: 用户注册
async function testUserRegistration() {
  console.log('=== 测试3: 用户注册 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: {
        email: TEST_USER.email,
        password: TEST_USER.password,
        username: TEST_USER.username
      }
    });
    
    const duration = Date.now() - startTime;
    
    const token = response.data.data?.token || response.data.token;
    if (response.status === 200 || response.status === 201) {
      recordTest('用户注册', true, `状态码: ${response.status}, 注册成功`, duration);
      return token;
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

// 测试4: 用户登录
async function testUserLogin() {
  console.log('=== 测试4: 用户登录 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signin`, {
      method: 'POST',
      body: {
        email: TEST_USER.email,
        password: TEST_USER.password
      }
    });
    
    const duration = Date.now() - startTime;
    
    const token = response.data.data?.token || response.data.token;
    if (response.status === 200 && token) {
      recordTest('用户登录', true, `状态码: ${response.status}, Token获取成功`, duration);
      return token;
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

// 测试5: 标注列表获取
async function testGetAnnotations(token) {
  console.log('=== 测试5: 标注列表获取 ===\n');
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations`, {
      method: 'GET',
      headers: token ? {
        'Authorization': `Bearer ${token}`
      } : {}
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('标注列表获取', true, `状态码: ${response.status}, 获取成功`, duration);
    } else {
      recordTest('标注列表获取', false, `状态码: ${response.status}, 错误: ${response.data.error || JSON.stringify(response.data)}`, duration);
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注列表获取', false, `请求失败: ${error.message}`, duration);
  }
}

// 测试6: 创建标注
async function testCreateAnnotation(token) {
  console.log('=== 测试6: 创建标注 ===\n');
  
  if (!token) {
    recordTest('创建标注', false, '没有可用的Token进行请求', 0);
    return;
  }
  
  const startTime = Date.now();
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: {
        latitude: 39.9042,
        longitude: 116.4074,
        smell_type: 'chemical',
        intensity: 3,
        description: '测试标注描述',
        location_name: '北京测试地点'
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201 || response.status === 200) {
      recordTest('创建标注', true, `状态码: ${response.status}, 标注创建成功`, duration);
      return response.data;
    } else {
      recordTest('创建标注', false, `状态码: ${response.status}, 错误: ${response.data.error || JSON.stringify(response.data)}`, duration);
      return null;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('创建标注', false, `请求失败: ${error.message}`, duration);
    return null;
  }
}

// 生成测试报告
function generateReport() {
  const totalTests = TEST_RESULTS.length;
  const passedTests = totalTests - failCount;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;
  
  console.log('============================================================');
  console.log('📊 本地后端API功能测试报告');
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
  console.log('✨ 本地后端API功能测试完成!');
  
  // 如果有失败的测试，返回非零退出码
  if (failCount > 0) {
    process.exit(1);
  }
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin本地后端API功能测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}`);
  console.log('');
  
  try {
    // 执行所有测试
    await testBasicConnection();
    await testDatabaseConnection();
    const registrationResult = await testUserRegistration();
    const token = await testUserLogin();
    await testGetAnnotations(token);
    await testCreateAnnotation(token);
    
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