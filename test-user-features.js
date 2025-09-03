// 用户功能测试脚本
const http = require('http');
const https = require('https');
const { URL } = require('url');

// 测试配置
const config = {
  frontendUrl: 'http://localhost:5176',
  apiUrl: 'https://smellpin-workers.dev-small-1.workers.dev',
  timeout: 10000
};

// 测试结果记录
const testResults = {
  passed: 0,
  failed: 0,
  errors: [],
  details: []
};

// 记录测试结果
function recordTest(testName, success, error = null, details = null) {
  if (success) {
    testResults.passed++;
    console.log(`✅ ${testName} - 通过`);
  } else {
    testResults.failed++;
    testResults.errors.push({ test: testName, error });
    console.log(`❌ ${testName} - 失败: ${error}`);
  }
  
  if (details) {
    testResults.details.push({ test: testName, details });
  }
}

// HTTP请求函数
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
        'User-Agent': 'SmellPin-Test-Agent/1.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...options.headers
      },
      timeout: config.timeout
    };
    
    const req = client.request(requestOptions, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('请求超时'));
    });
    
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// 测试API端点可用性
async function testAPIEndpoints() {
  console.log('\n=== 测试API端点可用性 ===');
  
  const endpoints = [
    { path: '/health', name: '健康检查' },
    { path: '/auth/signup', name: '用户注册', method: 'POST' },
    { path: '/auth/signin', name: '用户登录', method: 'POST' },
    { path: '/annotations', name: '标注列表' },
    { path: '/users/profile', name: '用户资料' }
  ];
  
  for (const endpoint of endpoints) {
    try {
      const url = `${config.apiUrl}${endpoint.path}`;
      const options = {
        method: endpoint.method || 'GET',
        body: endpoint.method === 'POST' ? JSON.stringify({ test: true }) : undefined
      };
      
      const response = await makeRequest(url, options);
      
      // 对于POST请求，400状态码是正常的（因为我们发送的是测试数据）
      const isSuccess = endpoint.method === 'POST' ? 
        (response.statusCode >= 200 && response.statusCode < 500) :
        (response.statusCode >= 200 && response.statusCode < 400);
      
      recordTest(
        `API端点 ${endpoint.name}`,
        isSuccess,
        !isSuccess ? `状态码: ${response.statusCode}` : null,
        { statusCode: response.statusCode, endpoint: endpoint.path }
      );
      
    } catch (error) {
      recordTest(
        `API端点 ${endpoint.name}`,
        false,
        error.message,
        { endpoint: endpoint.path, error: error.message }
      );
    }
    
    // 添加延迟避免请求过快
    await new Promise(resolve => setTimeout(resolve, 500));
  }
}

// 测试用户注册功能
async function testUserRegistration() {
  console.log('\n=== 测试用户注册功能 ===');
  
  const testUser = {
    email: `test${Date.now()}@example.com`,
    username: `testuser${Date.now()}`,
    password: 'TestPassword123!',
    displayName: '测试用户'
  };
  
  try {
    const response = await makeRequest(`${config.apiUrl}/auth/signup`, {
      method: 'POST',
      body: JSON.stringify(testUser)
    });
    
    if (response.statusCode === 201 || response.statusCode === 200) {
      recordTest('用户注册API调用', true, null, { user: testUser.username });
      
      try {
        const responseData = JSON.parse(response.body);
        if (responseData.user || responseData.data) {
          recordTest('用户注册响应格式', true);
        } else {
          recordTest('用户注册响应格式', false, '响应格式不正确');
        }
      } catch (e) {
        recordTest('用户注册响应格式', false, '响应不是有效JSON');
      }
      
    } else {
      recordTest('用户注册API调用', false, `状态码: ${response.statusCode}`);
    }
    
  } catch (error) {
    recordTest('用户注册功能', false, error.message);
  }
}

// 测试用户登录功能
async function testUserLogin() {
  console.log('\n=== 测试用户登录功能 ===');
  
  // 使用一个可能存在的测试账户
  const loginData = {
    email: 'test@example.com',
    password: 'password123'
  };
  
  try {
    const response = await makeRequest(`${config.apiUrl}/auth/signin`, {
      method: 'POST',
      body: JSON.stringify(loginData)
    });
    
    // 登录可能失败（因为账户不存在），但API应该正常响应
    if (response.statusCode >= 200 && response.statusCode < 500) {
      recordTest('用户登录API调用', true, null, { statusCode: response.statusCode });
      
      try {
        const responseData = JSON.parse(response.body);
        recordTest('用户登录响应格式', true);
        
        // 检查是否有token或错误信息
        if (responseData.token || responseData.access_token || responseData.error || responseData.message) {
          recordTest('用户登录响应内容', true);
        } else {
          recordTest('用户登录响应内容', false, '响应内容不完整');
        }
        
      } catch (e) {
        recordTest('用户登录响应格式', false, '响应不是有效JSON');
      }
      
    } else {
      recordTest('用户登录API调用', false, `状态码: ${response.statusCode}`);
    }
    
  } catch (error) {
    recordTest('用户登录功能', false, error.message);
  }
}

// 测试前端页面功能
async function testFrontendPages() {
  console.log('\n=== 测试前端页面功能 ===');
  
  const pages = [
    { path: '/', name: '主页' },
    { path: '/login', name: '登录页' },
    { path: '/register', name: '注册页' },
    { path: '/map', name: '地图页' },
    { path: '/profile', name: '个人资料页' }
  ];
  
  for (const page of pages) {
    try {
      const response = await makeRequest(`${config.frontendUrl}${page.path}`);
      
      if (response.statusCode === 200) {
        recordTest(`前端${page.name}可访问性`, true);
        
        // 检查页面内容
        const body = response.body;
        const hasRoot = body.includes('id="root"');
        const hasReact = body.includes('react') || body.includes('React');
        const hasTitle = body.includes('SmellPin');
        
        recordTest(`前端${page.name}React应用`, hasRoot && hasReact, 
          !hasRoot || !hasReact ? '未检测到完整的React应用' : null);
        recordTest(`前端${page.name}应用标识`, hasTitle, 
          !hasTitle ? '未找到应用标识' : null);
        
      } else {
        recordTest(`前端${page.name}可访问性`, false, `状态码: ${response.statusCode}`);
      }
      
    } catch (error) {
      recordTest(`前端${page.name}功能`, false, error.message);
    }
    
    // 添加延迟
    await new Promise(resolve => setTimeout(resolve, 300));
  }
}

// 测试核心功能模块
async function testCoreFeatures() {
  console.log('\n=== 测试核心功能模块 ===');
  
  // 测试标注相关API
  try {
    const annotationsResponse = await makeRequest(`${config.apiUrl}/annotations`);
    recordTest('标注列表API', 
      annotationsResponse.statusCode >= 200 && annotationsResponse.statusCode < 500,
      annotationsResponse.statusCode >= 500 ? `服务器错误: ${annotationsResponse.statusCode}` : null);
  } catch (error) {
    recordTest('标注列表API', false, error.message);
  }
  
  // 测试用户相关API
  try {
    const usersResponse = await makeRequest(`${config.apiUrl}/users/profile`);
    recordTest('用户资料API', 
      usersResponse.statusCode >= 200 && usersResponse.statusCode < 500,
      usersResponse.statusCode >= 500 ? `服务器错误: ${usersResponse.statusCode}` : null);
  } catch (error) {
    recordTest('用户资料API', false, error.message);
  }
}

// 测试错误处理
async function testErrorHandling() {
  console.log('\n=== 测试错误处理 ===');
  
  // 测试不存在的API端点
  try {
    const response = await makeRequest(`${config.apiUrl}/nonexistent`);
    recordTest('404错误处理', 
      response.statusCode === 404,
      response.statusCode !== 404 ? `期望404，实际: ${response.statusCode}` : null);
  } catch (error) {
    recordTest('404错误处理', false, error.message);
  }
  
  // 测试前端不存在的页面
  try {
    const response = await makeRequest(`${config.frontendUrl}/nonexistent`);
    recordTest('前端404处理', 
      response.statusCode === 200 || response.statusCode === 404,
      `状态码: ${response.statusCode}`);
  } catch (error) {
    recordTest('前端404处理', false, error.message);
  }
}

// 主测试函数
async function runUserFeatureTests() {
  console.log('🚀 开始用户功能测试...\n');
  console.log(`前端地址: ${config.frontendUrl}`);
  console.log(`API地址: ${config.apiUrl}`);
  
  try {
    // 测试API端点
    await testAPIEndpoints();
    
    // 测试用户注册
    await testUserRegistration();
    
    // 测试用户登录
    await testUserLogin();
    
    // 测试前端页面
    await testFrontendPages();
    
    // 测试核心功能
    await testCoreFeatures();
    
    // 测试错误处理
    await testErrorHandling();
    
  } catch (error) {
    console.error('测试执行失败:', error);
    recordTest('测试执行', false, error.message);
  }
  
  // 输出测试结果
  console.log('\n' + '='.repeat(60));
  console.log('📊 用户功能测试结果');
  console.log('='.repeat(60));
  console.log(`✅ 通过: ${testResults.passed}`);
  console.log(`❌ 失败: ${testResults.failed}`);
  
  if (testResults.passed + testResults.failed > 0) {
    const successRate = ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1);
    console.log(`📈 成功率: ${successRate}%`);
  }
  
  if (testResults.errors.length > 0) {
    console.log('\n🔍 失败详情:');
    testResults.errors.forEach((error, index) => {
      console.log(`${index + 1}. ${error.test}: ${error.error}`);
    });
  }
  
  // 输出关键发现
  console.log('\n🔑 关键发现:');
  const apiErrors = testResults.errors.filter(e => e.test.includes('API'));
  const frontendErrors = testResults.errors.filter(e => e.test.includes('前端'));
  
  if (apiErrors.length > 0) {
    console.log(`- API问题: ${apiErrors.length}个`);
  }
  if (frontendErrors.length > 0) {
    console.log(`- 前端问题: ${frontendErrors.length}个`);
  }
  
  console.log('\n✨ 用户功能测试完成!');
  
  return {
    passed: testResults.passed,
    failed: testResults.failed,
    errors: testResults.errors,
    successRate: testResults.passed + testResults.failed > 0 ? 
      ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1) : 0
  };
}

// 执行测试
if (require.main === module) {
  runUserFeatureTests().catch(console.error);
}

module.exports = { runUserFeatureTests, testResults };