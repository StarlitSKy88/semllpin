#!/usr/bin/env node

/**
 * 线上环境测试脚本
 * 测试腾讯云CloudBase前端、Cloudflare Workers后端、Neon PostgreSQL数据库
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// 从配置文件读取生产环境配置
let PRODUCTION_CONFIG;
try {
  const configPath = path.join(__dirname, 'production-config.json');
  const configData = fs.readFileSync(configPath, 'utf8');
  PRODUCTION_CONFIG = JSON.parse(configData);
  
  // 检查是否还是默认配置
  if (PRODUCTION_CONFIG.frontend.url.includes('your-cloudbase-app') || 
      PRODUCTION_CONFIG.backend.url.includes('your-workers')) {
    console.log('⚠️  警告: 检测到默认配置URL，请先在 production-config.json 中配置实际的生产环境地址');
    console.log('前端URL:', PRODUCTION_CONFIG.frontend.url);
    console.log('后端URL:', PRODUCTION_CONFIG.backend.url);
    console.log('\n请编辑 production-config.json 文件，将URL替换为您的实际生产环境地址后再运行测试。\n');
  }
} catch (error) {
  console.error('❌ 无法读取配置文件 production-config.json:', error.message);
  console.log('使用默认配置...');
  PRODUCTION_CONFIG = {
    frontend: {
      url: 'https://your-cloudbase-app.tcloudbaseapp.com',
      name: '腾讯云CloudBase前端'
    },
    backend: {
      url: 'https://your-workers.your-subdomain.workers.dev',
      name: 'Cloudflare Workers后端'
    },
    database: {
      name: 'Neon PostgreSQL数据库'
    }
  };
}

// 测试结果记录
const testResults = {
  deployment: [],
  configuration: [],
  endToEnd: [],
  performance: [],
  security: []
};

// HTTP请求工具函数
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const startTime = performance.now();
    const protocol = url.startsWith('https:') ? https : http;
    
    const req = protocol.request(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Production-Test-Script/1.0',
        ...options.headers
      },
      timeout: options.timeout || 10000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const endTime = performance.now();
        const responseTime = endTime - startTime;
        
        try {
          const jsonData = data ? JSON.parse(data) : {};
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: jsonData,
            responseTime,
            rawData: data
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data,
            responseTime,
            rawData: data
          });
        }
      });
    });
    
    req.on('error', (error) => {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      reject({ error, responseTime });
    });
    
    req.on('timeout', () => {
      req.destroy();
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      reject({ error: new Error('Request timeout'), responseTime });
    });
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

// 记录测试结果
function recordResult(category, test, success, message, details = {}) {
  const result = {
    test,
    success,
    message,
    timestamp: new Date().toISOString(),
    ...details
  };
  testResults[category].push(result);
  
  const status = success ? '✅' : '❌';
  console.log(`${status} ${test}: ${message}`);
  
  if (details.responseTime) {
    console.log(`   响应时间: ${details.responseTime.toFixed(2)}ms`);
  }
}

// 1. 部署验证测试
async function testDeploymentVerification() {
  console.log('\n🚀 开始部署验证测试...');
  
  // 测试前端部署
  try {
    const response = await makeRequest(PRODUCTION_CONFIG.frontend.url);
    if (response.status === 200) {
      recordResult('deployment', '前端部署检查', true, 
        `${PRODUCTION_CONFIG.frontend.name}部署正常`, 
        { responseTime: response.responseTime, status: response.status });
    } else {
      recordResult('deployment', '前端部署检查', false, 
        `${PRODUCTION_CONFIG.frontend.name}返回状态码: ${response.status}`, 
        { responseTime: response.responseTime, status: response.status });
    }
  } catch (error) {
    recordResult('deployment', '前端部署检查', false, 
      `${PRODUCTION_CONFIG.frontend.name}无法访问: ${error.error?.message || error.message}`, 
      { error: error.error?.message || error.message });
  }
  
  // 测试后端部署
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/health`);
    if (response.status === 200) {
      recordResult('deployment', '后端部署检查', true, 
        `${PRODUCTION_CONFIG.backend.name}部署正常`, 
        { responseTime: response.responseTime, status: response.status });
    } else {
      recordResult('deployment', '后端部署检查', false, 
        `${PRODUCTION_CONFIG.backend.name}健康检查失败: ${response.status}`, 
        { responseTime: response.responseTime, status: response.status });
    }
  } catch (error) {
    recordResult('deployment', '后端部署检查', false, 
      `${PRODUCTION_CONFIG.backend.name}无法访问: ${error.error?.message || error.message}`, 
      { error: error.error?.message || error.message });
  }
  
  // 测试API端点可用性
  const apiEndpoints = [
    '/auth/register',
    '/auth/login', 
    '/annotations',
    '/comments',
    '/lbs/checkin',
    '/payments/create'
  ];
  
  for (const endpoint of apiEndpoints) {
    try {
      const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}${endpoint}`, {
        method: 'OPTIONS' // 使用OPTIONS请求检查端点是否存在
      });
      
      if (response.status < 500) {
        recordResult('deployment', `API端点检查: ${endpoint}`, true, 
          `端点可访问`, 
          { responseTime: response.responseTime, status: response.status });
      } else {
        recordResult('deployment', `API端点检查: ${endpoint}`, false, 
          `端点返回服务器错误: ${response.status}`, 
          { responseTime: response.responseTime, status: response.status });
      }
    } catch (error) {
      recordResult('deployment', `API端点检查: ${endpoint}`, false, 
        `端点无法访问: ${error.error?.message || error.message}`, 
        { error: error.error?.message || error.message });
    }
  }
}

// 2. 环境配置验证
async function testConfigurationVerification() {
  console.log('\n⚙️ 开始环境配置验证...');
  
  // 测试CORS配置
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/health`, {
      headers: {
        'Origin': PRODUCTION_CONFIG.frontend.url
      }
    });
    
    const corsHeaders = response.headers['access-control-allow-origin'];
    if (corsHeaders) {
      recordResult('configuration', 'CORS配置检查', true, 
        `CORS配置正确: ${corsHeaders}`, 
        { corsHeaders });
    } else {
      recordResult('configuration', 'CORS配置检查', false, 
        'CORS头部缺失', 
        { headers: response.headers });
    }
  } catch (error) {
    recordResult('configuration', 'CORS配置检查', false, 
      `CORS检查失败: ${error.error?.message || error.message}`);
  }
  
  // 测试数据库连接（通过API）
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/health/db`);
    if (response.status === 200 && response.data.database) {
      recordResult('configuration', '数据库连接检查', true, 
        '数据库连接正常', 
        { responseTime: response.responseTime });
    } else {
      recordResult('configuration', '数据库连接检查', false, 
        '数据库连接异常', 
        { status: response.status, data: response.data });
    }
  } catch (error) {
    recordResult('configuration', '数据库连接检查', false, 
      `数据库连接检查失败: ${error.error?.message || error.message}`);
  }
  
  // 测试环境变量配置（通过API响应推断）
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/config/check`);
    if (response.status === 200) {
      recordResult('configuration', '环境变量配置检查', true, 
        '环境变量配置正常', 
        { responseTime: response.responseTime });
    } else {
      recordResult('configuration', '环境变量配置检查', false, 
        '环境变量配置可能有问题', 
        { status: response.status });
    }
  } catch (error) {
    recordResult('configuration', '环境变量配置检查', false, 
      `环境变量检查失败: ${error.error?.message || error.message}`);
  }
}

// 3. 端到端测试
async function testEndToEnd() {
  console.log('\n🔄 开始端到端测试...');
  
  const timestamp = Date.now();
  const testUser = {
    username: `prod-test-${timestamp}`,
    email: `prod-test-${timestamp}@example.com`,
    password: 'TestPassword123!'
  };
  
  let authToken = null;
  
  // 用户注册测试
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/auth/register`, {
      method: 'POST',
      body: testUser
    });
    
    if (response.status === 201 || (response.status === 200 && response.data.success)) {
      recordResult('endToEnd', '用户注册', true, 
        '用户注册成功', 
        { responseTime: response.responseTime });
    } else {
      recordResult('endToEnd', '用户注册', false, 
        `注册失败: ${response.data.message || response.status}`, 
        { status: response.status, data: response.data });
    }
  } catch (error) {
    recordResult('endToEnd', '用户注册', false, 
      `注册请求失败: ${error.error?.message || error.message}`);
  }
  
  // 用户登录测试
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/auth/login`, {
      method: 'POST',
      body: {
        email: testUser.email,
        password: testUser.password
      }
    });
    
    if (response.status === 200 && response.data.success && response.data.data?.token) {
      authToken = response.data.data.token;
      recordResult('endToEnd', '用户登录', true, 
        '用户登录成功', 
        { responseTime: response.responseTime });
    } else {
      recordResult('endToEnd', '用户登录', false, 
        `登录失败: ${response.data.message || response.status}`, 
        { status: response.status, data: response.data });
    }
  } catch (error) {
    recordResult('endToEnd', '用户登录', false, 
      `登录请求失败: ${error.error?.message || error.message}`);
  }
  
  // 认证API测试
  if (authToken) {
    try {
      const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/annotations`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });
      
      if (response.status === 200) {
        recordResult('endToEnd', '认证API访问', true, 
          '认证API访问成功', 
          { responseTime: response.responseTime });
      } else {
        recordResult('endToEnd', '认证API访问', false, 
          `认证API访问失败: ${response.status}`, 
          { status: response.status });
      }
    } catch (error) {
      recordResult('endToEnd', '认证API访问', false, 
        `认证API请求失败: ${error.error?.message || error.message}`);
    }
  } else {
    recordResult('endToEnd', '认证API访问', false, '无法获取认证令牌，跳过认证API测试');
  }
}

// 4. 性能测试
async function testPerformance() {
  console.log('\n⚡ 开始性能测试...');
  
  // 前端加载性能测试
  const frontendTests = [];
  for (let i = 0; i < 3; i++) {
    try {
      const response = await makeRequest(PRODUCTION_CONFIG.frontend.url);
      frontendTests.push(response.responseTime);
    } catch (error) {
      frontendTests.push(null);
    }
  }
  
  const validFrontendTests = frontendTests.filter(t => t !== null);
  if (validFrontendTests.length > 0) {
    const avgTime = validFrontendTests.reduce((a, b) => a + b, 0) / validFrontendTests.length;
    const success = avgTime < 3000; // 3秒内认为性能良好
    recordResult('performance', '前端加载性能', success, 
      `平均加载时间: ${avgTime.toFixed(2)}ms`, 
      { averageTime: avgTime, tests: validFrontendTests });
  } else {
    recordResult('performance', '前端加载性能', false, '无法测试前端加载性能');
  }
  
  // API响应性能测试
  const apiTests = [];
  for (let i = 0; i < 5; i++) {
    try {
      const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/health`);
      apiTests.push(response.responseTime);
    } catch (error) {
      apiTests.push(null);
    }
  }
  
  const validApiTests = apiTests.filter(t => t !== null);
  if (validApiTests.length > 0) {
    const avgTime = validApiTests.reduce((a, b) => a + b, 0) / validApiTests.length;
    const success = avgTime < 1000; // 1秒内认为性能良好
    recordResult('performance', 'API响应性能', success, 
      `平均响应时间: ${avgTime.toFixed(2)}ms`, 
      { averageTime: avgTime, tests: validApiTests });
  } else {
    recordResult('performance', 'API响应性能', false, '无法测试API响应性能');
  }
}

// 5. 安全测试
async function testSecurity() {
  console.log('\n🔒 开始安全测试...');
  
  // HTTPS检查
  const frontendHttps = PRODUCTION_CONFIG.frontend.url.startsWith('https://');
  const backendHttps = PRODUCTION_CONFIG.backend.url.startsWith('https://');
  
  recordResult('security', '前端HTTPS检查', frontendHttps, 
    frontendHttps ? '前端使用HTTPS' : '前端未使用HTTPS');
  
  recordResult('security', '后端HTTPS检查', backendHttps, 
    backendHttps ? '后端使用HTTPS' : '后端未使用HTTPS');
  
  // 安全头部检查
  try {
    const response = await makeRequest(PRODUCTION_CONFIG.backend.url);
    const securityHeaders = {
      'x-frame-options': response.headers['x-frame-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection'],
      'strict-transport-security': response.headers['strict-transport-security']
    };
    
    const hasSecurityHeaders = Object.values(securityHeaders).some(header => header);
    recordResult('security', '安全头部检查', hasSecurityHeaders, 
      hasSecurityHeaders ? '检测到安全头部' : '缺少安全头部', 
      { securityHeaders });
  } catch (error) {
    recordResult('security', '安全头部检查', false, 
      `安全头部检查失败: ${error.error?.message || error.message}`);
  }
  
  // 未授权访问测试
  try {
    const response = await makeRequest(`${PRODUCTION_CONFIG.backend.url}/annotations`);
    const success = response.status === 401 || response.status === 403;
    recordResult('security', '未授权访问保护', success, 
      success ? '正确拒绝未授权访问' : '未授权访问保护可能存在问题', 
      { status: response.status });
  } catch (error) {
    recordResult('security', '未授权访问保护', false, 
      `未授权访问测试失败: ${error.error?.message || error.message}`);
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n📊 生成测试报告...');
  
  const categories = Object.keys(testResults);
  const report = {
    timestamp: new Date().toISOString(),
    summary: {},
    details: testResults
  };
  
  categories.forEach(category => {
    const tests = testResults[category];
    const total = tests.length;
    const passed = tests.filter(t => t.success).length;
    const failed = total - passed;
    const successRate = total > 0 ? (passed / total * 100).toFixed(1) : '0.0';
    
    report.summary[category] = {
      total,
      passed,
      failed,
      successRate: `${successRate}%`
    };
    
    console.log(`\n${getCategoryName(category)}:`);
    console.log(`  总计: ${total}, 通过: ${passed}, 失败: ${failed}, 成功率: ${successRate}%`);
  });
  
  // 计算总体成功率
  const totalTests = categories.reduce((sum, cat) => sum + testResults[cat].length, 0);
  const totalPassed = categories.reduce((sum, cat) => sum + testResults[cat].filter(t => t.success).length, 0);
  const overallSuccessRate = totalTests > 0 ? (totalPassed / totalTests * 100).toFixed(1) : '0.0';
  
  report.summary.overall = {
    total: totalTests,
    passed: totalPassed,
    failed: totalTests - totalPassed,
    successRate: `${overallSuccessRate}%`
  };
  
  console.log(`\n🎯 总体测试结果:`);
  console.log(`  总计: ${totalTests}, 通过: ${totalPassed}, 失败: ${totalTests - totalPassed}, 成功率: ${overallSuccessRate}%`);
  
  return report;
}

function getCategoryName(category) {
  const names = {
    deployment: '🚀 部署验证',
    configuration: '⚙️ 环境配置',
    endToEnd: '🔄 端到端测试',
    performance: '⚡ 性能测试',
    security: '🔒 安全测试'
  };
  return names[category] || category;
}

// 主函数
async function main() {
  console.log('🌐 开始线上环境测试...');
  console.log(`前端: ${PRODUCTION_CONFIG.frontend.url}`);
  console.log(`后端: ${PRODUCTION_CONFIG.backend.url}`);
  
  try {
    await testDeploymentVerification();
    await testConfigurationVerification();
    await testEndToEnd();
    await testPerformance();
    await testSecurity();
    
    const report = generateReport();
    
    // 保存报告到文件
    const fs = require('fs');
    const reportPath = './production-test-report.json';
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n📄 详细报告已保存到: ${reportPath}`);
    
    console.log('\n✅ 线上环境测试完成!');
    
  } catch (error) {
    console.error('❌ 测试过程中发生错误:', error);
    process.exit(1);
  }
}

// 运行测试
if (require.main === module) {
  main();
}

module.exports = {
  main,
  testDeploymentVerification,
  testConfigurationVerification,
  testEndToEnd,
  testPerformance,
  testSecurity,
  generateReport
};