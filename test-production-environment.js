#!/usr/bin/env node

const https = require('https');
const http = require('http');

// 测试配置
const config = {
  frontend: {
    url: 'https://x1aoyang-1-5gimfr95c320432c.tcloudbaseapp.com',
    name: '腾讯云CloudBase前端'
  },
  backend: {
    url: 'https://smellpin-workers.dev-small-1.workers.dev',
    name: 'Cloudflare Workers后端'
  },
  database: {
    url: 'postgresql://neondb_owner:npg_e3mCxo2VtySa@ep-shy-frost-aehftle9-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    name: 'Neon PostgreSQL数据库'
  }
};

// 测试结果存储
const testResults = {
  deployment: [],
  environment: [],
  endpoints: [],
  performance: [],
  security: []
};

// HTTP请求工具函数
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith('https');
    const client = isHttps ? https : http;
    
    const req = client.request(url, {
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: 10000,
      ...options
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: data,
          responseTime: Date.now() - startTime
        });
      });
    });
    
    const startTime = Date.now();
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// 数据库连接测试
function testDatabase() {
  return new Promise((resolve) => {
    try {
      const { Client } = require('pg');
      const client = new Client({ connectionString: config.database.url });
      
      const startTime = Date.now();
      client.connect()
        .then(() => client.query('SELECT version(), NOW()'))
        .then((res) => {
          const responseTime = Date.now() - startTime;
          client.end();
          resolve({
            success: true,
            responseTime,
            version: res.rows[0].version,
            timestamp: res.rows[0].now
          });
        })
        .catch((error) => {
          client.end();
          resolve({
            success: false,
            error: error.message,
            responseTime: Date.now() - startTime
          });
        });
    } catch (error) {
      resolve({
        success: false,
        error: 'pg module not found: ' + error.message,
        responseTime: 0
      });
    }
  });
}

// 1. 部署验证测试
async function testDeployment() {
  console.log('\n🚀 开始部署验证测试...');
  
  // 测试前端部署
  try {
    const response = await makeRequest(config.frontend.url);
    testResults.deployment.push({
      component: config.frontend.name,
      status: response.statusCode === 200 ? '✅ 成功' : '❌ 失败',
      statusCode: response.statusCode,
      responseTime: response.responseTime,
      details: response.statusCode === 200 ? '前端页面正常加载' : `HTTP ${response.statusCode}`
    });
  } catch (error) {
    testResults.deployment.push({
      component: config.frontend.name,
      status: '❌ 失败',
      error: error.message,
      details: '无法访问前端服务'
    });
  }
  
  // 测试后端部署
  try {
    const response = await makeRequest(`${config.backend.url}/health`);
    testResults.deployment.push({
      component: config.backend.name,
      status: response.statusCode === 200 ? '✅ 成功' : '❌ 失败',
      statusCode: response.statusCode,
      responseTime: response.responseTime,
      details: response.statusCode === 200 ? 'API健康检查通过' : `HTTP ${response.statusCode}`
    });
  } catch (error) {
    testResults.deployment.push({
      component: config.backend.name,
      status: '❌ 失败',
      error: error.message,
      details: '无法访问后端API'
    });
  }
  
  // 测试数据库连接
  const dbResult = await testDatabase();
  testResults.deployment.push({
    component: config.database.name,
    status: dbResult.success ? '✅ 成功' : '❌ 失败',
    responseTime: dbResult.responseTime,
    details: dbResult.success ? `数据库连接正常 (${dbResult.version.split(',')[0]})` : dbResult.error
  });
}

// 2. 环境配置验证
async function testEnvironment() {
  console.log('\n⚙️ 开始环境配置验证...');
  
  // 测试API端点配置
  try {
    const response = await makeRequest(`${config.backend.url}/api/config`);
    testResults.environment.push({
      test: 'API配置检查',
      status: response.statusCode === 200 ? '✅ 通过' : '❌ 失败',
      details: response.statusCode === 200 ? '环境变量配置正确' : `HTTP ${response.statusCode}`
    });
  } catch (error) {
    testResults.environment.push({
      test: 'API配置检查',
      status: '❌ 失败',
      details: error.message
    });
  }
  
  // 测试CORS配置
  try {
    const response = await makeRequest(config.backend.url, {
      method: 'OPTIONS',
      headers: {
        'Origin': config.frontend.url,
        'Access-Control-Request-Method': 'POST'
      }
    });
    
    const corsEnabled = response.headers['access-control-allow-origin'];
    testResults.environment.push({
      test: 'CORS配置',
      status: corsEnabled ? '✅ 通过' : '❌ 失败',
      details: corsEnabled ? `允许来源: ${corsEnabled}` : '未配置CORS'
    });
  } catch (error) {
    testResults.environment.push({
      test: 'CORS配置',
      status: '❌ 失败',
      details: error.message
    });
  }
}

// 3. 端到端功能测试
async function testEndpoints() {
  console.log('\n🔗 开始API端点测试...');
  
  const endpoints = [
    { path: '/health', method: 'GET', name: '健康检查' },
    { path: '/api/users', method: 'GET', name: '用户列表' },
    { path: '/api/annotations', method: 'GET', name: '标注列表' },
    { path: '/api/auth/register', method: 'POST', name: '用户注册', body: JSON.stringify({
      username: 'test_user_' + Date.now(),
      email: 'test@example.com',
      password: 'test123456'
    }), headers: { 'Content-Type': 'application/json' }}
  ];
  
  for (const endpoint of endpoints) {
    try {
      const response = await makeRequest(`${config.backend.url}${endpoint.path}`, {
        method: endpoint.method,
        headers: endpoint.headers,
        body: endpoint.body
      });
      
      testResults.endpoints.push({
        endpoint: `${endpoint.method} ${endpoint.path}`,
        name: endpoint.name,
        status: response.statusCode < 500 ? '✅ 可访问' : '❌ 服务器错误',
        statusCode: response.statusCode,
        responseTime: response.responseTime
      });
    } catch (error) {
      testResults.endpoints.push({
        endpoint: `${endpoint.method} ${endpoint.path}`,
        name: endpoint.name,
        status: '❌ 连接失败',
        error: error.message
      });
    }
  }
}

// 4. 性能测试
async function testPerformance() {
  console.log('\n⚡ 开始性能测试...');
  
  // 前端加载性能
  const frontendTimes = [];
  for (let i = 0; i < 3; i++) {
    try {
      const response = await makeRequest(config.frontend.url);
      frontendTimes.push(response.responseTime);
    } catch (error) {
      frontendTimes.push(null);
    }
  }
  
  const avgFrontendTime = frontendTimes.filter(t => t !== null).reduce((a, b) => a + b, 0) / frontendTimes.filter(t => t !== null).length;
  testResults.performance.push({
    test: '前端加载性能',
    averageTime: Math.round(avgFrontendTime) || 0,
    status: avgFrontendTime < 3000 ? '✅ 良好' : avgFrontendTime < 5000 ? '⚠️ 一般' : '❌ 较慢',
    details: `平均响应时间: ${Math.round(avgFrontendTime) || 0}ms`
  });
  
  // API响应性能
  const apiTimes = [];
  for (let i = 0; i < 3; i++) {
    try {
      const response = await makeRequest(`${config.backend.url}/health`);
      apiTimes.push(response.responseTime);
    } catch (error) {
      apiTimes.push(null);
    }
  }
  
  const avgApiTime = apiTimes.filter(t => t !== null).reduce((a, b) => a + b, 0) / apiTimes.filter(t => t !== null).length;
  testResults.performance.push({
    test: 'API响应性能',
    averageTime: Math.round(avgApiTime) || 0,
    status: avgApiTime < 1000 ? '✅ 优秀' : avgApiTime < 2000 ? '⚠️ 良好' : '❌ 较慢',
    details: `平均响应时间: ${Math.round(avgApiTime) || 0}ms`
  });
  
  // 数据库性能
  const dbResult = await testDatabase();
  testResults.performance.push({
    test: '数据库连接性能',
    averageTime: dbResult.responseTime,
    status: dbResult.responseTime < 500 ? '✅ 优秀' : dbResult.responseTime < 1000 ? '⚠️ 良好' : '❌ 较慢',
    details: `连接时间: ${dbResult.responseTime}ms`
  });
}

// 5. 安全测试
async function testSecurity() {
  console.log('\n🔒 开始安全测试...');
  
  // 测试HTTPS
  testResults.security.push({
    test: 'HTTPS配置',
    status: config.frontend.url.startsWith('https') && config.backend.url.startsWith('https') ? '✅ 启用' : '❌ 未启用',
    details: '前端和后端均使用HTTPS协议'
  });
  
  // 测试安全头
  try {
    const response = await makeRequest(config.backend.url);
    const securityHeaders = {
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-frame-options': response.headers['x-frame-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    };
    
    const hasSecurityHeaders = Object.values(securityHeaders).some(header => header);
    testResults.security.push({
      test: '安全响应头',
      status: hasSecurityHeaders ? '✅ 配置' : '⚠️ 部分配置',
      details: `检测到安全头: ${Object.keys(securityHeaders).filter(key => securityHeaders[key]).join(', ') || '无'}`
    });
  } catch (error) {
    testResults.security.push({
      test: '安全响应头',
      status: '❌ 检测失败',
      details: error.message
    });
  }
  
  // 测试SQL注入防护（基础测试）
  try {
    const response = await makeRequest(`${config.backend.url}/api/users?id=1' OR '1'='1`);
    testResults.security.push({
      test: 'SQL注入防护',
      status: response.statusCode === 400 || response.statusCode === 422 ? '✅ 有防护' : '⚠️ 需检查',
      details: `测试响应: HTTP ${response.statusCode}`
    });
  } catch (error) {
    testResults.security.push({
      test: 'SQL注入防护',
      status: '⚠️ 无法测试',
      details: error.message
    });
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n📊 生成测试报告...');
  
  const report = {
    timestamp: new Date().toISOString(),
    environment: {
      frontend: config.frontend.url,
      backend: config.backend.url,
      database: 'Neon PostgreSQL'
    },
    summary: {
      deployment: {
        total: testResults.deployment.length,
        passed: testResults.deployment.filter(t => t.status.includes('✅')).length
      },
      environment: {
        total: testResults.environment.length,
        passed: testResults.environment.filter(t => t.status.includes('✅')).length
      },
      endpoints: {
        total: testResults.endpoints.length,
        passed: testResults.endpoints.filter(t => t.status.includes('✅')).length
      },
      performance: {
        total: testResults.performance.length,
        good: testResults.performance.filter(t => t.status.includes('✅')).length
      },
      security: {
        total: testResults.security.length,
        passed: testResults.security.filter(t => t.status.includes('✅')).length
      }
    },
    details: testResults
  };
  
  // 保存报告到文件
  const fs = require('fs');
  const reportPath = './production-test-report.json';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  return report;
}

// 打印测试结果
function printResults(report) {
  console.log('\n' + '='.repeat(80));
  console.log('🎯 线上环境测试报告');
  console.log('='.repeat(80));
  console.log(`📅 测试时间: ${new Date(report.timestamp).toLocaleString('zh-CN')}`);
  console.log(`🌐 前端地址: ${report.environment.frontend}`);
  console.log(`⚡ 后端地址: ${report.environment.backend}`);
  console.log(`🗄️ 数据库: ${report.environment.database}`);
  
  console.log('\n📋 测试概览:');
  console.log(`  部署验证: ${report.summary.deployment.passed}/${report.summary.deployment.total} 通过`);
  console.log(`  环境配置: ${report.summary.environment.passed}/${report.summary.environment.total} 通过`);
  console.log(`  API端点: ${report.summary.endpoints.passed}/${report.summary.endpoints.total} 可访问`);
  console.log(`  性能测试: ${report.summary.performance.good}/${report.summary.performance.total} 良好`);
  console.log(`  安全测试: ${report.summary.security.passed}/${report.summary.security.total} 通过`);
  
  // 详细结果
  console.log('\n🚀 部署验证结果:');
  testResults.deployment.forEach(result => {
    console.log(`  ${result.status} ${result.component} - ${result.details}`);
    if (result.responseTime) console.log(`    响应时间: ${result.responseTime}ms`);
  });
  
  console.log('\n⚙️ 环境配置结果:');
  testResults.environment.forEach(result => {
    console.log(`  ${result.status} ${result.test} - ${result.details}`);
  });
  
  console.log('\n🔗 API端点结果:');
  testResults.endpoints.forEach(result => {
    console.log(`  ${result.status} ${result.name} (${result.endpoint})`);
    if (result.responseTime) console.log(`    响应时间: ${result.responseTime}ms`);
  });
  
  console.log('\n⚡ 性能测试结果:');
  testResults.performance.forEach(result => {
    console.log(`  ${result.status} ${result.test} - ${result.details}`);
  });
  
  console.log('\n🔒 安全测试结果:');
  testResults.security.forEach(result => {
    console.log(`  ${result.status} ${result.test} - ${result.details}`);
  });
  
  // 总体评估
  const totalTests = Object.values(report.summary).reduce((sum, category) => sum + category.total, 0);
  const totalPassed = report.summary.deployment.passed + report.summary.environment.passed + 
                     report.summary.endpoints.passed + report.summary.performance.good + report.summary.security.passed;
  const successRate = Math.round((totalPassed / totalTests) * 100);
  
  console.log('\n' + '='.repeat(80));
  console.log(`🎯 总体成功率: ${successRate}% (${totalPassed}/${totalTests})`);
  
  if (successRate >= 90) {
    console.log('✅ 系统状态: 优秀 - 生产环境已准备就绪!');
  } else if (successRate >= 75) {
    console.log('⚠️ 系统状态: 良好 - 建议优化部分功能后上线');
  } else {
    console.log('❌ 系统状态: 需要改进 - 请修复关键问题后重新测试');
  }
  
  console.log(`📄 详细报告已保存至: production-test-report.json`);
  console.log('='.repeat(80));
}

// 主函数
async function main() {
  console.log('🚀 开始线上环境完整测试...');
  console.log('测试目标:');
  console.log(`  前端: ${config.frontend.url}`);
  console.log(`  后端: ${config.backend.url}`);
  console.log(`  数据库: Neon PostgreSQL`);
  
  try {
    await testDeployment();
    await testEnvironment();
    await testEndpoints();
    await testPerformance();
    await testSecurity();
    
    const report = generateReport();
    printResults(report);
    
  } catch (error) {
    console.error('❌ 测试过程中发生错误:', error.message);
    process.exit(1);
  }
}

// 运行测试
if (require.main === module) {
  main();
}

module.exports = { main, testResults, config };