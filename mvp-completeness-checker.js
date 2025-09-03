#!/usr/bin/env node

/**
 * SmellPin MVP 完整性检查工具
 * 用于全面检查SmellPin项目的MVP功能完整性
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 配置
const BASE_URL_3004 = 'http://localhost:3004';
const BASE_URL_3005 = 'http://localhost:3005';
const FRONTEND_URL = 'http://localhost:3000'; // Next.js 默认端口

/**
 * 检查结果结构
 */
const checkResults = {
  frontend: {
    status: 'pending',
    issues: [],
    pages: {}
  },
  backend: {
    status: 'pending',
    issues: [],
    apis: {}
  },
  database: {
    status: 'pending',
    issues: [],
    connections: {}
  },
  business: {
    status: 'pending',
    issues: [],
    flows: {}
  },
  security: {
    status: 'pending',
    issues: [],
    configs: {}
  }
};

/**
 * 颜色输出工具
 */
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function log(color, message) {
  console.log(color + message + colors.reset);
}

function logSection(title) {
  console.log('\n' + colors.bold + colors.blue + '='.repeat(60) + colors.reset);
  console.log(colors.bold + colors.blue + title + colors.reset);
  console.log(colors.bold + colors.blue + '='.repeat(60) + colors.reset);
}

function logSubSection(title) {
  console.log('\n' + colors.yellow + '--- ' + title + ' ---' + colors.reset);
}

/**
 * HTTP请求封装
 */
async function makeRequest(url, options = {}) {
  try {
    const response = await axios({
      url,
      timeout: 5000,
      validateStatus: () => true, // 不抛出错误，让我们处理所有状态码
      ...options
    });
    return {
      success: true,
      status: response.status,
      data: response.data,
      headers: response.headers
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      code: error.code
    };
  }
}

/**
 * 1. 检查前端页面完整性
 */
async function checkFrontendPages() {
  logSubSection('检查前端页面完整性');
  
  const pages = [
    { name: '主页', path: '/' },
    { name: '登录页面', path: '/auth/login' },
    { name: '注册页面', path: '/auth/register' },
    { name: '个人资料页面', path: '/profile' },
    { name: '设置页面', path: '/settings' },
    { name: 'API文档页面', path: '/api/docs' }
  ];

  for (const page of pages) {
    const result = await makeRequest(`${FRONTEND_URL}${page.path}`);
    
    if (result.success && result.status === 200) {
      log(colors.green, `✓ ${page.name}: 正常访问`);
      checkResults.frontend.pages[page.name] = 'pass';
    } else if (result.success && result.status === 404) {
      log(colors.red, `✗ ${page.name}: 页面不存在 (404)`);
      checkResults.frontend.pages[page.name] = 'not_found';
      checkResults.frontend.issues.push(`${page.name}页面不存在`);
    } else if (!result.success && result.code === 'ECONNREFUSED') {
      log(colors.red, `✗ ${page.name}: 前端服务未运行`);
      checkResults.frontend.pages[page.name] = 'service_down';
      checkResults.frontend.issues.push(`前端服务未运行`);
    } else {
      log(colors.yellow, `⚠ ${page.name}: 状态 ${result.status || 'unknown'}`);
      checkResults.frontend.pages[page.name] = 'warning';
      checkResults.frontend.issues.push(`${page.name}返回状态${result.status}`);
    }
  }
}

/**
 * 2. 检查后端API完整性
 */
async function checkBackendAPIs() {
  logSubSection('检查后端API完整性');
  
  // 检查两个后端服务
  const servers = [
    { name: 'Backend-3004', url: BASE_URL_3004 },
    { name: 'Backend-3005', url: BASE_URL_3005 }
  ];

  for (const server of servers) {
    log(colors.blue, `\n检查服务: ${server.name}`);
    
    const apis = [
      { name: '健康检查', path: '/health', method: 'GET' },
      { name: 'API文档', path: '/api/docs', method: 'HEAD' },
      { name: '用户注册', path: '/api/v1/auth/register', method: 'POST' },
      { name: '用户登录', path: '/api/v1/auth/login', method: 'POST' },
      { name: '标注列表', path: '/api/v1/annotations/list', method: 'GET' },
      { name: 'LBS位置查询', path: '/api/v1/lbs/locations', method: 'GET' },
      { name: '支付创建', path: '/api/v1/payments/create', method: 'POST' },
      { name: '地理编码', path: '/api/v1/geocoding/geocode', method: 'GET' },
      { name: '反地理编码', path: '/api/v1/geocoding/reverse-geocode', method: 'GET' }
    ];

    for (const api of apis) {
      const url = `${server.url}${api.path}`;
      let testParams = {};
      
      // 为特定API添加测试参数
      if (api.path.includes('/lbs/locations')) {
        testParams = { params: { latitude: 40.7128, longitude: -74.006, radius: 1000 } };
      } else if (api.path.includes('/geocode') && !api.path.includes('reverse')) {
        testParams = { params: { address: 'New York' } };
      } else if (api.path.includes('/reverse-geocode')) {
        testParams = { params: { latitude: 40.7128, longitude: -74.006 } };
      }

      const result = await makeRequest(url, { method: api.method, ...testParams });
      
      const apiKey = `${server.name}-${api.name}`;
      
      if (result.success && [200, 201, 204].includes(result.status)) {
        log(colors.green, `✓ ${api.name}: 正常响应 (${result.status})`);
        checkResults.backend.apis[apiKey] = 'pass';
      } else if (result.success && result.status === 500) {
        log(colors.red, `✗ ${api.name}: 服务器错误 (500)`);
        checkResults.backend.apis[apiKey] = 'server_error';
        checkResults.backend.issues.push(`${server.name} ${api.name} API服务器错误`);
      } else if (result.success && result.status === 401) {
        log(colors.yellow, `⚠ ${api.name}: 需要认证 (401)`);
        checkResults.backend.apis[apiKey] = 'auth_required';
      } else if (result.success && result.status === 404) {
        log(colors.red, `✗ ${api.name}: API不存在 (404)`);
        checkResults.backend.apis[apiKey] = 'not_found';
        checkResults.backend.issues.push(`${server.name} ${api.name} API不存在`);
      } else if (!result.success && result.code === 'ECONNREFUSED') {
        log(colors.red, `✗ ${api.name}: 服务未运行`);
        checkResults.backend.apis[apiKey] = 'service_down';
        checkResults.backend.issues.push(`${server.name}服务未运行`);
      } else {
        log(colors.yellow, `⚠ ${api.name}: ${result.status || result.error || 'unknown'}`);
        checkResults.backend.apis[apiKey] = 'warning';
        checkResults.backend.issues.push(`${server.name} ${api.name} 状态异常: ${result.status || result.error}`);
      }
    }
  }
}

/**
 * 3. 检查数据库连接状态
 */
async function checkDatabaseConnection() {
  logSubSection('检查数据库连接状态');
  
  // 通过健康检查端点检查数据库连接
  const servers = [
    { name: 'Backend-3004', url: BASE_URL_3004 },
    { name: 'Backend-3005', url: BASE_URL_3005 }
  ];

  for (const server of servers) {
    const result = await makeRequest(`${server.url}/health`);
    
    if (result.success && result.status === 200) {
      const healthData = result.data;
      if (healthData.database && healthData.database.status === 'connected') {
        log(colors.green, `✓ ${server.name}: 数据库连接正常`);
        checkResults.database.connections[server.name] = 'pass';
      } else {
        log(colors.red, `✗ ${server.name}: 数据库连接失败`);
        checkResults.database.connections[server.name] = 'fail';
        checkResults.database.issues.push(`${server.name}数据库连接失败`);
      }
    } else {
      log(colors.red, `✗ ${server.name}: 无法获取健康状态`);
      checkResults.database.connections[server.name] = 'unknown';
      checkResults.database.issues.push(`${server.name}健康检查失败`);
    }
  }

  // 测试特定的数据库查询
  log(colors.blue, '\n测试数据库查询功能:');
  
  const dbTests = [
    { name: 'PostGIS查询', server: BASE_URL_3005, path: '/api/v1/lbs/locations?latitude=40.7128&longitude=-74.006&radius=1000' },
    { name: '标注查询', server: BASE_URL_3005, path: '/api/v1/annotations/list' }
  ];

  for (const test of dbTests) {
    const result = await makeRequest(`${test.server}${test.path}`);
    
    if (result.success && result.status === 200) {
      log(colors.green, `✓ ${test.name}: 查询成功`);
      checkResults.database.connections[test.name] = 'pass';
    } else {
      log(colors.red, `✗ ${test.name}: 查询失败 (${result.status})`);
      checkResults.database.connections[test.name] = 'fail';
      checkResults.database.issues.push(`${test.name}查询失败`);
    }
  }
}

/**
 * 4. 检查核心业务流程
 */
async function checkBusinessFlows() {
  logSubSection('检查核心业务流程');
  
  // 用户认证流程测试
  log(colors.blue, '\n测试用户认证流程:');
  
  // 测试注册（不真实注册，只检查端点）
  const registerResult = await makeRequest(`${BASE_URL_3005}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    data: {
      username: 'test_user_' + Date.now(),
      email: 'test@example.com',
      password: 'testpassword123'
    }
  });

  if (registerResult.success && [200, 201, 400, 409].includes(registerResult.status)) {
    log(colors.green, '✓ 用户注册端点: 正常响应');
    checkResults.business.flows['用户注册'] = 'pass';
  } else {
    log(colors.red, `✗ 用户注册端点: 异常 (${registerResult.status || registerResult.error})`);
    checkResults.business.flows['用户注册'] = 'fail';
    checkResults.business.issues.push('用户注册端点异常');
  }

  // 测试登录
  const loginResult = await makeRequest(`${BASE_URL_3005}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    data: {
      email: 'test@example.com',
      password: 'wrongpassword'
    }
  });

  if (loginResult.success && [200, 401, 400].includes(loginResult.status)) {
    log(colors.green, '✓ 用户登录端点: 正常响应');
    checkResults.business.flows['用户登录'] = 'pass';
  } else {
    log(colors.red, `✗ 用户登录端点: 异常 (${loginResult.status || loginResult.error})`);
    checkResults.business.flows['用户登录'] = 'fail';
    checkResults.business.issues.push('用户登录端点异常');
  }

  // 地理位置功能测试
  log(colors.blue, '\n测试地理位置功能:');
  
  const lbsResult = await makeRequest(`${BASE_URL_3005}/api/v1/lbs/locations?latitude=40.7128&longitude=-74.006&radius=1000`);
  
  if (lbsResult.success && lbsResult.status === 200) {
    log(colors.green, '✓ LBS位置查询: 正常');
    checkResults.business.flows['LBS位置查询'] = 'pass';
  } else {
    log(colors.red, `✗ LBS位置查询: 失败 (${lbsResult.status})`);
    checkResults.business.flows['LBS位置查询'] = 'fail';
    checkResults.business.issues.push('LBS位置查询失败');
  }

  // 支付流程检查
  log(colors.blue, '\n测试支付流程:');
  
  const paymentResult = await makeRequest(`${BASE_URL_3005}/api/v1/payments/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    data: {
      amount: 100,
      currency: 'usd',
      description: 'test payment'
    }
  });

  if (paymentResult.success && [200, 201, 401].includes(paymentResult.status)) {
    log(colors.green, '✓ 支付创建端点: 正常响应');
    checkResults.business.flows['支付流程'] = 'pass';
  } else {
    log(colors.red, `✗ 支付创建端点: 异常 (${paymentResult.status || paymentResult.error})`);
    checkResults.business.flows['支付流程'] = 'fail';
    checkResults.business.issues.push('支付创建端点异常');
  }
}

/**
 * 5. 检查安全性配置
 */
async function checkSecurity() {
  logSubSection('检查安全性配置');
  
  const servers = [BASE_URL_3004, BASE_URL_3005];
  
  for (const serverUrl of servers) {
    const serverName = serverUrl.includes('3004') ? 'Backend-3004' : 'Backend-3005';
    log(colors.blue, `\n检查 ${serverName} 安全配置:`);
    
    // 检查健康端点的安全头部
    const healthResult = await makeRequest(`${serverUrl}/health`);
    
    if (healthResult.success && healthResult.headers) {
      const headers = healthResult.headers;
      
      // 检查关键安全头部
      const securityHeaders = [
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
        'strict-transport-security',
        'content-security-policy'
      ];

      let securityScore = 0;
      for (const header of securityHeaders) {
        if (headers[header] || headers[header.toLowerCase()]) {
          log(colors.green, `✓ ${header}: 已配置`);
          securityScore++;
        } else {
          log(colors.yellow, `⚠ ${header}: 未配置`);
        }
      }

      if (securityScore >= 3) {
        checkResults.security.configs[serverName] = 'pass';
      } else if (securityScore >= 1) {
        checkResults.security.configs[serverName] = 'partial';
        checkResults.security.issues.push(`${serverName}安全头部配置不完整`);
      } else {
        checkResults.security.configs[serverName] = 'fail';
        checkResults.security.issues.push(`${serverName}缺少安全头部配置`);
      }
    } else {
      log(colors.red, `✗ 无法检查 ${serverName} 安全配置`);
      checkResults.security.configs[serverName] = 'unknown';
      checkResults.security.issues.push(`${serverName}安全配置检查失败`);
    }
  }

  // 测试认证中间件
  log(colors.blue, '\n测试认证中间件:');
  
  const protectedEndpoints = [
    '/api/v1/annotations/create',
    '/api/v1/payments/create',
    '/api/v1/users/profile'
  ];

  for (const endpoint of protectedEndpoints) {
    const result = await makeRequest(`${BASE_URL_3005}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    if (result.success && result.status === 401) {
      log(colors.green, `✓ ${endpoint}: 正确要求认证`);
    } else if (result.success && result.status === 404) {
      log(colors.yellow, `⚠ ${endpoint}: 端点不存在`);
    } else {
      log(colors.red, `✗ ${endpoint}: 认证检查异常 (${result.status})`);
      checkResults.security.issues.push(`${endpoint}认证中间件异常`);
    }
  }
}

/**
 * 生成最终报告
 */
function generateFinalReport() {
  logSection('MVP完整性检查报告');
  
  // 计算各模块状态
  for (const module of Object.keys(checkResults)) {
    const moduleResult = checkResults[module];
    if (moduleResult.issues.length === 0) {
      moduleResult.status = 'pass';
    } else if (moduleResult.issues.length <= 2) {
      moduleResult.status = 'warning';
    } else {
      moduleResult.status = 'fail';
    }
  }

  console.log('\n' + colors.bold + '总体状态:' + colors.reset);
  
  const modules = {
    '前端页面': checkResults.frontend,
    '后端API': checkResults.backend,
    '数据库连接': checkResults.database,
    '核心业务流程': checkResults.business,
    '安全性配置': checkResults.security
  };

  let overallIssues = 0;
  let blockingIssues = 0;

  for (const [moduleName, moduleResult] of Object.entries(modules)) {
    const status = moduleResult.status;
    const issueCount = moduleResult.issues.length;
    overallIssues += issueCount;
    
    let statusIcon, statusColor;
    if (status === 'pass') {
      statusIcon = '✓';
      statusColor = colors.green;
    } else if (status === 'warning') {
      statusIcon = '⚠';
      statusColor = colors.yellow;
    } else {
      statusIcon = '✗';
      statusColor = colors.red;
      blockingIssues += issueCount;
    }

    console.log(`${statusColor}${statusIcon} ${moduleName}: ${status.toUpperCase()} (${issueCount} 个问题)${colors.reset}`);
  }

  console.log('\n' + colors.bold + '关键问题汇总:' + colors.reset);
  
  if (overallIssues === 0) {
    log(colors.green, '✓ 所有检查项目均通过，系统准备就绪');
  } else {
    console.log(`总问题数: ${overallIssues}`);
    console.log(`阻塞性问题: ${blockingIssues}`);
    
    // 显示所有问题
    for (const [moduleName, moduleResult] of Object.entries(modules)) {
      if (moduleResult.issues.length > 0) {
        console.log(`\n${colors.yellow}${moduleName}问题:${colors.reset}`);
        moduleResult.issues.forEach((issue, index) => {
          console.log(`  ${index + 1}. ${issue}`);
        });
      }
    }
  }

  console.log('\n' + colors.bold + '上线建议:' + colors.reset);
  
  if (blockingIssues === 0) {
    log(colors.green, '✓ 可以上线 - 没有阻塞性问题');
  } else if (blockingIssues <= 2) {
    log(colors.yellow, '⚠ 建议修复关键问题后上线');
  } else {
    log(colors.red, '✗ 不建议上线 - 存在多个阻塞性问题');
  }

  // 保存详细报告到文件
  const reportData = {
    timestamp: new Date().toISOString(),
    summary: {
      totalIssues: overallIssues,
      blockingIssues: blockingIssues,
      canDeploy: blockingIssues <= 2
    },
    modules: checkResults
  };

  fs.writeFileSync(
    '/Users/xiaoyang/Downloads/臭味/mvp-completeness-report.json',
    JSON.stringify(reportData, null, 2)
  );

  console.log('\n' + colors.blue + '详细报告已保存至: mvp-completeness-report.json' + colors.reset);
}

/**
 * 主函数
 */
async function main() {
  logSection('SmellPin MVP完整性检查开始');
  
  console.log(colors.blue + '检查项目:' + colors.reset);
  console.log('1. 前端页面完整性');
  console.log('2. 后端API完整性');
  console.log('3. 数据库连接状态');
  console.log('4. 核心业务流程');
  console.log('5. 安全性配置');

  try {
    await checkFrontendPages();
    await checkBackendAPIs();
    await checkDatabaseConnection();
    await checkBusinessFlows();
    await checkSecurity();
    
    generateFinalReport();
    
  } catch (error) {
    console.error('\n' + colors.red + '检查过程中发生错误:' + colors.reset);
    console.error(error.message);
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  main();
}

module.exports = {
  main,
  checkFrontendPages,
  checkBackendAPIs,
  checkDatabaseConnection,
  checkBusinessFlows,
  checkSecurity
};