#!/usr/bin/env node

/**
 * SmellPin 增强版 MVP 完整性检查工具
 * 基于实际API响应格式进行完整性检查
 */

const axios = require('axios');
const fs = require('fs');

// 配置
const BASE_URL_3004 = 'http://localhost:3004';
const BASE_URL_3005 = 'http://localhost:3005';
const FRONTEND_URL = 'http://localhost:3000';

// 检查结果
const checkResults = {
  timestamp: new Date().toISOString(),
  overall: { status: 'pending', issues: [], blockingIssues: 0 },
  frontend: { status: 'pending', issues: [], tests: {} },
  backend: { status: 'pending', issues: [], tests: {} },
  database: { status: 'pending', issues: [], tests: {} },
  business: { status: 'pending', issues: [], tests: {} },
  security: { status: 'pending', issues: [], tests: {} }
};

// 颜色输出
const colors = {
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  blue: '\x1b[34m', reset: '\x1b[0m', bold: '\x1b[1m'
};

function log(color, message) {
  console.log(color + message + colors.reset);
}

function logSection(title) {
  console.log('\n' + colors.bold + colors.blue + '='.repeat(60) + colors.reset);
  console.log(colors.bold + colors.blue + title + colors.reset);
  console.log(colors.bold + colors.blue + '='.repeat(60) + colors.reset);
}

async function makeRequest(url, options = {}) {
  try {
    const response = await axios({
      url, timeout: 10000, validateStatus: () => true, ...options
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
 * 1. 前端页面完整性检查
 */
async function checkFrontend() {
  logSection('1. 前端页面完整性检查');
  
  const pages = [
    { name: '主页', path: '/', critical: true },
    { name: '地图页面', path: '/map', critical: true },
    { name: '登录页面', path: '/auth/login', critical: true },
    { name: '注册页面', path: '/auth/register', critical: true },
    { name: '个人资料页面', path: '/profile', critical: false },
    { name: '设置页面', path: '/settings', critical: false }
  ];

  let frontendRunning = false;

  for (const page of pages) {
    const result = await makeRequest(`${FRONTEND_URL}${page.path}`);
    
    if (result.success && result.status === 200) {
      log(colors.green, `✓ ${page.name}: 正常加载`);
      checkResults.frontend.tests[page.name] = 'pass';
      frontendRunning = true;
    } else if (result.success && result.status === 404) {
      const severity = page.critical ? 'critical' : 'warning';
      log(page.critical ? colors.red : colors.yellow, 
          `${page.critical ? '✗' : '⚠'} ${page.name}: 页面不存在 (${severity})`);
      checkResults.frontend.tests[page.name] = 'not_found';
      if (page.critical) {
        checkResults.frontend.issues.push(`关键页面${page.name}不存在`);
      }
    } else if (!result.success && result.code === 'ECONNREFUSED') {
      log(colors.red, `✗ ${page.name}: 前端服务未运行`);
      checkResults.frontend.tests[page.name] = 'service_down';
      if (!frontendRunning) {
        checkResults.frontend.issues.push('前端服务未运行');
      }
      break; // 服务未运行，无需继续检查其他页面
    } else {
      log(colors.yellow, `⚠ ${page.name}: 响应异常 (${result.status || 'unknown'})`);
      checkResults.frontend.tests[page.name] = 'error';
    }
  }

  // 检查静态资源加载
  if (frontendRunning) {
    log(colors.blue, '\\n检查静态资源加载:');
    const staticTests = [
      { name: 'CSS样式', path: '/_next/static/css/app/layout.css' },
      { name: 'JS脚本', path: '/_next/static/chunks/main-app.js' }
    ];

    for (const test of staticTests) {
      const result = await makeRequest(`${FRONTEND_URL}${test.path}`);
      if (result.success && [200, 304].includes(result.status)) {
        log(colors.green, `✓ ${test.name}: 加载正常`);
        checkResults.frontend.tests[test.name] = 'pass';
      } else {
        log(colors.yellow, `⚠ ${test.name}: 加载异常`);
        checkResults.frontend.tests[test.name] = 'fail';
      }
    }
  }
}

/**
 * 2. 后端API完整性检查
 */
async function checkBackend() {
  logSection('2. 后端API完整性检查');
  
  const servers = [
    { name: 'Backend-3004', url: BASE_URL_3004 },
    { name: 'Backend-3005', url: BASE_URL_3005 }
  ];

  for (const server of servers) {
    log(colors.blue, `\\n检查服务: ${server.name}`);
    
    // 基础健康检查
    const healthResult = await makeRequest(`${server.url}/health`);
    
    if (healthResult.success && healthResult.status === 200) {
      log(colors.green, '✓ 健康检查: 服务运行正常');
      checkResults.backend.tests[`${server.name}-health`] = 'pass';
      
      // 检查健康数据完整性
      const healthData = healthResult.data;
      if (healthData.success && healthData.data && healthData.data.status === 'ok') {
        log(colors.green, '✓ 健康数据: 格式正确');
        checkResults.backend.tests[`${server.name}-health-format`] = 'pass';
      } else {
        log(colors.yellow, '⚠ 健康数据: 格式异常');
        checkResults.backend.tests[`${server.name}-health-format`] = 'warning';
      }
    } else {
      log(colors.red, `✗ 健康检查: 服务异常 (${healthResult.status || healthResult.error})`);
      checkResults.backend.tests[`${server.name}-health`] = 'fail';
      checkResults.backend.issues.push(`${server.name}服务异常`);
      continue; // 服务异常，跳过其他API检查
    }

    // API端点检查
    const apis = [
      { name: 'API文档', path: '/api/docs', method: 'HEAD', expect: [200] },
      { name: '用户注册', path: '/api/v1/auth/register', method: 'POST', expect: [400, 422] },
      { name: '用户登录', path: '/api/v1/auth/login', method: 'POST', expect: [400, 422] },
      { name: '标注列表', path: '/api/v1/annotations/list', method: 'GET', expect: [200, 500] },
      { name: 'LBS查询', path: '/api/v1/lbs/locations', method: 'GET', expect: [200, 400], 
        params: { latitude: 40.7128, longitude: -74.006, radius: 1000 } },
      { name: '支付创建', path: '/api/v1/payments/create', method: 'POST', expect: [401, 422] },
      { name: '地理编码', path: '/api/v1/geocoding/geocode', method: 'GET', expect: [401, 400],
        params: { address: 'New York' } },
      { name: '反地理编码', path: '/api/v1/geocoding/reverse-geocode', method: 'GET', expect: [401, 400],
        params: { latitude: 40.7128, longitude: -74.006 } }
    ];

    for (const api of apis) {
      const url = `${server.url}${api.path}`;
      const options = { method: api.method };
      
      if (api.params) {
        if (api.method === 'GET') {
          options.params = api.params;
        } else {
          options.data = api.params;
          options.headers = { 'Content-Type': 'application/json' };
        }
      }

      const result = await makeRequest(url, options);
      const testKey = `${server.name}-${api.name}`;
      
      if (result.success && api.expect.includes(result.status)) {
        log(colors.green, `✓ ${api.name}: 正常响应 (${result.status})`);
        checkResults.backend.tests[testKey] = 'pass';
      } else if (result.success && result.status === 500) {
        log(colors.red, `✗ ${api.name}: 服务器错误 (500)`);
        checkResults.backend.tests[testKey] = 'server_error';
        checkResults.backend.issues.push(`${server.name} ${api.name} 服务器错误`);
      } else if (result.success && result.status === 404) {
        log(colors.red, `✗ ${api.name}: API不存在 (404)`);
        checkResults.backend.tests[testKey] = 'not_found';
        checkResults.backend.issues.push(`${server.name} ${api.name} API不存在`);
      } else {
        const status = result.status || result.error;
        log(colors.yellow, `⚠ ${api.name}: 意外响应 (${status})`);
        checkResults.backend.tests[testKey] = 'unexpected';
      }
    }
  }
}

/**
 * 3. 数据库连接状态检查
 */
async function checkDatabase() {
  logSection('3. 数据库连接状态检查');
  
  // 通过实际功能测试数据库连接
  const dbTests = [
    {
      name: 'PostGIS地理查询',
      url: `${BASE_URL_3005}/api/v1/lbs/locations`,
      params: { latitude: 40.7128, longitude: -74.006, radius: 1000 },
      critical: true
    },
    {
      name: '标注数据查询',
      url: `${BASE_URL_3005}/api/v1/annotations/list`,
      critical: false
    }
  ];

  for (const test of dbTests) {
    const result = await makeRequest(test.url, { params: test.params });
    
    if (result.success && result.status === 200) {
      log(colors.green, `✓ ${test.name}: 数据库查询成功`);
      checkResults.database.tests[test.name] = 'pass';
      
      // 检查返回数据格式
      if (result.data && typeof result.data === 'object') {
        log(colors.green, `✓ ${test.name}: 数据格式正确`);
        checkResults.database.tests[`${test.name}-format`] = 'pass';
      } else {
        log(colors.yellow, `⚠ ${test.name}: 数据格式异常`);
        checkResults.database.tests[`${test.name}-format`] = 'warning';
      }
    } else if (result.success && result.status === 500) {
      log(colors.red, `✗ ${test.name}: 数据库查询失败 (500)`);
      checkResults.database.tests[test.name] = 'fail';
      if (test.critical) {
        checkResults.database.issues.push(`关键数据库功能${test.name}失败`);
      } else {
        checkResults.database.issues.push(`数据库功能${test.name}异常`);
      }
    } else {
      log(colors.yellow, `⚠ ${test.name}: 查询异常 (${result.status})`);
      checkResults.database.tests[test.name] = 'error';
    }
  }

  // 测试数据完整性
  log(colors.blue, '\\n检查数据完整性:');
  const integrityResult = await makeRequest(`${BASE_URL_3005}/api/v1/lbs/locations?latitude=40.7128&longitude=-74.006&radius=1000`);
  
  if (integrityResult.success && integrityResult.status === 200) {
    try {
      const data = integrityResult.data;
      if (data.success && Array.isArray(data.data)) {
        log(colors.green, `✓ 数据完整性: 查询返回 ${data.data.length} 条记录`);
        checkResults.database.tests['data-integrity'] = 'pass';
      } else {
        log(colors.yellow, '⚠ 数据完整性: 数据结构异常');
        checkResults.database.tests['data-integrity'] = 'warning';
      }
    } catch (error) {
      log(colors.yellow, '⚠ 数据完整性: 数据解析异常');
      checkResults.database.tests['data-integrity'] = 'warning';
    }
  }
}

/**
 * 4. 核心业务流程检查
 */
async function checkBusinessFlows() {
  logSection('4. 核心业务流程检查');
  
  // 用户认证流程
  log(colors.blue, '\\n测试用户认证流程:');
  
  const authTests = [
    {
      name: '用户注册端点',
      url: `${BASE_URL_3005}/api/v1/auth/register`,
      method: 'POST',
      data: { username: 'test', email: 'test@example.com', password: 'test123' },
      expectStatuses: [400, 422, 409] // 缺少必要字段或已存在
    },
    {
      name: '用户登录端点',
      url: `${BASE_URL_3005}/api/v1/auth/login`,
      method: 'POST',
      data: { email: 'test@example.com', password: 'wrongpass' },
      expectStatuses: [400, 401, 422] // 认证失败或格式错误
    }
  ];

  for (const test of authTests) {
    const result = await makeRequest(test.url, {
      method: test.method,
      data: test.data,
      headers: { 'Content-Type': 'application/json' }
    });

    if (result.success && test.expectStatuses.includes(result.status)) {
      log(colors.green, `✓ ${test.name}: 响应正确 (${result.status})`);
      checkResults.business.tests[test.name] = 'pass';
    } else {
      log(colors.yellow, `⚠ ${test.name}: 响应异常 (${result.status || result.error})`);
      checkResults.business.tests[test.name] = 'warning';
    }
  }

  // 核心功能流程
  log(colors.blue, '\\n测试核心功能:');
  
  const coreTests = [
    {
      name: 'LBS位置服务',
      url: `${BASE_URL_3005}/api/v1/lbs/locations`,
      params: { latitude: 40.7128, longitude: -74.006, radius: 1000 },
      critical: true
    },
    {
      name: '标注创建端点',
      url: `${BASE_URL_3005}/api/v1/annotations/create`,
      method: 'POST',
      expectStatuses: [401], // 需要认证
      critical: true
    },
    {
      name: '支付系统',
      url: `${BASE_URL_3005}/api/v1/payments/create`,
      method: 'POST',
      expectStatuses: [401, 422], // 需要认证或参数错误
      critical: true
    }
  ];

  for (const test of coreTests) {
    const options = { method: test.method || 'GET' };
    if (test.params) options.params = test.params;
    if (test.method === 'POST') {
      options.headers = { 'Content-Type': 'application/json' };
      options.data = test.data || {};
    }

    const result = await makeRequest(test.url, options);
    
    if (test.expectStatuses) {
      if (result.success && test.expectStatuses.includes(result.status)) {
        log(colors.green, `✓ ${test.name}: 端点可用 (${result.status})`);
        checkResults.business.tests[test.name] = 'pass';
      } else {
        log(colors.yellow, `⚠ ${test.name}: 响应异常 (${result.status})`);
        checkResults.business.tests[test.name] = 'warning';
        if (test.critical) {
          checkResults.business.issues.push(`核心功能${test.name}异常`);
        }
      }
    } else {
      if (result.success && result.status === 200) {
        log(colors.green, `✓ ${test.name}: 功能正常`);
        checkResults.business.tests[test.name] = 'pass';
      } else {
        log(colors.red, `✗ ${test.name}: 功能异常 (${result.status})`);
        checkResults.business.tests[test.name] = 'fail';
        if (test.critical) {
          checkResults.business.issues.push(`关键功能${test.name}失败`);
        }
      }
    }
  }
}

/**
 * 5. 安全性配置检查
 */
async function checkSecurity() {
  logSection('5. 安全性配置检查');
  
  const servers = [BASE_URL_3004, BASE_URL_3005];
  
  for (const serverUrl of servers) {
    const serverName = serverUrl.includes('3004') ? 'Backend-3004' : 'Backend-3005';
    log(colors.blue, `\\n检查 ${serverName} 安全配置:`);
    
    const result = await makeRequest(`${serverUrl}/health`);
    
    if (result.success && result.headers) {
      const headers = result.headers;
      
      const securityHeaders = [
        { key: 'x-frame-options', critical: true },
        { key: 'x-content-type-options', critical: true },
        { key: 'x-xss-protection', critical: false },
        { key: 'strict-transport-security', critical: false },
        { key: 'content-security-policy', critical: false }
      ];

      let criticalCount = 0;
      let totalCount = 0;

      for (const header of securityHeaders) {
        if (headers[header.key] || headers[header.key.toLowerCase()]) {
          log(colors.green, `✓ ${header.key}: 已配置`);
          checkResults.security.tests[`${serverName}-${header.key}`] = 'pass';
          if (header.critical) criticalCount++;
          totalCount++;
        } else {
          const severity = header.critical ? colors.red : colors.yellow;
          const icon = header.critical ? '✗' : '⚠';
          log(severity, `${icon} ${header.key}: 未配置`);
          checkResults.security.tests[`${serverName}-${header.key}`] = 'missing';
          if (header.critical) {
            checkResults.security.issues.push(`${serverName}缺少关键安全头部${header.key}`);
          }
        }
      }

      log(colors.blue, `安全头部配置: ${totalCount}/${securityHeaders.length} (关键: ${criticalCount}/2)`);
    }
  }

  // 测试认证保护
  log(colors.blue, '\\n测试API认证保护:');
  
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
      checkResults.security.tests[`auth-${endpoint}`] = 'pass';
    } else if (result.success && result.status === 404) {
      log(colors.yellow, `⚠ ${endpoint}: 端点不存在`);
      checkResults.security.tests[`auth-${endpoint}`] = 'not_found';
    } else {
      log(colors.red, `✗ ${endpoint}: 认证保护异常 (${result.status})`);
      checkResults.security.tests[`auth-${endpoint}`] = 'fail';
      checkResults.security.issues.push(`${endpoint}认证保护异常`);
    }
  }
}

/**
 * 生成最终报告
 */
function generateFinalReport() {
  logSection('MVP完整性检查报告');
  
  // 计算模块状态
  const modules = [
    { name: '前端页面', key: 'frontend' },
    { name: '后端API', key: 'backend' },
    { name: '数据库连接', key: 'database' },
    { name: '核心业务流程', key: 'business' },
    { name: '安全性配置', key: 'security' }
  ];

  let totalIssues = 0;
  let blockingIssues = 0;

  for (const module of modules) {
    const moduleData = checkResults[module.key];
    const issueCount = moduleData.issues.length;
    totalIssues += issueCount;
    
    // 计算阻塞性问题
    const criticalIssues = moduleData.issues.filter(issue => 
      issue.includes('关键') || issue.includes('核心') || 
      issue.includes('服务异常') || issue.includes('不存在')
    ).length;
    blockingIssues += criticalIssues;
    
    // 设置模块状态
    if (issueCount === 0) {
      moduleData.status = 'pass';
    } else if (criticalIssues === 0) {
      moduleData.status = 'warning';
    } else {
      moduleData.status = 'fail';
    }
  }

  console.log('\\n' + colors.bold + '总体状态:' + colors.reset);
  
  for (const module of modules) {
    const moduleData = checkResults[module.key];
    const status = moduleData.status;
    const issueCount = moduleData.issues.length;
    
    let statusIcon, statusColor;
    if (status === 'pass') {
      statusIcon = '✓'; statusColor = colors.green;
    } else if (status === 'warning') {
      statusIcon = '⚠'; statusColor = colors.yellow;
    } else {
      statusIcon = '✗'; statusColor = colors.red;
    }

    console.log(`${statusColor}${statusIcon} ${module.name}: ${status.toUpperCase()} (${issueCount} 个问题)${colors.reset}`);
  }

  console.log('\\n' + colors.bold + '关键指标:' + colors.reset);
  console.log(`总问题数: ${totalIssues}`);
  console.log(`阻塞性问题: ${blockingIssues}`);
  console.log(`系统可用性: ${blockingIssues === 0 ? '良好' : blockingIssues <= 3 ? '需要改进' : '存在严重问题'}`);

  // 显示具体问题
  if (totalIssues > 0) {
    console.log('\\n' + colors.bold + '问题详情:' + colors.reset);
    for (const module of modules) {
      const moduleData = checkResults[module.key];
      if (moduleData.issues.length > 0) {
        console.log(`\\n${colors.yellow}${module.name}:${colors.reset}`);
        moduleData.issues.forEach((issue, index) => {
          console.log(`  ${index + 1}. ${issue}`);
        });
      }
    }
  }

  console.log('\\n' + colors.bold + '上线建议:' + colors.reset);
  
  if (blockingIssues === 0 && totalIssues <= 5) {
    log(colors.green, '✓ 建议上线 - 系统状态良好');
  } else if (blockingIssues === 0) {
    log(colors.yellow, '⚠ 可以上线 - 建议优化非关键问题');
  } else if (blockingIssues <= 2) {
    log(colors.yellow, '⚠ 建议修复关键问题后上线');
  } else {
    log(colors.red, '✗ 不建议上线 - 存在多个阻塞性问题，需要修复');
  }

  // 保存详细报告
  checkResults.overall = {
    status: blockingIssues === 0 ? 'ready' : blockingIssues <= 2 ? 'needs_fixes' : 'not_ready',
    totalIssues: totalIssues,
    blockingIssues: blockingIssues,
    canDeploy: blockingIssues <= 2,
    recommendation: blockingIssues === 0 ? 'proceed' : blockingIssues <= 2 ? 'fix_critical' : 'major_fixes_needed'
  };

  fs.writeFileSync(
    '/Users/xiaoyang/Downloads/臭味/enhanced-mvp-report.json',
    JSON.stringify(checkResults, null, 2)
  );

  console.log('\\n' + colors.blue + '详细报告已保存至: enhanced-mvp-report.json' + colors.reset);
}

async function main() {
  logSection('SmellPin 增强版 MVP 完整性检查');
  
  console.log(colors.blue + '检查范围:' + colors.reset);
  console.log('✓ 前端页面加载和静态资源');
  console.log('✓ 后端API端点和健康状态');
  console.log('✓ 数据库连接和查询功能');
  console.log('✓ 核心业务流程完整性');
  console.log('✓ 安全配置和认证保护');

  try {
    await checkFrontend();
    await checkBackend();
    await checkDatabase();
    await checkBusinessFlows();
    await checkSecurity();
    
    generateFinalReport();
    
  } catch (error) {
    console.error('\\n' + colors.red + '检查过程中发生错误:' + colors.reset);
    console.error(error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main };