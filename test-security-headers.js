#!/usr/bin/env node

/**
 * SmellPin Security Headers Test Script
 * 验证前端和后端的安全头部配置是否正确
 */

const https = require('https');
const http = require('http');

// 测试配置
const BACKEND_URL = 'http://localhost:3004';
const FRONTEND_URL = 'http://localhost:3000';

// 期望的安全头部
const EXPECTED_HEADERS = {
  backend: {
    'content-security-policy': true,
    'x-frame-options': true,
    'x-content-type-options': true,
    'referrer-policy': true,
    'permissions-policy': true,
    'x-xss-protection': false, // Helmet 默认禁用此头部
    // HSTS 只在生产环境启用
    'strict-transport-security': false, // 开发环境不启用
  },
  frontend: {
    'content-security-policy': true,
    'x-frame-options': true,
    'x-content-type-options': true,
    'referrer-policy': true,
    'permissions-policy': true,
    'x-xss-protection': true,
    'x-dns-prefetch-control': true,
    // HSTS 只在生产环境启用
    'strict-transport-security': false, // 开发环境不启用
  }
};

// 颜色输出
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const request = client.request(url, { method: 'HEAD' }, (response) => {
      resolve({
        statusCode: response.statusCode,
        headers: response.headers
      });
    });
    
    request.on('error', reject);
    request.setTimeout(10000, () => {
      request.destroy();
      reject(new Error('Request timeout'));
    });
    
    request.end();
  });
}

function checkHeaders(headers, expected, serviceName) {
  log(`\n${colors.bold}=== ${serviceName} 安全头部检查 ===${colors.reset}`, 'blue');
  
  let passCount = 0;
  let totalCount = 0;
  
  for (const [headerName, shouldExist] of Object.entries(expected)) {
    totalCount++;
    const headerValue = headers[headerName];
    const exists = !!headerValue;
    
    if (shouldExist && exists) {
      log(`✓ ${headerName}: ${headerValue}`, 'green');
      passCount++;
    } else if (!shouldExist && !exists) {
      log(`✓ ${headerName}: 未设置 (符合预期)`, 'green');
      passCount++;
    } else if (shouldExist && !exists) {
      log(`✗ ${headerName}: 缺失`, 'red');
    } else {
      log(`! ${headerName}: 意外存在 - ${headerValue}`, 'yellow');
      passCount++; // 额外的安全头部也算通过
    }
  }
  
  // 检查是否有其他重要的安全头部
  const additionalSecurityHeaders = [
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
    'origin-agent-cluster'
  ];
  
  additionalSecurityHeaders.forEach(header => {
    if (headers[header]) {
      log(`+ ${header}: ${headers[header]}`, 'blue');
    }
  });
  
  const score = Math.round((passCount / totalCount) * 100);
  log(`\n${serviceName} 安全评分: ${score}% (${passCount}/${totalCount})`, 
      score >= 90 ? 'green' : score >= 70 ? 'yellow' : 'red');
  
  return { passCount, totalCount, score };
}

function validateCSP(csp, serviceName) {
  log(`\n${colors.bold}=== ${serviceName} CSP 策略验证 ===${colors.reset}`, 'blue');
  
  if (!csp) {
    log('✗ 未设置 Content-Security-Policy', 'red');
    return false;
  }
  
  const directives = csp.split(';').map(d => d.trim());
  const directiveMap = {};
  
  directives.forEach(directive => {
    const [key, ...values] = directive.split(/\s+/);
    directiveMap[key] = values;
  });
  
  // 检查关键的CSP指令
  const criticalDirectives = [
    'default-src',
    'script-src',
    'style-src',
    'img-src',
    'object-src'
  ];
  
  let validDirectives = 0;
  criticalDirectives.forEach(directive => {
    if (directiveMap[directive]) {
      log(`✓ ${directive}: ${directiveMap[directive].join(' ')}`, 'green');
      validDirectives++;
    } else {
      log(`! ${directive}: 未设置`, 'yellow');
    }
  });
  
  // 检查是否有危险的配置
  if (directiveMap['script-src']?.includes('*')) {
    log('⚠ script-src 包含通配符 (*) - 可能不安全', 'yellow');
  }
  
  if (directiveMap['object-src']?.includes("'none'")) {
    log('✓ object-src 正确设置为 none', 'green');
    validDirectives++;
  }
  
  return validDirectives >= 4;
}

function validatePermissionsPolicy(policy, serviceName) {
  log(`\n${colors.bold}=== ${serviceName} Permissions Policy 验证 ===${colors.reset}`, 'blue');
  
  if (!policy) {
    log('✗ 未设置 Permissions-Policy', 'red');
    return false;
  }
  
  // 检查关键权限
  const expectedPermissions = [
    'geolocation=(self)',
    'camera=()',
    'microphone=()',
    'payment=(self)'
  ];
  
  let validPermissions = 0;
  expectedPermissions.forEach(permission => {
    if (policy.includes(permission)) {
      log(`✓ ${permission}`, 'green');
      validPermissions++;
    } else {
      log(`! ${permission}: 未找到`, 'yellow');
    }
  });
  
  return validPermissions >= 3;
}

async function testSecurityHeaders() {
  log(`${colors.bold}🔒 SmellPin 安全头部测试开始${colors.reset}`, 'blue');
  log('==========================================\n');
  
  const results = {};
  
  try {
    // 测试后端
    log('📡 测试后端安全头部...', 'blue');
    const backendResponse = await makeRequest(`${BACKEND_URL}/health`);
    results.backend = checkHeaders(
      backendResponse.headers, 
      EXPECTED_HEADERS.backend, 
      'Backend API'
    );
    
    validateCSP(backendResponse.headers['content-security-policy'], 'Backend');
    validatePermissionsPolicy(backendResponse.headers['permissions-policy'], 'Backend');
    
  } catch (error) {
    log(`✗ 后端测试失败: ${error.message}`, 'red');
    results.backend = { passCount: 0, totalCount: 0, score: 0 };
  }
  
  try {
    // 测试前端
    log('\n🌐 测试前端安全头部...', 'blue');
    const frontendResponse = await makeRequest(`${FRONTEND_URL}/`);
    results.frontend = checkHeaders(
      frontendResponse.headers, 
      EXPECTED_HEADERS.frontend, 
      'Frontend (Next.js)'
    );
    
    validateCSP(frontendResponse.headers['content-security-policy'], 'Frontend');
    validatePermissionsPolicy(frontendResponse.headers['permissions-policy'], 'Frontend');
    
  } catch (error) {
    log(`✗ 前端测试失败: ${error.message}`, 'red');
    results.frontend = { passCount: 0, totalCount: 0, score: 0 };
  }
  
  // 生成总体报告
  log(`\n${colors.bold}📊 总体安全评估${colors.reset}`, 'blue');
  log('==========================================');
  
  const totalScore = Math.round(
    (results.backend.score + results.frontend.score) / 2
  );
  
  log(`Backend 评分: ${results.backend.score}%`, 
      results.backend.score >= 90 ? 'green' : 'yellow');
  log(`Frontend 评分: ${results.frontend.score}%`, 
      results.frontend.score >= 90 ? 'green' : 'yellow');
  log(`总体评分: ${totalScore}%`, 
      totalScore >= 90 ? 'green' : totalScore >= 70 ? 'yellow' : 'red');
  
  // 建议
  log(`\n${colors.bold}💡 改进建议${colors.reset}`, 'blue');
  log('==========================================');
  
  if (totalScore >= 95) {
    log('🎉 安全头部配置优秀！', 'green');
  } else if (totalScore >= 80) {
    log('👍 安全头部配置良好，可考虑以下改进：', 'yellow');
  } else {
    log('⚠️  安全头部配置需要改进：', 'red');
  }
  
  if (results.backend.score < 90) {
    log('- 完善后端安全头部配置', 'yellow');
  }
  
  if (results.frontend.score < 90) {
    log('- 完善前端安全头部配置', 'yellow');
  }
  
  log('- 在生产环境中启用 HSTS (Strict-Transport-Security)', 'blue');
  log('- 定期审查和更新 CSP 策略', 'blue');
  log('- 考虑添加 Certificate Transparency (Expect-CT) 头部', 'blue');
  
  process.exit(totalScore >= 80 ? 0 : 1);
}

// 运行测试
if (require.main === module) {
  testSecurityHeaders().catch(error => {
    log(`\n💥 测试运行失败: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  });
}

module.exports = { testSecurityHeaders, makeRequest, checkHeaders };