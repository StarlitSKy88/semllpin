const axios = require('axios');

// 配置
const API_BASE_URL = 'http://localhost:3002';
const TEST_USER = {
  email: `e2e.test.${Date.now()}@example.com`,
  password: 'E2ETestPassword123!',
  username: `e2euser${Date.now()}`
};

// 全局变量
let authToken = null;
let userId = null;
let createdAnnotationId = null;
const testResults = [];

// 工具函数
function recordTest(name, success, details, duration) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString()
  };
  testResults.push(result);
  
  const status = success ? '[PASS]' : '[FAIL]';
  console.log(`${status} ${name}`);
  console.log(`   详情: ${details}`);
  console.log(`   耗时: ${duration}ms\n`);
}

async function makeRequest(url, options = {}) {
  try {
    const response = await axios({
      url,
      method: options.method || 'GET',
      data: options.body,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: 10000
    });
    return response;
  } catch (error) {
    if (error.response) {
      return error.response;
    }
    throw error;
  }
}

// 端到端测试函数
async function testUserRegistrationFlow() {
  console.log('=== E2E测试1: 用户注册流程 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/v1/users/register`, {
      method: 'POST',
      body: TEST_USER
    });
    
    const duration = Date.now() - startTime;
    const token = response.data.data?.tokens?.accessToken || response.data.tokens?.accessToken;
    const user = response.data.data?.user || response.data.user;
    
    if (response.status === 201 && token) {
      authToken = token;
      userId = user?.id || user?.user_id;
      recordTest('用户注册流程', true, `状态码: ${response.status}, Token获取成功, 用户ID: ${userId}`, duration);
      return true;
    } else {
      recordTest('用户注册流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserLoginFlow() {
  console.log('=== E2E测试2: 用户登录流程 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/v1/users/login`, {
      method: 'POST',
      body: {
        email: TEST_USER.email,
        password: TEST_USER.password
      }
    });
    
    const duration = Date.now() - startTime;
    const token = response.data.data?.tokens?.accessToken || response.data.tokens?.accessToken;
    
    if (response.status === 200 && token) {
      authToken = token; // 更新token
      recordTest('用户登录流程', true, `状态码: ${response.status}, 登录成功，Token更新`, duration);
      return true;
    } else {
      recordTest('用户登录流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户登录流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserProfileAccess() {
  console.log('=== E2E测试3: 用户资料访问 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('用户资料访问', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/v1/users/profile/me`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const userData = response.data.data || response.data;
      recordTest('用户资料访问', true, `状态码: ${response.status}, 用户资料获取成功`, duration);
      return true;
    } else {
      recordTest('用户资料访问', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户资料访问', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationCreationFlow() {
  console.log('=== E2E测试4: 标注创建流程 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('标注创建流程', false, '没有可用的认证Token', 0);
    return false;
  }
  
  const annotationData = {
    description: '这是一个端到端测试创建的标注',
    latitude: 39.9042,
    longitude: 116.4074,
    smellIntensity: 4
  };
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/v1/annotations`, {
      method: 'POST',
      body: annotationData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201 || response.status === 200) {
      const data = response.data;
      const annotation = data.data?.annotation || data.annotation;
      createdAnnotationId = annotation?.id;
      console.log('   响应数据结构:', JSON.stringify(data, null, 2));
      recordTest('标注创建流程', true, `状态码: ${response.status}, 标注创建成功, ID: ${createdAnnotationId}`, duration);
      return true;
    } else {
      recordTest('标注创建流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注创建流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationListingFlow() {
  console.log('=== E2E测试5: 标注列表查看流程 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/v1/annotations/list?limit=10`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('标注列表查看流程', true, `状态码: ${response.status}, 获取${count}条标注`, duration);
      return true;
    } else {
      recordTest('标注列表查看流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注列表查看流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testMapSearchFlow() {
  console.log('=== E2E测试6: 地图搜索流程 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('地图搜索流程', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 测试附近搜索
    const response = await makeRequest(`${API_BASE_URL}/api/v1/search/location?latitude=39.9042&longitude=116.4074&radius=1000`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const results = response.data.data || response.data;
      recordTest('地图搜索流程', true, `状态码: ${response.status}, 附近搜索成功`, duration);
      return true;
    } else {
      recordTest('地图搜索流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('地图搜索流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationFilterFlow() {
  console.log('=== E2E测试7: 标注筛选流程 ===\n');
  const startTime = Date.now();
  
  try {
    // 测试按气味类型筛选
    const response = await makeRequest(`${API_BASE_URL}/api/v1/annotations/list?smell_type=industrial&limit=5`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('标注筛选流程', true, `状态码: ${response.status}, 筛选到${count}条工业气味标注`, duration);
      return true;
    } else {
      recordTest('标注筛选流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注筛选流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationDetailFlow() {
  console.log('=== E2E测试8: 标注详情查看流程 ===\n');
  const startTime = Date.now();
  
  console.log('   调试信息: createdAnnotationId =', createdAnnotationId);
  console.log('   调试信息: createdAnnotationId类型 =', typeof createdAnnotationId);
  
  if (!createdAnnotationId) {
    recordTest('标注详情查看流程', false, '没有可用的标注ID', 0);
    return false;
  }
  
  try {
    console.log('   请求URL:', `${API_BASE_URL}/api/v1/annotations/${createdAnnotationId}`);
    const response = await makeRequest(`${API_BASE_URL}/api/v1/annotations/${createdAnnotationId}`);
    const duration = Date.now() - startTime;
    
    console.log('   响应状态码:', response.status);
    console.log('   响应数据:', JSON.stringify(response.data, null, 2));
    
    if (response.status === 200) {
      const annotation = response.data.data || response.data;
      recordTest('标注详情查看流程', true, `状态码: ${response.status}, 标注详情获取成功`, duration);
      return true;
    } else {
      recordTest('标注详情查看流程', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log('   捕获错误:', error.message);
    console.log('   错误详情:', error);
    recordTest('标注详情查看流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserPermissionFlow() {
  console.log('=== E2E测试9: 用户权限验证流程 ===\n');
  const startTime = Date.now();
  
  try {
    // 测试无Token访问受保护资源
    const response = await makeRequest(`${API_BASE_URL}/api/v1/users/profile/me`);
    const duration = Date.now() - startTime;
    
    if (response.status === 401 || response.status === 403) {
      recordTest('用户权限验证流程', true, `状态码: ${response.status}, 权限验证正常工作`, duration);
      return true;
    } else {
      recordTest('用户权限验证流程', false, `状态码: ${response.status}, 权限验证可能存在问题`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户权限验证流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testErrorHandlingFlow() {
  console.log('=== E2E测试10: 错误处理流程 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('错误处理流程', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 测试访问不存在的端点
    const response = await makeRequest(`${API_BASE_URL}/api/v1/nonexistent-endpoint`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    const duration = Date.now() - startTime;
    
    if (response.status === 404) {
      recordTest('错误处理流程', true, `状态码: ${response.status}, 404错误处理正常`, duration);
      return true;
    } else {
      recordTest('错误处理流程', false, `状态码: ${response.status}, 错误处理可能存在问题`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('错误处理流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n============================================================');
  console.log('🔄 端到端集成测试报告');
  console.log('============================================================');
  
  const passedTests = testResults.filter(test => test.success).length;
  const totalTests = testResults.length;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;
  
  console.log(`✅ 通过: ${passedTests}`);
  console.log(`❌ 失败: ${totalTests - passedTests}`);
  console.log(`📈 成功率: ${successRate}%\n`);
  
  console.log('📋 详细测试结果:');
  testResults.forEach((test, index) => {
    const status = test.success ? '[PASS]' : '[FAIL]';
    console.log(`${index + 1}. ${status} ${test.name} (${test.duration})`);
    if (!test.success) {
      console.log(`   ❌ ${test.details}`);
    }
  });
  
  console.log('\n🔍 测试覆盖范围:');
  console.log('✓ 用户注册和登录流程');
  console.log('✓ 用户资料管理');
  console.log('✓ 标注创建和管理');
  console.log('✓ 地图搜索功能');
  console.log('✓ 数据筛选和查询');
  console.log('✓ 权限验证机制');
  console.log('✓ 错误处理机制');
  
  console.log('\n✨ 端到端集成测试完成!');
  
  // 保存测试报告到文件
  const fs = require('fs');
  const reportData = {
    timestamp: new Date().toISOString(),
    testType: 'End-to-End Integration Test',
    summary: {
      total: totalTests,
      passed: passedTests,
      failed: totalTests - passedTests,
      successRate: `${successRate}%`
    },
    testUser: {
      email: TEST_USER.email,
      userId: userId,
      createdAnnotationId: createdAnnotationId
    },
    tests: testResults
  };
  
  fs.writeFileSync('end-to-end-test-report.json', JSON.stringify(reportData, null, 2));
  console.log('📄 测试报告已保存到: end-to-end-test-report.json');
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin端到端集成测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}\n`);
  
  try {
    // 执行完整的端到端测试流程
    await testUserRegistrationFlow();
    await testUserLoginFlow();
    await testUserProfileAccess();
    await testAnnotationCreationFlow();
    await testAnnotationListingFlow();
    await testMapSearchFlow();
    await testAnnotationFilterFlow();
    await testAnnotationDetailFlow();
    await testUserPermissionFlow();
    await testErrorHandlingFlow();
    
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

module.exports = {
  runTests,
  testResults
};