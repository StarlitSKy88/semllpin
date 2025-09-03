const axios = require('axios');

// 配置
const API_BASE_URL = 'http://localhost:8787';
const TEST_USER = {
  email: `test_annotation_${Date.now()}@example.com`,
  password: 'TestPassword123!',
  username: `testuser_annotation_${Date.now()}`
};

// 全局变量
let authToken = null;
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

// 测试函数
async function testUserRegistration() {
  console.log('=== 测试1: 用户注册 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USER
    });
    
    const duration = Date.now() - startTime;
    const token = response.data.data?.token || response.data.token;
    
    if (response.status === 201 && token) {
      authToken = token;
      recordTest('用户注册', true, `状态码: ${response.status}, 注册成功`, duration);
      return true;
    } else {
      recordTest('用户注册', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testCreateAnnotation() {
  console.log('=== 测试2: 创建标注 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('创建标注', false, '没有可用的认证Token', 0);
    return false;
  }
  
  const annotationData = {
    title: '测试标注 - CRUD测试',
    description: '这是一个用于CRUD测试的标注',
    latitude: 39.9042,
    longitude: 116.4074,
    smell_type: 'chemical',
    intensity: 4,
    tags: ['测试', 'CRUD']
  };
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      body: annotationData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201 || response.status === 200) {
      createdAnnotationId = response.data.data?.id || response.data.id;
      recordTest('创建标注', true, `状态码: ${response.status}, 标注ID: ${createdAnnotationId}`, duration);
      return true;
    } else {
      recordTest('创建标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('创建标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testReadAnnotation() {
  console.log('=== 测试3: 读取标注 ===\n');
  const startTime = Date.now();
  
  if (!createdAnnotationId) {
    recordTest('读取标注', false, '没有可用的标注ID', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations/${createdAnnotationId}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotation = response.data.data || response.data;
      recordTest('读取标注', true, `状态码: ${response.status}, 标注标题: ${annotation.title}`, duration);
      return true;
    } else {
      recordTest('读取标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('读取标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUpdateAnnotation() {
  console.log('=== 测试4: 更新标注 ===\n');
  const startTime = Date.now();
  
  if (!createdAnnotationId || !authToken) {
    recordTest('更新标注', false, '没有可用的标注ID或认证Token', 0);
    return false;
  }
  
  const updateData = {
    title: '更新后的测试标注',
    description: '这是一个已更新的测试标注',
    intensity: 5
  };
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations/${createdAnnotationId}`, {
      method: 'PUT',
      body: updateData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      recordTest('更新标注', true, `状态码: ${response.status}, 更新成功`, duration);
      return true;
    } else {
      recordTest('更新标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('更新标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testListAnnotations() {
  console.log('=== 测试5: 获取标注列表 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('获取标注列表', true, `状态码: ${response.status}, 标注数量: ${count}`, duration);
      return true;
    } else {
      recordTest('获取标注列表', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('获取标注列表', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testDeleteAnnotation() {
  console.log('=== 测试6: 删除标注 ===\n');
  const startTime = Date.now();
  
  if (!createdAnnotationId || !authToken) {
    recordTest('删除标注', false, '没有可用的标注ID或认证Token', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations/${createdAnnotationId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 204) {
      recordTest('删除标注', true, `状态码: ${response.status}, 删除成功`, duration);
      return true;
    } else {
      recordTest('删除标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('删除标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testVerifyDeletion() {
  console.log('=== 测试7: 验证删除结果 ===\n');
  const startTime = Date.now();
  
  if (!createdAnnotationId) {
    recordTest('验证删除结果', false, '没有可用的标注ID', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations/${createdAnnotationId}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 404) {
      recordTest('验证删除结果', true, `状态码: ${response.status}, 标注已成功删除`, duration);
      return true;
    } else if (response.status === 200) {
      recordTest('验证删除结果', false, `状态码: ${response.status}, 标注仍然存在`, duration);
      return false;
    } else {
      recordTest('验证删除结果', false, `状态码: ${response.status}, 未知错误`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('验证删除结果', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n============================================================');
  console.log('📊 标注CRUD操作测试报告');
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
  
  console.log('\n✨ 标注CRUD操作测试完成!');
  
  // 保存测试报告到文件
  const fs = require('fs');
  const reportData = {
    timestamp: new Date().toISOString(),
    summary: {
      total: totalTests,
      passed: passedTests,
      failed: totalTests - passedTests,
      successRate: `${successRate}%`
    },
    tests: testResults
  };
  
  fs.writeFileSync('annotation-crud-test-report.json', JSON.stringify(reportData, null, 2));
  console.log('📄 测试报告已保存到: annotation-crud-test-report.json');
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin标注CRUD操作测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}\n`);
  
  try {
    // 执行所有测试
    await testUserRegistration();
    await testCreateAnnotation();
    await testReadAnnotation();
    await testUpdateAnnotation();
    await testListAnnotations();
    await testDeleteAnnotation();
    await testVerifyDeletion();
    
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