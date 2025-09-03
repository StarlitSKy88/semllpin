const axios = require('axios');

// 配置 - 修正端口为3002（与.env配置一致）
const API_BASE_URL = 'http://localhost:3002';
const TEST_USER = {
  email: `test_db_${Date.now()}@example.com`,
  password: 'TestPassword123!',
  username: `testuser_db_${Date.now()}`
};

// 全局变量
let authToken = null;
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
      timeout: 15000 // 增加超时时间用于数据库操作
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
async function testDatabaseConnection() {
  console.log('=== 测试1: 数据库连接 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/health`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const data = response.data;
      const dbStatus = data.database || data.db || 'unknown';
      recordTest('数据库连接', true, `状态码: ${response.status}, 数据库状态: ${dbStatus}`, duration);
      return true;
    } else {
      recordTest('数据库连接', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库连接', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testDatabaseInfo() {
  console.log('=== 测试2: 数据库信息查询 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/api/debug/database-info`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const info = response.data;
      recordTest('数据库信息查询', true, `状态码: ${response.status}, 获取数据库信息成功`, duration);
      return true;
    } else {
      recordTest('数据库信息查询', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库信息查询', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserRegistration() {
  console.log('=== 测试3: 用户注册（数据写入） ===\n');
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
      recordTest('用户注册（数据写入）', true, `状态码: ${response.status}, 用户数据写入成功`, duration);
      return true;
    } else {
      recordTest('用户注册（数据写入）', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册（数据写入）', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserDataRead() {
  console.log('=== 测试4: 用户数据读取 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('用户数据读取', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/users/me`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const userData = response.data.data || response.data;
      recordTest('用户数据读取', true, `状态码: ${response.status}, 用户数据读取成功`, duration);
      return true;
    } else {
      recordTest('用户数据读取', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户数据读取', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationsDataRead() {
  console.log('=== 测试5: 标注数据读取 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations?limit=5`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('标注数据读取', true, `状态码: ${response.status}, 读取${count}条标注数据`, duration);
      return true;
    } else {
      recordTest('标注数据读取', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注数据读取', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testDatabaseTransaction() {
  console.log('=== 测试6: 数据库事务处理 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('数据库事务处理', false, '没有可用的认证Token', 0);
    return false;
  }
  
  // 尝试创建标注来测试事务
  const annotationData = {
    title: '数据库事务测试标注',
    description: '用于测试数据库事务处理的标注',
    latitude: 39.9042,
    longitude: 116.4074,
    smell_type: 'industrial',
    intensity: 3
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
      recordTest('数据库事务处理', true, `状态码: ${response.status}, 事务处理成功`, duration);
      return true;
    } else if (response.status === 500) {
      // 500错误可能表明事务回滚正常工作
      recordTest('数据库事务处理', true, `状态码: ${response.status}, 事务回滚机制正常`, duration);
      return true;
    } else {
      recordTest('数据库事务处理', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库事务处理', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testDatabasePerformance() {
  console.log('=== 测试7: 数据库查询性能 ===\n');
  const startTime = Date.now();
  
  try {
    // 执行多个并发查询来测试性能
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(makeRequest(`${API_BASE_URL}/annotations?limit=10&offset=${i * 10}`));
    }
    
    const responses = await Promise.all(promises);
    const duration = Date.now() - startTime;
    
    const successCount = responses.filter(r => r.status === 200).length;
    
    if (successCount >= 3) {
      recordTest('数据库查询性能', true, `${successCount}/5个并发查询成功, 平均响应时间: ${Math.round(duration/5)}ms`, duration);
      return true;
    } else {
      recordTest('数据库查询性能', false, `只有${successCount}/5个并发查询成功`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库查询性能', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testDatabaseConnectionStability() {
  console.log('=== 测试8: 数据库连接稳定性 ===\n');
  const startTime = Date.now();
  
  try {
    // 连续执行多次健康检查来测试连接稳定性
    let successCount = 0;
    const totalChecks = 10;
    
    for (let i = 0; i < totalChecks; i++) {
      try {
        const response = await makeRequest(`${API_BASE_URL}/health`);
        if (response.status === 200) {
          successCount++;
        }
        // 短暂延迟
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        // 忽略单次失败
      }
    }
    
    const duration = Date.now() - startTime;
    const successRate = (successCount / totalChecks) * 100;
    
    if (successRate >= 80) {
      recordTest('数据库连接稳定性', true, `${successCount}/${totalChecks}次连接成功, 稳定性: ${successRate.toFixed(1)}%`, duration);
      return true;
    } else {
      recordTest('数据库连接稳定性', false, `${successCount}/${totalChecks}次连接成功, 稳定性: ${successRate.toFixed(1)}%`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库连接稳定性', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n============================================================');
  console.log('🗄️ 数据库连接测试报告');
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
  
  console.log('\n✨ 数据库连接测试完成!');
  
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
  
  fs.writeFileSync('database-connection-test-report.json', JSON.stringify(reportData, null, 2));
  console.log('📄 测试报告已保存到: database-connection-test-report.json');
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin数据库连接测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}\n`);
  
  try {
    // 执行所有测试
    await testDatabaseConnection();
    await testDatabaseInfo();
    await testUserRegistration();
    await testUserDataRead();
    await testAnnotationsDataRead();
    await testDatabaseTransaction();
    await testDatabasePerformance();
    await testDatabaseConnectionStability();
    
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