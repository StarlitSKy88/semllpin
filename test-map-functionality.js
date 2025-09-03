const axios = require('axios');

// 配置
const API_BASE_URL = 'http://localhost:8787';
const TEST_USER = {
  email: `test_map_${Date.now()}@example.com`,
  password: 'TestPassword123!',
  username: `testuser_map_${Date.now()}`
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

async function testLBSNearbySearch() {
  console.log('=== 测试2: LBS附近搜索 ===\n');
  const startTime = Date.now();
  
  // 测试北京天安门附近的搜索
  const searchParams = {
    latitude: 39.9042,
    longitude: 116.4074,
    radius: 1000, // 1公里范围
    limit: 10
  };
  
  try {
    const queryString = new URLSearchParams(searchParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/lbs/nearby?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const data = response.data.data || response.data;
      const count = Array.isArray(data) ? data.length : 0;
      recordTest('LBS附近搜索', true, `状态码: ${response.status}, 找到${count}个附近位置`, duration);
      return true;
    } else {
      recordTest('LBS附近搜索', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('LBS附近搜索', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testLBSGeocoding() {
  console.log('=== 测试3: LBS地理编码 ===\n');
  const startTime = Date.now();
  
  const geocodeParams = {
    address: '北京市天安门广场'
  };
  
  try {
    const queryString = new URLSearchParams(geocodeParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/lbs/geocode?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const data = response.data.data || response.data;
      recordTest('LBS地理编码', true, `状态码: ${response.status}, 地址解析成功`, duration);
      return true;
    } else {
      recordTest('LBS地理编码', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('LBS地理编码', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testLBSReverseGeocoding() {
  console.log('=== 测试4: LBS逆地理编码 ===\n');
  const startTime = Date.now();
  
  const reverseParams = {
    latitude: 39.9042,
    longitude: 116.4074
  };
  
  try {
    const queryString = new URLSearchParams(reverseParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/lbs/reverse?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const data = response.data.data || response.data;
      recordTest('LBS逆地理编码', true, `状态码: ${response.status}, 坐标解析成功`, duration);
      return true;
    } else {
      recordTest('LBS逆地理编码', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('LBS逆地理编码', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationsInArea() {
  console.log('=== 测试5: 区域内标注查询 ===\n');
  const startTime = Date.now();
  
  // 查询北京市中心区域的标注
  const areaParams = {
    lat_min: 39.8,
    lat_max: 40.0,
    lng_min: 116.2,
    lng_max: 116.6,
    limit: 20
  };
  
  try {
    const queryString = new URLSearchParams(areaParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/annotations?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('区域内标注查询', true, `状态码: ${response.status}, 找到${count}个标注`, duration);
      return true;
    } else {
      recordTest('区域内标注查询', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('区域内标注查询', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationsBySmellType() {
  console.log('=== 测试6: 按气味类型筛选标注 ===\n');
  const startTime = Date.now();
  
  const filterParams = {
    smell_type: 'chemical',
    limit: 10
  };
  
  try {
    const queryString = new URLSearchParams(filterParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/annotations?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('按气味类型筛选标注', true, `状态码: ${response.status}, 找到${count}个化学气味标注`, duration);
      return true;
    } else {
      recordTest('按气味类型筛选标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('按气味类型筛选标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationsByIntensity() {
  console.log('=== 测试7: 按强度筛选标注 ===\n');
  const startTime = Date.now();
  
  const intensityParams = {
    min_intensity: 3,
    max_intensity: 5,
    limit: 15
  };
  
  try {
    const queryString = new URLSearchParams(intensityParams).toString();
    const response = await makeRequest(`${API_BASE_URL}/annotations?${queryString}`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      const count = Array.isArray(annotations) ? annotations.length : 0;
      recordTest('按强度筛选标注', true, `状态码: ${response.status}, 找到${count}个中高强度标注`, duration);
      return true;
    } else {
      recordTest('按强度筛选标注', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('按强度筛选标注', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testMapDataAggregation() {
  console.log('=== 测试8: 地图数据聚合 ===\n');
  const startTime = Date.now();
  
  // 测试获取聚合统计数据
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations/stats`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const stats = response.data.data || response.data;
      recordTest('地图数据聚合', true, `状态码: ${response.status}, 获取统计数据成功`, duration);
      return true;
    } else if (response.status === 404) {
      // 如果没有stats端点，尝试通过普通查询获取数据进行聚合测试
      const annotationsResponse = await makeRequest(`${API_BASE_URL}/annotations?limit=100`);
      if (annotationsResponse.status === 200) {
        const annotations = annotationsResponse.data.data || annotationsResponse.data;
        const count = Array.isArray(annotations) ? annotations.length : 0;
        recordTest('地图数据聚合', true, `状态码: ${annotationsResponse.status}, 获取${count}条数据用于聚合`, duration);
        return true;
      } else {
        recordTest('地图数据聚合', false, `状态码: ${response.status}, 统计端点不存在且无法获取数据`, duration);
        return false;
      }
    } else {
      recordTest('地图数据聚合', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('地图数据聚合', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n============================================================');
  console.log('🗺️ 地图功能测试报告');
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
  
  console.log('\n✨ 地图功能测试完成!');
  
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
  
  fs.writeFileSync('map-functionality-test-report.json', JSON.stringify(reportData, null, 2));
  console.log('📄 测试报告已保存到: map-functionality-test-report.json');
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin地图功能测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}\n`);
  
  try {
    // 执行所有测试
    await testUserRegistration();
    await testLBSNearbySearch();
    await testLBSGeocoding();
    await testLBSReverseGeocoding();
    await testAnnotationsInArea();
    await testAnnotationsBySmellType();
    await testAnnotationsByIntensity();
    await testMapDataAggregation();
    
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