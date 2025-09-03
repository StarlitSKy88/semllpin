const BASE_URL = 'http://localhost:8787';

// Test data
const testUser = {
  username: 'lbs_test_user',
  email: 'lbs_test@example.com',
  password: 'testpassword123',
  full_name: 'LBS Test User'
};

const testLocations = [
  {
    latitude: 40.7128,
    longitude: -74.0060,
    location_name: 'New York City',
    accuracy: 5
  },
  {
    latitude: 34.0522,
    longitude: -118.2437,
    location_name: 'Los Angeles',
    accuracy: 8
  },
  {
    latitude: 41.8781,
    longitude: -87.6298,
    location_name: 'Chicago',
    accuracy: 3
  }
];

let authToken = null;
let testResults = [];

// Helper function to make API requests
async function makeRequest(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const defaultHeaders = {
    'Content-Type': 'application/json',
    ...(authToken && { 'Authorization': `Bearer ${authToken}` })
  };
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers
    }
  });
  
  const data = await response.json();
  return { response, data };
}

// Test function wrapper
async function runTest(testName, testFunction) {
  const startTime = Date.now();
  try {
    console.log(`\n=== LBS测试${testResults.length + 1}: ${testName} ===\n`);
    const result = await testFunction();
    const duration = Date.now() - startTime;
    
    testResults.push({
      name: testName,
      status: 'PASS',
      duration,
      details: result
    });
    
    console.log(`[PASS] ${testName}`);
    console.log(`   详情: ${result}`);
    console.log(`   耗时: ${duration}ms`);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    testResults.push({
      name: testName,
      status: 'FAIL',
      duration,
      error: error.message
    });
    
    console.log(`[FAIL] ${testName}`);
    console.log(`   错误: ${error.message}`);
    console.log(`   耗时: ${duration}ms`);
  }
}

// Test 1: User registration
async function testUserRegistration() {
  const { response, data } = await makeRequest('/auth/register', {
    method: 'POST',
    body: JSON.stringify(testUser)
  });
  
  if (response.status !== 201) {
    throw new Error(`注册失败: ${data.message || '未知错误'}`);
  }
  
  if (!data.token) {
    throw new Error('注册成功但未返回token');
  }
  
  authToken = data.token;
  return `状态码: ${response.status}, Token获取成功`;
}

// Test 2: Initialize LBS tables
async function testInitializeLbsTables() {
  const { response, data } = await makeRequest('/lbs/init', {
    method: 'POST'
  });
  
  if (response.status !== 200) {
    throw new Error(`LBS表初始化失败: ${data.message || '未知错误'}`);
  }
  
  return `状态码: ${response.status}, LBS表初始化成功`;
}

// Test 3: Check-in at location
async function testCheckIn() {
  const location = testLocations[0];
  const { response, data } = await makeRequest('/lbs/checkin', {
    method: 'POST',
    body: JSON.stringify(location)
  });
  
  if (response.status !== 201) {
    throw new Error(`签到失败: ${data.message || '未知错误'}`);
  }
  
  if (!data.data || !data.data.reward_earned) {
    throw new Error('签到成功但未返回奖励信息');
  }
  
  return `状态码: ${response.status}, 奖励: ${data.data.reward_earned} credits, 位置: ${location.location_name}`;
}

// Test 4: Multiple check-ins
async function testMultipleCheckIns() {
  let totalRewards = 0;
  
  for (let i = 1; i < testLocations.length; i++) {
    const location = testLocations[i];
    const { response, data } = await makeRequest('/lbs/checkin', {
      method: 'POST',
      body: JSON.stringify(location)
    });
    
    if (response.status === 201 && data.data && data.data.reward_earned) {
      totalRewards += data.data.reward_earned;
    }
    
    // Wait a bit between check-ins
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  return `成功签到 ${testLocations.length - 1} 个额外位置, 总奖励: ${totalRewards} credits`;
}

// Test 5: Get nearby rewards
async function testGetNearbyRewards() {
  const { latitude, longitude } = testLocations[0];
  const { response, data } = await makeRequest(`/lbs/nearby?latitude=${latitude}&longitude=${longitude}&radius=10`);
  
  if (response.status !== 200) {
    throw new Error(`获取附近奖励失败: ${data.message || '未知错误'}`);
  }
  
  if (!Array.isArray(data.data)) {
    throw new Error('返回数据格式错误');
  }
  
  return `状态码: ${response.status}, 找到 ${data.data.length} 个附近奖励`;
}

// Test 6: Get check-in history
async function testGetCheckInHistory() {
  const { response, data } = await makeRequest('/lbs/history');
  
  if (response.status !== 200) {
    throw new Error(`获取签到历史失败: ${data.message || '未知错误'}`);
  }
  
  if (!Array.isArray(data.data)) {
    throw new Error('返回数据格式错误');
  }
  
  const stats = data.statistics;
  return `状态码: ${response.status}, 签到记录: ${data.data.length}, 总奖励: ${stats.total_rewards_earned}`;
}

// Test 7: Get area leaderboard
async function testGetAreaLeaderboard() {
  const { latitude, longitude } = testLocations[0];
  const { response, data } = await makeRequest(`/lbs/leaderboard?latitude=${latitude}&longitude=${longitude}&radius=10&timeframe=week`);
  
  if (response.status !== 200) {
    throw new Error(`获取排行榜失败: ${data.message || '未知错误'}`);
  }
  
  if (!Array.isArray(data.data)) {
    throw new Error('返回数据格式错误');
  }
  
  return `状态码: ${response.status}, 排行榜参与者: ${data.data.length}`;
}

// Test 8: Duplicate check-in prevention
async function testDuplicateCheckInPrevention() {
  const location = testLocations[0]; // Same location as first check-in
  const { response, data } = await makeRequest('/lbs/checkin', {
    method: 'POST',
    body: JSON.stringify(location)
  });
  
  if (response.status !== 400) {
    throw new Error(`重复签到应该被阻止，但状态码是: ${response.status}`);
  }
  
  if (!data.error || !data.error.includes('Too close')) {
    throw new Error('错误信息不正确');
  }
  
  return `状态码: ${response.status}, 重复签到被正确阻止`;
}

// Main test runner
async function runLbsTests() {
  console.log('🚀 开始LBS系统测试...\n');
  
  await runTest('用户注册', testUserRegistration);
  await runTest('LBS表初始化', testInitializeLbsTables);
  await runTest('位置签到', testCheckIn);
  await runTest('多位置签到', testMultipleCheckIns);
  await runTest('获取附近奖励', testGetNearbyRewards);
  await runTest('获取签到历史', testGetCheckInHistory);
  await runTest('获取区域排行榜', testGetAreaLeaderboard);
  await runTest('重复签到防护', testDuplicateCheckInPrevention);
  
  // Print summary
  console.log('\n==================================================');
  console.log('📊 LBS系统测试总结');
  console.log('==================================================');
  
  const totalTests = testResults.length;
  const passedTests = testResults.filter(t => t.status === 'PASS').length;
  const failedTests = totalTests - passedTests;
  const successRate = ((passedTests / totalTests) * 100).toFixed(1);
  
  console.log(`总测试数: ${totalTests}`);
  console.log(`通过测试: ${passedTests}`);
  console.log(`失败测试: ${failedTests}`);
  console.log(`成功率: ${successRate}%`);
  
  if (failedTests === 0) {
    console.log('\n✅ 所有LBS系统测试通过！');
  } else {
    console.log('\n❌ 部分LBS系统测试失败，请检查错误信息。');
  }
  
  console.log('\n📋 详细测试结果:');
  testResults.forEach((result, index) => {
    const icon = result.status === 'PASS' ? '✅' : '❌';
    console.log(`${index + 1}. ${icon} ${result.name} (${result.duration}ms)`);
    if (result.status === 'FAIL') {
      console.log(`   错误: ${result.error}`);
    }
  });
}

// Run the tests
runLbsTests().catch(console.error);