const BASE_URL = 'http://localhost:8787';

// Test data
const testUser = {
  email: 'lbs-test@example.com',
  password: 'testpassword123',
  username: 'lbstester'
};

const testLocations = [
  {
    latitude: 39.9042,
    longitude: 116.4074,
    location_name: '北京天安门',
    accuracy: 10.5
  },
  {
    latitude: 31.2304,
    longitude: 121.4737,
    location_name: '上海外滩',
    accuracy: 8.2
  },
  {
    latitude: 22.3193,
    longitude: 114.1694,
    location_name: '香港维多利亚港',
    accuracy: 12.1
  }
];

let authToken = null;
let userId = null;

// Helper function to make HTTP requests
async function makeRequest(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
      ...(authToken && { 'Authorization': `Bearer ${authToken}` })
    }
  };
  
  const response = await fetch(url, { ...defaultOptions, ...options });
  const data = await response.text();
  
  try {
    return {
      status: response.status,
      data: JSON.parse(data),
      ok: response.ok
    };
  } catch (e) {
    return {
      status: response.status,
      data: data,
      ok: response.ok
    };
  }
}

// Test functions
async function testUserRegistration() {
  console.log('\n🔐 Testing user registration...');
  
  // First try to login with existing user
  const loginResponse = await makeRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: testUser.email,
      password: testUser.password
    })
  });
  
  if (loginResponse.ok && loginResponse.data.success && loginResponse.data.data?.token) {
    authToken = loginResponse.data.data.token;
    userId = loginResponse.data.data.user?.id;
    console.log('✅ User login successful (existing user)');
    console.log(`   User ID: ${userId}`);
    return true;
  }
  
  // If login fails, try registration
  const response = await makeRequest('/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      username: testUser.username,
      email: testUser.email,
      password: testUser.password,
      full_name: 'LBS Test User'
    })
  });
  
  if (response.ok && response.data.success && response.data.data?.token) {
    authToken = response.data.data.token;
    userId = response.data.data.user?.id;
    console.log('✅ User registration successful');
    console.log(`   User ID: ${userId}`);
    return true;
  } else {
    console.log('❌ User registration failed:', response.data);
    return false;
  }
}

async function testLbsTablesInitialization() {
  console.log('\n🗄️ Testing LBS tables initialization...');
  
  const response = await makeRequest('/lbs/init-tables', {
    method: 'POST'
  });
  
  if (response.ok) {
    console.log('✅ LBS tables initialized successfully');
    return true;
  } else {
    console.log('❌ LBS tables initialization failed:', response.data);
    return false;
  }
}

async function testLocationCheckIn(location, index) {
  console.log(`\n📍 Testing location check-in ${index + 1}...`);
  
  const response = await makeRequest('/lbs/checkin', {
    method: 'POST',
    body: JSON.stringify(location)
  });
  
  if (response.ok) {
    console.log(`✅ Check-in successful at ${location.location_name}`);
    console.log(`   Reward: ${response.data.reward_amount} points`);
    console.log(`   Reward type: ${response.data.reward_type}`);
    return true;
  } else {
    console.log(`❌ Check-in failed at ${location.location_name}:`, response.data);
    return false;
  }
}

async function testGetNearbyRewards() {
  console.log('\n🌍 Testing get nearby rewards...');
  
  const location = testLocations[0];
  const response = await makeRequest(
    `/lbs/nearby?latitude=${location.latitude}&longitude=${location.longitude}&radius=1000`
  );
  
  if (response.ok) {
    console.log('✅ Get nearby rewards successful');
    console.log(`   Found ${response.data.rewards?.length || 0} nearby rewards`);
    if (response.data.rewards?.length > 0) {
      console.log(`   First reward: ${response.data.rewards[0].reward_amount} points`);
    }
    return true;
  } else {
    console.log('❌ Get nearby rewards failed:', response.data);
    return false;
  }
}

async function testGetCheckInHistory() {
  console.log('\n📜 Testing get check-in history...');
  
  const response = await makeRequest('/lbs/history?page=1&limit=10');
  
  if (response.ok) {
    console.log('✅ Get check-in history successful');
    console.log(`   Total check-ins: ${response.data.total || 0}`);
    console.log(`   Total rewards: ${response.data.total_rewards || 0} points`);
    console.log(`   Average reward: ${response.data.average_reward || 0} points`);
    return true;
  } else {
    console.log('❌ Get check-in history failed:', response.data);
    return false;
  }
}

async function testGetAreaLeaderboard() {
  console.log('\n🏆 Testing get area leaderboard...');
  
  const location = testLocations[0];
  const response = await makeRequest(
    `/lbs/leaderboard?latitude=${location.latitude}&longitude=${location.longitude}&radius=1000&days=7`
  );
  
  if (response.ok) {
    console.log('✅ Get area leaderboard successful');
    console.log(`   Found ${response.data.leaderboard?.length || 0} users in leaderboard`);
    if (response.data.leaderboard?.length > 0) {
      console.log(`   Top user: ${response.data.leaderboard[0].username} with ${response.data.leaderboard[0].total_rewards} points`);
    }
    return true;
  } else {
    console.log('❌ Get area leaderboard failed:', response.data);
    return false;
  }
}

async function testDuplicateCheckInPrevention() {
  console.log('\n🚫 Testing duplicate check-in prevention...');
  
  // Try to check in at the same location again
  const location = testLocations[0];
  const response = await makeRequest('/lbs/checkin', {
    method: 'POST',
    body: JSON.stringify(location)
  });
  
  if (!response.ok && response.data.error) {
    console.log('✅ Duplicate check-in prevention working');
    console.log(`   Error message: ${response.data.error}`);
    return true;
  } else {
    console.log('❌ Duplicate check-in prevention failed - should have been blocked');
    return false;
  }
}

// Main test runner
async function runLbsTests() {
  console.log('🧪 Starting LBS System Tests');
  console.log('=' .repeat(50));
  
  const tests = [
    { name: 'User Registration', fn: testUserRegistration },
    { name: 'LBS Tables Initialization', fn: testLbsTablesInitialization },
    { name: 'Location Check-in 1', fn: () => testLocationCheckIn(testLocations[0], 0) },
    { name: 'Location Check-in 2', fn: () => testLocationCheckIn(testLocations[1], 1) },
    { name: 'Location Check-in 3', fn: () => testLocationCheckIn(testLocations[2], 2) },
    { name: 'Get Nearby Rewards', fn: testGetNearbyRewards },
    { name: 'Get Check-in History', fn: testGetCheckInHistory },
    { name: 'Get Area Leaderboard', fn: testGetAreaLeaderboard },
    { name: 'Duplicate Check-in Prevention', fn: testDuplicateCheckInPrevention }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    try {
      const result = await test.fn();
      if (result) {
        passed++;
      } else {
        failed++;
      }
    } catch (error) {
      console.log(`❌ ${test.name} failed with error:`, error.message);
      failed++;
    }
    
    // Add delay between tests
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  console.log('\n' + '=' .repeat(50));
  console.log('🧪 LBS System Test Results');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📊 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  
  if (failed === 0) {
    console.log('🎉 All LBS tests passed!');
  } else {
    console.log('⚠️  Some LBS tests failed. Please check the logs above.');
  }
}

// Run the tests
runLbsTests().catch(console.error);