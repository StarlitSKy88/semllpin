const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Configuration
const BASE_URL = 'http://localhost:8787';
const TEST_EMAIL = `api-test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'testpassword123';
const TEST_USERNAME = `api-tester-${Date.now()}`;

// Test results storage
const results = [];
let token = null;
let userId = null;

// Helper function to make HTTP requests
async function makeRequest(url, options = {}) {
  return new Promise((resolve) => {
    try {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === 'https:';
      const client = isHttps ? https : http;
      
      const requestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: options.method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        }
      };
      
      const req = client.request(requestOptions, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const jsonData = data ? JSON.parse(data) : {};
            resolve({
              response: { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode },
              data: jsonData,
              error: null
            });
          } catch (parseError) {
            resolve({
              response: { ok: false, status: res.statusCode },
              data: { raw: data },
              error: null
            });
          }
        });
      });
      
      req.on('error', (error) => {
        resolve({ response: null, data: null, error: error.message });
      });
      
      if (options.body) {
        req.write(options.body);
      }
      
      req.end();
    } catch (error) {
      resolve({ response: null, data: null, error: error.message });
    }
  });
}

// Helper function to log test results
function logTest(testName, passed, details = '') {
  const status = passed ? '✅' : '❌';
  console.log(`${status} ${testName}`);
  if (details) {
    console.log(`   ${details}`);
  }
  results.push({ test: testName, status: passed ? 'passed' : 'failed', details });
}

// Test authentication endpoints
async function testAuthEndpoints() {
  console.log('\n🔐 Testing Authentication Endpoints...');
  
  // Test user registration
  const { response: regResponse, data: regData, error: regError } = await makeRequest(`${BASE_URL}/auth/register`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      username: TEST_USERNAME
    })
  });
  
  if (regError) {
    logTest('POST /auth/register', false, `Error: ${regError}`);
  } else if (regResponse.ok && regData.success) {
    logTest('POST /auth/register', true, 'User registered successfully');
    userId = regData.data?.user?.id;
  } else {
    logTest('POST /auth/register', false, `Status: ${regResponse.status}`);
  }
  
  // Test user login
  const { response: loginResponse, data: loginData, error: loginError } = await makeRequest(`${BASE_URL}/auth/login`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    })
  });
  
  if (loginError) {
    logTest('POST /auth/login', false, `Error: ${loginError}`);
  } else if (loginResponse.ok && loginData.success && loginData.data?.token) {
    logTest('POST /auth/login', true, 'Login successful, token received');
    token = loginData.data.token;
    userId = loginData.data.user?.id || userId;
  } else {
    logTest('POST /auth/login', false, `Status: ${loginResponse.status}`);
  }
}

// Test user endpoints
async function testUserEndpoints() {
  console.log('\n👤 Testing User Endpoints...');
  
  if (!token) {
    logTest('User endpoints', false, 'No authentication token available');
    return;
  }
  
  // Test get user profile
  const { response: profileResponse, data: profileData, error: profileError } = await makeRequest(`${BASE_URL}/users/profile`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (profileError) {
    logTest('GET /users/profile', false, `Error: ${profileError}`);
  } else if (profileResponse.ok) {
    logTest('GET /users/profile', true, `Profile retrieved`);
  } else {
    logTest('GET /users/profile', false, `Status: ${profileResponse.status}`);
  }
  
  // Test get all users
  const { response: usersResponse, data: usersData, error: usersError } = await makeRequest(`${BASE_URL}/users`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (usersError) {
    logTest('GET /users', false, `Error: ${usersError}`);
  } else if (usersResponse.ok) {
    logTest('GET /users', true, `Users list retrieved`);
  } else {
    logTest('GET /users', false, `Status: ${usersResponse.status}`);
  }
}

// Test payment endpoints
async function testPaymentEndpoints() {
  console.log('\n💳 Testing Payment Endpoints...');
  
  if (!token) {
    logTest('Payment endpoints', false, 'No authentication token available');
    return;
  }
  
  // Test payment history
  const { response: historyResponse, data: historyData, error: historyError } = await makeRequest(`${BASE_URL}/payments/history`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (historyError) {
    logTest('GET /payments/history', false, `Error: ${historyError}`);
  } else if (historyResponse.ok) {
    logTest('GET /payments/history', true, 'Payment history retrieved');
  } else {
    logTest('GET /payments/history', false, `Status: ${historyResponse.status}`);
  }
  
  // Test wallet info
  const { response: walletResponse, data: walletData, error: walletError } = await makeRequest(`${BASE_URL}/payments/wallet`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (walletError) {
    logTest('GET /payments/wallet', false, `Error: ${walletError}`);
  } else if (walletResponse.ok) {
    logTest('GET /payments/wallet', true, 'Wallet info retrieved');
  } else {
    logTest('GET /payments/wallet', false, `Status: ${walletResponse.status}`);
  }
  
  // Test create payment
  const { response: createResponse, data: createData, error: createError } = await makeRequest(`${BASE_URL}/payments/create`, {
    method: 'POST',
    body: JSON.stringify({
      amount: 500,
      currency: 'usd',
      description: 'API test payment'
    }),
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (createError) {
    logTest('POST /payments/create', false, `Error: ${createError}`);
  } else if (createResponse.ok) {
    logTest('POST /payments/create', true, 'Payment intent created');
  } else {
    logTest('POST /payments/create', false, `Status: ${createResponse.status}`);
  }
}

// Test LBS endpoints
async function testLBSEndpoints() {
  console.log('\n📍 Testing LBS Endpoints...');
  
  if (!token) {
    logTest('LBS endpoints', false, 'No authentication token available');
    return;
  }
  
  // Test get nearby annotations
  const { response: nearbyResponse, data: nearbyData, error: nearbyError } = await makeRequest(`${BASE_URL}/lbs/nearby?lat=40.7128&lng=-74.0060&radius=1000`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (nearbyError) {
    logTest('GET /lbs/nearby', false, `Error: ${nearbyError}`);
  } else if (nearbyResponse.ok) {
    logTest('GET /lbs/nearby', true, 'Nearby annotations retrieved');
  } else {
    logTest('GET /lbs/nearby', false, `Status: ${nearbyResponse.status}`);
  }
  
  // Test get annotations in area
  const { response: areaResponse, data: areaData, error: areaError } = await makeRequest(`${BASE_URL}/lbs/area?minLat=40.7&maxLat=40.8&minLng=-74.1&maxLng=-74.0`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (areaError) {
    logTest('GET /lbs/area', false, `Error: ${areaError}`);
  } else if (areaResponse.ok) {
    logTest('GET /lbs/area', true, 'Area annotations retrieved');
  } else {
    logTest('GET /lbs/area', false, `Status: ${areaResponse.status}`);
  }
}

// Test geocoding endpoints
async function testGeocodingEndpoints() {
  console.log('\n🌍 Testing Geocoding Endpoints...');
  
  // Test geocoding
  const { response: geocodeResponse, data: geocodeData, error: geocodeError } = await makeRequest(`${BASE_URL}/geocoding/geocode?address=New York, NY`, {
    method: 'GET'
  });
  
  if (geocodeError) {
    logTest('GET /geocoding/geocode', false, `Error: ${geocodeError}`);
  } else if (geocodeResponse.ok) {
    logTest('GET /geocoding/geocode', true, 'Geocoding successful');
  } else {
    logTest('GET /geocoding/geocode', false, `Status: ${geocodeResponse.status}`);
  }
  
  // Test reverse geocoding
  const { response: reverseResponse, data: reverseData, error: reverseError } = await makeRequest(`${BASE_URL}/geocoding/reverse?lat=40.7128&lng=-74.0060`, {
    method: 'GET'
  });
  
  if (reverseError) {
    logTest('GET /geocoding/reverse', false, `Error: ${reverseError}`);
  } else if (reverseResponse.ok) {
    logTest('GET /geocoding/reverse', true, 'Reverse geocoding successful');
  } else {
    logTest('GET /geocoding/reverse', false, `Status: ${reverseResponse.status}`);
  }
}

// Test health and utility endpoints
async function testUtilityEndpoints() {
  console.log('\n🔧 Testing Utility Endpoints...');
  
  // Test health check
  const { response: healthResponse, data: healthData, error: healthError } = await makeRequest(`${BASE_URL}/health`, {
    method: 'GET'
  });
  
  if (healthError) {
    logTest('GET /health', false, `Error: ${healthError}`);
  } else if (healthResponse.ok) {
    logTest('GET /health', true, 'Health check passed');
  } else {
    logTest('GET /health', false, `Status: ${healthResponse.status}`);
  }
  
  // Test root endpoint
  const { response: rootResponse, data: rootData, error: rootError } = await makeRequest(`${BASE_URL}/`, {
    method: 'GET'
  });
  
  if (rootError) {
    logTest('GET /', false, `Error: ${rootError}`);
  } else if (rootResponse.ok) {
    logTest('GET /', true, 'Root endpoint accessible');
  } else {
    logTest('GET /', false, `Status: ${rootResponse.status}`);
  }
}

// Main test function
async function runAPITests() {
  console.log('🧪 Starting API Endpoints Tests');
  console.log('==================================================');
  
  try {
    await testAuthEndpoints();
    await testUserEndpoints();
    await testPaymentEndpoints();
    await testLBSEndpoints();
    await testGeocodingEndpoints();
    await testUtilityEndpoints();
    
    // Print summary
    console.log('\n==================================================');
    console.log('🧪 API Endpoints Test Results');
    
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const total = results.length;
    const successRate = ((passed / total) * 100).toFixed(1);
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📊 Success Rate: ${successRate}%`);
    
    if (failed > 0) {
      console.log('⚠️  Some API tests failed. Please check the logs above.');
    } else {
      console.log('🎉 All API tests passed!');
    }
    
  } catch (error) {
    console.error('❌ Test execution failed:', error.message);
  }
}

// Run the tests
runAPITests();