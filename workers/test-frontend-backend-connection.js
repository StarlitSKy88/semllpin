const http = require('http');
const https = require('https');
const { URL } = require('url');

// Configuration
const FRONTEND_URL = 'http://localhost:5176';
const BACKEND_URL = 'http://localhost:8787';
const TEST_EMAIL = `connection-test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'testpassword123';
const TEST_USERNAME = `connection-tester-${Date.now()}`;

// Test results storage
const results = [];

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
          'User-Agent': 'Frontend-Backend-Connection-Test',
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
              response: { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode },
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

// Test frontend server accessibility
async function testFrontendServer() {
  console.log('\n🌐 Testing Frontend Server...');
  
  const { response, data, error } = await makeRequest(FRONTEND_URL, {
    method: 'GET'
  });
  
  if (error) {
    logTest('Frontend server accessibility', false, `Error: ${error}`);
    return false;
  } else if (response.ok) {
    logTest('Frontend server accessibility', true, `Frontend running on ${FRONTEND_URL}`);
    return true;
  } else {
    logTest('Frontend server accessibility', false, `Status: ${response.status}`);
    return false;
  }
}

// Test backend server accessibility
async function testBackendServer() {
  console.log('\n🔧 Testing Backend Server...');
  
  const { response, data, error } = await makeRequest(`${BACKEND_URL}/health`, {
    method: 'GET'
  });
  
  if (error) {
    logTest('Backend server accessibility', false, `Error: ${error}`);
    return false;
  } else if (response.ok) {
    logTest('Backend server accessibility', true, `Backend running on ${BACKEND_URL}`);
    return true;
  } else {
    logTest('Backend server accessibility', false, `Status: ${response.status}`);
    return false;
  }
}

// Test CORS configuration
async function testCORSConfiguration() {
  console.log('\n🔒 Testing CORS Configuration...');
  
  const { response, data, error } = await makeRequest(`${BACKEND_URL}/health`, {
    method: 'OPTIONS',
    headers: {
      'Origin': FRONTEND_URL,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'Content-Type, Authorization'
    }
  });
  
  if (error) {
    logTest('CORS preflight request', false, `Error: ${error}`);
  } else if (response.ok || response.status === 204) {
    logTest('CORS preflight request', true, 'CORS headers properly configured');
  } else {
    logTest('CORS preflight request', false, `Status: ${response.status}`);
  }
}

// Test authentication flow from frontend perspective
async function testAuthenticationFlow() {
  console.log('\n🔐 Testing Authentication Flow...');
  
  // Test user registration
  const { response: regResponse, data: regData, error: regError } = await makeRequest(`${BACKEND_URL}/auth/register`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      username: TEST_USERNAME
    }),
    headers: {
      'Origin': FRONTEND_URL
    }
  });
  
  if (regError) {
    logTest('User registration from frontend', false, `Error: ${regError}`);
    return null;
  } else if (regResponse.ok && regData.success) {
    logTest('User registration from frontend', true, 'Registration successful');
  } else {
    logTest('User registration from frontend', false, `Status: ${regResponse.status}`);
  }
  
  // Test user login
  const { response: loginResponse, data: loginData, error: loginError } = await makeRequest(`${BACKEND_URL}/auth/login`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    }),
    headers: {
      'Origin': FRONTEND_URL
    }
  });
  
  if (loginError) {
    logTest('User login from frontend', false, `Error: ${loginError}`);
    return null;
  } else if (loginResponse.ok && loginData.success && loginData.data?.token) {
    logTest('User login from frontend', true, 'Login successful, token received');
    return loginData.data.token;
  } else {
    logTest('User login from frontend', false, `Status: ${loginResponse.status}`);
    return null;
  }
}

// Test authenticated API calls
async function testAuthenticatedAPICalls(token) {
  console.log('\n🔑 Testing Authenticated API Calls...');
  
  if (!token) {
    logTest('Authenticated API calls', false, 'No authentication token available');
    return;
  }
  
  // Test wallet info with authentication
  const { response: walletResponse, data: walletData, error: walletError } = await makeRequest(`${BACKEND_URL}/payments/wallet`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Origin': FRONTEND_URL
    }
  });
  
  if (walletError) {
    logTest('Authenticated wallet API call', false, `Error: ${walletError}`);
  } else if (walletResponse.ok) {
    logTest('Authenticated wallet API call', true, 'Wallet data retrieved with authentication');
  } else {
    logTest('Authenticated wallet API call', false, `Status: ${walletResponse.status}`);
  }
  
  // Test LBS nearby with authentication
  const { response: lbsResponse, data: lbsData, error: lbsError } = await makeRequest(`${BACKEND_URL}/lbs/nearby?lat=40.7128&lng=-74.0060&radius=1000`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Origin': FRONTEND_URL
    }
  });
  
  if (lbsError) {
    logTest('Authenticated LBS API call', false, `Error: ${lbsError}`);
  } else if (lbsResponse.ok) {
    logTest('Authenticated LBS API call', true, 'LBS data retrieved with authentication');
  } else {
    logTest('Authenticated LBS API call', false, `Status: ${lbsResponse.status}`);
  }
}

// Test API response format compatibility
async function testAPIResponseFormat() {
  console.log('\n📋 Testing API Response Format...');
  
  const { response, data, error } = await makeRequest(`${BACKEND_URL}/health`, {
    method: 'GET',
    headers: {
      'Origin': FRONTEND_URL
    }
  });
  
  if (error) {
    logTest('API response format', false, `Error: ${error}`);
  } else if (response.ok && typeof data === 'object') {
    logTest('API response format', true, 'API returns valid JSON format');
  } else {
    logTest('API response format', false, 'API response format incompatible');
  }
}

// Main test function
async function runConnectionTests() {
  console.log('🧪 Starting Frontend-Backend Connection Tests');
  console.log('==================================================');
  
  try {
    // Test server accessibility
    const frontendRunning = await testFrontendServer();
    const backendRunning = await testBackendServer();
    
    if (!frontendRunning || !backendRunning) {
      console.log('\n⚠️  Cannot proceed with connection tests - servers not accessible');
      return;
    }
    
    // Test CORS and authentication
    await testCORSConfiguration();
    const token = await testAuthenticationFlow();
    await testAuthenticatedAPICalls(token);
    await testAPIResponseFormat();
    
    // Print summary
    console.log('\n==================================================');
    console.log('🧪 Frontend-Backend Connection Test Results');
    
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const total = results.length;
    const successRate = ((passed / total) * 100).toFixed(1);
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📊 Success Rate: ${successRate}%`);
    
    if (failed > 0) {
      console.log('⚠️  Some connection tests failed. Please check the logs above.');
    } else {
      console.log('🎉 All connection tests passed! Frontend and backend are properly connected.');
    }
    
  } catch (error) {
    console.error('❌ Test execution failed:', error.message);
  }
}

// Run the tests
runConnectionTests();