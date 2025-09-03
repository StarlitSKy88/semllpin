const http = require('http');
const https = require('https');
const { URL } = require('url');

// Configuration
const BACKEND_URL = 'http://localhost:8787';
const TEST_EMAIL = `geocoding-test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'testpassword123';
const TEST_USERNAME = `geocoding-tester-${Date.now()}`;

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
          'User-Agent': 'Geocoding-Test',
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

// Get authentication token
async function getAuthToken() {
  console.log('🔐 Setting up authentication...');
  
  // Register test user
  const { response: regResponse, data: regData, error: regError } = await makeRequest(`${BACKEND_URL}/auth/register`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      username: TEST_USERNAME
    })
  });
  
  if (regError || !regResponse.ok) {
    console.log('⚠️  Registration failed, trying to login with existing user');
  }
  
  // Login to get token
  const { response: loginResponse, data: loginData, error: loginError } = await makeRequest(`${BACKEND_URL}/auth/login`, {
    method: 'POST',
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    })
  });
  
  if (loginError || !loginResponse.ok || !loginData.success || !loginData.data?.token) {
    console.log('❌ Failed to get authentication token');
    return null;
  }
  
  console.log('✅ Authentication successful');
  return loginData.data.token;
}

// Test geocoding (address to coordinates)
async function testGeocoding(token) {
  console.log('\n🌍 Testing Geocoding (Address to Coordinates)...');
  
  const testCases = [
    {
      name: 'Basic address geocoding',
      address: 'New York, NY, USA',
      language: 'en'
    },
    {
      name: 'Detailed address geocoding',
      address: '1600 Amphitheatre Parkway, Mountain View, CA, USA',
      language: 'en'
    },
    {
      name: 'International address geocoding',
      address: 'Tokyo, Japan',
      language: 'en'
    }
  ];
  
  for (const testCase of testCases) {
    const { response, data, error } = await makeRequest(`${BACKEND_URL}/geocoding/geocode`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        address: testCase.address,
        language: testCase.language
      })
    });
    
    if (error) {
      logTest(testCase.name, false, `Error: ${error}`);
    } else if (response.ok && data.success && data.data && Array.isArray(data.data) && data.data.length > 0) {
      const result = data.data[0];
      if (result.latitude && result.longitude && result.formatted_address) {
        logTest(testCase.name, true, `Found: ${result.formatted_address} (${result.latitude}, ${result.longitude})`);
      } else {
        logTest(testCase.name, false, 'Invalid geocoding result format');
      }
    } else {
      logTest(testCase.name, false, `Status: ${response.status}, Response: ${JSON.stringify(data)}`);
    }
  }
}

// Test reverse geocoding (coordinates to address)
async function testReverseGeocoding(token) {
  console.log('\n🗺️  Testing Reverse Geocoding (Coordinates to Address)...');
  
  const testCases = [
    {
      name: 'New York coordinates',
      latitude: 40.7128,
      longitude: -74.0060,
      language: 'en'
    },
    {
      name: 'San Francisco coordinates',
      latitude: 37.7749,
      longitude: -122.4194,
      language: 'en'
    },
    {
      name: 'Tokyo coordinates',
      latitude: 35.6762,
      longitude: 139.6503,
      language: 'en'
    }
  ];
  
  for (const testCase of testCases) {
    const { response, data, error } = await makeRequest(`${BACKEND_URL}/geocoding/reverse`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        latitude: testCase.latitude,
        longitude: testCase.longitude,
        language: testCase.language
      })
    });
    
    if (error) {
      logTest(testCase.name, false, `Error: ${error}`);
    } else if (response.ok && data.success && data.data && Array.isArray(data.data) && data.data.length > 0) {
      const result = data.data[0];
      if (result.formatted_address) {
        logTest(testCase.name, true, `Found: ${result.formatted_address}`);
      } else {
        logTest(testCase.name, false, 'Invalid reverse geocoding result format');
      }
    } else {
      logTest(testCase.name, false, `Status: ${response.status}, Response: ${JSON.stringify(data)}`);
    }
  }
}

// Test geocoding cache functionality
async function testGeocodingCache(token) {
  console.log('\n💾 Testing Geocoding Cache...');
  
  // Test cache stats
  const { response: statsResponse, data: statsData, error: statsError } = await makeRequest(`${BACKEND_URL}/geocoding/cache/stats`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (statsError) {
    logTest('Cache stats retrieval', false, `Error: ${statsError}`);
  } else if (statsResponse.ok && statsData.success) {
    logTest('Cache stats retrieval', true, `Cache entries: ${statsData.data?.total_entries || 0}`);
  } else {
    logTest('Cache stats retrieval', false, `Status: ${statsResponse.status}`);
  }
  
  // Test the same geocoding request twice to verify caching
  const testAddress = 'Test Cache Address, Test City';
  
  // First request (should not be cached)
  const { response: firstResponse, data: firstData } = await makeRequest(`${BACKEND_URL}/geocoding/geocode`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      address: testAddress,
      language: 'en'
    })
  });
  
  // Second request (should be cached)
  const { response: secondResponse, data: secondData } = await makeRequest(`${BACKEND_URL}/geocoding/geocode`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      address: testAddress,
      language: 'en'
    })
  });
  
  if (firstResponse.ok && secondResponse.ok && 
      firstData.success && secondData.success &&
      !firstData.cached && secondData.cached) {
    logTest('Cache functionality', true, 'First request not cached, second request cached');
  } else {
    logTest('Cache functionality', false, 'Cache behavior not working as expected');
  }
}

// Test geocoding error handling
async function testGeocodingErrorHandling(token) {
  console.log('\n⚠️  Testing Error Handling...');
  
  // Test invalid geocoding request
  const { response: invalidGeoResponse, data: invalidGeoData, error: invalidGeoError } = await makeRequest(`${BACKEND_URL}/geocoding/geocode`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      // Missing required address field
      language: 'en'
    })
  });
  
  if (invalidGeoResponse && invalidGeoResponse.status === 400 && invalidGeoData.error) {
    logTest('Invalid geocoding request handling', true, 'Properly rejected invalid request');
  } else {
    logTest('Invalid geocoding request handling', false, 'Did not properly handle invalid request');
  }
  
  // Test invalid reverse geocoding request
  const { response: invalidRevResponse, data: invalidRevData, error: invalidRevError } = await makeRequest(`${BACKEND_URL}/geocoding/reverse`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      // Missing required latitude/longitude fields
      language: 'en'
    })
  });
  
  if (invalidRevResponse && invalidRevResponse.status === 400 && invalidRevData.error) {
    logTest('Invalid reverse geocoding request handling', true, 'Properly rejected invalid request');
  } else {
    logTest('Invalid reverse geocoding request handling', false, 'Did not properly handle invalid request');
  }
  
  // Test unauthorized access
  const { response: unauthResponse, data: unauthData } = await makeRequest(`${BACKEND_URL}/geocoding/cache/stats`, {
    method: 'GET'
    // No authorization header
  });
  
  if (unauthResponse && unauthResponse.status === 401) {
    logTest('Unauthorized access handling', true, 'Properly rejected unauthorized request');
  } else {
    logTest('Unauthorized access handling', false, 'Did not properly handle unauthorized request');
  }
}

// Test cache management
async function testCacheManagement(token) {
  console.log('\n🗑️  Testing Cache Management...');
  
  // Test cache clearing (admin function)
  const { response: clearResponse, data: clearData, error: clearError } = await makeRequest(`${BACKEND_URL}/geocoding/cache`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (clearError) {
    logTest('Cache clearing', false, `Error: ${clearError}`);
  } else if (clearResponse.ok && clearData.success) {
    logTest('Cache clearing', true, 'Cache cleared successfully');
  } else {
    logTest('Cache clearing', false, `Status: ${clearResponse.status}, may require admin privileges`);
  }
}

// Main test function
async function runGeocodingTests() {
  console.log('🧪 Starting Geocoding Functionality Tests');
  console.log('==========================================');
  
  try {
    // Get authentication token
    const token = await getAuthToken();
    if (!token) {
      console.log('❌ Cannot proceed without authentication token');
      return;
    }
    
    // Run all geocoding tests
    await testGeocoding(token);
    await testReverseGeocoding(token);
    await testGeocodingCache(token);
    await testGeocodingErrorHandling(token);
    await testCacheManagement(token);
    
    // Print summary
    console.log('\n==========================================');
    console.log('🧪 Geocoding Functionality Test Results');
    
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const total = results.length;
    const successRate = ((passed / total) * 100).toFixed(1);
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📊 Success Rate: ${successRate}%`);
    
    if (failed > 0) {
      console.log('\n⚠️  Failed tests:');
      results.filter(r => r.status === 'failed').forEach(result => {
        console.log(`   • ${result.test}: ${result.details}`);
      });
    } else {
      console.log('🎉 All geocoding tests passed!');
    }
    
  } catch (error) {
    console.error('❌ Test execution failed:', error.message);
  }
}

// Run the tests
runGeocodingTests();