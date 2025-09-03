const API_BASE_URL = 'http://localhost:8787';

// Test file upload authentication
async function testFileUploadAuth() {
  console.log('🧪 Testing File Upload Authentication...');
  
  try {
    // Step 1: Register a test user
    console.log('\n1. Registering test user...');
    const signupResponse = await fetch(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: `test-upload-${Date.now()}@example.com`,
        password: 'testpass123',
        username: `testuser${Date.now()}`,
        full_name: 'Test Upload User'
      })
    });
    
    const signupData = await signupResponse.json();
    console.log('Signup response:', signupData);
    
    if (!signupData.success) {
      throw new Error('Failed to register user');
    }
    
    const token = signupData.data.token;
    console.log('✅ User registered successfully');
    
    // Step 2: Test upload endpoint without auth (should fail)
    console.log('\n2. Testing upload without auth (should fail)...');
    const noAuthResponse = await fetch(`${API_BASE_URL}/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    
    console.log('No auth response status:', noAuthResponse.status);
    const noAuthData = await noAuthResponse.json();
    console.log('No auth response:', noAuthData);
    
    if (noAuthResponse.status === 401) {
      console.log('✅ Correctly rejected request without auth');
    } else {
      console.log('❌ Should have rejected request without auth');
    }
    
    // Step 3: Test upload URL endpoint with auth
    console.log('\n3. Testing upload URL endpoint with auth...');
    const uploadUrlResponse = await fetch(`${API_BASE_URL}/upload/url`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Upload URL response status:', uploadUrlResponse.status);
    const uploadUrlData = await uploadUrlResponse.json();
    console.log('Upload URL response:', uploadUrlData);
    
    if (uploadUrlResponse.status === 200) {
      console.log('✅ Upload URL endpoint works with auth');
    } else {
      console.log('❌ Upload URL endpoint failed with auth');
    }
    
    // Step 4: Test get user files endpoint
    console.log('\n4. Testing get user files endpoint...');
    const filesResponse = await fetch(`${API_BASE_URL}/upload/files`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Files response status:', filesResponse.status);
    const filesData = await filesResponse.json();
    console.log('Files response:', filesData);
    
    if (filesResponse.status === 200) {
      console.log('✅ Get files endpoint works with auth');
    } else {
      console.log('❌ Get files endpoint failed with auth');
    }
    
    // Step 5: Test with invalid token
    console.log('\n5. Testing with invalid token...');
    const invalidTokenResponse = await fetch(`${API_BASE_URL}/upload/files`, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid-token',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Invalid token response status:', invalidTokenResponse.status);
    const invalidTokenData = await invalidTokenResponse.json();
    console.log('Invalid token response:', invalidTokenData);
    
    if (invalidTokenResponse.status === 401) {
      console.log('✅ Correctly rejected invalid token');
    } else {
      console.log('❌ Should have rejected invalid token');
    }
    
    console.log('\n🎉 File upload authentication test completed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test
testFileUploadAuth();