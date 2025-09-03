// 简单的用户注册测试脚本
const BASE_URL = 'http://localhost:8787';

async function testRegistration() {
  console.log('Testing user registration...');
  
  const timestamp = Date.now();
  const testEmail = `payment-test-${timestamp}@example.com`;
  const testUsername = `payment-tester-${timestamp}`;
  
  try {
    const response = await fetch(`${BASE_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: testEmail,
        password: 'password123',
        username: testUsername
      })
    });
    
    const data = await response.json();
    console.log('Registration response status:', response.status);
    console.log('Registration response data:', JSON.stringify(data, null, 2));
    
    if (response.ok) {
      console.log('✅ Registration successful');
      
      // 立即尝试登录
      console.log('\nTesting login...');
      const loginResponse = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: testEmail,
          password: 'password123'
        })
      });
      
      const loginData = await loginResponse.json();
      console.log('Login response status:', loginResponse.status);
      console.log('Login response data:', JSON.stringify(loginData, null, 2));
      
      if (loginResponse.ok) {
        console.log('✅ Login successful');
        return loginData.token;
      } else {
        console.log('❌ Login failed');
      }
    } else {
      console.log('❌ Registration failed');
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

testRegistration();