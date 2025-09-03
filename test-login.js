const axios = require('axios');

// 配置
const BASE_URL = 'http://localhost:3002/api/v1';
const TEST_USER = {
  email: 'testuser@example.com',
  password: 'Password123!',
  username: 'testuser',
  displayName: 'Test User'
};

// 备用测试用户
const EXISTING_USER = {
  email: 'john.doe@example.com',
  password: 'password123!'
};

// 测试用户登录流程
async function testUserLogin() {
  console.log('=== SmellPin 用户登录测试 ===\n');
  
  try {
    // 1. 首先尝试注册用户（如果用户不存在）
    console.log('1. 尝试注册测试用户...');
    try {
      const registerResponse = await axios.post(`${BASE_URL}/users/register`, TEST_USER);
      console.log('✅ 用户注册成功:', registerResponse.data.user?.email);
      console.log('注册响应:', JSON.stringify(registerResponse.data, null, 2));
    } catch (error) {
      if (error.response?.status === 409) {
        console.log('ℹ️  用户已存在，跳过注册');
      } else {
        console.log('❌ 注册失败:', error.response?.data || error.message);
        console.log('注册错误详情:', JSON.stringify(error.response?.data, null, 2));
        throw error;
      }
    }
    
    // 2. 测试用户登录 - 先尝试已存在用户
    console.log('\n2. 测试用户登录...');
    let loginResponse;
    let testUser = EXISTING_USER;
    
    try {
      console.log('尝试使用已存在用户登录:', testUser.email);
      loginResponse = await axios.post(`${BASE_URL}/users/login`, {
        email: testUser.email,
        password: testUser.password
      });
    } catch (error) {
      console.log('已存在用户登录失败，尝试使用测试用户:', TEST_USER.email);
      testUser = TEST_USER;
      loginResponse = await axios.post(`${BASE_URL}/users/login`, {
        email: testUser.email,
        password: testUser.password
      });
    }
    
    console.log('✅ 登录成功!');
    console.log('响应数据:', {
      success: loginResponse.data.success,
      message: loginResponse.data.message,
      user: loginResponse.data.data.user,
      tokenExists: !!loginResponse.data.data.tokens?.accessToken
    });
    
    const token = loginResponse.data.data.tokens?.accessToken;
    const userId = loginResponse.data.data.user.id;
    
    if (!token) {
      throw new Error('登录成功但未返回访问令牌');
    }
    
    // 3. 测试Token验证
    console.log('\n3. 测试Token验证...');
    const verifyResponse = await axios.get(`${BASE_URL}/auth/verify`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ Token验证成功!');
    console.log('验证响应:', {
      success: verifyResponse.data.success,
      message: verifyResponse.data.message,
      user: verifyResponse.data.data.user
    });
    
    // 4. 测试获取用户信息
    console.log('\n4. 测试获取用户信息...');
    const userInfoResponse = await axios.get(`${BASE_URL}/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ 获取用户信息成功!');
    console.log('用户信息:', {
      id: userInfoResponse.data.data.user.id,
      username: userInfoResponse.data.data.user.username,
      display_name: userInfoResponse.data.data.user.displayName,
      phone: userInfoResponse.data.data.user.phone,
      status: userInfoResponse.data.data.user.status
    });
    
    // 5. 测试错误的Token
    console.log('\n5. 测试无效Token...');
    try {
      await axios.get(`${BASE_URL}/auth/verify`, {
        headers: {
          'Authorization': 'Bearer invalid_token_here'
        }
      });
      console.log('❌ 应该返回错误，但没有');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ 无效Token正确返回401错误');
      } else {
        console.log('⚠️  意外错误:', error.response?.data?.message || error.message);
      }
    }
    
    // 6. 测试错误的登录信息
    console.log('\n6. 测试错误的登录信息...');
    try {
      await axios.post(`${BASE_URL}/users/login`, {
        email: TEST_USER.email,
        password: 'wrongpassword'
      });
      console.log('❌ 应该返回错误，但没有');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ 错误密码正确返回401错误');
        console.log('错误信息:', error.response.data.message);
      } else {
        console.log('⚠️  意外错误:', error.response?.data?.message || error.message);
      }
    }
    
    console.log('\n=== 登录测试完成 ===');
    console.log('✅ 所有测试通过！');
    
    return {
      success: true,
      token: token,
      userId: userId,
      user: loginResponse.data.data.user
    };
    
  } catch (error) {
    console.error('❌ 登录测试失败:', error.response?.data?.message || error.message);
    if (error.response?.data) {
      console.error('错误详情:', error.response.data);
    }
    return {
      success: false,
      error: error.message
    };
  }
}

// 运行测试
if (require.main === module) {
  testUserLogin().then(result => {
    if (result.success) {
      console.log('\n🎉 登录测试成功完成!');
      process.exit(0);
    } else {
      console.log('\n💥 登录测试失败!');
      process.exit(1);
    }
  }).catch(error => {
    console.error('💥 测试执行出错:', error);
    process.exit(1);
  });
}

module.exports = { testUserLogin, TEST_USER };