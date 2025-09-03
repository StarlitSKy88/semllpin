// 测试用户注册功能的脚本
// 模拟用户在浏览器中的操作

// Node.js环境下的fetch polyfill
if (typeof fetch === 'undefined') {
  global.fetch = require('node-fetch');
}

const testRegistration = async () => {
  console.log('开始测试用户注册功能...');
  
  // 测试数据
  const testUser = {
    username: 'testuser' + Date.now(),
    email: 'test' + Date.now() + '@example.com',
    password: 'TestPass123!',
    confirmPassword: 'TestPass123!',
    university: '测试大学'
  };
  
  console.log('测试用户数据:', testUser);
  
  try {
    // 模拟API调用
    const response = await fetch('https://smellpin-workers.dev-small-1.workers.dev/auth/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: testUser.username,
        email: testUser.email,
        password: testUser.password,
        university: testUser.university
      })
    });
    
    console.log('API响应状态:', response.status);
    
    if (response.ok) {
      const data = await response.json();
      console.log('注册成功:', data);
      return { success: true, data };
    } else {
      const error = await response.json();
      console.log('注册失败:', error);
      return { success: false, error };
    }
  } catch (error) {
    console.log('网络错误:', error.message);
    return { success: false, error: error.message };
  }
};

// 测试登录功能
const testLogin = async (email, password) => {
  console.log('开始测试用户登录功能...');
  
  try {
    const response = await fetch('https://smellpin-workers.dev-small-1.workers.dev/auth/signin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password
      })
    });
    
    console.log('登录API响应状态:', response.status);
    
    if (response.ok) {
      const data = await response.json();
      console.log('登录成功:', data);
      return { success: true, data };
    } else {
      const error = await response.json();
      console.log('登录失败:', error);
      return { success: false, error };
    }
  } catch (error) {
    console.log('登录网络错误:', error.message);
    return { success: false, error: error.message };
  }
};

// 运行测试
if (typeof window !== 'undefined') {
  // 浏览器环境
  window.testRegistration = testRegistration;
  window.testLogin = testLogin;
  console.log('测试函数已加载到window对象，可以在控制台调用 testRegistration() 和 testLogin()');
} else {
  // Node.js环境
  module.exports = { testRegistration, testLogin };
  
  // 自动运行测试
  (async () => {
    console.log('=== SmellPin 项目功能测试 ===\n');
    
    // 测试注册功能
    const registrationResult = await testRegistration();
    
    if (registrationResult.success) {
      console.log('\n✅ 注册功能测试通过');
      
      // 如果注册成功，测试登录功能
      const testUser = {
        email: 'test' + Date.now() + '@example.com',
        password: 'TestPass123!'
      };
      
      console.log('\n--- 开始测试登录功能 ---');
      const loginResult = await testLogin(testUser.email, testUser.password);
      
      if (loginResult.success) {
        console.log('\n✅ 登录功能测试通过');
      } else {
        console.log('\n❌ 登录功能测试失败');
      }
    } else {
      console.log('\n❌ 注册功能测试失败');
    }
    
    console.log('\n=== 测试完成 ===');
  })();
}