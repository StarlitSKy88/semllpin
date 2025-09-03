// 本地 Cloudflare Workers API 测试脚本
// 测试本地运行的 Workers API (http://localhost:8787)

const BASE_URL = 'http://localhost:8787';

// 生成唯一的测试用户数据
const timestamp = Date.now();
const testUser = {
  email: `test${timestamp}@example.com`,
  password: 'testpassword123',
  username: `testuser${timestamp}`,
  full_name: 'Test User'
};

// 测试健康检查端点
async function testHealthCheck() {
  console.log('\n=== 测试健康检查 ===');
  try {
    const response = await fetch(`${BASE_URL}/health`);
    const data = await response.json();
    console.log('✅ 健康检查成功:', data);
    return true;
  } catch (error) {
    console.log('❌ 健康检查失败:', error.message);
    return false;
  }
}

// 测试用户注册
async function testUserRegistration() {
  console.log('\n=== 测试用户注册 ===');
  
  try {
    const response = await fetch(`${BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(testUser)
    });
    
    const data = await response.json();
    console.log('状态码:', response.status);
    console.log('响应数据:', data);
    
    if (response.ok) {
      console.log('✅ 用户注册成功');
      return { success: true, user: data };
    } else {
      console.log('❌ 用户注册失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.log('❌ 用户注册请求失败:', error.message);
    return { success: false, error: error.message };
  }
}

// 测试用户登录
async function testUserLogin(userEmail) {
  console.log('\n=== 测试用户登录 ===');
  const loginData = {
    email: userEmail || 'test@example.com',
    password: 'testpassword123'
  };
  
  try {
    const response = await fetch(`${BASE_URL}/auth/signin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(loginData)
    });
    
    const data = await response.json();
    console.log('状态码:', response.status);
    console.log('响应数据:', data);
    
    if (response.ok) {
      console.log('✅ 用户登录成功');
      return { success: true, token: data.data.token };
    } else {
      console.log('❌ 用户登录失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.log('❌ 用户登录请求失败:', error.message);
    return { success: false, error: error.message };
  }
}

// 测试获取标注
async function testGetAnnotations() {
  console.log('\n=== 测试获取标注 ===');
  try {
    const response = await fetch(`${BASE_URL}/annotations`);
    const data = await response.json();
    console.log('状态码:', response.status);
    console.log('响应数据:', data);
    
    if (response.ok) {
      console.log('✅ 获取标注成功');
      return { success: true, annotations: data };
    } else {
      console.log('❌ 获取标注失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.log('❌ 获取标注请求失败:', error.message);
    return { success: false, error: error.message };
  }
}

// 测试LBS附近查询
async function testLBSNearby() {
  console.log('\n=== 测试LBS附近查询 ===');
  try {
    const response = await fetch(`${BASE_URL}/lbs/nearby?lat=39.9042&lng=116.4074&radius=1000`);
    const data = await response.json();
    console.log('状态码:', response.status);
    console.log('响应数据:', data);
    
    if (response.ok) {
      console.log('✅ LBS附近查询成功');
      return { success: true, data };
    } else {
      console.log('❌ LBS附近查询失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.log('❌ LBS附近查询请求失败:', error.message);
    return { success: false, error: error.message };
  }
}

// 测试创建标注
async function testCreateAnnotation(token) {
  console.log('\n=== 测试创建标注 ===');
  const annotationData = {
    content: '这是一个测试标注',
    location: {
      latitude: 39.9042,
      longitude: 116.4074,
      address: '北京市朝阳区',
      place_name: '测试地点'
    },
    media_urls: [],
    tags: ['测试', '化学'],
    visibility: 'public',
    smell_intensity: 3,
    smell_category: 'chemical'
  };
  
  try {
    const headers = {
      'Content-Type': 'application/json'
    };
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${BASE_URL}/annotations`, {
      method: 'POST',
      headers,
      body: JSON.stringify(annotationData)
    });
    
    const data = await response.json();
    console.log('状态码:', response.status);
    console.log('响应数据:', data);
    
    if (response.ok) {
      console.log('✅ 创建标注成功');
      return { success: true, annotation: data };
    } else {
      console.log('❌ 创建标注失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.log('❌ 创建标注请求失败:', error.message);
    return { success: false, error: error.message };
  }
}

// 主测试函数
async function runLocalAPITests() {
  console.log('🚀 开始测试本地 Cloudflare Workers API');
  console.log('API 基础URL:', BASE_URL);
  
  const results = {
    healthCheck: false,
    userRegistration: false,
    userLogin: false,
    getAnnotations: false,
    lbsNearby: false,
    createAnnotation: false
  };
  
  // 1. 测试健康检查
  results.healthCheck = await testHealthCheck();
  
  // 2. 测试用户注册
  const registrationResult = await testUserRegistration();
  results.userRegistration = registrationResult.success;
  
  // 3. 测试用户登录
  const loginResult = await testUserLogin(registrationResult.user?.data?.user?.email || testUser.email);
  results.userLogin = loginResult.success;
  
  // 4. 测试获取标注
  const annotationsResult = await testGetAnnotations();
  results.getAnnotations = annotationsResult.success;
  
  // 5. 测试LBS附近查询
  const lbsResult = await testLBSNearby();
  results.lbsNearby = lbsResult.success;
  
  // 6. 测试创建标注（使用登录token，如果有的话）
  const createResult = await testCreateAnnotation(loginResult.token);
  results.createAnnotation = createResult.success;
  
  // 输出测试总结
  console.log('\n\n📊 测试结果总结:');
  console.log('==================');
  Object.entries(results).forEach(([test, passed]) => {
    const status = passed ? '✅ 通过' : '❌ 失败';
    console.log(`${test}: ${status}`);
  });
  
  const passedTests = Object.values(results).filter(Boolean).length;
  const totalTests = Object.keys(results).length;
  console.log(`\n总计: ${passedTests}/${totalTests} 个测试通过`);
  
  if (passedTests === totalTests) {
    console.log('🎉 所有测试都通过了！');
  } else {
    console.log('⚠️  有些测试失败了，请检查API配置和数据库连接。');
  }
}

// 运行测试
runLocalAPITests().catch(console.error);