// 测试本地Node.js API的脚本
const LOCAL_API_URL = 'http://localhost:3002';

// 测试用户数据
const testUser = {
  email: 'apitest@example.com',
  password: 'Password123!',
  username: 'apitest',
  displayName: 'API Test User'
};

// 登录用户数据（只需要email和password）
const loginUser = {
  email: 'apitest@example.com',
  password: 'Password123!'
};

// 颜色输出函数
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function log(color, message) {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// 测试健康检查端点
async function testHealthEndpoint() {
  console.log('\n1. 测试健康检查端点...');
  try {
    const response = await fetch(`${LOCAL_API_URL}/api/v1/health`);
    if (response.ok) {
      const data = await response.json();
      log('green', '✅ 健康检查通过:');
      console.log(JSON.stringify(data, null, 2));
      return true;
    } else {
      log('red', `❌ 健康检查失败: ${response.status}`);
      return false;
    }
  } catch (error) {
    log('red', `❌ 健康检查错误: ${error.message}`);
    return false;
  }
}

// 添加延迟函数
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 测试用户注册端点
async function testUserRegistration() {
  console.log('\n2. 测试用户注册端点...');
  try {
    const response = await fetch(`${LOCAL_API_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(testUser)
    });
    
    const data = await response.text();
    
    if (response.ok) {
      log('green', '✅ 用户注册成功:');
      console.log(data);
      return true;
    } else {
      log('yellow', `⚠️ 用户注册响应 (${response.status}):`);
      console.log(data);
      // 如果是409冲突（用户已存在），也算作成功
      return response.status === 409;
    }
  } catch (error) {
    log('red', `❌ 用户注册错误: ${error.message}`);
    return false;
  }
}

// 存储登录token
let authToken = null;

// 测试用户登录端点
async function testUserLogin() {
  console.log('\n3. 测试用户登录端点...');
  try {
    const response = await fetch(`${LOCAL_API_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(loginUser)
    });
    
    if (response.ok) {
      const data = await response.json();
      log('green', '✅ 用户登录成功:');
      console.log(JSON.stringify(data, null, 2));
      // 保存token用于后续请求
      if (data.data && data.data.tokens && data.data.tokens.accessToken) {
        authToken = data.data.tokens.accessToken;
        log('green', '🔑 Token已保存，用于后续认证请求');
      }
      return true;
    } else {
      const errorData = await response.text();
      log('yellow', `⚠️ 用户登录响应 (${response.status}):`);
      console.log(errorData);
      return false;
    }
  } catch (error) {
    log('red', `❌ 用户登录错误: ${error.message}`);
    return false;
  }
}

// 测试标注获取端点
async function testAnnotationsEndpoint() {
  console.log('\n4. 测试标注获取端点...');
  try {
    const headers = {
      'Content-Type': 'application/json'
    };
    
    // 如果有token，添加认证头
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    const response = await fetch(`${LOCAL_API_URL}/api/v1/annotations/list`, {
      headers
    });
    
    if (response.ok) {
      const data = await response.json();
      log('green', '✅ 标注获取成功:');
      console.log(JSON.stringify(data, null, 2));
      return true;
    } else {
      log('yellow', `⚠️ 标注获取响应 (${response.status}):`);
      const errorData = await response.text();
      console.log(errorData);
      return false;
    }
  } catch (error) {
    log('red', `❌ 标注获取错误: ${error.message}`);
    return false;
  }
}

// 测试LBS附近端点
async function testLBSNearbyEndpoint() {
  console.log('\n5. 测试LBS附近端点...');
  try {
    const headers = {
      'Content-Type': 'application/json'
    };
    
    // LBS端点需要认证
    if (!authToken) {
      log('yellow', '⚠️ 没有认证token，LBS查询将失败');
      return false;
    }
    
    headers['Authorization'] = `Bearer ${authToken}`;
    
    const response = await fetch(`${LOCAL_API_URL}/api/v1/lbs/rewards`, {
      headers
    });
    
    if (response.ok) {
      const data = await response.json();
      log('green', '✅ LBS附近查询成功:');
      console.log(JSON.stringify(data, null, 2));
      return true;
    } else {
      log('yellow', `⚠️ LBS附近查询响应 (${response.status}):`);
      const errorData = await response.text();
      console.log(errorData);
      return false;
    }
  } catch (error) {
    log('red', `❌ LBS附近查询错误: ${error.message}`);
    return false;
  }
}

// 测试标注创建端点
async function testCreateAnnotation() {
  console.log('\n6. 测试标注创建端点...');
  const testAnnotation = {
    latitude: 39.9042,
    longitude: 116.4074,
    smellIntensity: 3,
    description: '测试标注描述'
  };
  
  try {
    const headers = {
      'Content-Type': 'application/json'
    };
    
    // 标注创建需要认证
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    } else {
      log('yellow', '⚠️ 没有认证token，标注创建可能失败');
    }
    
    const response = await fetch(`${LOCAL_API_URL}/api/v1/annotations`, {
      method: 'POST',
      headers,
      body: JSON.stringify(testAnnotation)
    });
    
    if (response.ok) {
      const data = await response.json();
      log('green', '✅ 标注创建成功:');
      console.log(JSON.stringify(data, null, 2));
      return true;
    } else {
      const errorData = await response.text();
      log('yellow', `⚠️ 标注创建响应 (${response.status}):`);
      console.log(errorData);
      return false;
    }
  } catch (error) {
    log('red', `❌ 标注创建错误: ${error.message}`);
    return false;
  }
}

// 主测试函数
async function runLocalAPITests() {
  log('blue', '🚀 开始测试本地Cloudflare Workers API...');
  log('blue', `📍 API地址: ${LOCAL_API_URL}`);
  
  const results = {
    health: false,
    registration: false,
    login: false,
    annotations: false,
    lbsNearby: false,
    createAnnotation: false
  };
  
  // 执行所有测试，在每个测试之间添加延迟避免速率限制
  results.health = await testHealthEndpoint();
  await delay(2000); // 等待2秒
  
  results.registration = await testUserRegistration();
  await delay(2000); // 等待2秒
  
  results.login = await testUserLogin();
  await delay(2000); // 等待2秒
  
  results.annotations = await testAnnotationsEndpoint();
  await delay(2000); // 等待2秒
  
  results.lbsNearby = await testLBSNearbyEndpoint();
  await delay(2000); // 等待2秒
  
  results.createAnnotation = await testCreateAnnotation();
  
  // 输出测试总结
  console.log('\n' + '='.repeat(50));
  log('blue', '📊 测试结果总结:');
  console.log('='.repeat(50));
  
  const passed = Object.values(results).filter(Boolean).length;
  const total = Object.keys(results).length;
  
  Object.entries(results).forEach(([test, passed]) => {
    const status = passed ? '✅ 通过' : '❌ 失败';
    const color = passed ? 'green' : 'red';
    log(color, `${test.padEnd(20)} ${status}`);
  });
  
  console.log('='.repeat(50));
  log('blue', `总计: ${passed}/${total} 个测试通过`);
  
  if (passed === total) {
    log('green', '🎉 所有API端点测试通过！');
  } else {
    log('yellow', '⚠️ 部分API端点存在问题，请检查服务器日志');
  }
  
  return results;
}

// 运行测试
if (require.main === module) {
  runLocalAPITests().then((results) => {
    console.log('\n🏁 本地API测试完成！');
    process.exit(0);
  }).catch(error => {
    log('red', `💥 测试脚本错误: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { runLocalAPITests };