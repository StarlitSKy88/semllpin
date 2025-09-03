// 完整的标注功能测试（包含用户注册）
const API_BASE_URL = 'http://localhost:8787';

// 生成唯一的测试用户数据
const timestamp = Date.now();
const testUser = {
  email: `test${timestamp}@example.com`,
  password: 'password123',
  username: `testuser${timestamp}`,
  full_name: 'Test User'
};

// 测试用户注册
async function testUserRegistration() {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testUser)
    });

    const data = await response.json();
    console.log('注册响应状态:', response.status);
    console.log('注册响应数据:', JSON.stringify(data, null, 2));
    
    if (response.ok && data.success) {
      console.log('✅ 用户注册成功');
      return true;
    } else {
      console.log('❌ 用户注册失败');
      return false;
    }
  } catch (error) {
    console.log('注册错误:', error.message);
    return false;
  }
}

// 测试用户登录
async function testUserLogin() {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/signin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: testUser.email,
        password: testUser.password
      })
    });

    const data = await response.json();
    console.log('登录响应状态:', response.status);
    console.log('登录响应数据:', JSON.stringify(data, null, 2));
    
    if (response.ok && data.success && data.data.token) {
      console.log('✅ 用户登录成功');
      return data.data.token;
    } else {
      console.log('❌ 用户登录失败');
      return null;
    }
  } catch (error) {
    console.log('登录错误:', error.message);
    return null;
  }
}

// 测试创建标注
async function testCreateAnnotation(token) {
  if (!token) {
    console.log('❌ 无有效token，跳过创建标注测试');
    return false;
  }

  try {
    const annotationData = {
      content: '测试标注内容 - 完整流程测试',
      location: {
        latitude: 39.9042,
        longitude: 116.4074,
        address: '北京市朝阳区',
        place_name: '测试地点'
      },
      smell_intensity: 8,
      smell_category: 'chemical',
      tags: ['test', 'complete-flow'],
      visibility: 'public'
    };

    const response = await fetch(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(annotationData)
    });

    const data = await response.json();
    console.log('创建标注响应状态:', response.status);
    console.log('创建标注响应数据:', JSON.stringify(data, null, 2));
    
    if (response.ok && data.success && data.data && data.data.id) {
      console.log('✅ 标注创建成功，ID:', data.data.id);
      return data.data.id;
    } else {
      console.log('❌ 标注创建失败');
      return null;
    }
  } catch (error) {
    console.log('创建标注错误:', error.message);
    return null;
  }
}

// 测试获取标注详情
async function testGetAnnotationById(annotationId) {
  if (!annotationId) {
    console.log('❌ 无有效标注ID，跳过获取详情测试');
    return false;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/annotations/${annotationId}`);
    const data = await response.json();
    
    console.log('获取标注详情响应状态:', response.status);
    console.log('获取标注详情数据:', JSON.stringify(data, null, 2));
    
    if (response.ok && data.success && data.data && data.data.id) {
      console.log('✅ 获取标注详情成功');
      return true;
    } else {
      console.log('❌ 获取标注详情失败');
      return false;
    }
  } catch (error) {
    console.log('获取标注详情错误:', error.message);
    return false;
  }
}

// 测试获取标注列表
async function testGetAnnotations() {
  try {
    const response = await fetch(`${API_BASE_URL}/annotations`);
    const data = await response.json();
    
    console.log('获取标注列表响应状态:', response.status);
    console.log('获取标注数量:', data.annotations ? data.annotations.length : 0);
    
    if (response.ok) {
      console.log('✅ 获取标注列表成功');
      return true;
    } else {
      console.log('❌ 获取标注列表失败');
      return false;
    }
  } catch (error) {
    console.log('获取标注列表错误:', error.message);
    return false;
  }
}

// 测试数据库连接
async function testDatabaseConnection() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();
    
    console.log('健康检查响应状态:', response.status);
    console.log('健康检查数据:', JSON.stringify(data, null, 2));
    
    if (response.ok) {
      console.log('✅ 数据库连接正常');
      return true;
    } else {
      console.log('❌ 数据库连接异常');
      return false;
    }
  } catch (error) {
    console.log('数据库连接错误:', error.message);
    return false;
  }
}

// 主测试函数
async function runCompleteAnnotationTest() {
  console.log('🚀 开始完整标注功能测试');
  console.log('API 基础URL:', API_BASE_URL);
  console.log('测试用户:', testUser.email);
  console.log('');

  const results = {
    database: false,
    register: false,
    login: false,
    create: false,
    getById: false,
    getList: false
  };

  // 测试数据库连接
  console.log('=== 1. 测试数据库连接 ===');
  results.database = await testDatabaseConnection();
  console.log('');

  // 测试用户注册
  console.log('=== 2. 测试用户注册 ===');
  results.register = await testUserRegistration();
  console.log('');

  // 等待一下，确保注册完成
  if (results.register) {
    console.log('等待注册完成...');
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  // 测试用户登录
  console.log('=== 3. 测试用户登录 ===');
  const token = await testUserLogin();
  results.login = !!token;
  console.log('');

  // 测试创建标注
  console.log('=== 4. 测试创建标注 ===');
  const annotationId = await testCreateAnnotation(token);
  results.create = !!annotationId;
  console.log('');

  // 测试获取标注详情
  console.log('=== 5. 测试获取标注详情 ===');
  results.getById = await testGetAnnotationById(annotationId);
  console.log('');

  // 测试获取标注列表
  console.log('=== 6. 测试获取标注列表 ===');
  results.getList = await testGetAnnotations();
  console.log('');

  // 汇总结果
  const successCount = Object.values(results).filter(Boolean).length;
  const totalCount = Object.keys(results).length;
  
  console.log('📊 完整测试结果汇总:');
  console.log('- 数据库连接:', results.database ? '✅ 成功' : '❌ 失败');
  console.log('- 用户注册:', results.register ? '✅ 成功' : '❌ 失败');
  console.log('- 用户登录:', results.login ? '✅ 成功' : '❌ 失败');
  console.log('- 创建标注:', results.create ? '✅ 成功' : '❌ 失败');
  console.log('- 获取标注详情:', results.getById ? '✅ 成功' : '❌ 失败');
  console.log('- 获取标注列表:', results.getList ? '✅ 成功' : '❌ 失败');
  console.log('');
  console.log('总体成功率:', successCount + '/' + totalCount + ' (' + Math.round(successCount/totalCount*100) + '%)');
  console.log('');
  
  if (results.create) {
    console.log('🎉 标注创建功能修复成功！');
    console.log('✅ 完整的用户注册 -> 登录 -> 创建标注流程正常工作');
  } else {
    console.log('⚠️ 标注创建功能仍需进一步修复');
    
    if (!results.register) {
      console.log('🔍 问题可能在用户注册环节');
    } else if (!results.login) {
      console.log('🔍 问题可能在用户登录环节');
    } else {
      console.log('🔍 问题可能在标注创建API本身');
    }
  }
}

// 运行测试
runCompleteAnnotationTest().catch(console.error);