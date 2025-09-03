// 测试本地标注创建修复
const API_BASE_URL = 'http://localhost:8787';

// 测试用户登录
async function testLogin() {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password123'
      })
    });

    const data = await response.json();
    console.log('登录响应状态:', response.status);
    console.log('登录响应数据:', data);
    
    if (response.ok && data.token) {
      console.log('✅ 用户登录成功');
      return data.token;
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
      content: '测试标注内容 - 修复后',
      latitude: 39.9042,
      longitude: 116.4074,
      smell_intensity: 7,
      smell_category: 'industrial',
      tags: ['test', 'fix']
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
    console.log('创建标注响应数据:', data);
    
    if (response.ok && data.id) {
      console.log('✅ 标注创建成功');
      return data.id;
    } else {
      console.log('❌ 标注创建失败');
      return null;
    }
  } catch (error) {
    console.log('创建标注错误:', error.message);
    return null;
  }
}

// 测试获取标注列表
async function testGetAnnotations() {
  try {
    const response = await fetch(`${API_BASE_URL}/annotations`);
    const data = await response.json();
    
    console.log('获取标注响应状态:', response.status);
    console.log('获取标注数量:', data.annotations ? data.annotations.length : 0);
    
    if (response.ok) {
      console.log('✅ 获取标注成功');
      return true;
    } else {
      console.log('❌ 获取标注失败');
      return false;
    }
  } catch (error) {
    console.log('获取标注错误:', error.message);
    return false;
  }
}

// 测试数据库连接
async function testDatabaseConnection() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();
    
    console.log('健康检查响应状态:', response.status);
    console.log('健康检查数据:', data);
    
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
async function runLocalAnnotationTest() {
  console.log('🚀 开始本地标注创建修复测试');
  console.log('API 基础URL:', API_BASE_URL);
  console.log('');

  const results = {
    database: false,
    login: false,
    create: false,
    get: false
  };

  // 测试数据库连接
  console.log('=== 测试数据库连接 ===');
  results.database = await testDatabaseConnection();
  console.log('');

  // 测试用户登录
  console.log('=== 测试用户登录 ===');
  const token = await testLogin();
  results.login = !!token;
  console.log('');

  // 测试创建标注
  console.log('=== 测试创建标注 ===');
  const annotationId = await testCreateAnnotation(token);
  results.create = !!annotationId;
  console.log('');

  // 测试获取标注列表
  console.log('=== 测试获取标注列表 ===');
  results.get = await testGetAnnotations();
  console.log('');

  // 汇总结果
  const successCount = Object.values(results).filter(Boolean).length;
  const totalCount = Object.keys(results).length;
  
  console.log('📊 本地测试结果汇总:');
  console.log('- 数据库连接:', results.database ? '✅ 成功' : '❌ 失败');
  console.log('- 用户登录:', results.login ? '✅ 成功' : '❌ 失败');
  console.log('- 创建标注:', results.create ? '✅ 成功' : '❌ 失败');
  console.log('- 获取标注:', results.get ? '✅ 成功' : '❌ 失败');
  console.log('');
  console.log('总体成功率:', successCount + '/' + totalCount + ' (' + Math.round(successCount/totalCount*100) + '%)');
  console.log('');
  
  if (results.create) {
    console.log('🎉 标注创建功能修复成功！');
  } else {
    console.log('⚠️ 标注创建功能仍需进一步修复');
  }
}

// 运行测试
runLocalAnnotationTest().catch(console.error);