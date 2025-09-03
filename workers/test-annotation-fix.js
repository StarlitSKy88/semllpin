const BASE_URL = 'https://smellpin-workers.dev-small-1.workers.dev';

// 测试用户登录
async function testLogin() {
  console.log('\n=== 测试用户登录 ===');
  try {
    const response = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password123'
      })
    });
    
    const data = await response.json();
    console.log('登录状态码:', response.status);
    console.log('登录响应:', data);
    
    if (response.ok && data.token) {
      console.log('✅ 登录成功');
      return data.token;
    } else {
      console.log('❌ 登录失败');
      return null;
    }
  } catch (error) {
    console.error('登录错误:', error);
    return null;
  }
}

// 测试创建标注
async function testCreateAnnotation(token) {
  console.log('\n=== 测试创建标注 ===');
  const annotationData = {
    content: '修复测试 - 这是一个测试标注',
    location: {
      latitude: 39.9042,
      longitude: 116.4074,
      address: '北京市朝阳区',
      place_name: '测试地点'
    },
    media_urls: [],
    tags: ['测试', '修复'],
    visibility: 'public',
    smell_intensity: 3,
    smell_category: 'chemical'
  };
  
  try {
    const response = await fetch(`${BASE_URL}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(annotationData)
    });
    
    const data = await response.json();
    console.log('创建标注状态码:', response.status);
    console.log('创建标注响应:', JSON.stringify(data, null, 2));
    
    if (response.ok) {
      console.log('✅ 标注创建成功');
      return { success: true, annotation: data.data };
    } else {
      console.log('❌ 标注创建失败');
      console.log('错误详情:', data);
      return { success: false, error: data };
    }
  } catch (error) {
    console.error('创建标注错误:', error);
    return { success: false, error: error.message };
  }
}

// 测试获取标注列表
async function testGetAnnotations() {
  console.log('\n=== 测试获取标注列表 ===');
  try {
    const response = await fetch(`${BASE_URL}/annotations`);
    const data = await response.json();
    console.log('获取标注状态码:', response.status);
    console.log('获取标注数量:', data.data ? data.data.length : 0);
    
    if (response.ok) {
      console.log('✅ 获取标注成功');
      if (data.data && data.data.length > 0) {
        console.log('最新标注:', JSON.stringify(data.data[0], null, 2));
      }
      return { success: true, annotations: data.data };
    } else {
      console.log('❌ 获取标注失败');
      return { success: false, error: data };
    }
  } catch (error) {
    console.error('获取标注错误:', error);
    return { success: false, error: error.message };
  }
}

// 主测试函数
async function runAnnotationFixTest() {
  console.log('🚀 开始测试标注创建修复');
  console.log('API 基础URL:', BASE_URL);
  
  const results = {
    login: false,
    createAnnotation: false,
    getAnnotations: false
  };
  
  // 1. 测试登录
  const token = await testLogin();
  if (token) {
    results.login = true;
    
    // 2. 测试创建标注
    const createResult = await testCreateAnnotation(token);
    if (createResult.success) {
      results.createAnnotation = true;
    }
  }
  
  // 3. 测试获取标注
  const getResult = await testGetAnnotations();
  if (getResult.success) {
    results.getAnnotations = true;
  }
  
  // 输出测试结果
  console.log('\n📊 测试结果汇总:');
  console.log('- 用户登录:', results.login ? '✅ 成功' : '❌ 失败');
  console.log('- 创建标注:', results.createAnnotation ? '✅ 成功' : '❌ 失败');
  console.log('- 获取标注:', results.getAnnotations ? '✅ 成功' : '❌ 失败');
  
  const successCount = Object.values(results).filter(Boolean).length;
  const totalCount = Object.keys(results).length;
  console.log(`\n总体成功率: ${successCount}/${totalCount} (${Math.round(successCount/totalCount*100)}%)`);
  
  if (results.createAnnotation) {
    console.log('\n🎉 标注创建功能修复成功！');
  } else {
    console.log('\n⚠️ 标注创建功能仍需进一步修复');
  }
}

// 运行测试
runAnnotationFixTest().catch(console.error);