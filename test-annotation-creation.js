// 测试标注创建功能
const API_BASE_URL = 'http://localhost:8787';

// 真实登录获取JWT token
const realLogin = async () => {
  console.log('🔐 用户登录...');
  try {
    const response = await fetch(`${API_BASE_URL}/auth/signin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: 'admin@smellpin.com',
        password: 'password'
      })
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      console.log('✅ 登录成功，获得JWT token');
      return data.data.token;
    } else {
      console.log('❌ 登录失败:', data.message || '未知错误');
      return null;
    }
  } catch (error) {
    console.log('❌ 登录请求失败:', error.message);
    return null;
  }
};

// 测试标注创建API
async function testCreateAnnotation(token) {
  console.log('\n📍 测试标注创建API...');
  
  const annotationData = {
    content: "测试标注\n\n这是一个测试标注，用于验证标注创建功能是否正常工作。",
    location: {
      latitude: 39.9042,
      longitude: 116.4074,
      address: "北京市东城区天安门广场",
      place_name: "天安门广场"
    },
    media_urls: [],
    tags: ["测试", "标注"],
    visibility: "public",
    smell_intensity: 3,
    smell_category: "other"
  };
  
  try {
    const response = await fetch(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(annotationData)
    });
    
    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ 标注创建成功!');
      console.log('📋 创建的标注信息:', JSON.stringify(result, null, 2));
      return result.data;
    } else {
      console.log('❌ 标注创建失败:', result.message || result.error);
      return null;
    }
  } catch (error) {
    console.log('❌ 请求错误:', error.message);
    return null;
  }
}

// 测试获取标注列表
async function testGetAnnotations() {
  console.log('\n📋 测试获取标注列表...');
  
  try {
    const response = await fetch(`${API_BASE_URL}/annotations`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ 获取标注列表成功!');
      console.log(`📊 共找到 ${result.data.length} 个标注`);
      
      // 显示最新的几个标注
      const recentAnnotations = result.data.slice(0, 3);
      recentAnnotations.forEach((annotation, index) => {
        console.log(`${index + 1}. ${annotation.content.split('\n')[0]} (ID: ${annotation.id})`);
      });
      
      return result.data;
    } else {
      console.log('❌ 获取标注列表失败:', result.message || result.error);
      return [];
    }
  } catch (error) {
    console.log('❌ 请求错误:', error.message);
    return [];
  }
}

// 主测试函数
async function runAnnotationTest() {
  console.log('🚀 开始测试标注创建功能\n');
  
  try {
    // 1. 真实登录获取JWT token
    const token = await realLogin();
    if (!token) {
      console.log('❌ 无法获取认证token，测试终止');
      return;
    }
    
    // 2. 测试创建标注
    const newAnnotation = await testCreateAnnotation(token);
    
    // 3. 测试获取标注列表
    const annotations = await testGetAnnotations();
    
    // 4. 验证新标注是否在列表中
    if (newAnnotation && annotations.length > 0) {
      const foundAnnotation = annotations.find(a => a.id === newAnnotation.id);
      if (foundAnnotation) {
        console.log('\n✅ 验证成功: 新创建的标注已出现在标注列表中!');
      } else {
        console.log('\n⚠️  警告: 新创建的标注未在列表中找到');
      }
    }
    
    console.log('\n🎉 标注创建功能测试完成!');
    
  } catch (error) {
    console.log('\n❌ 测试过程中发生错误:', error.message);
  }
}

// 运行测试
runAnnotationTest();