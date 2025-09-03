// 测试API连接的简单脚本
const API_URL = 'https://smellpin-workers.dev-small-1.workers.dev';

async function testAPI() {
  console.log('Testing SmellPin API...');
  
  try {
    // 测试健康检查端点
    console.log('\n1. Testing health endpoint...');
    const healthResponse = await fetch(`${API_URL}/health`);
    if (healthResponse.ok) {
      const healthData = await healthResponse.json();
      console.log('✅ Health check passed:', healthData);
    } else {
      console.log('❌ Health check failed:', healthResponse.status);
    }
  } catch (error) {
    console.log('❌ Health check error:', error.message);
  }
  
  try {
    // 测试获取标注端点
    console.log('\n2. Testing annotations endpoint...');
    const annotationsResponse = await fetch(`${API_URL}/annotations`);
    if (annotationsResponse.ok) {
      const annotationsData = await annotationsResponse.json();
      console.log('✅ Annotations endpoint working:', annotationsData);
    } else {
      console.log('❌ Annotations endpoint failed:', annotationsResponse.status);
    }
  } catch (error) {
    console.log('❌ Annotations endpoint error:', error.message);
  }
  
  try {
    // 测试LBS附近奖励端点
    console.log('\n3. Testing LBS nearby endpoint...');
    const lbsResponse = await fetch(`${API_URL}/lbs/nearby?lat=39.9042&lng=116.4074`);
    if (lbsResponse.ok) {
      const lbsData = await lbsResponse.json();
      console.log('✅ LBS nearby endpoint working:', lbsData);
    } else {
      console.log('❌ LBS nearby endpoint failed:', lbsResponse.status);
    }
  } catch (error) {
    console.log('❌ LBS nearby endpoint error:', error.message);
  }
}

// 运行测试
testAPI().then(() => {
  console.log('\n🎉 API testing completed!');
}).catch(error => {
  console.error('💥 Test script error:', error);
});