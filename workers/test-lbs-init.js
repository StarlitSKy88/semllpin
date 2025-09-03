// LBS表初始化测试脚本
const BASE_URL = 'http://localhost:8787';

async function testLbsInit() {
  console.log('🗄️ Testing LBS tables initialization...');
  
  try {
    const response = await fetch(`${BASE_URL}/lbs/init-tables`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      console.log('✅ LBS tables initialized successfully');
      console.log('   Tables created:', data.message);
      return true;
    } else {
      console.log('❌ LBS tables initialization failed:', data);
      return false;
    }
  } catch (error) {
    console.log('❌ LBS tables initialization error:', error.message);
    return false;
  }
}

// 运行测试
testLbsInit().then(success => {
  if (success) {
    console.log('\n🎉 LBS表初始化成功！现在可以测试其他LBS功能了。');
  } else {
    console.log('\n⚠️ LBS表初始化失败，请检查错误信息。');
  }
  process.exit(success ? 0 : 1);
});