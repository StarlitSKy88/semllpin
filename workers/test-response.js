// 测试服务器响应格式
const BASE_URL = 'http://localhost:8787';

async function testResponse() {
  console.log('测试服务器响应格式...');
  
  try {
    const response = await fetch(`${BASE_URL}/health`);
    console.log('状态码:', response.status);
    console.log('Content-Type:', response.headers.get('content-type'));
    
    const text = await response.text();
    console.log('响应内容:');
    console.log(text.substring(0, 500)); // 只显示前500个字符
    
    if (text.startsWith('<')) {
      console.log('\n❌ 服务器返回HTML而不是JSON');
    } else {
      console.log('\n✅ 服务器返回非HTML内容');
    }
  } catch (error) {
    console.log('❌ 请求失败:', error.message);
  }
}

testResponse();