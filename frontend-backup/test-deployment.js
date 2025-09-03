import https from 'https';
import http from 'http';

async function testDeployment() {
  console.log('=== 测试前端部署状态 ===\n');
  
  const urls = [
    'https://frontend-rkbsuheke-starlitsky88s-projects.vercel.app',
    'https://frontend-rkbsuheke-starlitsky88s-projects.vercel.app/login',
    'https://frontend-rkbsuheke-starlitsky88s-projects.vercel.app/register'
  ];
  
  for (const url of urls) {
    try {
      console.log(`测试: ${url}`);
      
      const response = await new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, data }));
        });
        
        req.on('error', reject);
        req.setTimeout(10000, () => {
          req.destroy();
          reject(new Error('请求超时'));
        });
      });
      
      console.log(`  状态码: ${response.statusCode}`);
      console.log(`  内容类型: ${response.headers['content-type'] || 'unknown'}`);
      console.log(`  内容长度: ${response.data.length} 字符`);
      
      if (response.statusCode === 200) {
        console.log('  ✅ 响应正常');
        
        // 检查是否包含React应用的标识
        if (response.data.includes('<!doctype html>') || response.data.includes('<div id="root">')) {
          console.log('  ✅ 检测到React应用结构');
        }
        
        // 检查是否包含预期的资源
        if (response.data.includes('.js') && response.data.includes('.css')) {
          console.log('  ✅ 检测到JS和CSS资源');
        }
      } else if (response.statusCode === 418) {
        console.log('  ❌ 418错误 - 这是之前CloudBase的问题');
      } else {
        console.log(`  ⚠️  非200状态码: ${response.statusCode}`);
      }
      
    } catch (error) {
      console.log(`  ❌ 请求失败: ${error.message}`);
    }
    
    console.log('');
  }
  
  console.log('=== 测试完成 ===');
}

testDeployment().catch(console.error);