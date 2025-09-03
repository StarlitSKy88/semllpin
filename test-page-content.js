// 测试前端页面内容的脚本
const http = require('http');
const { URL } = require('url');

// 测试配置
const config = {
  baseUrl: 'http://localhost:5176',
  timeout: 10000
};

// HTTP请求函数
function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || 80,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'SmellPin-Test-Agent/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout: config.timeout
    };
    
    const req = http.request(requestOptions, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('请求超时'));
    });
    
    req.end();
  });
}

// 分析页面内容
function analyzePage(body, pageName) {
  console.log(`\n=== ${pageName}页面内容分析 ===`);
  
  // 检查基本HTML结构
  console.log('📄 HTML结构:');
  console.log(`  - DOCTYPE: ${body.includes('<!DOCTYPE') ? '✅' : '❌'}`);
  console.log(`  - HTML标签: ${body.includes('<html') ? '✅' : '❌'}`);
  console.log(`  - HEAD标签: ${body.includes('<head') ? '✅' : '❌'}`);
  console.log(`  - BODY标签: ${body.includes('<body') ? '✅' : '❌'}`);
  
  // 检查React相关内容
  console.log('\n⚛️ React应用:');
  console.log(`  - Root容器: ${body.includes('id="root"') ? '✅' : '❌'}`);
  console.log(`  - React脚本: ${body.includes('react') || body.includes('React') ? '✅' : '❌'}`);
  console.log(`  - Vite客户端: ${body.includes('@vite/client') ? '✅' : '❌'}`);
  console.log(`  - 主入口文件: ${body.includes('src/main') ? '✅' : '❌'}`);
  
  // 检查CSS和样式
  console.log('\n🎨 样式资源:');
  console.log(`  - CSS文件: ${body.includes('.css') ? '✅' : '❌'}`);
  console.log(`  - Tailwind: ${body.includes('tailwind') ? '✅' : '❌'}`);
  console.log(`  - 内联样式: ${body.includes('<style') ? '✅' : '❌'}`);
  
  // 检查JavaScript资源
  console.log('\n📜 JavaScript资源:');
  console.log(`  - JS文件: ${body.includes('.js') ? '✅' : '❌'}`);
  console.log(`  - 模块脚本: ${body.includes('type="module"') ? '✅' : '❌'}`);
  console.log(`  - 内联脚本: ${body.includes('<script') ? '✅' : '❌'}`);
  
  // 检查元数据
  console.log('\n📋 页面元数据:');
  console.log(`  - 标题: ${body.includes('<title') ? '✅' : '❌'}`);
  console.log(`  - 字符集: ${body.includes('charset') ? '✅' : '❌'}`);
  console.log(`  - 视口设置: ${body.includes('viewport') ? '✅' : '❌'}`);
  
  // 提取并显示标题
  const titleMatch = body.match(/<title[^>]*>([^<]*)<\/title>/i);
  if (titleMatch) {
    console.log(`  - 页面标题: "${titleMatch[1]}"`);
  }
  
  // 检查特定的应用内容
  console.log('\n🔍 应用特定内容:');
  if (body.includes('SmellPin') || body.includes('臭味')) {
    console.log('  - 应用名称: ✅');
  } else {
    console.log('  - 应用名称: ❌');
  }
  
  // 检查错误信息
  console.log('\n⚠️ 错误检查:');
  const hasError = body.includes('error') || body.includes('Error') || body.includes('404') || body.includes('500');
  console.log(`  - 错误信息: ${hasError ? '⚠️ 发现错误' : '✅ 无错误'}`);
  
  // 显示页面大小
  console.log(`\n📏 页面大小: ${(body.length / 1024).toFixed(2)} KB`);
  
  return {
    hasRoot: body.includes('id="root"'),
    hasReact: body.includes('react') || body.includes('React'),
    hasVite: body.includes('@vite/client'),
    hasMainEntry: body.includes('src/main'),
    hasError: hasError,
    size: body.length
  };
}

// 测试主页面详细内容
async function testMainPageContent() {
  try {
    console.log('🔍 获取主页面详细内容...');
    
    const response = await makeRequest(config.baseUrl);
    
    if (response.statusCode === 200) {
      const analysis = analyzePage(response.body, '主页');
      
      // 如果没有检测到React应用，显示页面的前500个字符
      if (!analysis.hasRoot || !analysis.hasVite) {
        console.log('\n📝 页面内容预览 (前500字符):');
        console.log('=' + '='.repeat(50));
        console.log(response.body.substring(0, 500));
        console.log('=' + '='.repeat(50));
      }
      
      return analysis;
    } else {
      console.log(`❌ 无法获取页面内容，状态码: ${response.statusCode}`);
      return null;
    }
    
  } catch (error) {
    console.log(`❌ 页面内容测试失败: ${error.message}`);
    return null;
  }
}

// 检查开发服务器状态
async function checkDevServerStatus() {
  console.log('\n🔧 检查开发服务器状态...');
  
  try {
    // 尝试访问Vite的特殊端点
    const viteEndpoints = [
      '/@vite/client',
      '/@id/__x00__virtual:vite/modulepreload-polyfill',
      '/src/main.tsx'
    ];
    
    for (const endpoint of viteEndpoints) {
      try {
        const response = await makeRequest(`${config.baseUrl}${endpoint}`);
        console.log(`  - ${endpoint}: ${response.statusCode === 200 ? '✅' : '❌'} (${response.statusCode})`);
      } catch (error) {
        console.log(`  - ${endpoint}: ❌ (${error.message})`);
      }
    }
    
  } catch (error) {
    console.log(`❌ 开发服务器状态检查失败: ${error.message}`);
  }
}

// 主函数
async function runDetailedTest() {
  console.log('🚀 开始详细的前端内容测试...\n');
  
  // 测试主页面内容
  const mainPageAnalysis = await testMainPageContent();
  
  // 检查开发服务器状态
  await checkDevServerStatus();
  
  console.log('\n✨ 详细测试完成!');
  
  return mainPageAnalysis;
}

// 执行测试
if (require.main === module) {
  runDetailedTest().catch(console.error);
}

module.exports = { runDetailedTest, analyzePage };