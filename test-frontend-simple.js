// 简化的前端功能测试脚本
const http = require('http');
const https = require('https');
const { URL } = require('url');

// 测试配置
const config = {
  baseUrl: 'http://localhost:5173',
  timeout: 10000
};

// 测试结果记录
const testResults = {
  passed: 0,
  failed: 0,
  errors: []
};

// 记录测试结果
function recordTest(testName, success, error = null) {
  if (success) {
    testResults.passed++;
    console.log(`✅ ${testName} - 通过`);
  } else {
    testResults.failed++;
    testResults.errors.push({ test: testName, error });
    console.log(`❌ ${testName} - 失败: ${error}`);
  }
}

// HTTP请求函数
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'SmellPin-Test-Agent/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...options.headers
      },
      timeout: config.timeout
    };
    
    const req = client.request(requestOptions, (res) => {
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
    
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// 测试页面可访问性
async function testPageAccessibility(path, pageName) {
  try {
    console.log(`\n=== 测试${pageName}页面可访问性 ===`);
    
    const url = `${config.baseUrl}${path}`;
    const response = await makeRequest(url);
    
    // 检查状态码
    if (response.statusCode === 200) {
      recordTest(`${pageName}页面HTTP状态`, true);
    } else {
      recordTest(`${pageName}页面HTTP状态`, false, `状态码: ${response.statusCode}`);
      return false;
    }
    
    // 检查内容类型
    const contentType = response.headers['content-type'] || '';
    if (contentType.includes('text/html')) {
      recordTest(`${pageName}页面内容类型`, true);
    } else {
      recordTest(`${pageName}页面内容类型`, false, `内容类型: ${contentType}`);
    }
    
    // 检查HTML内容
    const body = response.body;
    if (body.includes('<html') && body.includes('</html>')) {
      recordTest(`${pageName}页面HTML结构`, true);
    } else {
      recordTest(`${pageName}页面HTML结构`, false, 'HTML结构不完整');
    }
    
    // 检查React应用
    if (body.includes('id="root"') || body.includes('React') || body.includes('react')) {
      recordTest(`${pageName}页面React应用`, true);
    } else {
      recordTest(`${pageName}页面React应用`, false, '未检测到React应用');
    }
    
    // 检查CSS和JS资源
    const hasCSS = body.includes('.css') || body.includes('<style');
    const hasJS = body.includes('.js') || body.includes('<script');
    
    recordTest(`${pageName}页面CSS资源`, hasCSS, !hasCSS ? '未找到CSS资源' : null);
    recordTest(`${pageName}页面JS资源`, hasJS, !hasJS ? '未找到JS资源' : null);
    
    return true;
    
  } catch (error) {
    recordTest(`${pageName}页面可访问性`, false, error.message);
    return false;
  }
}

// 测试API端点连通性
async function testAPIConnectivity() {
  console.log('\n=== 测试API连通性 ===');
  
  const apiUrl = 'https://smellpin-workers.dev-small-1.workers.dev';
  
  try {
    // 测试健康检查端点
    const healthResponse = await makeRequest(`${apiUrl}/health`);
    
    if (healthResponse.statusCode === 200) {
      recordTest('API健康检查端点', true);
      
      try {
        const healthData = JSON.parse(healthResponse.body);
        if (healthData.status === 'ok') {
          recordTest('API健康状态', true);
        } else {
          recordTest('API健康状态', false, `状态: ${healthData.status}`);
        }
      } catch (e) {
        recordTest('API健康状态', false, '响应格式错误');
      }
    } else {
      recordTest('API健康检查端点', false, `状态码: ${healthResponse.statusCode}`);
    }
    
  } catch (error) {
    recordTest('API连通性', false, error.message);
  }
}

// 测试前端服务器状态
async function testFrontendServer() {
  console.log('\n=== 测试前端服务器状态 ===');
  
  try {
    const response = await makeRequest(config.baseUrl);
    
    if (response.statusCode === 200) {
      recordTest('前端服务器运行状态', true);
      
      // 检查Vite开发服务器特征
      if (response.body.includes('vite') || response.body.includes('@vite')) {
        recordTest('Vite开发服务器', true);
      } else {
        recordTest('Vite开发服务器', false, '未检测到Vite特征');
      }
      
      return true;
    } else {
      recordTest('前端服务器运行状态', false, `状态码: ${response.statusCode}`);
      return false;
    }
    
  } catch (error) {
    recordTest('前端服务器状态', false, error.message);
    return false;
  }
}

// 测试路由配置
async function testRouting() {
  console.log('\n=== 测试前端路由配置 ===');
  
  const routes = [
    { path: '/', name: '主页' },
    { path: '/login', name: '登录页' },
    { path: '/register', name: '注册页' },
    { path: '/map', name: '地图页' },
    { path: '/profile', name: '个人资料页' }
  ];
  
  for (const route of routes) {
    await testPageAccessibility(route.path, route.name);
    // 添加延迟避免请求过快
    await new Promise(resolve => setTimeout(resolve, 500));
  }
}

// 测试静态资源
async function testStaticResources() {
  console.log('\n=== 测试静态资源 ===');
  
  try {
    // 测试favicon
    const faviconResponse = await makeRequest(`${config.baseUrl}/favicon.ico`);
    recordTest('Favicon资源', faviconResponse.statusCode === 200, 
      faviconResponse.statusCode !== 200 ? `状态码: ${faviconResponse.statusCode}` : null);
    
  } catch (error) {
    recordTest('静态资源测试', false, error.message);
  }
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始前端功能测试...\n');
  console.log(`测试目标: ${config.baseUrl}`);
  
  try {
    // 测试前端服务器
    const serverRunning = await testFrontendServer();
    
    if (serverRunning) {
      // 测试路由
      await testRouting();
      
      // 测试静态资源
      await testStaticResources();
    }
    
    // 测试API连通性
    await testAPIConnectivity();
    
  } catch (error) {
    console.error('测试执行失败:', error);
    recordTest('测试执行', false, error.message);
  }
  
  // 输出测试结果
  console.log('\n' + '='.repeat(50));
  console.log('📊 前端功能测试结果');
  console.log('='.repeat(50));
  console.log(`✅ 通过: ${testResults.passed}`);
  console.log(`❌ 失败: ${testResults.failed}`);
  
  if (testResults.passed + testResults.failed > 0) {
    const successRate = ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1);
    console.log(`📈 成功率: ${successRate}%`);
  }
  
  if (testResults.errors.length > 0) {
    console.log('\n🔍 失败详情:');
    testResults.errors.forEach((error, index) => {
      console.log(`${index + 1}. ${error.test}: ${error.error}`);
    });
  }
  
  console.log('\n✨ 前端功能测试完成!');
  
  // 返回测试结果供其他脚本使用
  return {
    passed: testResults.passed,
    failed: testResults.failed,
    errors: testResults.errors,
    successRate: testResults.passed + testResults.failed > 0 ? 
      ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1) : 0
  };
}

// 执行测试
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests, testResults };