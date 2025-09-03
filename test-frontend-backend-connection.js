const axios = require('axios');

// 测试前端到后端的连接
async function testFrontendBackendConnection() {
  console.log('🔄 开始测试前端与后端连接...');
  
  const frontendUrl = 'http://localhost:5176';
  const backendUrl = 'http://localhost:8787';
  
  const tests = [
    {
      name: '前端页面加载',
      test: async () => {
        const response = await axios.get(frontendUrl, { timeout: 5000 });
        return response.status === 200 && response.data.includes('SmellPin');
      }
    },
    {
      name: '后端API健康检查',
      test: async () => {
        const response = await axios.get(`${backendUrl}/health`, { timeout: 5000 });
        return response.status === 200 && response.data.status === 'healthy';
      }
    },
    {
      name: '后端根路径响应',
      test: async () => {
        const response = await axios.get(backendUrl, { timeout: 5000 });
        return response.status === 200 && response.data.message === 'SmellPin Workers API';
      }
    },
    {
      name: '前端环境变量配置',
      test: async () => {
        // 检查前端是否正确配置了后端API地址
        const fs = require('fs');
        const envContent = fs.readFileSync('/Users/xiaoyang/Downloads/臭味/frontend/.env', 'utf8');
        return envContent.includes('VITE_API_URL=http://localhost:8787');
      }
    },
    {
      name: '跨域请求测试',
      test: async () => {
        // 模拟前端发起的API请求
        const response = await axios.get(`${backendUrl}/health`, {
          headers: {
            'Origin': frontendUrl,
            'Content-Type': 'application/json'
          },
          timeout: 5000
        });
        return response.status === 200;
      }
    }
  ];
  
  const results = [];
  
  for (const test of tests) {
    try {
      console.log(`\n🧪 测试: ${test.name}`);
      const result = await test.test();
      if (result) {
        console.log(`✅ ${test.name} - 通过`);
        results.push({ name: test.name, status: 'PASS', error: null });
      } else {
        console.log(`❌ ${test.name} - 失败`);
        results.push({ name: test.name, status: 'FAIL', error: '测试条件不满足' });
      }
    } catch (error) {
      console.log(`❌ ${test.name} - 错误: ${error.message}`);
      results.push({ name: test.name, status: 'ERROR', error: error.message });
    }
  }
  
  // 生成测试报告
  const report = {
    timestamp: new Date().toISOString(),
    frontend_url: frontendUrl,
    backend_url: backendUrl,
    total_tests: tests.length,
    passed: results.filter(r => r.status === 'PASS').length,
    failed: results.filter(r => r.status === 'FAIL').length,
    errors: results.filter(r => r.status === 'ERROR').length,
    results: results
  };
  
  console.log('\n📊 测试报告:');
  console.log(`总测试数: ${report.total_tests}`);
  console.log(`通过: ${report.passed}`);
  console.log(`失败: ${report.failed}`);
  console.log(`错误: ${report.errors}`);
  
  // 保存详细报告
  const fs = require('fs');
  fs.writeFileSync(
    '/Users/xiaoyang/Downloads/臭味/frontend-backend-connection-test-report.json',
    JSON.stringify(report, null, 2)
  );
  
  console.log('\n📄 详细报告已保存到: frontend-backend-connection-test-report.json');
  
  if (report.passed === report.total_tests) {
    console.log('\n🎉 所有测试通过！前端与后端连接正常。');
    return true;
  } else {
    console.log('\n⚠️  部分测试失败，请检查配置。');
    return false;
  }
}

// 运行测试
testFrontendBackendConnection()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('测试执行失败:', error);
    process.exit(1);
  });