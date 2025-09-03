const autocannon = require('autocannon');
const { performance } = require('perf_hooks');
const fs = require('fs');
const path = require('path');

// 性能测试配置
const testConfig = {
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:8787',
  duration: 30, // 测试持续时间（秒）
  connections: 10, // 并发连接数
  pipelining: 1, // 管道请求数
  timeout: 10, // 超时时间（秒）
};

// 测试场景
const testScenarios = [
  {
    name: 'Health Check',
    path: '/health',
    method: 'GET',
    connections: 50,
    duration: 10,
  },
  {
    name: 'User Registration',
    path: '/auth/register',
    method: 'POST',
    body: JSON.stringify({
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
    }),
    headers: {
      'Content-Type': 'application/json',
    },
    connections: 5,
    duration: 15,
  },
  {
    name: 'User Login',
    path: '/auth/login',
    method: 'POST',
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'password123',
    }),
    headers: {
      'Content-Type': 'application/json',
    },
    connections: 10,
    duration: 15,
  },
  {
    name: 'Get Annotations',
    path: '/annotations',
    method: 'GET',
    connections: 20,
    duration: 20,
  },
  {
    name: 'Create Annotation',
    path: '/annotations',
    method: 'POST',
    body: JSON.stringify({
      latitude: 40.7128,
      longitude: -74.0060,
      smell_intensity: 5,
      description: 'Test annotation',
      category: 'sewage',
    }),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token',
    },
    connections: 10,
    duration: 20,
  },
  {
    name: 'Get User Profile',
    path: '/users/me',
    method: 'GET',
    headers: {
      'Authorization': 'Bearer test-token',
    },
    connections: 15,
    duration: 15,
  },
];

// 运行单个测试场景
async function runTestScenario(scenario) {
  console.log(`\n🚀 Running test: ${scenario.name}`);
  console.log(`📍 Endpoint: ${scenario.method} ${scenario.path}`);
  console.log(`⏱️  Duration: ${scenario.duration}s, Connections: ${scenario.connections}`);
  
  const startTime = performance.now();
  
  try {
    const result = await autocannon({
      url: `${testConfig.baseUrl}${scenario.path}`,
      method: scenario.method,
      body: scenario.body,
      headers: scenario.headers,
      connections: scenario.connections || testConfig.connections,
      duration: scenario.duration || testConfig.duration,
      pipelining: testConfig.pipelining,
      timeout: testConfig.timeout,
    });
    
    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;
    
    // 分析结果
    const analysis = analyzeResults(result, scenario, testDuration);
    
    console.log(`✅ Test completed in ${testDuration.toFixed(2)}s`);
    console.log(`📊 Results:`);
    console.log(`   • Requests: ${result.requests.total} (${result.requests.average}/s)`);
    console.log(`   • Latency: avg ${result.latency.average}ms, p99 ${result.latency.p99}ms`);
    console.log(`   • Throughput: ${(result.throughput.average / 1024 / 1024).toFixed(2)} MB/s`);
    console.log(`   • Errors: ${result.errors} (${((result.errors / result.requests.total) * 100).toFixed(2)}%)`);
    console.log(`   • Status: ${analysis.status}`);
    
    return {
      scenario: scenario.name,
      ...result,
      analysis,
      testDuration,
    };
  } catch (error) {
    console.error(`❌ Test failed: ${error.message}`);
    return {
      scenario: scenario.name,
      error: error.message,
      status: 'FAILED',
    };
  }
}

// 分析测试结果
function analyzeResults(result, scenario, testDuration) {
  const analysis = {
    status: 'UNKNOWN',
    issues: [],
    recommendations: [],
  };
  
  // 检查错误率
  const errorRate = (result.errors / result.requests.total) * 100;
  if (errorRate > 5) {
    analysis.issues.push(`High error rate: ${errorRate.toFixed(2)}%`);
    analysis.recommendations.push('Check server logs for errors');
  }
  
  // 检查响应时间
  if (result.latency.average > 1000) {
    analysis.issues.push(`High average latency: ${result.latency.average}ms`);
    analysis.recommendations.push('Optimize database queries and add caching');
  }
  
  if (result.latency.p99 > 5000) {
    analysis.issues.push(`Very high p99 latency: ${result.latency.p99}ms`);
    analysis.recommendations.push('Investigate slow queries and bottlenecks');
  }
  
  // 检查吞吐量
  const expectedMinThroughput = {
    'GET': 100, // 每秒最少100个请求
    'POST': 50, // 每秒最少50个请求
    'PUT': 50,
    'DELETE': 50,
  };
  
  const minThroughput = expectedMinThroughput[scenario.method] || 50;
  if (result.requests.average < minThroughput) {
    analysis.issues.push(`Low throughput: ${result.requests.average} req/s (expected: >${minThroughput})`);
    analysis.recommendations.push('Scale up server resources or optimize code');
  }
  
  // 确定整体状态
  if (analysis.issues.length === 0) {
    analysis.status = 'EXCELLENT';
  } else if (analysis.issues.length <= 2 && errorRate < 1) {
    analysis.status = 'GOOD';
  } else if (errorRate < 5) {
    analysis.status = 'NEEDS_IMPROVEMENT';
  } else {
    analysis.status = 'POOR';
  }
  
  return analysis;
}

// 生成性能报告
function generateReport(results) {
  const timestamp = new Date().toISOString();
  const report = {
    timestamp,
    testConfig,
    summary: {
      totalTests: results.length,
      passed: results.filter(r => !r.error).length,
      failed: results.filter(r => r.error).length,
      excellent: results.filter(r => r.analysis?.status === 'EXCELLENT').length,
      good: results.filter(r => r.analysis?.status === 'GOOD').length,
      needsImprovement: results.filter(r => r.analysis?.status === 'NEEDS_IMPROVEMENT').length,
      poor: results.filter(r => r.analysis?.status === 'POOR').length,
    },
    results,
    recommendations: [],
  };
  
  // 收集所有建议
  const allRecommendations = new Set();
  results.forEach(result => {
    if (result.analysis?.recommendations) {
      result.analysis.recommendations.forEach(rec => allRecommendations.add(rec));
    }
  });
  report.recommendations = Array.from(allRecommendations);
  
  return report;
}

// 保存报告到文件
function saveReport(report) {
  const reportsDir = path.join(__dirname, 'reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
  
  const filename = `performance-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  const filepath = path.join(reportsDir, filename);
  
  fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
  console.log(`\n📄 Report saved to: ${filepath}`);
  
  return filepath;
}

// 打印总结报告
function printSummary(report) {
  console.log('\n' + '='.repeat(60));
  console.log('🎯 PERFORMANCE TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`📅 Test Date: ${new Date(report.timestamp).toLocaleString()}`);
  console.log(`🎪 Total Tests: ${report.summary.totalTests}`);
  console.log(`✅ Passed: ${report.summary.passed}`);
  console.log(`❌ Failed: ${report.summary.failed}`);
  console.log('');
  console.log('📊 Performance Grades:');
  console.log(`   🌟 Excellent: ${report.summary.excellent}`);
  console.log(`   👍 Good: ${report.summary.good}`);
  console.log(`   ⚠️  Needs Improvement: ${report.summary.needsImprovement}`);
  console.log(`   🚨 Poor: ${report.summary.poor}`);
  
  if (report.recommendations.length > 0) {
    console.log('\n💡 Recommendations:');
    report.recommendations.forEach((rec, index) => {
      console.log(`   ${index + 1}. ${rec}`);
    });
  }
  
  console.log('\n' + '='.repeat(60));
}

// 主测试函数
async function runPerformanceTests() {
  console.log('🚀 Starting Performance Tests...');
  console.log(`🎯 Target: ${testConfig.baseUrl}`);
  console.log(`⏱️  Total scenarios: ${testScenarios.length}`);
  
  const results = [];
  
  for (const scenario of testScenarios) {
    const result = await runTestScenario(scenario);
    results.push(result);
    
    // 在测试之间稍作停顿
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  // 生成和保存报告
  const report = generateReport(results);
  saveReport(report);
  printSummary(report);
  
  return report;
}

// 如果直接运行此脚本
if (require.main === module) {
  runPerformanceTests()
    .then(() => {
      console.log('\n🎉 Performance tests completed!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Performance tests failed:', error);
      process.exit(1);
    });
}

module.exports = {
  runPerformanceTests,
  runTestScenario,
  testScenarios,
  testConfig,
};