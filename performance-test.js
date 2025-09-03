/**
 * SmellPin API性能测试脚本
 * 用于验证优化效果和监控API性能
 */

const axios = require('axios');
const { performance } = require('perf_hooks');

// 测试配置
const config = {
  baseURL: 'http://localhost:3000',
  testDuration: 60000, // 60秒测试
  concurrentUsers: 10, // 并发用户数
  requests: [
    { method: 'GET', path: '/api/v1/annotations/list', weight: 40 },
    { method: 'GET', path: '/health', weight: 20 },
    { method: 'GET', path: '/api/v1/annotations/nearby?latitude=40.7128&longitude=-74.0060&radius=5000', weight: 20 },
    { method: 'GET', path: '/api/v1/users/1', weight: 20 },
  ]
};

// 测试结果存储
const results = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  responseTimes: [],
  errors: [],
  startTime: null,
  endTime: null,
};

// 颜色输出
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

// 创建HTTP客户端
const client = axios.create({
  baseURL: config.baseURL,
  timeout: 10000,
  validateStatus: (status) => status < 500, // 4xx也算成功，只有5xx算失败
});

// 选择随机请求
function getRandomRequest() {
  const totalWeight = config.requests.reduce((sum, req) => sum + req.weight, 0);
  let random = Math.random() * totalWeight;
  
  for (const request of config.requests) {
    random -= request.weight;
    if (random <= 0) {
      return request;
    }
  }
  return config.requests[0];
}

// 执行单个请求
async function makeRequest() {
  const request = getRandomRequest();
  const startTime = performance.now();
  
  try {
    results.totalRequests++;
    
    const response = await client.request({
      method: request.method,
      url: request.path,
    });
    
    const endTime = performance.now();
    const responseTime = endTime - startTime;
    
    results.responseTimes.push(responseTime);
    results.successfulRequests++;
    
    // 记录详细信息
    if (responseTime > 1000) {
      log(`⚠️  Slow request: ${request.method} ${request.path} - ${responseTime.toFixed(2)}ms`, colors.yellow);
    }
    
    return {
      success: true,
      responseTime,
      statusCode: response.status,
      url: request.path,
    };
  } catch (error) {
    const endTime = performance.now();
    const responseTime = endTime - startTime;
    
    results.failedRequests++;
    results.errors.push({
      url: request.path,
      error: error.message,
      responseTime,
    });
    
    log(`❌ Failed request: ${request.method} ${request.path} - ${error.message}`, colors.red);
    
    return {
      success: false,
      responseTime,
      error: error.message,
      url: request.path,
    };
  }
}

// 模拟单个用户的请求
async function simulateUser(userId) {
  const userResults = {
    requests: 0,
    successfulRequests: 0,
    failedRequests: 0,
  };
  
  const startTime = Date.now();
  
  while (Date.now() - startTime < config.testDuration) {
    const result = await makeRequest();
    userResults.requests++;
    
    if (result.success) {
      userResults.successfulRequests++;
    } else {
      userResults.failedRequests++;
    }
    
    // 模拟用户思考时间（100-500ms）
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 400));
  }
  
  return userResults;
}

// 计算统计信息
function calculateStats() {
  const responseTimes = results.responseTimes.sort((a, b) => a - b);
  const totalTime = results.endTime - results.startTime;
  
  return {
    duration: totalTime / 1000,
    totalRequests: results.totalRequests,
    successfulRequests: results.successfulRequests,
    failedRequests: results.failedRequests,
    successRate: (results.successfulRequests / results.totalRequests * 100).toFixed(2),
    requestsPerSecond: (results.totalRequests / (totalTime / 1000)).toFixed(2),
    avgResponseTime: (responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length).toFixed(2),
    minResponseTime: responseTimes[0]?.toFixed(2) || 0,
    maxResponseTime: responseTimes[responseTimes.length - 1]?.toFixed(2) || 0,
    p50ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.5)]?.toFixed(2) || 0,
    p95ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.95)]?.toFixed(2) || 0,
    p99ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.99)]?.toFixed(2) || 0,
  };
}

// 检查API健康状态
async function checkAPIHealth() {
  try {
    const response = await client.get('/health');
    if (response.status === 200) {
      log('✅ API is healthy and ready for testing', colors.green);
      return true;
    } else {
      log('❌ API health check failed', colors.red);
      return false;
    }
  } catch (error) {
    log(`❌ Cannot connect to API: ${error.message}`, colors.red);
    return false;
  }
}

// 获取性能监控数据（如果可用）
async function getPerformanceMonitoring() {
  try {
    // 注意：需要管理员权限，这里可能会失败
    const response = await client.get('/api/performance/overview');
    if (response.status === 200) {
      return response.data.data;
    }
  } catch (error) {
    // 忽略错误，性能监控可能需要认证
  }
  return null;
}

// 显示测试结果
function displayResults(stats, performanceData) {
  log('\n' + '='.repeat(60), colors.cyan);
  log('                 PERFORMANCE TEST RESULTS', colors.cyan);
  log('='.repeat(60), colors.cyan);
  
  log(`\n📊 Test Summary:`, colors.blue);
  log(`   Duration: ${stats.duration} seconds`);
  log(`   Total Requests: ${stats.totalRequests}`);
  log(`   Successful: ${stats.successfulRequests} (${stats.successRate}%)`, 
      stats.successRate >= 95 ? colors.green : colors.yellow);
  log(`   Failed: ${stats.failedRequests}`, 
      stats.failedRequests === 0 ? colors.green : colors.red);
  log(`   Throughput: ${stats.requestsPerSecond} requests/sec`);
  
  log(`\n⏱️  Response Times:`, colors.blue);
  log(`   Average: ${stats.avgResponseTime}ms`, 
      stats.avgResponseTime < 200 ? colors.green : stats.avgResponseTime < 500 ? colors.yellow : colors.red);
  log(`   Min: ${stats.minResponseTime}ms`);
  log(`   Max: ${stats.maxResponseTime}ms`);
  log(`   P50: ${stats.p50ResponseTime}ms`);
  log(`   P95: ${stats.p95ResponseTime}ms`, 
      stats.p95ResponseTime < 500 ? colors.green : colors.yellow);
  log(`   P99: ${stats.p99ResponseTime}ms`, 
      stats.p99ResponseTime < 1000 ? colors.green : colors.yellow);
  
  // 性能等级评估
  const grade = getPerformanceGrade(parseFloat(stats.avgResponseTime));
  const gradeColor = grade === 'A' ? colors.green : grade === 'B' ? colors.yellow : colors.red;
  log(`\n🎯 Performance Grade: ${grade}`, gradeColor);
  
  if (results.errors.length > 0) {
    log(`\n❌ Errors (${results.errors.length}):`, colors.red);
    const errorSummary = {};
    results.errors.forEach(error => {
      const key = `${error.url}: ${error.error}`;
      errorSummary[key] = (errorSummary[key] || 0) + 1;
    });
    
    Object.entries(errorSummary).forEach(([error, count]) => {
      log(`   ${count}x ${error}`, colors.red);
    });
  }
  
  // 显示性能监控数据
  if (performanceData) {
    log(`\n📈 Current System Status:`, colors.blue);
    log(`   System Status: ${performanceData.summary.status}`, 
        performanceData.summary.status === 'healthy' ? colors.green : colors.yellow);
    log(`   Cache Hit Rate: ${performanceData.cache.hitRate}%`);
    log(`   Memory Usage: ${performanceData.system.memory.percentage}%`);
  }
  
  // 优化建议
  log(`\n💡 Optimization Recommendations:`, colors.magenta);
  if (parseFloat(stats.avgResponseTime) > 200) {
    log(`   • Response time is high - check database queries and caching`, colors.yellow);
  }
  if (parseFloat(stats.successRate) < 95) {
    log(`   • Success rate is low - investigate error causes`, colors.yellow);
  }
  if (parseFloat(stats.p95ResponseTime) > 1000) {
    log(`   • P95 response time is high - optimize slowest endpoints`, colors.yellow);
  }
  if (parseFloat(stats.avgResponseTime) <= 200 && parseFloat(stats.successRate) >= 95) {
    log(`   • Excellent performance! 🎉`, colors.green);
  }
  
  log('\n' + '='.repeat(60), colors.cyan);
}

function getPerformanceGrade(avgResponseTime) {
  if (avgResponseTime < 100) return 'A+';
  if (avgResponseTime < 200) return 'A';
  if (avgResponseTime < 500) return 'B';
  if (avgResponseTime < 1000) return 'C';
  if (avgResponseTime < 2000) return 'D';
  return 'F';
}

// 主测试函数
async function runPerformanceTest() {
  log('🚀 Starting SmellPin API Performance Test', colors.cyan);
  log(`   Base URL: ${config.baseURL}`);
  log(`   Duration: ${config.testDuration / 1000}s`);
  log(`   Concurrent Users: ${config.concurrentUsers}`);
  log(`   Test Endpoints: ${config.requests.length}\n`);
  
  // 检查API健康状态
  const isHealthy = await checkAPIHealth();
  if (!isHealthy) {
    log('❌ Cannot proceed with testing - API is not available', colors.red);
    process.exit(1);
  }
  
  // 获取测试前的性能数据
  const preTestPerformance = await getPerformanceMonitoring();
  
  log('\n🏃 Starting load test...', colors.yellow);
  results.startTime = Date.now();
  
  // 启动并发用户
  const userPromises = [];
  for (let i = 0; i < config.concurrentUsers; i++) {
    userPromises.push(simulateUser(i));
  }
  
  // 显示进度
  const progressInterval = setInterval(() => {
    const elapsed = (Date.now() - results.startTime) / 1000;
    const progress = (elapsed / (config.testDuration / 1000) * 100).toFixed(1);
    process.stdout.write(`\r⏳ Progress: ${progress}% - Requests: ${results.totalRequests} - Success Rate: ${(results.successfulRequests / Math.max(results.totalRequests, 1) * 100).toFixed(1)}%`);
  }, 1000);
  
  // 等待所有用户完成
  await Promise.all(userPromises);
  results.endTime = Date.now();
  
  clearInterval(progressInterval);
  process.stdout.write('\n\n');
  
  log('✅ Load test completed!', colors.green);
  
  // 计算统计信息
  const stats = calculateStats();
  
  // 获取测试后的性能数据
  const postTestPerformance = await getPerformanceMonitoring();
  
  // 显示结果
  displayResults(stats, postTestPerformance);
  
  // 保存结果到文件
  const reportData = {
    timestamp: new Date().toISOString(),
    config,
    results: stats,
    errors: results.errors,
    preTestPerformance,
    postTestPerformance,
  };
  
  const fs = require('fs');
  const reportFile = `performance-test-report-${Date.now()}.json`;
  fs.writeFileSync(reportFile, JSON.stringify(reportData, null, 2));
  log(`\n📄 Detailed report saved to: ${reportFile}`, colors.cyan);
  
  // 退出码基于测试结果
  const exitCode = parseFloat(stats.successRate) >= 95 && parseFloat(stats.avgResponseTime) <= 500 ? 0 : 1;
  process.exit(exitCode);
}

// 处理中断信号
process.on('SIGINT', () => {
  log('\n\n⚠️  Test interrupted by user', colors.yellow);
  if (results.startTime && results.totalRequests > 0) {
    results.endTime = Date.now();
    const stats = calculateStats();
    displayResults(stats, null);
  }
  process.exit(1);
});

// 启动测试
runPerformanceTest().catch(error => {
  log(`\n❌ Test failed with error: ${error.message}`, colors.red);
  console.error(error);
  process.exit(1);
});