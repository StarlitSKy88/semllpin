#!/usr/bin/env node

/**
 * SmellPin 综合性能测试套件
 * 测试后端API性能、数据库查询性能、缓存系统效率
 * 
 * 运行方式: node tests/performance/comprehensive-performance-test.js
 */

const autocannon = require('autocannon');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// 测试配置
const TEST_CONFIG = {
  baseURL: 'http://localhost:3003',
  duration: 30, // 测试持续时间（秒）
  connections: 10, // 并发连接数
  pipelining: 1, // HTTP管道请求数
  targetRPS: 1000, // 目标每秒请求数
  
  // 测试阈值
  thresholds: {
    responseTime: 200, // 期望响应时间 < 200ms
    throughput: 500,   // 期望吞吐量 > 500 req/s
    errorRate: 0.01,   // 允许错误率 < 1%
    p95ResponseTime: 300, // P95响应时间 < 300ms
  }
};

// 测试结果存储
const testResults = {
  timestamp: new Date().toISOString(),
  config: TEST_CONFIG,
  tests: [],
  summary: {},
  recommendations: []
};

class PerformanceTestSuite {
  constructor() {
    this.testToken = null;
    this.testUser = null;
  }

  // 生成测试用户令牌
  async generateTestToken() {
    try {
      const response = await axios.post(`${TEST_CONFIG.baseURL}/api/v1/users/login`, {
        email: 'test@example.com',
        password: 'testpassword123'
      });
      
      if (response.data.success && response.data.data.accessToken) {
        this.testToken = response.data.data.accessToken;
        this.testUser = response.data.data.user;
        console.log('✓ 测试令牌生成成功');
        return true;
      }
    } catch (error) {
      console.warn('⚠ 测试用户不存在，将使用公开API进行测试');
      return false;
    }
  }

  // 1. 基础健康检查性能测试
  async testHealthCheck() {
    console.log('\n🏥 执行健康检查性能测试...');
    
    const startTime = performance.now();
    
    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/health`,
      connections: TEST_CONFIG.connections,
      duration: 10, // 较短的测试时间
      pipelining: TEST_CONFIG.pipelining,
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Health Check Performance',
      endpoint: '/health',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p50: result.latency.p50,
      p95: result.latency.p95,
      p99: result.latency.p99,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      timeouts: result.timeouts,
      passed: this.evaluatePerformance(result),
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('Health Check', testResult);
    return testResult;
  }

  // 2. API文档访问性能测试
  async testApiDocs() {
    console.log('\n📚 执行API文档访问性能测试...');
    
    const startTime = performance.now();
    
    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/api/v1/docs`,
      connections: TEST_CONFIG.connections,
      duration: 15,
      pipelining: TEST_CONFIG.pipelining,
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'API Documentation Access',
      endpoint: '/api/v1/docs',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p95: result.latency.p95,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      passed: this.evaluatePerformance(result),
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('API Docs', testResult);
    return testResult;
  }

  // 3. 标注列表查询性能测试（数据库密集型）
  async testAnnotationsList() {
    console.log('\n📍 执行标注列表查询性能测试...');
    
    const startTime = performance.now();
    
    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/api/v1/annotations/list?page=1&limit=10`,
      connections: TEST_CONFIG.connections,
      duration: TEST_CONFIG.duration,
      pipelining: TEST_CONFIG.pipelining,
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Annotations List Query',
      endpoint: '/api/v1/annotations/list',
      type: 'database-intensive',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p95: result.latency.p95,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      passed: this.evaluatePerformance(result),
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('Annotations List', testResult);
    return testResult;
  }

  // 4. 地理位置查询性能测试（PostGIS查询）
  async testNearbyAnnotations() {
    console.log('\n🌍 执行附近标注查询性能测试...');
    
    const startTime = performance.now();
    
    // 测试不同的地理位置
    const locations = [
      { lat: 39.9042, lng: 116.4074 }, // 北京
      { lat: 31.2304, lng: 121.4737 }, // 上海
      { lat: 22.3193, lng: 114.1694 }, // 香港
    ];

    let totalResult = null;
    
    for (const location of locations) {
      const result = await autocannon({
        url: `${TEST_CONFIG.baseURL}/api/v1/annotations/nearby?lat=${location.lat}&lng=${location.lng}&radius=5000`,
        connections: Math.ceil(TEST_CONFIG.connections / locations.length),
        duration: Math.ceil(TEST_CONFIG.duration / locations.length),
        pipelining: TEST_CONFIG.pipelining,
      });

      // 合并结果
      if (!totalResult) {
        totalResult = result;
      } else {
        totalResult.requests.total += result.requests.total;
        totalResult.latency.average = (totalResult.latency.average + result.latency.average) / 2;
        totalResult.latency.max = Math.max(totalResult.latency.max, result.latency.max);
        totalResult.errors += result.errors;
      }
    }

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Nearby Annotations GeoQuery',
      endpoint: '/api/v1/annotations/nearby',
      type: 'geospatial-query',
      duration: testDuration,
      avgLatency: totalResult.latency.average,
      maxLatency: totalResult.latency.max,
      p95: totalResult.latency.p95,
      throughput: totalResult.requests.average,
      totalRequests: totalResult.requests.total,
      errors: totalResult.errors,
      passed: this.evaluatePerformance(totalResult),
      raw: totalResult
    };

    testResults.tests.push(testResult);
    this.logTestResult('Nearby Annotations', testResult);
    return testResult;
  }

  // 5. 认证端点性能测试
  async testAuthEndpoints() {
    if (!this.testToken) {
      console.log('⚠ 跳过认证端点测试（无测试令牌）');
      return null;
    }

    console.log('\n🔐 执行认证端点性能测试...');
    
    const startTime = performance.now();
    
    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/api/v1/users/profile/me`,
      connections: TEST_CONFIG.connections,
      duration: 20,
      pipelining: TEST_CONFIG.pipelining,
      headers: {
        'Authorization': `Bearer ${this.testToken}`,
        'Content-Type': 'application/json'
      }
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Authenticated Profile Access',
      endpoint: '/api/v1/users/profile/me',
      type: 'authenticated',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p95: result.latency.p95,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      passed: this.evaluatePerformance(result),
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('Auth Profile', testResult);
    return testResult;
  }

  // 6. 并发写入性能测试（创建标注）
  async testConcurrentWrites() {
    if (!this.testToken) {
      console.log('⚠ 跳过并发写入测试（需要认证）');
      return null;
    }

    console.log('\n✍️ 执行并发写入性能测试...');
    
    const startTime = performance.now();
    
    // 模拟创建标注的POST请求
    const postData = JSON.stringify({
      title: `性能测试标注 ${Date.now()}`,
      description: '这是一个性能测试创建的标注',
      category: 'industrial',
      intensity: 7,
      location: {
        lat: 39.9042 + Math.random() * 0.01,
        lng: 116.4074 + Math.random() * 0.01
      },
      address: '北京市测试地址'
    });

    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/api/v1/annotations`,
      connections: 5, // 较低的并发数避免过度创建测试数据
      duration: 10,   // 较短的测试时间
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.testToken}`,
        'Content-Type': 'application/json'
      },
      body: postData
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Concurrent Annotation Creation',
      endpoint: '/api/v1/annotations',
      type: 'write-operation',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p95: result.latency.p95,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      passed: this.evaluatePerformance(result, { responseTime: 500 }), // 写操作允许更高的响应时间
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('Concurrent Writes', testResult);
    return testResult;
  }

  // 7. 静态资源服务性能测试
  async testStaticResources() {
    console.log('\n📁 执行静态资源服务性能测试...');
    
    const startTime = performance.now();
    
    const result = await autocannon({
      url: `${TEST_CONFIG.baseURL}/uploads/test.txt`,
      connections: TEST_CONFIG.connections * 2, // 静态资源可以更高并发
      duration: 15,
      pipelining: TEST_CONFIG.pipelining,
    });

    const endTime = performance.now();
    const testDuration = (endTime - startTime) / 1000;

    const testResult = {
      name: 'Static Resource Serving',
      endpoint: '/uploads/*',
      type: 'static-content',
      duration: testDuration,
      avgLatency: result.latency.average,
      maxLatency: result.latency.max,
      p95: result.latency.p95,
      throughput: result.requests.average,
      totalRequests: result.requests.total,
      errors: result.errors,
      passed: this.evaluatePerformance(result, { responseTime: 100 }), // 静态资源应该更快
      raw: result
    };

    testResults.tests.push(testResult);
    this.logTestResult('Static Resources', testResult);
    return testResult;
  }

  // 8. 内存和CPU使用率测试
  async testResourceUsage() {
    console.log('\n💾 执行资源使用率测试...');
    
    const startTime = performance.now();
    const startMemory = process.memoryUsage();
    
    // 执行一系列请求来测试资源消耗
    const promises = [];
    for (let i = 0; i < 100; i++) {
      promises.push(
        axios.get(`${TEST_CONFIG.baseURL}/health`).catch(() => {})
      );
    }
    
    await Promise.all(promises);
    
    const endTime = performance.now();
    const endMemory = process.memoryUsage();
    
    const resourceUsage = {
      name: 'Resource Usage Analysis',
      duration: (endTime - startTime) / 1000,
      memoryUsage: {
        heapUsedDelta: endMemory.heapUsed - startMemory.heapUsed,
        heapTotalDelta: endMemory.heapTotal - startMemory.heapTotal,
        externalDelta: endMemory.external - startMemory.external,
        rss: endMemory.rss,
      },
      passed: (endMemory.heapUsed - startMemory.heapUsed) < (50 * 1024 * 1024), // 内存增长 < 50MB
    };

    testResults.tests.push(resourceUsage);
    console.log(`📊 内存使用增长: ${Math.round((endMemory.heapUsed - startMemory.heapUsed) / 1024 / 1024)}MB`);
    return resourceUsage;
  }

  // 性能评估
  evaluatePerformance(result, customThresholds = {}) {
    const thresholds = { ...TEST_CONFIG.thresholds, ...customThresholds };
    
    const checks = {
      responseTime: result.latency.average <= thresholds.responseTime,
      throughput: result.requests.average >= thresholds.throughput,
      errorRate: (result.errors / result.requests.total) <= thresholds.errorRate,
      p95ResponseTime: result.latency.p95 <= thresholds.p95ResponseTime,
    };

    return Object.values(checks).every(check => check);
  }

  // 记录测试结果
  logTestResult(testName, result) {
    const status = result.passed ? '✅ PASSED' : '❌ FAILED';
    console.log(`\n${status} ${testName}:`);
    console.log(`  平均响应时间: ${Math.round(result.avgLatency)}ms`);
    console.log(`  P95响应时间: ${Math.round(result.p95)}ms`);
    console.log(`  吞吐量: ${Math.round(result.throughput)} req/s`);
    console.log(`  总请求数: ${result.totalRequests}`);
    console.log(`  错误数: ${result.errors}`);
  }

  // 生成性能报告
  generateReport() {
    console.log('\n📋 生成性能测试报告...');
    
    const passedTests = testResults.tests.filter(test => test.passed).length;
    const totalTests = testResults.tests.length;
    const overallScore = (passedTests / totalTests) * 100;

    // 计算汇总统计
    const avgResponseTimes = testResults.tests
      .filter(test => test.avgLatency)
      .map(test => test.avgLatency);
    
    const totalThroughput = testResults.tests
      .filter(test => test.throughput)
      .reduce((sum, test) => sum + test.throughput, 0);

    testResults.summary = {
      overallScore,
      passedTests,
      totalTests,
      avgResponseTime: avgResponseTimes.length > 0 
        ? Math.round(avgResponseTimes.reduce((a, b) => a + b) / avgResponseTimes.length)
        : 0,
      totalThroughput: Math.round(totalThroughput),
      totalErrors: testResults.tests.reduce((sum, test) => sum + (test.errors || 0), 0),
    };

    // 生成优化建议
    this.generateRecommendations();

    // 输出结果到文件
    const reportPath = path.join(__dirname, `../test-results/performance-report-${Date.now()}.json`);
    
    // 确保目录存在
    const reportDir = path.dirname(reportPath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(testResults, null, 2));

    console.log(`\n🎯 整体性能评分: ${overallScore.toFixed(1)}%`);
    console.log(`📊 测试通过率: ${passedTests}/${totalTests}`);
    console.log(`⚡ 平均响应时间: ${testResults.summary.avgResponseTime}ms`);
    console.log(`🚀 总吞吐量: ${testResults.summary.totalThroughput} req/s`);
    console.log(`❌ 总错误数: ${testResults.summary.totalErrors}`);
    console.log(`📄 详细报告: ${reportPath}`);

    return testResults;
  }

  // 生成优化建议
  generateRecommendations() {
    const recommendations = [];

    // 分析响应时间
    const slowTests = testResults.tests.filter(test => 
      test.avgLatency && test.avgLatency > TEST_CONFIG.thresholds.responseTime
    );
    
    if (slowTests.length > 0) {
      recommendations.push({
        category: 'Performance',
        priority: 'High',
        issue: '响应时间过慢',
        tests: slowTests.map(test => test.name),
        suggestion: '考虑添加缓存、优化数据库查询、增加服务器资源'
      });
    }

    // 分析吞吐量
    const lowThroughputTests = testResults.tests.filter(test =>
      test.throughput && test.throughput < TEST_CONFIG.thresholds.throughput
    );

    if (lowThroughputTests.length > 0) {
      recommendations.push({
        category: 'Scalability',
        priority: 'Medium',
        issue: '吞吐量不足',
        tests: lowThroughputTests.map(test => test.name),
        suggestion: '考虑负载均衡、增加服务器实例、优化代码性能'
      });
    }

    // 分析错误率
    const errorTests = testResults.tests.filter(test =>
      test.errors && test.errors > 0
    );

    if (errorTests.length > 0) {
      recommendations.push({
        category: 'Reliability',
        priority: 'High',
        issue: '存在错误请求',
        tests: errorTests.map(test => test.name),
        suggestion: '检查错误日志、修复API问题、增强错误处理'
      });
    }

    // 数据库优化建议
    const dbTests = testResults.tests.filter(test => 
      test.type === 'database-intensive' && (!test.passed || test.avgLatency > 100)
    );

    if (dbTests.length > 0) {
      recommendations.push({
        category: 'Database',
        priority: 'Medium',
        issue: '数据库查询性能需要优化',
        tests: dbTests.map(test => test.name),
        suggestion: '添加数据库索引、优化查询语句、使用Redis缓存、考虑读写分离'
      });
    }

    testResults.recommendations = recommendations;
  }

  // 执行所有测试
  async runAllTests() {
    console.log('🚀 开始SmellPin性能测试套件');
    console.log(`🎯 目标服务: ${TEST_CONFIG.baseURL}`);
    console.log(`⏱️ 测试持续时间: ${TEST_CONFIG.duration}秒`);
    console.log(`🔗 并发连接数: ${TEST_CONFIG.connections}`);
    
    try {
      // 生成测试令牌
      await this.generateTestToken();

      // 执行所有测试
      await this.testHealthCheck();
      await this.testApiDocs();
      await this.testAnnotationsList();
      await this.testNearbyAnnotations();
      await this.testAuthEndpoints();
      await this.testConcurrentWrites();
      await this.testStaticResources();
      await this.testResourceUsage();

      // 生成报告
      return this.generateReport();

    } catch (error) {
      console.error('❌ 测试执行失败:', error);
      throw error;
    }
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const testSuite = new PerformanceTestSuite();
  
  testSuite.runAllTests()
    .then(results => {
      console.log('\n✅ 所有性能测试完成');
      process.exit(results.summary.overallScore >= 80 ? 0 : 1);
    })
    .catch(error => {
      console.error('❌ 性能测试失败:', error);
      process.exit(1);
    });
}

module.exports = PerformanceTestSuite;