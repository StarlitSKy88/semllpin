#!/usr/bin/env node

/**
 * SmellPin 系统可靠性测试套件
 * 测试错误处理、恢复机制、服务可用性、数据完整性
 * 
 * 运行方式: node tests/reliability/system-reliability-test.js
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// 可靠性测试配置
const RELIABILITY_CONFIG = {
  baseURL: 'http://localhost:3003',
  testTimeout: 30000,
  retryAttempts: 3,
  
  // 测试阈值
  thresholds: {
    uptime: 99.5,        // 期望正常运行时间 > 99.5%
    errorRecovery: 5000, // 错误恢复时间 < 5秒
    dataIntegrity: 100,  // 数据完整性 = 100%
    responseConsistency: 95, // 响应一致性 > 95%
  }
};

// 测试结果存储
const reliabilityResults = {
  timestamp: new Date().toISOString(),
  config: RELIABILITY_CONFIG,
  tests: [],
  summary: {},
  issues: [],
  recommendations: []
};

class SystemReliabilityTestSuite {
  constructor() {
    this.testToken = null;
    this.systemMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      uptimeStart: Date.now()
    };
  }

  // 1. 服务可用性和正常运行时间测试
  async testServiceUptime() {
    console.log('\n⏰ 执行服务可用性测试...');
    
    const testResult = {
      name: 'Service Uptime & Availability Test',
      category: 'Availability',
      duration: 0,
      totalChecks: 0,
      successfulChecks: 0,
      failedChecks: 0,
      uptimePercentage: 0,
      averageResponseTime: 0,
      downtimeEvents: [],
      passed: true
    };

    const startTime = Date.now();
    const testDuration = 60000; // 1分钟测试
    const checkInterval = 2000; // 每2秒检查一次
    
    console.log('  持续监控服务可用性60秒...');
    
    while ((Date.now() - startTime) < testDuration) {
      const checkStart = Date.now();
      try {
        const response = await axios.get(`${RELIABILITY_CONFIG.baseURL}/health`, {
          timeout: 5000
        });
        
        const responseTime = Date.now() - checkStart;
        testResult.totalChecks++;
        
        if (response.status === 200) {
          testResult.successfulChecks++;
          testResult.averageResponseTime = 
            (testResult.averageResponseTime * (testResult.successfulChecks - 1) + responseTime) / testResult.successfulChecks;
        } else {
          testResult.failedChecks++;
          testResult.downtimeEvents.push({
            timestamp: new Date().toISOString(),
            status: response.status,
            responseTime
          });
        }
        
      } catch (error) {
        testResult.totalChecks++;
        testResult.failedChecks++;
        testResult.downtimeEvents.push({
          timestamp: new Date().toISOString(),
          error: error.message,
          responseTime: Date.now() - checkStart
        });
      }
      
      // 等待下次检查
      await new Promise(resolve => setTimeout(resolve, checkInterval));
    }
    
    testResult.duration = Date.now() - startTime;
    testResult.uptimePercentage = (testResult.successfulChecks / testResult.totalChecks) * 100;
    testResult.passed = testResult.uptimePercentage >= RELIABILITY_CONFIG.thresholds.uptime;
    
    if (!testResult.passed) {
      const issue = {
        type: 'Low Service Availability',
        severity: 'High',
        description: `服务可用性 ${testResult.uptimePercentage.toFixed(2)}% 低于阈值 ${RELIABILITY_CONFIG.thresholds.uptime}%`,
        evidence: {
          uptimePercentage: testResult.uptimePercentage,
          downtimeEvents: testResult.downtimeEvents.length,
          totalChecks: testResult.totalChecks
        }
      };
      
      reliabilityResults.issues.push(issue);
    }
    
    reliabilityResults.tests.push(testResult);
    this.logReliabilityResult('Service Uptime', testResult);
    return testResult;
  }

  // 2. 错误处理和恢复机制测试
  async testErrorHandling() {
    console.log('\n🚨 执行错误处理机制测试...');
    
    const testResult = {
      name: 'Error Handling & Recovery Test',
      category: 'Error Handling',
      tests: [],
      totalTests: 0,
      passedTests: 0,
      issues: [],
      passed: true
    };

    // 测试各种错误场景
    const errorScenarios = [
      {
        name: '404 Not Found',
        method: 'GET',
        url: '/api/v1/nonexistent-endpoint',
        expectedStatus: 404,
        description: '访问不存在的端点'
      },
      {
        name: '400 Bad Request',
        method: 'POST',
        url: '/api/v1/users/login',
        data: { invalidField: 'test' },
        expectedStatus: 400,
        description: '发送无效的请求数据'
      },
      {
        name: '401 Unauthorized',
        method: 'GET',
        url: '/api/v1/users/profile/me',
        expectedStatus: 401,
        description: '未授权访问受保护资源'
      },
      {
        name: '413 Payload Too Large',
        method: 'POST',
        url: '/api/v1/annotations',
        data: { description: 'x'.repeat(50000) }, // 超大payload
        expectedStatus: 413,
        description: '发送超大请求体'
      },
      {
        name: '429 Too Many Requests',
        method: 'POST',
        url: '/api/v1/users/login',
        data: { email: 'test@test.com', password: 'wrong' },
        expectedStatus: 429,
        description: '触发速率限制',
        repeat: 10 // 重复请求触发限制
      }
    ];

    for (const scenario of errorScenarios) {
      console.log(`  测试场景: ${scenario.name}`);
      
      try {
        let response;
        const repeatCount = scenario.repeat || 1;
        
        for (let i = 0; i < repeatCount; i++) {
          response = await axios({
            method: scenario.method,
            url: `${RELIABILITY_CONFIG.baseURL}${scenario.url}`,
            data: scenario.data,
            timeout: RELIABILITY_CONFIG.testTimeout,
            validateStatus: () => true // 不抛出错误
          });
          
          if (repeatCount > 1 && i < repeatCount - 1) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        }
        
        const testCase = {
          scenario: scenario.name,
          method: scenario.method,
          url: scenario.url,
          expectedStatus: scenario.expectedStatus,
          actualStatus: response.status,
          hasErrorStructure: this.validateErrorResponse(response.data),
          responseTime: response.headers['x-response-time'],
          passed: response.status === scenario.expectedStatus
        };
        
        testResult.tests.push(testCase);
        testResult.totalTests++;
        
        if (testCase.passed && testCase.hasErrorStructure) {
          testResult.passedTests++;
          console.log(`    ✅ ${scenario.name}: 返回正确状态码 ${response.status}`);
        } else {
          testResult.issues.push({
            scenario: scenario.name,
            expected: scenario.expectedStatus,
            actual: response.status,
            hasValidErrorStructure: testCase.hasErrorStructure
          });
          console.log(`    ❌ ${scenario.name}: 期望 ${scenario.expectedStatus}, 实际 ${response.status}`);
        }
        
      } catch (error) {
        testResult.totalTests++;
        testResult.issues.push({
          scenario: scenario.name,
          error: error.message
        });
        console.log(`    ❌ ${scenario.name}: 测试异常 - ${error.message}`);
      }
    }
    
    testResult.passed = testResult.passedTests === testResult.totalTests;
    
    if (!testResult.passed) {
      const issue = {
        type: 'Inadequate Error Handling',
        severity: 'Medium',
        description: `错误处理测试通过率 ${testResult.passedTests}/${testResult.totalTests}`,
        evidence: testResult.issues
      };
      
      reliabilityResults.issues.push(issue);
    }
    
    reliabilityResults.tests.push(testResult);
    this.logReliabilityResult('Error Handling', testResult);
    return testResult;
  }

  // 3. 数据一致性和完整性测试
  async testDataIntegrity() {
    console.log('\n🗄️ 执行数据完整性测试...');
    
    const testResult = {
      name: 'Data Integrity & Consistency Test',
      category: 'Data Integrity',
      tests: [],
      totalOperations: 0,
      successfulOperations: 0,
      dataInconsistencies: [],
      passed: true
    };

    // 测试数据CRUD操作的一致性
    const testOperations = [
      {
        name: 'Read Annotations List',
        operation: async () => {
          const response = await axios.get(`${RELIABILITY_CONFIG.baseURL}/api/v1/annotations/list`);
          return {
            success: response.status === 200,
            dataCount: response.data?.data?.annotations?.length || 0,
            hasExpectedStructure: this.validateAnnotationListStructure(response.data)
          };
        }
      },
      {
        name: 'Read Health Check',
        operation: async () => {
          const response = await axios.get(`${RELIABILITY_CONFIG.baseURL}/health`);
          return {
            success: response.status === 200,
            hasExpectedStructure: this.validateHealthResponse(response.data)
          };
        }
      },
      {
        name: 'Read API Documentation',
        operation: async () => {
          const response = await axios.get(`${RELIABILITY_CONFIG.baseURL}/api/v1/docs`);
          return {
            success: response.status === 200,
            hasExpectedStructure: this.validateApiDocsStructure(response.data)
          };
        }
      }
    ];

    // 多次执行相同操作，检查一致性
    const iterations = 5;
    
    for (const testOp of testOperations) {
      console.log(`  测试操作: ${testOp.name}`);
      
      const results = [];
      
      for (let i = 0; i < iterations; i++) {
        try {
          const result = await testOp.operation();
          results.push(result);
          testResult.totalOperations++;
          
          if (result.success) {
            testResult.successfulOperations++;
          }
          
        } catch (error) {
          testResult.totalOperations++;
          results.push({
            success: false,
            error: error.message
          });
        }
      }
      
      // 分析结果一致性
      const consistencyAnalysis = this.analyzeConsistency(results);
      
      const testCase = {
        operation: testOp.name,
        iterations,
        results,
        consistency: consistencyAnalysis,
        passed: consistencyAnalysis.isConsistent && results.every(r => r.success)
      };
      
      testResult.tests.push(testCase);
      
      if (!testCase.passed) {
        testResult.dataInconsistencies.push({
          operation: testOp.name,
          issue: consistencyAnalysis.isConsistent ? 'Operation failures' : 'Data inconsistency',
          details: consistencyAnalysis
        });
        console.log(`    ❌ ${testOp.name}: 数据不一致或操作失败`);
      } else {
        console.log(`    ✅ ${testOp.name}: 数据一致`);
      }
    }
    
    const integrityPercentage = (testResult.successfulOperations / testResult.totalOperations) * 100;
    testResult.integrityPercentage = integrityPercentage;
    testResult.passed = integrityPercentage >= RELIABILITY_CONFIG.thresholds.dataIntegrity && 
                       testResult.dataInconsistencies.length === 0;
    
    if (!testResult.passed) {
      const issue = {
        type: 'Data Integrity Issues',
        severity: 'High',
        description: `数据完整性 ${integrityPercentage.toFixed(2)}% 或存在一致性问题`,
        evidence: {
          integrityPercentage,
          inconsistencies: testResult.dataInconsistencies.length,
          totalOperations: testResult.totalOperations
        }
      };
      
      reliabilityResults.issues.push(issue);
    }
    
    reliabilityResults.tests.push(testResult);
    this.logReliabilityResult('Data Integrity', testResult);
    return testResult;
  }

  // 4. 负载下的系统稳定性测试
  async testStabilityUnderLoad() {
    console.log('\n⚡ 执行负载稳定性测试...');
    
    const testResult = {
      name: 'System Stability Under Load Test',
      category: 'Load Stability',
      duration: 0,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      maxResponseTime: 0,
      memoryUsage: [],
      performanceDegradation: [],
      passed: true
    };

    const startTime = Date.now();
    const testDuration = 30000; // 30秒负载测试
    const concurrency = 20; // 20个并发请求
    
    console.log(`  执行${testDuration/1000}秒的并发负载测试...`);
    
    // 监控内存使用
    const memoryMonitor = setInterval(() => {
      const memUsage = process.memoryUsage();
      testResult.memoryUsage.push({
        timestamp: Date.now(),
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external,
        rss: memUsage.rss
      });
    }, 5000);

    const promises = [];
    
    // 创建并发请求
    for (let i = 0; i < concurrency; i++) {
      const promise = this.runConcurrentRequests(startTime, testDuration, testResult);
      promises.push(promise);
    }
    
    await Promise.all(promises);
    clearInterval(memoryMonitor);
    
    testResult.duration = Date.now() - startTime;
    
    if (testResult.totalRequests > 0) {
      const successRate = (testResult.successfulRequests / testResult.totalRequests) * 100;
      testResult.successRate = successRate;
      
      // 分析性能退化
      testResult.performanceDegradation = this.analyzePerformanceDegradation(testResult.memoryUsage);
      
      testResult.passed = successRate >= 95 && testResult.averageResponseTime < 1000;
      
      if (!testResult.passed) {
        const issue = {
          type: 'System Instability Under Load',
          severity: 'High',
          description: `负载测试中成功率 ${successRate.toFixed(2)}% 或响应时间过慢`,
          evidence: {
            successRate,
            averageResponseTime: testResult.averageResponseTime,
            maxResponseTime: testResult.maxResponseTime,
            totalRequests: testResult.totalRequests
          }
        };
        
        reliabilityResults.issues.push(issue);
      }
    }
    
    reliabilityResults.tests.push(testResult);
    this.logReliabilityResult('Load Stability', testResult);
    return testResult;
  }

  // 5. 数据库连接池和Redis连接测试
  async testConnectionPooling() {
    console.log('\n🔗 执行连接池稳定性测试...');
    
    const testResult = {
      name: 'Database & Redis Connection Pool Test',
      category: 'Connection Management',
      dbTests: [],
      redisTests: [],
      connectionLeaks: [],
      passed: true
    };

    // 测试数据库连接
    console.log('  测试数据库连接稳定性...');
    
    const dbPromises = [];
    for (let i = 0; i < 50; i++) { // 50个并发数据库查询
      dbPromises.push(
        axios.get(`${RELIABILITY_CONFIG.baseURL}/api/v1/annotations/list?page=${i%5+1}&limit=5`)
          .then(response => ({
            success: response.status === 200,
            responseTime: parseInt(response.headers['x-response-time'] || '0'),
            timestamp: Date.now()
          }))
          .catch(error => ({
            success: false,
            error: error.message,
            timestamp: Date.now()
          }))
      );
    }
    
    testResult.dbTests = await Promise.all(dbPromises);
    
    // 测试Redis连接（通过健康检查）
    console.log('  测试Redis缓存连接...');
    
    const redisPromises = [];
    for (let i = 0; i < 30; i++) { // 30个并发健康检查（涉及Redis）
      redisPromises.push(
        axios.get(`${RELIABILITY_CONFIG.baseURL}/health`)
          .then(response => ({
            success: response.status === 200,
            responseTime: parseInt(response.headers['x-response-time'] || '0'),
            timestamp: Date.now()
          }))
          .catch(error => ({
            success: false,
            error: error.message,
            timestamp: Date.now()
          }))
      );
    }
    
    testResult.redisTests = await Promise.all(redisPromises);
    
    // 分析连接问题
    const dbFailures = testResult.dbTests.filter(test => !test.success);
    const redisFailures = testResult.redisTests.filter(test => !test.success);
    
    testResult.dbSuccessRate = ((testResult.dbTests.length - dbFailures.length) / testResult.dbTests.length) * 100;
    testResult.redisSuccessRate = ((testResult.redisTests.length - redisFailures.length) / testResult.redisTests.length) * 100;
    
    testResult.passed = testResult.dbSuccessRate >= 95 && testResult.redisSuccessRate >= 95;
    
    if (!testResult.passed) {
      const issue = {
        type: 'Connection Pool Issues',
        severity: 'High',
        description: '数据库或Redis连接池存在稳定性问题',
        evidence: {
          dbSuccessRate: testResult.dbSuccessRate,
          redisSuccessRate: testResult.redisSuccessRate,
          dbFailures: dbFailures.length,
          redisFailures: redisFailures.length
        }
      };
      
      reliabilityResults.issues.push(issue);
    }
    
    reliabilityResults.tests.push(testResult);
    this.logReliabilityResult('Connection Pooling', testResult);
    return testResult;
  }

  // 辅助方法

  async runConcurrentRequests(startTime, duration, testResult) {
    const endpoints = [
      '/health',
      '/api/v1/annotations/list',
      '/api/v1/docs'
    ];
    
    while ((Date.now() - startTime) < duration) {
      const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
      const requestStart = Date.now();
      
      try {
        const response = await axios.get(`${RELIABILITY_CONFIG.baseURL}${endpoint}`, {
          timeout: 10000
        });
        
        const responseTime = Date.now() - requestStart;
        
        testResult.totalRequests++;
        if (response.status === 200) {
          testResult.successfulRequests++;
          
          // 更新平均响应时间
          testResult.averageResponseTime = 
            (testResult.averageResponseTime * (testResult.successfulRequests - 1) + responseTime) / testResult.successfulRequests;
          
          // 更新最大响应时间
          testResult.maxResponseTime = Math.max(testResult.maxResponseTime, responseTime);
        } else {
          testResult.failedRequests++;
        }
        
      } catch (error) {
        testResult.totalRequests++;
        testResult.failedRequests++;
      }
      
      // 短暂等待避免过度负载
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  }

  validateErrorResponse(data) {
    return data && 
           typeof data.success === 'boolean' && 
           !data.success && 
           (data.message || data.error);
  }

  validateAnnotationListStructure(data) {
    return data && 
           typeof data.success === 'boolean' && 
           data.data && 
           Array.isArray(data.data.annotations);
  }

  validateHealthResponse(data) {
    return data && 
           typeof data.success === 'boolean' && 
           data.success && 
           data.data && 
           data.data.status === 'ok';
  }

  validateApiDocsStructure(data) {
    return data && 
           typeof data.success === 'boolean' && 
           data.success && 
           data.endpoints;
  }

  analyzeConsistency(results) {
    if (results.length === 0) return { isConsistent: false, reason: 'No results' };
    
    const successCount = results.filter(r => r.success).length;
    const hasExpectedStructure = results.filter(r => r.hasExpectedStructure).length;
    
    return {
      isConsistent: successCount === results.length,
      successRate: (successCount / results.length) * 100,
      structureValidationRate: (hasExpectedStructure / results.length) * 100,
      reason: successCount === results.length ? 'All operations successful' : 'Some operations failed'
    };
  }

  analyzePerformanceDegradation(memoryUsage) {
    if (memoryUsage.length < 2) return [];
    
    const degradation = [];
    for (let i = 1; i < memoryUsage.length; i++) {
      const current = memoryUsage[i];
      const previous = memoryUsage[i - 1];
      
      const heapGrowth = ((current.heapUsed - previous.heapUsed) / previous.heapUsed) * 100;
      
      if (heapGrowth > 20) { // 20%以上的内存增长
        degradation.push({
          timestamp: current.timestamp,
          heapGrowthPercent: heapGrowth,
          heapUsed: current.heapUsed
        });
      }
    }
    
    return degradation;
  }

  logReliabilityResult(testName, result) {
    const status = result.passed ? '✅ PASSED' : '❌ FAILED';
    
    console.log(`\n${status} ${testName}:`);
    
    if (result.uptimePercentage !== undefined) {
      console.log(`  正常运行时间: ${result.uptimePercentage.toFixed(2)}%`);
      console.log(`  平均响应时间: ${Math.round(result.averageResponseTime)}ms`);
    }
    
    if (result.passedTests !== undefined) {
      console.log(`  测试通过率: ${result.passedTests}/${result.totalTests}`);
    }
    
    if (result.successRate !== undefined) {
      console.log(`  成功率: ${result.successRate.toFixed(2)}%`);
    }
    
    if (result.integrityPercentage !== undefined) {
      console.log(`  数据完整性: ${result.integrityPercentage.toFixed(2)}%`);
    }
  }

  // 生成可靠性报告
  generateReliabilityReport() {
    console.log('\n📊 生成系统可靠性报告...');
    
    const passedTests = reliabilityResults.tests.filter(test => test.passed).length;
    const totalTests = reliabilityResults.tests.length;
    const totalIssues = reliabilityResults.issues.length;
    
    // 计算整体可靠性分数
    const reliabilityScore = totalIssues === 0 ? 100 : 
      Math.max(0, 100 - (reliabilityResults.issues.length * 15));

    reliabilityResults.summary = {
      reliabilityScore,
      passedTests,
      totalTests,
      totalIssues,
      riskLevel: this.calculateReliabilityRisk(reliabilityResults.issues)
    };

    // 生成改进建议
    this.generateReliabilityRecommendations();

    // 输出结果到文件
    const reportPath = path.join(__dirname, `../test-results/reliability-report-${Date.now()}.json`);
    
    // 确保目录存在
    const reportDir = path.dirname(reportPath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(reliabilityResults, null, 2));

    console.log(`\n🎯 可靠性评分: ${reliabilityScore.toFixed(1)}/100`);
    console.log(`🛡️ 风险等级: ${reliabilityResults.summary.riskLevel}`);
    console.log(`📊 测试通过率: ${passedTests}/${totalTests}`);
    console.log(`🚨 发现问题: ${totalIssues} 个`);
    console.log(`📄 详细报告: ${reportPath}`);

    return reliabilityResults;
  }

  calculateReliabilityRisk(issues) {
    const highSeverityIssues = issues.filter(issue => issue.severity === 'High').length;
    const mediumSeverityIssues = issues.filter(issue => issue.severity === 'Medium').length;
    
    if (highSeverityIssues > 0) return 'High';
    if (mediumSeverityIssues > 1) return 'Medium';
    if (mediumSeverityIssues > 0) return 'Low';
    return 'Minimal';
  }

  generateReliabilityRecommendations() {
    const recommendations = [];

    // 基于发现的问题生成建议
    const issueTypes = [...new Set(reliabilityResults.issues.map(issue => issue.type))];
    
    issueTypes.forEach(issueType => {
      switch (issueType) {
        case 'Low Service Availability':
          recommendations.push({
            priority: 'High',
            category: '可用性',
            title: '提高服务可用性',
            description: '实施高可用性架构和监控',
            actions: [
              '部署多实例负载均衡',
              '实施健康检查和自动重启',
              '配置服务监控和告警',
              '实施灾难恢复计划'
            ]
          });
          break;
        
        case 'Inadequate Error Handling':
          recommendations.push({
            priority: 'Medium',
            category: '错误处理',
            title: '改善错误处理机制',
            description: '标准化错误响应格式和处理流程',
            actions: [
              '统一错误响应格式',
              '实施全局错误处理器',
              '添加详细的错误日志',
              '改善用户友好的错误消息'
            ]
          });
          break;
        
        case 'Data Integrity Issues':
          recommendations.push({
            priority: 'High',
            category: '数据完整性',
            title: '确保数据一致性',
            description: '实施数据验证和事务管理',
            actions: [
              '添加数据验证规则',
              '实施数据库事务',
              '配置数据备份策略',
              '实施数据完整性检查'
            ]
          });
          break;
      }
    });

    // 通用可靠性建议
    recommendations.push({
      priority: 'Medium',
      category: '监控和维护',
      title: '增强系统监控',
      description: '实施全面的系统监控和性能追踪',
      actions: [
        '配置应用性能监控(APM)',
        '实施日志聚合和分析',
        '设置关键指标告警',
        '建立运维手册和流程'
      ]
    });

    reliabilityResults.recommendations = recommendations;
  }

  // 执行所有可靠性测试
  async runAllTests() {
    console.log('🔧 开始SmellPin系统可靠性测试套件');
    console.log(`🎯 目标服务: ${RELIABILITY_CONFIG.baseURL}`);
    console.log(`⏱️ 请求超时: ${RELIABILITY_CONFIG.testTimeout}ms`);
    
    try {
      // 执行所有可靠性测试
      await this.testServiceUptime();
      await this.testErrorHandling();
      await this.testDataIntegrity();
      await this.testStabilityUnderLoad();
      await this.testConnectionPooling();

      // 生成报告
      return this.generateReliabilityReport();

    } catch (error) {
      console.error('❌ 可靠性测试执行失败:', error);
      throw error;
    }
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const testSuite = new SystemReliabilityTestSuite();
  
  testSuite.runAllTests()
    .then(results => {
      console.log('\n✅ 所有可靠性测试完成');
      process.exit(results.summary.reliabilityScore >= 80 ? 0 : 1);
    })
    .catch(error => {
      console.error('❌ 可靠性测试失败:', error);
      process.exit(1);
    });
}

module.exports = SystemReliabilityTestSuite;