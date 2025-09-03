#!/usr/bin/env node

/**
 * SmellPin项目综合功能集成测试
 * 测试所有核心业务功能的完整性和正确性
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 测试配置
const CONFIG = {
  API_BASE_URL: process.env.API_BASE_URL || 'http://localhost:3003',
  TEST_TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 1000,
  LOG_LEVEL: 'INFO' // DEBUG, INFO, WARN, ERROR
};

// 测试结果收集
const testResults = {
  summary: {
    timestamp: new Date().toISOString(),
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    successRate: '0%',
    totalDuration: 0
  },
  modules: {},
  recommendations: []
};

// 日志工具
const Logger = {
  debug: (message) => CONFIG.LOG_LEVEL === 'DEBUG' && console.log(`🔍 [DEBUG] ${message}`),
  info: (message) => ['DEBUG', 'INFO'].includes(CONFIG.LOG_LEVEL) && console.log(`ℹ️  [INFO] ${message}`),
  warn: (message) => ['DEBUG', 'INFO', 'WARN'].includes(CONFIG.LOG_LEVEL) && console.warn(`⚠️  [WARN] ${message}`),
  error: (message) => console.error(`❌ [ERROR] ${message}`)
};

// HTTP客户端配置
const apiClient = axios.create({
  baseURL: CONFIG.API_BASE_URL,
  timeout: CONFIG.TEST_TIMEOUT,
  validateStatus: () => true // 不自动抛出错误状态码
});

// 测试工具函数
class TestUtils {
  static async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  static async retryRequest(requestFn, attempts = CONFIG.RETRY_ATTEMPTS) {
    for (let i = 0; i < attempts; i++) {
      try {
        const result = await requestFn();
        if (result.status < 500) return result; // 非服务器错误直接返回
      } catch (error) {
        if (i === attempts - 1) throw error;
        await this.sleep(CONFIG.RETRY_DELAY);
      }
    }
  }

  static generateTestUser(suffix = Date.now()) {
    return {
      username: `testuser${suffix}`, // 只使用字母数字字符
      email: `test${suffix}@example.com`,
      password: 'Test123!@#', // 包含特殊字符的密码
      displayName: `Test User ${suffix}`
    };
  }

  static generateTestAnnotation(userId, suffix = Date.now()) {
    return {
      user_id: userId,
      title: `Test Smell ${suffix}`,
      description: `This is a test smell annotation created at ${new Date().toISOString()}`,
      smell_type: 'chemical',
      intensity: Math.floor(Math.random() * 5) + 1,
      latitude: 40.7128 + (Math.random() - 0.5) * 0.01,
      longitude: -74.0060 + (Math.random() - 0.5) * 0.01,
      is_public: true,
      tags: ['test', 'integration']
    };
  }

  static validateResponse(response, expectedStatus = 200, requiredFields = []) {
    if (response.status !== expectedStatus) {
      throw new Error(`Expected status ${expectedStatus}, got ${response.status}`);
    }

    if (requiredFields.length > 0 && response.data) {
      for (const field of requiredFields) {
        if (!(field in response.data)) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
    }

    return true;
  }

  static extractToken(response) {
    return response.data?.token || response.headers?.authorization?.replace('Bearer ', '');
  }

  static createAuthHeaders(token) {
    return token ? { Authorization: `Bearer ${token}` } : {};
  }
}

// 测试执行器
class TestRunner {
  constructor(moduleName) {
    this.moduleName = moduleName;
    this.tests = [];
    this.moduleResults = {
      name: moduleName,
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, skipped: 0, duration: 0 }
    };
  }

  addTest(name, testFn, options = {}) {
    this.tests.push({
      name,
      testFn,
      skip: options.skip || false,
      timeout: options.timeout || CONFIG.TEST_TIMEOUT
    });
    return this;
  }

  async runTest(test) {
    if (test.skip) {
      Logger.info(`⏭️  跳过测试: ${test.name}`);
      return { name: test.name, status: 'skipped', duration: 0 };
    }

    const startTime = Date.now();
    Logger.info(`🧪 运行测试: ${test.name}`);

    try {
      await Promise.race([
        test.testFn(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Test timeout')), test.timeout)
        )
      ]);

      const duration = Date.now() - startTime;
      Logger.info(`✅ 测试通过: ${test.name} (${duration}ms)`);
      
      return {
        name: test.name,
        status: 'passed',
        duration,
        details: null
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      Logger.error(`❌ 测试失败: ${test.name} - ${error.message} (${duration}ms)`);
      
      return {
        name: test.name,
        status: 'failed',
        duration,
        details: error.message,
        stack: error.stack
      };
    }
  }

  async run() {
    Logger.info(`\n📦 开始模块测试: ${this.moduleName}`);
    Logger.info(`📊 测试数量: ${this.tests.length}`);

    const moduleStartTime = Date.now();

    for (const test of this.tests) {
      const result = await this.runTest(test);
      this.moduleResults.tests.push(result);
      
      switch (result.status) {
        case 'passed':
          this.moduleResults.summary.passed++;
          testResults.summary.passedTests++;
          break;
        case 'failed':
          this.moduleResults.summary.failed++;
          testResults.summary.failedTests++;
          break;
        case 'skipped':
          this.moduleResults.summary.skipped++;
          testResults.summary.skippedTests++;
          break;
      }
      
      this.moduleResults.summary.total++;
      testResults.summary.totalTests++;
    }

    this.moduleResults.summary.duration = Date.now() - moduleStartTime;
    testResults.summary.totalDuration += this.moduleResults.summary.duration;

    const successRate = this.moduleResults.summary.total > 0 
      ? (this.moduleResults.summary.passed / this.moduleResults.summary.total * 100).toFixed(1)
      : 0;

    Logger.info(`\n📈 模块 ${this.moduleName} 测试完成:`);
    Logger.info(`   ✅ 通过: ${this.moduleResults.summary.passed}`);
    Logger.info(`   ❌ 失败: ${this.moduleResults.summary.failed}`);
    Logger.info(`   ⏭️  跳过: ${this.moduleResults.summary.skipped}`);
    Logger.info(`   📊 成功率: ${successRate}%`);
    Logger.info(`   ⏱️  耗时: ${this.moduleResults.summary.duration}ms`);

    testResults.modules[this.moduleName] = this.moduleResults;
    return this.moduleResults;
  }
}

// ===== 1. 用户管理系统测试 =====
async function testUserManagement() {
  const runner = new TestRunner('用户管理系统');
  let testUser = null;
  let authToken = null;
  let adminToken = null;

  runner
    .addTest('用户注册功能', async () => {
      testUser = TestUtils.generateTestUser();
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/v1/auth/register', testUser)
      );
      
      TestUtils.validateResponse(response, 201, ['user', 'token']);
      authToken = response.data?.data?.tokens?.accessToken;
      
      if (!authToken) throw new Error('未获取到认证token');
    })
    
    .addTest('用户登录功能', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/login', {
          email: testUser.email,
          password: testUser.password
        })
      );
      
      TestUtils.validateResponse(response, 200, ['user', 'token']);
      const loginToken = response.data?.data?.tokens?.accessToken;
      
      if (!loginToken) throw new Error('登录未获取到token');
    })
    
    .addTest('用户信息获取', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/user/profile', {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['id', 'username', 'email']);
    })
    
    .addTest('用户信息更新', async () => {
      const updateData = {
        display_name: 'Updated Test User',
        bio: 'This is an updated test user bio'
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.put('/api/v1/user/profile', updateData, {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    })
    
    .addTest('权限验证', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/users', {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      if (response.status === 200) {
        throw new Error('普通用户不应能访问管理员接口');
      }
      
      if (response.status !== 403) {
        throw new Error(`期望403状态码，得到${response.status}`);
      }
    });

  return await runner.run();
}

// ===== 2. LBS奖励系统测试 =====
async function testLBSRewardSystem() {
  const runner = new TestRunner('LBS奖励系统');
  let creatorUser = null;
  let discovererUser = null;
  let creatorToken = null;
  let discovererToken = null;
  let testAnnotation = null;

  runner
    .addTest('准备测试用户', async () => {
      // 创建标注者
      creatorUser = TestUtils.generateTestUser('creator');
      let response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', creatorUser)
      );
      TestUtils.validateResponse(response, 201);
      creatorToken = response.data?.data?.tokens?.accessToken;

      // 创建发现者
      discovererUser = TestUtils.generateTestUser('discoverer');
      response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', discovererUser)
      );
      TestUtils.validateResponse(response, 201);
      discovererToken = response.data?.data?.tokens?.accessToken;
    })
    
    .addTest('创建奖励标注', async () => {
      const annotationData = TestUtils.generateTestAnnotation();
      annotationData.reward_amount = 10; // 设置奖励金额
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/annotations', annotationData, {
          headers: TestUtils.createAuthHeaders(creatorToken)
        })
      );
      
      TestUtils.validateResponse(response, 201, ['id', 'reward_amount']);
      testAnnotation = response.data;
    })
    
    .addTest('地理围栏检测', async () => {
      const checkInData = {
        annotation_id: testAnnotation.id,
        latitude: testAnnotation.latitude + 0.0001, // 很近的位置
        longitude: testAnnotation.longitude + 0.0001,
        accuracy: 10
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/lbs/checkin', checkInData, {
          headers: TestUtils.createAuthHeaders(discovererToken)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    })
    
    .addTest('奖励计算验证', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get(`/api/rewards/user/${discovererUser.id}`, {
          headers: TestUtils.createAuthHeaders(discovererToken)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['total_rewards']);
    })
    
    .addTest('防作弊验证', async () => {
      // 尝试重复签到
      const checkInData = {
        annotation_id: testAnnotation.id,
        latitude: testAnnotation.latitude,
        longitude: testAnnotation.longitude,
        accuracy: 10
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/lbs/checkin', checkInData, {
          headers: TestUtils.createAuthHeaders(discovererToken)
        })
      );
      
      if (response.status === 200) {
        throw new Error('不应允许重复签到获得奖励');
      }
    });

  return await runner.run();
}

// ===== 3. GPS防作弊系统测试 =====
async function testGPSAntiCheat() {
  const runner = new TestRunner('GPS防作弊系统');
  let testUser = null;
  let authToken = null;

  runner
    .addTest('准备测试用户', async () => {
      testUser = TestUtils.generateTestUser('gps');
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', testUser)
      );
      TestUtils.validateResponse(response, 201);
      authToken = response.data?.data?.tokens?.accessToken;
    })
    
    .addTest('异常位置检测', async () => {
      const suspiciousLocation = {
        latitude: 0, // 明显异常的坐标
        longitude: 0,
        accuracy: 1000, // 精度很差
        speed: 100 // 异常高速移动
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/gps/validate', suspiciousLocation, {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      if (response.status === 200 && response.data?.risk_score <= 50) {
        throw new Error('应该检测到异常GPS数据');
      }
    })
    
    .addTest('正常位置验证', async () => {
      const normalLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10,
        speed: 5
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/gps/validate', normalLocation, {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['risk_score', 'is_valid']);
    })
    
    .addTest('位置历史分析', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/gps/history', {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    });

  return await runner.run();
}

// ===== 4. 实时奖励分发引擎测试 =====
async function testRewardDistribution() {
  const runner = new TestRunner('实时奖励分发引擎');
  let testUser = null;
  let authToken = null;

  runner
    .addTest('准备测试用户', async () => {
      testUser = TestUtils.generateTestUser('reward');
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', testUser)
      );
      TestUtils.validateResponse(response, 201);
      authToken = response.data?.data?.tokens?.accessToken;
    })
    
    .addTest('奖励发放功能', async () => {
      const rewardData = {
        amount: 100,
        reason: 'Test reward distribution',
        type: 'discovery_bonus'
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post(`/api/rewards/distribute/${testUser.id}`, rewardData, {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    })
    
    .addTest('钱包余额查询', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/wallet/balance', {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['balance']);
    })
    
    .addTest('交易记录查询', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/wallet/transactions', {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['transactions']);
    })
    
    .addTest('资金管理功能', async () => {
      const withdrawData = {
        amount: 50,
        method: 'bank_transfer',
        account: 'test_account_123'
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/wallet/withdraw', withdrawData, {
          headers: TestUtils.createAuthHeaders(authToken)
        })
      );
      
      // 可能需要管理员审批，所以接受多种状态码
      if (![200, 202].includes(response.status)) {
        throw new Error(`Unexpected status: ${response.status}`);
      }
    });

  return await runner.run();
}

// ===== 5. 社交互动功能测试 =====
async function testSocialInteraction() {
  const runner = new TestRunner('社交互动功能');
  let user1 = null;
  let user2 = null;
  let token1 = null;
  let token2 = null;
  let testAnnotation = null;

  runner
    .addTest('准备测试用户', async () => {
      user1 = TestUtils.generateTestUser('social1');
      let response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', user1)
      );
      TestUtils.validateResponse(response, 201);
      token1 = response.data?.data?.tokens?.accessToken;

      user2 = TestUtils.generateTestUser('social2');
      response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/users/register', user2)
      );
      TestUtils.validateResponse(response, 201);
      token2 = response.data?.data?.tokens?.accessToken;
    })
    
    .addTest('关注系统测试', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.post(`/api/social/follow/${user2.username}`, {}, {
          headers: TestUtils.createAuthHeaders(token1)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    })
    
    .addTest('创建标注用于互动', async () => {
      const annotationData = TestUtils.generateTestAnnotation();
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/annotations', annotationData, {
          headers: TestUtils.createAuthHeaders(token1)
        })
      );
      
      TestUtils.validateResponse(response, 201, ['id']);
      testAnnotation = response.data;
    })
    
    .addTest('评论功能测试', async () => {
      const commentData = {
        content: 'This is a test comment for social interaction testing',
        annotation_id: testAnnotation.id
      };
      
      const response = await TestUtils.retryRequest(() => 
        apiClient.post('/api/v1/comments', commentData, {
          headers: TestUtils.createAuthHeaders(token2)
        })
      );
      
      TestUtils.validateResponse(response, 201, ['id', 'content']);
    })
    
    .addTest('点赞功能测试', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.post(`/api/annotations/${testAnnotation.id}/like`, {}, {
          headers: TestUtils.createAuthHeaders(token2)
        })
      );
      
      TestUtils.validateResponse(response, 200);
    })
    
    .addTest('动态流查询', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/social/feed', {
          headers: TestUtils.createAuthHeaders(token1)
        })
      );
      
      TestUtils.validateResponse(response, 200, ['items']);
    });

  return await runner.run();
}

// ===== 6. 管理后台功能测试 =====
async function testAdminPanel() {
  const runner = new TestRunner('管理后台功能');
  
  // 注意：这些测试可能会跳过，因为没有管理员权限
  runner
    .addTest('内容审核功能', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/admin/content/pending')
      );
      
      // 期望401或403，因为没有管理员权限
      if (![401, 403].includes(response.status)) {
        throw new Error(`Expected 401/403, got ${response.status}`);
      }
    }, { skip: false })
    
    .addTest('数据统计查询', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/admin/stats/dashboard')
      );
      
      if (![401, 403].includes(response.status)) {
        throw new Error(`Expected 401/403, got ${response.status}`);
      }
    }, { skip: false })
    
    .addTest('日志管理功能', async () => {
      const response = await TestUtils.retryRequest(() => 
        apiClient.get('/api/v1/admin/logs/system')
      );
      
      if (![401, 403].includes(response.status)) {
        throw new Error(`Expected 401/403, got ${response.status}`);
      }
    }, { skip: false });

  return await runner.run();
}

// ===== 主测试执行函数 =====
async function runComprehensiveFunctionalTests() {
  console.log('============================================================');
  console.log('  SmellPin项目综合功能集成测试');
  console.log('============================================================\n');

  const startTime = Date.now();

  try {
    // 系统健康检查
    Logger.info('🔍 执行系统健康检查...');
    const healthResponse = await TestUtils.retryRequest(() => 
      apiClient.get('/health')
    );
    
    if (healthResponse.status !== 200) {
      Logger.warn('系统健康检查失败，但继续执行测试');
    } else {
      Logger.info('✅ 系统健康检查通过');
    }

    // 执行各模块测试
    const testModules = [
      { name: '用户管理系统', testFn: testUserManagement },
      { name: 'LBS奖励系统', testFn: testLBSRewardSystem },
      { name: 'GPS防作弊系统', testFn: testGPSAntiCheat },
      { name: '实时奖励分发引擎', testFn: testRewardDistribution },
      { name: '社交互动功能', testFn: testSocialInteraction },
      { name: '管理后台功能', testFn: testAdminPanel }
    ];

    for (const module of testModules) {
      try {
        await module.testFn();
      } catch (error) {
        Logger.error(`模块 ${module.name} 测试执行失败: ${error.message}`);
        testResults.recommendations.push({
          type: 'module_failure',
          module: module.name,
          message: `${module.name}模块测试失败: ${error.message}`
        });
      }
    }

  } catch (error) {
    Logger.error(`测试执行过程中发生错误: ${error.message}`);
    testResults.recommendations.push({
      type: 'execution_error',
      message: `测试执行错误: ${error.message}`
    });
  }

  // 计算最终结果
  testResults.summary.totalDuration = Date.now() - startTime;
  testResults.summary.successRate = testResults.summary.totalTests > 0 
    ? ((testResults.summary.passedTests / testResults.summary.totalTests) * 100).toFixed(1) + '%'
    : '0%';

  // 生成建议
  if (testResults.summary.passedTests < testResults.summary.totalTests * 0.8) {
    testResults.recommendations.push({
      type: 'low_success_rate',
      message: `测试成功率较低(${testResults.summary.successRate})，建议检查失败的测试用例`
    });
  }

  // 输出测试结果摘要
  console.log('\n============================================================');
  console.log('  综合功能测试结果摘要');
  console.log('============================================================');
  console.log(`📊 总测试数: ${testResults.summary.totalTests}`);
  console.log(`✅ 通过: ${testResults.summary.passedTests}`);
  console.log(`❌ 失败: ${testResults.summary.failedTests}`);
  console.log(`⏭️  跳过: ${testResults.summary.skippedTests}`);
  console.log(`📈 成功率: ${testResults.summary.successRate}`);
  console.log(`⏱️  总耗时: ${testResults.summary.totalDuration}ms`);

  // 各模块结果
  console.log('\n📦 各模块测试结果:');
  for (const [moduleName, moduleResult] of Object.entries(testResults.modules)) {
    const moduleSuccessRate = moduleResult.summary.total > 0 
      ? (moduleResult.summary.passed / moduleResult.summary.total * 100).toFixed(1)
      : 0;
    console.log(`   ${moduleName}: ${moduleResult.summary.passed}/${moduleResult.summary.total} (${moduleSuccessRate}%)`);
  }

  // 保存详细报告
  const reportPath = path.join(__dirname, 'comprehensive-functional-test-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(testResults, null, 2));
  console.log(`\n📄 详细测试报告已保存到: ${reportPath}`);

  // 建议
  if (testResults.recommendations.length > 0) {
    console.log('\n💡 改进建议:');
    testResults.recommendations.forEach((rec, index) => {
      console.log(`   ${index + 1}. ${rec.message}`);
    });
  }

  console.log('\n============================================================');
  console.log('  综合功能测试完成');
  console.log('============================================================');

  return testResults;
}

// 脚本执行入口
if (require.main === module) {
  runComprehensiveFunctionalTests().catch(error => {
    console.error('测试执行失败:', error);
    process.exit(1);
  });
}

module.exports = {
  runComprehensiveFunctionalTests,
  TestUtils,
  TestRunner
};