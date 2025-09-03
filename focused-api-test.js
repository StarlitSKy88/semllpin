/**
 * SmellPin 专注的核心API功能测试
 * 不重复创建用户，专注测试核心业务功能
 */

const axios = require('axios');
const fs = require('fs');

// 配置
const CONFIG = {
  BASE_URL: 'http://localhost:3004',
  API_VERSION: 'v1',
  // 使用已存在的测试用户
  TEST_USER: {
    email: 'test1756785913602@example.com',  // 使用之前成功创建的用户
    password: 'Test123456'
  },
  // 测试坐标
  TEST_LOCATIONS: [
    { name: '北京天安门', lat: 39.9042, lng: 116.4074 },
    { name: '上海外滩', lat: 31.2304, lng: 121.4737 },
    { name: '深圳腾讯大厦', lat: 22.5431, lng: 114.0579 }
  ]
};

// 全局变量
let authToken = null;
let testUserId = null;
let createdAnnotations = [];

// 工具函数
const logger = {
  info: (msg, data = '') => console.log(`[INFO] ${msg}`, data ? JSON.stringify(data, null, 2) : ''),
  error: (msg, error = '') => console.error(`[ERROR] ${msg}`, error.response?.data || error.message || error),
  success: (msg, data = '') => console.log(`[✅] ${msg}`, data ? JSON.stringify(data, null, 2) : ''),
  warn: (msg, data = '') => console.log(`[⚠️] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
};

const httpClient = axios.create({
  baseURL: `${CONFIG.BASE_URL}/api/${CONFIG.API_VERSION}`,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// 添加请求拦截器
httpClient.interceptors.request.use((config) => {
  if (authToken) {
    config.headers.Authorization = `Bearer ${authToken}`;
  }
  return config;
});

/**
 * 登录并获取token
 */
async function loginAndAuthenticate() {
  try {
    logger.info('🔑 用户登录...');
    
    const response = await httpClient.post('/users/login', {
      email: CONFIG.TEST_USER.email,
      password: CONFIG.TEST_USER.password
    });
    
    if (response.data.success) {
      authToken = response.data.data.tokens.accessToken;
      testUserId = response.data.data.user.id;
      
      logger.success('用户登录成功', {
        userId: testUserId,
        tokenLength: authToken.length
      });
      return true;
    }
    return false;
  } catch (error) {
    logger.error('登录失败', error);
    return false;
  }
}

/**
 * 1. 标注创建API测试
 */
async function testAnnotationCreation() {
  logger.info('\n=== 📍 标注创建API测试 ===');
  
  const results = {
    basic: { success: false, error: null, data: null },
    validation: { success: false, error: null, details: [] },
    geographic: { success: false, error: null, data: null }
  };
  
  try {
    // 1.1 基本标注创建测试
    logger.info('测试基本标注创建...');
    const location = CONFIG.TEST_LOCATIONS[0];
    
    const annotationData = {
      latitude: location.lat,
      longitude: location.lng,
      smellIntensity: 7,
      description: `API测试标注 - ${location.name} - ${new Date().toISOString()}`,
      mediaFiles: []
    };
    
    const createResponse = await httpClient.post('/annotations', annotationData);
    
    if (createResponse.data.success) {
      const annotation = createResponse.data.data.annotation;
      createdAnnotations.push(annotation);
      results.basic.success = true;
      results.basic.data = annotation;
      
      logger.success('基本标注创建成功', {
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        status: annotation.status
      });
      
      // 1.2 数据验证测试
      logger.info('验证标注数据完整性...');
      
      const validationChecks = [];
      
      // 必需字段验证
      if (annotation.id) validationChecks.push({ field: 'id', status: 'pass' });
      else validationChecks.push({ field: 'id', status: 'fail', issue: '缺少id字段' });
      
      if (annotation.latitude === annotationData.latitude) 
        validationChecks.push({ field: 'latitude', status: 'pass' });
      else 
        validationChecks.push({ field: 'latitude', status: 'fail', issue: '纬度不匹配' });
      
      if (annotation.longitude === annotationData.longitude) 
        validationChecks.push({ field: 'longitude', status: 'pass' });
      else 
        validationChecks.push({ field: 'longitude', status: 'fail', issue: '经度不匹配' });
      
      if (annotation.smellIntensity === annotationData.smellIntensity) 
        validationChecks.push({ field: 'smellIntensity', status: 'pass' });
      else 
        validationChecks.push({ field: 'smellIntensity', status: 'fail', issue: '臭味强度不匹配' });
      
      // 地理坐标范围验证
      if (annotation.latitude >= -90 && annotation.latitude <= 90) 
        validationChecks.push({ field: 'latitude_range', status: 'pass' });
      else 
        validationChecks.push({ field: 'latitude_range', status: 'fail', issue: '纬度超出有效范围' });
      
      if (annotation.longitude >= -180 && annotation.longitude <= 180) 
        validationChecks.push({ field: 'longitude_range', status: 'pass' });
      else 
        validationChecks.push({ field: 'longitude_range', status: 'fail', issue: '经度超出有效范围' });
      
      results.validation.details = validationChecks;
      results.validation.success = validationChecks.every(check => check.status === 'pass');
      
      logger.success('数据验证完成', {
        totalChecks: validationChecks.length,
        passed: validationChecks.filter(c => c.status === 'pass').length,
        failed: validationChecks.filter(c => c.status === 'fail').length
      });
      
      // 1.3 地理数据精度测试
      logger.info('测试地理数据精度...');
      
      // 创建第二个附近的标注来测试地理查询
      const nearbyAnnotationData = {
        latitude: location.lat + 0.001, // 约100米距离
        longitude: location.lng + 0.001,
        smellIntensity: 5,
        description: `附近测试标注 - ${location.name}`,
        mediaFiles: []
      };
      
      const nearbyResponse = await httpClient.post('/annotations', nearbyAnnotationData);
      if (nearbyResponse.data.success) {
        createdAnnotations.push(nearbyResponse.data.data.annotation);
        results.geographic.success = true;
        results.geographic.data = {
          original: annotation,
          nearby: nearbyResponse.data.data.annotation,
          distance: '约100米'
        };
        
        logger.success('地理数据测试完成', results.geographic.data);
      }
      
    } else {
      results.basic.error = createResponse.data;
      logger.error('基本标注创建失败', createResponse.data);
    }
    
  } catch (error) {
    results.basic.error = error.message;
    logger.error('标注创建测试异常', error);
  }
  
  return results;
}

/**
 * 2. 标注查询API测试
 */
async function testAnnotationQueries() {
  logger.info('\n=== 🔍 标注查询API测试 ===');
  
  const results = {
    list: { success: false, error: null, count: 0 },
    nearby: { success: false, error: null, annotations: [] },
    mapData: { success: false, error: null, count: 0 },
    byId: { success: false, error: null, data: null }
  };
  
  try {
    // 2.1 获取标注列表
    logger.info('测试获取标注列表...');
    
    const listResponse = await httpClient.get('/annotations/list', {
      params: { page: 1, limit: 10 }
    });
    
    if (listResponse.data.success) {
      results.list.success = true;
      results.list.count = listResponse.data.data.annotations.length;
      logger.success('获取标注列表成功', {
        count: results.list.count,
        total: listResponse.data.data.pagination.total
      });
    } else {
      results.list.error = listResponse.data;
      logger.error('获取标注列表失败', listResponse.data);
    }
    
  } catch (error) {
    results.list.error = error.message;
    logger.error('获取标注列表异常', error);
  }
  
  try {
    // 2.2 附近标注查询
    logger.info('测试附近标注查询...');
    
    const location = CONFIG.TEST_LOCATIONS[0];
    const nearbyResponse = await httpClient.get('/annotations/nearby', {
      params: {
        latitude: location.lat,
        longitude: location.lng,
        radius: 5000,
        limit: 10
      }
    });
    
    if (nearbyResponse.data.success) {
      results.nearby.success = true;
      results.nearby.annotations = nearbyResponse.data.data.annotations;
      logger.success('附近标注查询成功', {
        count: results.nearby.annotations.length,
        location: location.name
      });
    } else {
      results.nearby.error = nearbyResponse.data;
      logger.error('附近标注查询失败', nearbyResponse.data);
    }
    
  } catch (error) {
    results.nearby.error = error.message;
    logger.error('附近标注查询异常', error);
  }
  
  try {
    // 2.3 地图数据查询
    logger.info('测试地图数据查询...');
    
    const mapResponse = await httpClient.get('/annotations/map', {
      params: {
        north: 40.0,
        south: 39.0,
        east: 117.0,
        west: 116.0,
        zoom: 12
      }
    });
    
    if (mapResponse.data.success) {
      results.mapData.success = true;
      results.mapData.count = mapResponse.data.data.annotations.length;
      logger.success('地图数据查询成功', {
        count: results.mapData.count
      });
    } else {
      results.mapData.error = mapResponse.data;
      logger.error('地图数据查询失败', mapResponse.data);
    }
    
  } catch (error) {
    results.mapData.error = error.message;
    logger.error('地图数据查询异常', error);
  }
  
  try {
    // 2.4 单个标注详情查询
    if (createdAnnotations.length > 0) {
      logger.info('测试单个标注详情查询...');
      
      const annotationId = createdAnnotations[0].id;
      const detailResponse = await httpClient.get(`/annotations/${annotationId}`);
      
      if (detailResponse.data.success) {
        results.byId.success = true;
        results.byId.data = detailResponse.data.data.annotation;
        logger.success('标注详情查询成功', {
          id: annotationId,
          viewCount: results.byId.data.viewCount
        });
      } else {
        results.byId.error = detailResponse.data;
        logger.error('标注详情查询失败', detailResponse.data);
      }
    }
    
  } catch (error) {
    results.byId.error = error.message;
    logger.error('标注详情查询异常', error);
  }
  
  return results;
}

/**
 * 3. LBS奖励系统测试
 */
async function testLBSRewardSystem() {
  logger.info('\n=== 🎁 LBS奖励系统测试 ===');
  
  const results = {
    checkRewards: { success: false, error: null, data: null },
    rewardHistory: { success: false, error: null, data: null }
  };
  
  try {
    // 3.1 检查奖励
    logger.info('测试检查LBS奖励...');
    
    const location = CONFIG.TEST_LOCATIONS[0];
    const rewardResponse = await httpClient.get('/lbs/check-rewards', {
      params: {
        lat: location.lat,
        lng: location.lng
      }
    });
    
    if (rewardResponse.data.success) {
      results.checkRewards.success = true;
      results.checkRewards.data = rewardResponse.data.data;
      logger.success('LBS奖励检查成功', rewardResponse.data.data);
    } else {
      results.checkRewards.error = rewardResponse.data;
      logger.warn('LBS奖励检查失败(可能是功能未完全实现)', rewardResponse.data);
    }
    
  } catch (error) {
    results.checkRewards.error = error.message;
    if (error.response?.status === 404) {
      logger.warn('LBS奖励API不存在或未实现', error.response.data);
    } else {
      logger.error('LBS奖励检查异常', error);
    }
  }
  
  try {
    // 3.2 获取奖励历史
    logger.info('测试获取奖励历史...');
    
    const historyResponse = await httpClient.get('/lbs/rewards/history');
    
    if (historyResponse.data.success) {
      results.rewardHistory.success = true;
      results.rewardHistory.data = historyResponse.data.data;
      logger.success('奖励历史获取成功', historyResponse.data.data);
    } else {
      results.rewardHistory.error = historyResponse.data;
      logger.warn('奖励历史获取失败(可能是功能未完全实现)', historyResponse.data);
    }
    
  } catch (error) {
    results.rewardHistory.error = error.message;
    if (error.response?.status === 404) {
      logger.warn('奖励历史API不存在或未实现', error.response.data);
    } else {
      logger.error('奖励历史获取异常', error);
    }
  }
  
  return results;
}

/**
 * 4. 支付和钱包系统测试
 */
async function testPaymentSystem() {
  logger.info('\n=== 💰 支付和钱包系统测试 ===');
  
  const results = {
    walletBalance: { success: false, error: null, data: null },
    paidAnnotation: { success: false, error: null, data: null }
  };
  
  try {
    // 4.1 获取钱包余额
    logger.info('测试获取钱包余额...');
    
    const walletResponse = await httpClient.get('/wallet/balance');
    
    if (walletResponse.data.success) {
      results.walletBalance.success = true;
      results.walletBalance.data = walletResponse.data.data;
      logger.success('钱包余额获取成功', walletResponse.data.data);
    } else {
      results.walletBalance.error = walletResponse.data;
      logger.warn('钱包余额获取失败(可能是功能未完全实现)', walletResponse.data);
    }
    
  } catch (error) {
    results.walletBalance.error = error.message;
    if (error.response?.status === 404) {
      logger.warn('钱包API不存在或未实现', error.response.data);
    } else {
      logger.error('钱包余额获取异常', error);
    }
  }
  
  try {
    // 4.2 创建付费恶搞标注
    logger.info('测试付费恶搞标注创建...');
    
    const location = CONFIG.TEST_LOCATIONS[1];
    const paidAnnotationData = {
      latitude: location.lat,
      longitude: location.lng,
      smellIntensity: 10,
      description: `付费恶搞标注测试 - ${location.name}`,
      mediaFiles: [],
      amount: 5,
      currency: 'usd',
      paymentDescription: '测试付费恶搞标注'
    };
    
    const paidResponse = await httpClient.post('/annotations/paid-prank', paidAnnotationData);
    
    if (paidResponse.data.success) {
      results.paidAnnotation.success = true;
      results.paidAnnotation.data = paidResponse.data.data;
      logger.success('付费恶搞标注会话创建成功', {
        sessionId: paidResponse.data.data.sessionId,
        amount: paidResponse.data.data.amount
      });
    } else {
      results.paidAnnotation.error = paidResponse.data;
      logger.error('付费恶搞标注创建失败', paidResponse.data);
    }
    
  } catch (error) {
    results.paidAnnotation.error = error.message;
    logger.error('付费恶搞标注创建异常', error);
  }
  
  return results;
}

/**
 * 5. 性能测试
 */
async function testPerformance() {
  logger.info('\n=== ⚡ 性能测试 ===');
  
  const results = {
    concurrentQueries: { success: false, error: null, data: null },
    responseTime: { success: false, error: null, data: null }
  };
  
  try {
    // 5.1 并发查询测试
    logger.info('测试并发查询性能...');
    
    const concurrentRequests = 5;
    const startTime = Date.now();
    
    const promises = CONFIG.TEST_LOCATIONS.slice(0, concurrentRequests).map(location => 
      httpClient.get('/annotations/nearby', {
        params: {
          latitude: location.lat,
          longitude: location.lng,
          radius: 1000,
          limit: 5
        }
      })
    );
    
    const responses = await Promise.allSettled(promises);
    const endTime = Date.now();
    
    const successful = responses.filter(r => r.status === 'fulfilled' && r.value.data.success).length;
    const totalTime = endTime - startTime;
    
    results.concurrentQueries.success = true;
    results.concurrentQueries.data = {
      totalRequests: concurrentRequests,
      successful: successful,
      failed: concurrentRequests - successful,
      totalTimeMs: totalTime,
      avgTimeMs: Math.round(totalTime / concurrentRequests)
    };
    
    logger.success('并发查询测试完成', results.concurrentQueries.data);
    
  } catch (error) {
    results.concurrentQueries.error = error.message;
    logger.error('并发查询测试异常', error);
  }
  
  try {
    // 5.2 响应时间测试
    logger.info('测试API响应时间...');
    
    const iterations = 3;
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await httpClient.get('/annotations/list', { params: { page: 1, limit: 5 } });
      times.push(Date.now() - start);
    }
    
    const avgResponseTime = Math.round(times.reduce((sum, time) => sum + time, 0) / times.length);
    
    results.responseTime.success = true;
    results.responseTime.data = {
      iterations: iterations,
      times: times,
      avgResponseTimeMs: avgResponseTime,
      minTimeMs: Math.min(...times),
      maxTimeMs: Math.max(...times)
    };
    
    logger.success('响应时间测试完成', results.responseTime.data);
    
  } catch (error) {
    results.responseTime.error = error.message;
    logger.error('响应时间测试异常', error);
  }
  
  return results;
}

/**
 * 生成测试报告
 */
async function generateReport(testResults) {
  const report = {
    timestamp: new Date().toISOString(),
    testEnvironment: {
      baseUrl: CONFIG.BASE_URL,
      apiVersion: CONFIG.API_VERSION
    },
    summary: {
      totalTests: 0,
      passedTests: 0,
      failedTests: 0,
      passRate: 0
    },
    results: testResults,
    issues: [],
    recommendations: []
  };
  
  // 计算测试摘要
  function countResults(obj, path = '') {
    for (const key in obj) {
      const currentPath = path ? `${path}.${key}` : key;
      const value = obj[key];
      
      if (typeof value === 'object' && value.hasOwnProperty('success')) {
        report.summary.totalTests++;
        if (value.success) {
          report.summary.passedTests++;
        } else {
          report.summary.failedTests++;
          report.issues.push({
            test: currentPath,
            error: value.error,
            category: 'API错误'
          });
        }
      } else if (typeof value === 'object' && value !== null) {
        countResults(value, currentPath);
      }
    }
  }
  
  countResults(testResults);
  
  report.summary.passRate = report.summary.totalTests > 0 
    ? Math.round((report.summary.passedTests / report.summary.totalTests) * 100) 
    : 0;
  
  // 生成建议
  if (report.issues.length > 0) {
    report.recommendations.push('发现API错误，需要修复相关接口实现');
  }
  
  if (testResults.performance?.concurrentQueries?.success) {
    const data = testResults.performance.concurrentQueries.data;
    if (data.avgTimeMs > 1000) {
      report.recommendations.push('并发查询响应时间较长，建议优化数据库查询和缓存策略');
    }
  }
  
  if (!testResults.lbsRewards?.checkRewards?.success) {
    report.recommendations.push('LBS奖励系统API未完全实现，建议完善相关功能');
  }
  
  // 保存报告
  const reportPath = '/Users/xiaoyang/Downloads/臭味/focused-api-test-report.json';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  logger.success(`测试报告已保存: ${reportPath}`);
  logger.info('📊 测试总结', report.summary);
  
  return report;
}

/**
 * 主测试入口
 */
async function runAllTests() {
  logger.info('🚀 开始SmellPin专注API功能测试...\n');
  
  // 1. 登录认证
  if (!(await loginAndAuthenticate())) {
    logger.error('❌ 认证失败，无法继续测试');
    return;
  }
  
  const testResults = {};
  
  // 2. 运行各个测试模块
  testResults.annotationCreation = await testAnnotationCreation();
  testResults.annotationQueries = await testAnnotationQueries();
  testResults.lbsRewards = await testLBSRewardSystem();
  testResults.payment = await testPaymentSystem();
  testResults.performance = await testPerformance();
  
  // 3. 生成报告
  const report = await generateReport(testResults);
  
  logger.success('\n🎉 测试完成！');
  logger.info('📈 关键指标:', {
    '总测试数': report.summary.totalTests,
    '通过测试': report.summary.passedTests,
    '失败测试': report.summary.failedTests,
    '通过率': `${report.summary.passRate}%`,
    '创建标注': createdAnnotations.length
  });
  
  if (report.recommendations.length > 0) {
    logger.warn('💡 改进建议:', report.recommendations);
  }
}

// 运行测试
if (require.main === module) {
  runAllTests().catch(error => {
    logger.error('测试运行失败', error);
    process.exit(1);
  });
}

module.exports = { runAllTests };