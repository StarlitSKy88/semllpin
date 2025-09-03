const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 配置
const API_BASE_URL = 'http://localhost:8787';
const TEST_USER = {
  email: `thirdparty_test_${Date.now()}@example.com`,
  password: 'ThirdPartyTest123!',
  username: `thirdparty_${Date.now()}`
};

// 全局变量
let authToken = null;
let userId = null;
const testResults = [];
const integrationResults = {};

// 工具函数
function recordTest(name, success, details, duration, integrationData = null) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
    integrationData
  };
  testResults.push(result);
  
  const status = success ? '[PASS]' : '[FAIL]';
  console.log(`${status} ${name}`);
  console.log(`   详情: ${details}`);
  console.log(`   耗时: ${duration}ms`);
  if (integrationData) {
    console.log(`   集成数据: ${JSON.stringify(integrationData, null, 2)}`);
  }
  console.log('');
}

async function makeRequest(url, options = {}) {
  try {
    const response = await axios({
      url,
      method: options.method || 'GET',
      data: options.body,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: 30000 // 第三方服务可能需要更长时间
    });
    return response;
  } catch (error) {
    if (error.response) {
      return error.response;
    }
    throw error;
  }
}

// 检测第三方服务响应的真实性
function analyzeThirdPartyResponse(serviceName, response, expectedIndicators = []) {
  const analysis = {
    serviceName,
    statusCode: response.status,
    hasRealHeaders: false,
    hasServiceIdentifiers: false,
    responseTime: null,
    realityScore: 0
  };
  
  // 检查响应头中的服务标识
  const headers = response.headers || {};
  const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
  
  // 不同服务的真实性指标
  const serviceIndicators = {
    stripe: ['stripe-version', 'request-id', 'stripe-account'],
    sendgrid: ['x-message-id', 'x-sendgrid-id'],
    twilio: ['x-twilio-request-id', 'x-twilio-request-duration'],
    aws: ['x-amzn-requestid', 'x-amz-request-id'],
    redis: ['redis-version'],
    postgresql: ['server']
  };
  
  const indicators = serviceIndicators[serviceName.toLowerCase()] || expectedIndicators;
  
  // 检查服务特定的响应头
  analysis.hasServiceIdentifiers = indicators.some(indicator => 
    headerKeys.includes(indicator.toLowerCase())
  );
  
  // 检查是否有真实的服务响应头
  analysis.hasRealHeaders = headerKeys.some(header => 
    ['server', 'x-powered-by', 'x-request-id', 'x-correlation-id'].includes(header)
  );
  
  // 计算真实性评分
  if (analysis.hasServiceIdentifiers) analysis.realityScore += 40;
  if (analysis.hasRealHeaders) analysis.realityScore += 20;
  if (response.status >= 200 && response.status < 300) analysis.realityScore += 20;
  if (response.data && typeof response.data === 'object') analysis.realityScore += 20;
  
  return analysis;
}

// 第三方服务测试函数
async function testStripeIntegration() {
  console.log('=== 第三方集成测试1: Stripe支付服务 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('Stripe支付服务集成', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 1. 测试创建支付意图
    const paymentData = {
      amount: 100, // 1元
      currency: 'cny',
      description: 'Stripe集成测试支付'
    };
    
    const createResponse = await makeRequest(`${API_BASE_URL}/payments/create-intent`, {
      method: 'POST',
      body: paymentData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const createAnalysis = analyzeThirdPartyResponse('stripe', createResponse);
    
    // 2. 测试获取支付方法
    const methodsResponse = await makeRequest(`${API_BASE_URL}/payments/methods`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const methodsAnalysis = analyzeThirdPartyResponse('stripe', methodsResponse);
    
    // 3. 测试Stripe webhook端点
    const webhookResponse = await makeRequest(`${API_BASE_URL}/webhooks/stripe`, {
      method: 'POST',
      body: {
        type: 'payment_intent.succeeded',
        data: { object: { id: 'pi_test_123' } }
      },
      headers: {
        'stripe-signature': 'test_signature'
      }
    });
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      createPaymentIntent: {
        success: createResponse.status >= 200 && createResponse.status < 300,
        analysis: createAnalysis,
        hasPaymentIntentId: !!(createResponse.data?.id || createResponse.data?.data?.id)
      },
      paymentMethods: {
        success: methodsResponse.status >= 200 && methodsResponse.status < 300,
        analysis: methodsAnalysis
      },
      webhookEndpoint: {
        accessible: webhookResponse.status !== 404,
        status: webhookResponse.status
      },
      overallRealityScore: Math.max(createAnalysis.realityScore, methodsAnalysis.realityScore)
    };
    
    integrationResults.stripe = integrationData;
    
    const success = integrationData.createPaymentIntent.success && 
                   integrationData.overallRealityScore >= 60;
    
    recordTest('Stripe支付服务集成', success, 
      `Stripe集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('Stripe支付服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testEmailNotificationIntegration() {
  console.log('=== 第三方集成测试2: 邮件通知服务 ===\n');
  const startTime = Date.now();
  
  try {
    // 1. 测试发送验证邮件
    const emailData = {
      email: TEST_USER.email,
      type: 'verification',
      template: 'email_verification'
    };
    
    const sendResponse = await makeRequest(`${API_BASE_URL}/notifications/email/send`, {
      method: 'POST',
      body: emailData,
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const sendAnalysis = analyzeThirdPartyResponse('sendgrid', sendResponse);
    
    // 2. 测试邮件模板获取
    const templatesResponse = await makeRequest(`${API_BASE_URL}/notifications/email/templates`);
    
    const templatesAnalysis = analyzeThirdPartyResponse('sendgrid', templatesResponse);
    
    // 3. 测试邮件发送状态查询
    const statusResponse = await makeRequest(`${API_BASE_URL}/notifications/email/status`, {
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      emailSending: {
        success: sendResponse.status >= 200 && sendResponse.status < 300,
        analysis: sendAnalysis,
        hasMessageId: !!(sendResponse.data?.message_id || sendResponse.data?.id)
      },
      templateAccess: {
        success: templatesResponse.status >= 200 && templatesResponse.status < 300,
        analysis: templatesAnalysis
      },
      statusTracking: {
        accessible: statusResponse.status !== 404,
        status: statusResponse.status
      },
      overallRealityScore: Math.max(sendAnalysis.realityScore, templatesAnalysis.realityScore)
    };
    
    integrationResults.email = integrationData;
    
    const success = integrationData.emailSending.success && 
                   integrationData.overallRealityScore >= 40;
    
    recordTest('邮件通知服务集成', success, 
      `邮件服务集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('邮件通知服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testSMSNotificationIntegration() {
  console.log('=== 第三方集成测试3: 短信通知服务 ===\n');
  const startTime = Date.now();
  
  try {
    // 1. 测试发送验证码短信
    const smsData = {
      phone: '+8613800138000', // 测试号码
      type: 'verification_code',
      code: '123456'
    };
    
    const sendResponse = await makeRequest(`${API_BASE_URL}/notifications/sms/send`, {
      method: 'POST',
      body: smsData,
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const sendAnalysis = analyzeThirdPartyResponse('twilio', sendResponse);
    
    // 2. 测试短信发送状态查询
    const statusResponse = await makeRequest(`${API_BASE_URL}/notifications/sms/status`, {
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      smsSending: {
        success: sendResponse.status >= 200 && sendResponse.status < 300,
        analysis: sendAnalysis,
        hasSmsId: !!(sendResponse.data?.sid || sendResponse.data?.message_id)
      },
      statusTracking: {
        accessible: statusResponse.status !== 404,
        status: statusResponse.status
      },
      overallRealityScore: sendAnalysis.realityScore
    };
    
    integrationResults.sms = integrationData;
    
    const success = integrationData.smsSending.success && 
                   integrationData.overallRealityScore >= 40;
    
    recordTest('短信通知服务集成', success, 
      `短信服务集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('短信通知服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testFileStorageIntegration() {
  console.log('=== 第三方集成测试4: 文件存储服务 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('文件存储服务集成', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 1. 测试获取上传签名URL
    const uploadData = {
      filename: 'test-image.jpg',
      content_type: 'image/jpeg',
      size: 1024000 // 1MB
    };
    
    const signedUrlResponse = await makeRequest(`${API_BASE_URL}/files/upload-url`, {
      method: 'POST',
      body: uploadData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const urlAnalysis = analyzeThirdPartyResponse('aws', signedUrlResponse);
    
    // 2. 测试文件列表获取
    const listResponse = await makeRequest(`${API_BASE_URL}/files/list`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const listAnalysis = analyzeThirdPartyResponse('aws', listResponse);
    
    // 3. 测试文件删除
    const deleteResponse = await makeRequest(`${API_BASE_URL}/files/test-file.jpg`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      signedUrlGeneration: {
        success: signedUrlResponse.status >= 200 && signedUrlResponse.status < 300,
        analysis: urlAnalysis,
        hasSignedUrl: !!(signedUrlResponse.data?.upload_url || signedUrlResponse.data?.url)
      },
      fileListAccess: {
        success: listResponse.status >= 200 && listResponse.status < 300,
        analysis: listAnalysis
      },
      fileDeletion: {
        accessible: deleteResponse.status !== 404,
        status: deleteResponse.status
      },
      overallRealityScore: Math.max(urlAnalysis.realityScore, listAnalysis.realityScore)
    };
    
    integrationResults.storage = integrationData;
    
    const success = integrationData.signedUrlGeneration.success && 
                   integrationData.overallRealityScore >= 40;
    
    recordTest('文件存储服务集成', success, 
      `文件存储集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('文件存储服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testRedisIntegration() {
  console.log('=== 第三方集成测试5: Redis缓存服务 ===\n');
  const startTime = Date.now();
  
  try {
    // 1. 测试缓存写入
    const cacheData = {
      key: `test_cache_${Date.now()}`,
      value: { test: true, timestamp: Date.now() },
      ttl: 300 // 5分钟
    };
    
    const setResponse = await makeRequest(`${API_BASE_URL}/cache/set`, {
      method: 'POST',
      body: cacheData,
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const setAnalysis = analyzeThirdPartyResponse('redis', setResponse);
    
    // 2. 测试缓存读取
    const getResponse = await makeRequest(`${API_BASE_URL}/cache/get/${cacheData.key}`, {
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    const getAnalysis = analyzeThirdPartyResponse('redis', getResponse);
    
    // 3. 测试缓存状态
    const statusResponse = await makeRequest(`${API_BASE_URL}/cache/status`);
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      cacheWrite: {
        success: setResponse.status >= 200 && setResponse.status < 300,
        analysis: setAnalysis
      },
      cacheRead: {
        success: getResponse.status >= 200 && getResponse.status < 300,
        analysis: getAnalysis,
        dataMatches: JSON.stringify(getResponse.data?.value) === JSON.stringify(cacheData.value)
      },
      cacheStatus: {
        accessible: statusResponse.status >= 200 && statusResponse.status < 300,
        connected: statusResponse.data?.connected || statusResponse.data?.status === 'connected'
      },
      overallRealityScore: Math.max(setAnalysis.realityScore, getAnalysis.realityScore)
    };
    
    integrationResults.redis = integrationData;
    
    const success = integrationData.cacheStatus.connected && 
                   integrationData.overallRealityScore >= 40;
    
    recordTest('Redis缓存服务集成', success, 
      `Redis集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('Redis缓存服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testGeocodingIntegration() {
  console.log('=== 第三方集成测试6: 地理编码服务 ===\n');
  const startTime = Date.now();
  
  try {
    // 1. 测试地址转坐标
    const geocodeData = {
      address: '北京市天安门广场'
    };
    
    const geocodeResponse = await makeRequest(`${API_BASE_URL}/geo/geocode`, {
      method: 'POST',
      body: geocodeData
    });
    
    const geocodeAnalysis = analyzeThirdPartyResponse('geocoding', geocodeResponse);
    
    // 2. 测试坐标转地址
    const reverseData = {
      latitude: 39.9042,
      longitude: 116.4074
    };
    
    const reverseResponse = await makeRequest(`${API_BASE_URL}/geo/reverse`, {
      method: 'POST',
      body: reverseData
    });
    
    const reverseAnalysis = analyzeThirdPartyResponse('geocoding', reverseResponse);
    
    const duration = Date.now() - startTime;
    
    const integrationData = {
      geocoding: {
        success: geocodeResponse.status >= 200 && geocodeResponse.status < 300,
        analysis: geocodeAnalysis,
        hasCoordinates: !!(geocodeResponse.data?.latitude && geocodeResponse.data?.longitude)
      },
      reverseGeocoding: {
        success: reverseResponse.status >= 200 && reverseResponse.status < 300,
        analysis: reverseAnalysis,
        hasAddress: !!(reverseResponse.data?.address || reverseResponse.data?.formatted_address)
      },
      overallRealityScore: Math.max(geocodeAnalysis.realityScore, reverseAnalysis.realityScore)
    };
    
    integrationResults.geocoding = integrationData;
    
    const success = (integrationData.geocoding.success || integrationData.reverseGeocoding.success) && 
                   integrationData.overallRealityScore >= 40;
    
    recordTest('地理编码服务集成', success, 
      `地理编码集成${success ? '正常' : '异常'}，真实性评分: ${integrationData.overallRealityScore}`, 
      duration, integrationData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('地理编码服务集成', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 用户注册（为其他测试准备）
async function setupTestUser() {
  console.log('=== 准备测试用户 ===\n');
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USER
    });
    
    if (response.status === 201) {
      const userData = response.data.data || response.data;
      authToken = userData.token;
      userId = userData.user?.id || userData.id;
      console.log('测试用户创建成功\n');
      return true;
    } else {
      console.log('测试用户创建失败\n');
      return false;
    }
  } catch (error) {
    console.log(`测试用户创建错误: ${error.message}\n`);
    return false;
  }
}

// 生成第三方集成测试报告
function generateThirdPartyReport() {
  const passedTests = testResults.filter(test => test.success).length;
  const totalTests = testResults.length;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(2) : 0;
  
  // 计算整体集成健康度
  const integrationScores = Object.values(integrationResults)
    .map(result => result.overallRealityScore || 0);
  const avgIntegrationScore = integrationScores.length > 0 ? 
    (integrationScores.reduce((a, b) => a + b, 0) / integrationScores.length).toFixed(2) : 0;
  
  const report = {
    summary: {
      timestamp: new Date().toISOString(),
      totalTests,
      passedTests,
      failedTests: totalTests - passedTests,
      successRate: `${successRate}%`,
      averageIntegrationScore: `${avgIntegrationScore}/100`,
      testType: 'Third-Party Integration'
    },
    integrationResults,
    testResults,
    recommendations: generateThirdPartyRecommendations()
  };
  
  // 保存报告到文件
  const reportPath = path.join(__dirname, 'third-party-integration-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  console.log('\n=== 第三方服务集成测试报告 ===');
  console.log(`测试总数: ${totalTests}`);
  console.log(`通过测试: ${passedTests}`);
  console.log(`失败测试: ${totalTests - passedTests}`);
  console.log(`成功率: ${successRate}%`);
  console.log(`平均集成真实性评分: ${avgIntegrationScore}/100`);
  console.log(`\n各服务集成状态:`);
  
  Object.entries(integrationResults).forEach(([service, result]) => {
    const status = result.overallRealityScore >= 60 ? '✓ 良好' : 
                  result.overallRealityScore >= 40 ? '⚠ 一般' : '✗ 异常';
    console.log(`- ${service}: ${status} (${result.overallRealityScore}/100)`);
  });
  
  console.log(`\n详细报告已保存到: ${reportPath}`);
  
  return report;
}

function generateThirdPartyRecommendations() {
  const recommendations = [];
  
  // 检查各个第三方服务的集成状态
  Object.entries(integrationResults).forEach(([service, result]) => {
    if (result.overallRealityScore < 40) {
      recommendations.push({
        type: 'integration_issue',
        service,
        priority: 'high',
        message: `${service}服务集成异常，真实性评分过低 (${result.overallRealityScore}/100)`,
        suggestion: `检查${service}服务的API密钥、配置和网络连接`
      });
    } else if (result.overallRealityScore < 60) {
      recommendations.push({
        type: 'integration_warning',
        service,
        priority: 'medium',
        message: `${service}服务集成需要优化，真实性评分偏低 (${result.overallRealityScore}/100)`,
        suggestion: `优化${service}服务的配置和错误处理`
      });
    }
  });
  
  // 检查失败的测试
  const failedTests = testResults.filter(test => !test.success);
  if (failedTests.length > 0) {
    recommendations.push({
      type: 'test_failures',
      priority: 'medium',
      message: `有 ${failedTests.length} 个第三方服务测试失败`,
      details: failedTests.map(test => test.name),
      suggestion: '检查相关服务的可用性和配置'
    });
  }
  
  // 如果所有服务都正常，给出优化建议
  if (recommendations.length === 0) {
    recommendations.push({
      type: 'optimization',
      priority: 'low',
      message: '所有第三方服务集成正常',
      suggestion: '可以考虑添加更多的监控和告警机制'
    });
  }
  
  return recommendations;
}

// 主测试函数
async function runThirdPartyIntegrationTests() {
  console.log('开始第三方服务集成测试...\n');
  
  try {
    // 准备测试用户
    await setupTestUser();
    
    // 运行各项集成测试
    await testStripeIntegration();
    await testEmailNotificationIntegration();
    await testSMSNotificationIntegration();
    await testFileStorageIntegration();
    await testRedisIntegration();
    await testGeocodingIntegration();
    
    const report = generateThirdPartyReport();
    
    console.log('\n第三方服务集成测试完成！');
    return report;
  } catch (error) {
    console.error('测试过程中发生错误:', error);
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  runThirdPartyIntegrationTests()
    .then(report => {
      if (report) {
        process.exit(report.summary.failedTests > 0 ? 1 : 0);
      } else {
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('测试失败:', error);
      process.exit(1);
    });
}

module.exports = {
  runThirdPartyIntegrationTests,
  analyzeThirdPartyResponse,
  integrationResults
};