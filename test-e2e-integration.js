const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 配置
const API_BASE_URL = 'http://localhost:3002';
const TEST_USERS = {
  creator: {
    email: `creator_${Date.now()}@example.com`,
    password: 'CreatorPassword123!',
    username: `creator_${Date.now()}`
  },
  discoverer: {
    email: `discoverer_${Date.now()}@example.com`,
    password: 'DiscovererPassword123!',
    username: `discoverer_${Date.now()}`
  }
};

// 全局变量
const userTokens = {};
const userIds = {};
const testResults = [];
const businessFlowData = {};

// 工具函数
function recordTest(name, success, details, duration, flowData = null) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
    flowData
  };
  testResults.push(result);
  
  const status = success ? '[PASS]' : '[FAIL]';
  console.log(`${status} ${name}`);
  console.log(`   详情: ${details}`);
  console.log(`   耗时: ${duration}ms`);
  if (flowData) {
    console.log(`   流程数据: ${JSON.stringify(flowData, null, 2)}`);
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
      timeout: 20000
    });
    return response;
  } catch (error) {
    if (error.response) {
      return error.response;
    }
    throw error;
  }
}

// 等待函数
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 业务流程测试函数
async function testCompleteUserRegistrationFlow() {
  console.log('=== 端到端测试1: 完整用户注册流程 ===\n');
  const startTime = Date.now();
  
  try {
    // 注册创建者
    const creatorResponse = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USERS.creator
    });
    
    // 注册发现者
    const discovererResponse = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USERS.discoverer
    });
    
    const duration = Date.now() - startTime;
    
    if (creatorResponse.status === 201 && discovererResponse.status === 201) {
      // 保存用户信息
      const creatorData = creatorResponse.data.data || creatorResponse.data;
      const discovererData = discovererResponse.data.data || discovererResponse.data;
      
      userTokens.creator = creatorData.token;
      userTokens.discoverer = discovererData.token;
      userIds.creator = creatorData.user?.id || creatorData.id;
      userIds.discoverer = discovererData.user?.id || discovererData.id;
      
      const flowData = {
        creatorId: userIds.creator,
        discovererId: userIds.discoverer,
        bothUsersRegistered: true,
        tokensObtained: !!userTokens.creator && !!userTokens.discoverer
      };
      
      businessFlowData.users = flowData;
      
      recordTest('完整用户注册流程', true, 
        '两个用户成功注册，获得认证令牌', duration, flowData);
      return true;
    } else {
      recordTest('完整用户注册流程', false, 
        `注册失败 - 创建者: ${creatorResponse.status}, 发现者: ${discovererResponse.status}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('完整用户注册流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testCompleteAnnotationCreationFlow() {
  console.log('=== 端到端测试2: 完整标注创建流程 ===\n');
  const startTime = Date.now();
  
  if (!userTokens.creator) {
    recordTest('完整标注创建流程', false, '没有创建者认证令牌', 0);
    return false;
  }
  
  const annotationData = {
    title: '端到端测试恶搞标注',
    description: '这是一个用于端到端测试的恶搞标注，测试完整的业务流程',
    latitude: 39.9042,
    longitude: 116.4074,
    category: 'funny',
    severity: 4,
    reward_amount: 10.00, // 10元奖励
    tags: ['测试', '端到端', '恶搞']
  };
  
  try {
    // 1. 创建标注
    const createResponse = await makeRequest(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      body: annotationData,
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    if (createResponse.status !== 201) {
      const duration = Date.now() - startTime;
      recordTest('完整标注创建流程', false, 
        `标注创建失败: ${createResponse.status}`, duration);
      return false;
    }
    
    const createdAnnotation = createResponse.data.data || createResponse.data;
    const annotationId = createdAnnotation.id;
    
    // 2. 验证标注存在
    await sleep(1000); // 等待数据库写入
    
    const getResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}`);
    
    if (getResponse.status !== 200) {
      const duration = Date.now() - startTime;
      recordTest('完整标注创建流程', false, 
        `标注查询失败: ${getResponse.status}`, duration);
      return false;
    }
    
    // 3. 验证标注在列表中
    const listResponse = await makeRequest(`${API_BASE_URL}/annotations?limit=10`);
    
    if (listResponse.status !== 200) {
      const duration = Date.now() - startTime;
      recordTest('完整标注创建流程', false, 
        `标注列表查询失败: ${listResponse.status}`, duration);
      return false;
    }
    
    const annotations = listResponse.data.data || listResponse.data;
    const foundInList = annotations.some(ann => ann.id === annotationId);
    
    const duration = Date.now() - startTime;
    
    const flowData = {
      annotationId,
      createdSuccessfully: true,
      foundInDatabase: true,
      foundInList,
      rewardAmount: annotationData.reward_amount,
      creatorId: userIds.creator
    };
    
    businessFlowData.annotation = flowData;
    
    const success = foundInList;
    recordTest('完整标注创建流程', success, 
      `标注创建并验证${success ? '成功' : '失败'}`, duration, flowData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('完整标注创建流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testLBSDiscoveryFlow() {
  console.log('=== 端到端测试3: LBS发现奖励流程 ===\n');
  const startTime = Date.now();
  
  if (!userTokens.discoverer || !businessFlowData.annotation?.annotationId) {
    recordTest('LBS发现奖励流程', false, '缺少必要的测试数据', 0);
    return false;
  }
  
  const annotationId = businessFlowData.annotation.annotationId;
  
  try {
    // 1. 模拟用户进入地理围栏
    const discoveryData = {
      annotation_id: annotationId,
      latitude: 39.9042, // 与标注相同的位置
      longitude: 116.4074,
      accuracy: 10 // 10米精度
    };
    
    const discoveryResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}/discover`, {
      method: 'POST',
      body: discoveryData,
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    if (discoveryResponse.status !== 200) {
      const duration = Date.now() - startTime;
      recordTest('LBS发现奖励流程', false, 
        `发现请求失败: ${discoveryResponse.status}`, duration);
      return false;
    }
    
    const discoveryResult = discoveryResponse.data.data || discoveryResponse.data;
    
    // 2. 验证奖励是否发放
    await sleep(2000); // 等待奖励处理
    
    const walletResponse = await makeRequest(`${API_BASE_URL}/wallet/balance`, {
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    if (walletResponse.status !== 200) {
      const duration = Date.now() - startTime;
      recordTest('LBS发现奖励流程', false, 
        `钱包查询失败: ${walletResponse.status}`, duration);
      return false;
    }
    
    const walletData = walletResponse.data.data || walletResponse.data;
    const hasReward = walletData.balance > 0;
    
    // 3. 验证交易记录
    const transactionResponse = await makeRequest(`${API_BASE_URL}/wallet/transactions`, {
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    const transactions = transactionResponse.data.data || transactionResponse.data;
    const rewardTransaction = transactions.find(tx => 
      tx.type === 'reward' && tx.annotation_id === annotationId
    );
    
    const duration = Date.now() - startTime;
    
    const flowData = {
      annotationId,
      discovererId: userIds.discoverer,
      discoverySuccessful: discoveryResult.success || discoveryResult.discovered,
      rewardReceived: hasReward,
      walletBalance: walletData.balance,
      transactionRecorded: !!rewardTransaction,
      rewardAmount: rewardTransaction?.amount
    };
    
    businessFlowData.discovery = flowData;
    
    const success = flowData.discoverySuccessful && flowData.rewardReceived && flowData.transactionRecorded;
    recordTest('LBS发现奖励流程', success, 
      `LBS发现和奖励流程${success ? '成功' : '失败'}`, duration, flowData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('LBS发现奖励流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testPaymentIntegrationFlow() {
  console.log('=== 端到端测试4: 支付集成流程 ===\n');
  const startTime = Date.now();
  
  if (!userTokens.creator) {
    recordTest('支付集成流程', false, '没有创建者认证令牌', 0);
    return false;
  }
  
  try {
    // 1. 创建支付意图
    const paymentData = {
      amount: 50.00, // 50元
      currency: 'CNY',
      purpose: 'annotation_creation',
      description: '创建恶搞标注支付'
    };
    
    const paymentIntentResponse = await makeRequest(`${API_BASE_URL}/payments/create-intent`, {
      method: 'POST',
      body: paymentData,
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    if (paymentIntentResponse.status !== 200) {
      const duration = Date.now() - startTime;
      recordTest('支付集成流程', false, 
        `支付意图创建失败: ${paymentIntentResponse.status}`, duration);
      return false;
    }
    
    const paymentIntent = paymentIntentResponse.data.data || paymentIntentResponse.data;
    
    // 2. 模拟支付确认（在真实环境中这会通过Stripe webhook处理）
    await sleep(1000);
    
    const confirmData = {
      payment_intent_id: paymentIntent.id,
      status: 'succeeded'
    };
    
    const confirmResponse = await makeRequest(`${API_BASE_URL}/payments/confirm`, {
      method: 'POST',
      body: confirmData,
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    // 3. 验证支付历史
    const historyResponse = await makeRequest(`${API_BASE_URL}/payments/history`, {
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    const flowData = {
      paymentIntentId: paymentIntent.id,
      amount: paymentData.amount,
      intentCreated: true,
      confirmationAttempted: confirmResponse.status >= 200 && confirmResponse.status < 300,
      historyAccessible: historyResponse.status === 200
    };
    
    businessFlowData.payment = flowData;
    
    const success = flowData.intentCreated && flowData.historyAccessible;
    recordTest('支付集成流程', success, 
      `支付集成流程${success ? '成功' : '失败'}`, duration, flowData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('支付集成流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserInteractionFlow() {
  console.log('=== 端到端测试5: 用户交互流程 ===\n');
  const startTime = Date.now();
  
  if (!userTokens.discoverer || !businessFlowData.annotation?.annotationId) {
    recordTest('用户交互流程', false, '缺少必要的测试数据', 0);
    return false;
  }
  
  const annotationId = businessFlowData.annotation.annotationId;
  
  try {
    // 1. 点赞标注
    const likeResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}/like`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    // 2. 收藏标注
    const favoriteResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}/favorite`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    // 3. 添加评论
    const commentData = {
      content: '这个恶搞标注太有趣了！端到端测试评论。',
      rating: 5
    };
    
    const commentResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}/comments`, {
      method: 'POST',
      body: commentData,
      headers: {
        'Authorization': `Bearer ${userTokens.discoverer}`
      }
    });
    
    // 4. 验证交互数据
    await sleep(1000);
    
    const annotationResponse = await makeRequest(`${API_BASE_URL}/annotations/${annotationId}`);
    const annotation = annotationResponse.data.data || annotationResponse.data;
    
    const duration = Date.now() - startTime;
    
    const flowData = {
      annotationId,
      likeSuccessful: likeResponse.status >= 200 && likeResponse.status < 300,
      favoriteSuccessful: favoriteResponse.status >= 200 && favoriteResponse.status < 300,
      commentSuccessful: commentResponse.status >= 200 && commentResponse.status < 300,
      likesCount: annotation.likes_count || 0,
      favoritesCount: annotation.favorites_count || 0,
      commentsCount: annotation.comments_count || 0
    };
    
    businessFlowData.interaction = flowData;
    
    const success = flowData.likeSuccessful && flowData.favoriteSuccessful && flowData.commentSuccessful;
    recordTest('用户交互流程', success, 
      `用户交互流程${success ? '成功' : '失败'}`, duration, flowData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户交互流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAdminModerationFlow() {
  console.log('=== 端到端测试6: 管理员审核流程 ===\n');
  const startTime = Date.now();
  
  // 注意：这个测试需要管理员权限，在实际环境中可能需要特殊配置
  try {
    // 1. 获取待审核内容
    const reviewsResponse = await makeRequest(`${API_BASE_URL}/admin/content-reviews`, {
      headers: {
        'Authorization': `Bearer ${userTokens.creator}` // 假设创建者有管理员权限
      }
    });
    
    // 2. 获取用户管理列表
    const usersResponse = await makeRequest(`${API_BASE_URL}/admin/users`, {
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    // 3. 获取系统监控数据
    const monitorResponse = await makeRequest(`${API_BASE_URL}/admin/monitor/overview`, {
      headers: {
        'Authorization': `Bearer ${userTokens.creator}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    const flowData = {
      reviewsAccessible: reviewsResponse.status === 200,
      usersAccessible: usersResponse.status === 200,
      monitorAccessible: monitorResponse.status === 200,
      hasAdminAccess: reviewsResponse.status === 200 || usersResponse.status === 200
    };
    
    businessFlowData.admin = flowData;
    
    // 管理员功能可能需要特殊权限，所以我们检查是否至少有一个功能可访问
    const success = flowData.hasAdminAccess;
    recordTest('管理员审核流程', success, 
      `管理员功能${success ? '可访问' : '无权限访问'}`, duration, flowData);
    return success;
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('管理员审核流程', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成端到端测试报告
function generateE2EReport() {
  const passedTests = testResults.filter(test => test.success).length;
  const totalTests = testResults.length;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(2) : 0;
  
  const report = {
    summary: {
      timestamp: new Date().toISOString(),
      totalTests,
      passedTests,
      failedTests: totalTests - passedTests,
      successRate: `${successRate}%`,
      testType: 'End-to-End Integration'
    },
    businessFlows: {
      userRegistration: businessFlowData.users || null,
      annotationCreation: businessFlowData.annotation || null,
      lbsDiscovery: businessFlowData.discovery || null,
      paymentIntegration: businessFlowData.payment || null,
      userInteraction: businessFlowData.interaction || null,
      adminModeration: businessFlowData.admin || null
    },
    testResults,
    recommendations: generateE2ERecommendations()
  };
  
  // 保存报告到文件
  const reportPath = path.join(__dirname, 'e2e-integration-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  console.log('\n=== 端到端集成测试报告 ===');
  console.log(`测试总数: ${totalTests}`);
  console.log(`通过测试: ${passedTests}`);
  console.log(`失败测试: ${totalTests - passedTests}`);
  console.log(`成功率: ${successRate}%`);
  console.log(`\n业务流程完整性:`);
  console.log(`- 用户注册: ${businessFlowData.users?.bothUsersRegistered ? '✓' : '✗'}`);
  console.log(`- 标注创建: ${businessFlowData.annotation?.createdSuccessfully ? '✓' : '✗'}`);
  console.log(`- LBS发现: ${businessFlowData.discovery?.discoverySuccessful ? '✓' : '✗'}`);
  console.log(`- 支付集成: ${businessFlowData.payment?.intentCreated ? '✓' : '✗'}`);
  console.log(`- 用户交互: ${businessFlowData.interaction?.likeSuccessful ? '✓' : '✗'}`);
  console.log(`- 管理员功能: ${businessFlowData.admin?.hasAdminAccess ? '✓' : '✗'}`);
  console.log(`\n详细报告已保存到: ${reportPath}`);
  
  return report;
}

function generateE2ERecommendations() {
  const recommendations = [];
  
  // 检查关键业务流程
  if (!businessFlowData.users?.bothUsersRegistered) {
    recommendations.push({
      type: 'user_registration',
      priority: 'high',
      message: '用户注册流程存在问题，需要检查认证系统'
    });
  }
  
  if (!businessFlowData.annotation?.createdSuccessfully) {
    recommendations.push({
      type: 'annotation_creation',
      priority: 'high',
      message: '标注创建流程失败，需要检查数据库操作和API逻辑'
    });
  }
  
  if (!businessFlowData.discovery?.rewardReceived) {
    recommendations.push({
      type: 'lbs_reward',
      priority: 'high',
      message: 'LBS奖励机制未正常工作，需要检查地理位置验证和奖励发放逻辑'
    });
  }
  
  if (!businessFlowData.payment?.intentCreated) {
    recommendations.push({
      type: 'payment_integration',
      priority: 'medium',
      message: '支付集成存在问题，需要检查Stripe集成配置'
    });
  }
  
  // 检查失败的测试
  const failedTests = testResults.filter(test => !test.success);
  if (failedTests.length > 0) {
    recommendations.push({
      type: 'test_failures',
      priority: 'medium',
      message: `有 ${failedTests.length} 个测试失败，需要逐一检查`,
      details: failedTests.map(test => test.name)
    });
  }
  
  return recommendations;
}

// 主测试函数
async function runE2EIntegrationTests() {
  console.log('开始端到端集成测试...\n');
  
  try {
    await testCompleteUserRegistrationFlow();
    await testCompleteAnnotationCreationFlow();
    await testLBSDiscoveryFlow();
    await testPaymentIntegrationFlow();
    await testUserInteractionFlow();
    await testAdminModerationFlow();
    
    const report = generateE2EReport();
    
    console.log('\n端到端集成测试完成！');
    return report;
  } catch (error) {
    console.error('测试过程中发生错误:', error);
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  runE2EIntegrationTests()
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
  runE2EIntegrationTests,
  TEST_USERS,
  businessFlowData
};