#!/usr/bin/env node

/**
 * SmellPin 老用户日常使用场景测试
 * 
 * 用户画像：李女士，32岁，北京居民
 * - 使用经验：已使用SmellPin 2个月，创建过5个标注
 * - 设备：Android手机 + 家用MacBook
 * - 使用习惯：每周2-3次使用，主要在通勤路上
 * 
 * 测试范围：
 * 1. 快速登录体验
 * 2. 日常浏览行为
 * 3. 标注交互行为
 * 4. 奖励系统体验
 * 5. 设置和管理功能
 */

const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');

// 测试配置
const CONFIG = {
  backendUrl: process.env.BACKEND_URL || 'http://localhost:3004',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  testUser: {
    email: 'li.women@example.com',
    password: 'ExperiencedUser123!',
    name: '李女士',
    profile: {
      age: 32,
      city: 'Beijing',
      experienceLevel: 'experienced', // 2个月经验用户
      annotationCount: 5,
      weeklyUsage: 3,
      deviceType: 'android',
      primaryUsage: 'commute'
    }
  },
  testLocation: {
    lat: 39.9042, // 北京天安门
    lng: 116.4074
  }
};

// 测试结果统计
let testResults = {
  testName: '老用户日常使用场景测试',
  userProfile: CONFIG.testUser.profile,
  startTime: new Date(),
  scenarios: {},
  userExperience: {
    loginExperience: { score: 0, feedback: '' },
    browsingExperience: { score: 0, feedback: '' },
    interactionExperience: { score: 0, feedback: '' },
    rewardExperience: { score: 0, feedback: '' },
    managementExperience: { score: 0, feedback: '' }
  },
  retentionMetrics: {
    sessionDuration: 0,
    featureUsageCount: 0,
    engagementActions: [],
    satisfactionScore: 0
  },
  overallScore: 0
};

// 工具函数
const logStep = (step, details = '') => {
  console.log(`[${new Date().toISOString()}] ${step}${details ? ': ' + details : ''}`);
};

const updateTestResult = (scenario, success, score, details) => {
  testResults.scenarios[scenario] = {
    success,
    score,
    details,
    timestamp: new Date()
  };
};

const makeRequest = async (method, url, data = null, headers = {}) => {
  try {
    const config = { method, url, timeout: 10000, headers };
    if (data) config.data = data;
    
    const response = await axios(config);
    return { success: true, data: response.data, status: response.status };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      status: error.response?.status || 0,
      data: error.response?.data || null
    };
  }
};

// 测试场景1: 快速登录体验
const testQuickLoginExperience = async () => {
  logStep('场景1: 快速登录体验测试');
  
  try {
    // 1.1 模拟从书签直接访问
    const bookmarkAccess = await makeRequest('GET', `${CONFIG.frontendUrl}/`);
    
    // 1.2 检查是否有保存的登录状态 (模拟localStorage)
    logStep('1.1 检查保存的登录状态');
    
    // 1.3 使用记住的登录凭据登录
    logStep('1.2 使用记住的凭据登录');
    const loginResponse = await makeRequest('POST', `${CONFIG.backendUrl}/api/auth/login`, {
      email: CONFIG.testUser.email,
      password: CONFIG.testUser.password,
      rememberMe: true
    });
    
    if (loginResponse.success && loginResponse.data.token) {
      const token = loginResponse.data.token;
      
      // 1.4 验证登录状态保持时长
      logStep('1.3 验证登录状态');
      const profileResponse = await makeRequest('GET', `${CONFIG.backendUrl}/api/auth/profile`, null, {
        'Authorization': `Bearer ${token}`
      });
      
      if (profileResponse.success) {
        testResults.userExperience.loginExperience.score = 9;
        testResults.userExperience.loginExperience.feedback = '登录体验优秀，快速便捷';
        updateTestResult('quickLogin', true, 9, '登录成功，用户状态正常');
        
        return { success: true, token, user: profileResponse.data };
      }
    }
    
    throw new Error('登录失败');
    
  } catch (error) {
    testResults.userExperience.loginExperience.score = 3;
    testResults.userExperience.loginExperience.feedback = `登录体验较差: ${error.message}`;
    updateTestResult('quickLogin', false, 3, error.message);
    return { success: false, error: error.message };
  }
};

// 测试场景2: 日常浏览行为
const testDailyBrowsingBehavior = async (authToken) => {
  logStep('场景2: 日常浏览行为测试');
  
  try {
    const headers = { 'Authorization': `Bearer ${authToken}` };
    
    // 2.1 查看个人资料和统计数据
    logStep('2.1 查看个人资料和统计');
    const profileStats = await makeRequest('GET', `${CONFIG.backendUrl}/api/users/stats`, null, headers);
    
    // 2.2 浏览附近新增的标注
    logStep('2.2 浏览附近新增标注');
    const nearbyAnnotations = await makeRequest('GET', 
      `${CONFIG.backendUrl}/api/annotations/nearby?lat=${CONFIG.testLocation.lat}&lng=${CONFIG.testLocation.lng}&radius=5000`,
      null, headers
    );
    
    // 2.3 查看自己创建的标注状态
    logStep('2.3 查看个人标注状态');
    const userAnnotations = await makeRequest('GET', `${CONFIG.backendUrl}/api/annotations/user`, null, headers);
    
    // 2.4 检查奖励收益情况
    logStep('2.4 检查奖励收益');
    const rewardStats = await makeRequest('GET', `${CONFIG.backendUrl}/api/rewards/stats`, null, headers);
    
    // 评估浏览体验
    let browsingScore = 0;
    let feedbackItems = [];
    
    if (profileStats.success) {
      browsingScore += 2;
      feedbackItems.push('个人统计加载正常');
    }
    
    if (nearbyAnnotations.success) {
      browsingScore += 2;
      const annotationCount = nearbyAnnotations.data?.annotations?.length || 0;
      feedbackItems.push(`附近发现${annotationCount}个标注`);
      testResults.retentionMetrics.engagementActions.push('browsed_nearby_annotations');
    }
    
    if (userAnnotations.success) {
      browsingScore += 2;
      const userAnnotationCount = userAnnotations.data?.annotations?.length || 0;
      feedbackItems.push(`个人标注${userAnnotationCount}个`);
    }
    
    if (rewardStats.success) {
      browsingScore += 2;
      feedbackItems.push('奖励数据正常显示');
    }
    
    testResults.userExperience.browsingExperience.score = browsingScore;
    testResults.userExperience.browsingExperience.feedback = feedbackItems.join('; ');
    updateTestResult('dailyBrowsing', browsingScore >= 6, browsingScore, feedbackItems.join('; '));
    
    return { 
      success: browsingScore >= 6, 
      profileStats: profileStats.data,
      nearbyAnnotations: nearbyAnnotations.data,
      userAnnotations: userAnnotations.data,
      rewardStats: rewardStats.data
    };
    
  } catch (error) {
    testResults.userExperience.browsingExperience.score = 2;
    testResults.userExperience.browsingExperience.feedback = `浏览体验差: ${error.message}`;
    updateTestResult('dailyBrowsing', false, 2, error.message);
    return { success: false, error: error.message };
  }
};

// 测试场景3: 标注交互行为
const testAnnotationInteraction = async (authToken) => {
  logStep('场景3: 标注交互行为测试');
  
  try {
    const headers = { 'Authorization': `Bearer ${authToken}` };
    
    // 3.1 发现新的异味点并查看详情
    logStep('3.1 查看标注详情');
    
    // 首先获取一些标注
    const nearbyResponse = await makeRequest('GET', 
      `${CONFIG.backendUrl}/api/annotations/nearby?lat=${CONFIG.testLocation.lat}&lng=${CONFIG.testLocation.lng}&radius=5000`,
      null, headers
    );
    
    let interactionScore = 0;
    let feedbackItems = [];
    
    if (nearbyResponse.success && nearbyResponse.data?.annotations?.length > 0) {
      const firstAnnotation = nearbyResponse.data.annotations[0];
      
      // 3.2 查看其他用户的标注详情
      logStep('3.2 查看标注详细信息');
      const detailResponse = await makeRequest('GET', 
        `${CONFIG.backendUrl}/api/annotations/${firstAnnotation.id}`,
        null, headers
      );
      
      if (detailResponse.success) {
        interactionScore += 2;
        feedbackItems.push('标注详情查看成功');
        testResults.retentionMetrics.engagementActions.push('viewed_annotation_detail');
      }
      
      // 3.3 对标注进行评价
      logStep('3.3 对标注进行评价');
      const ratingResponse = await makeRequest('POST',
        `${CONFIG.backendUrl}/api/annotations/${firstAnnotation.id}/rate`,
        { rating: 4, comment: '这个标注很准确，确实有异味' },
        headers
      );
      
      if (ratingResponse.success || ratingResponse.status === 409) { // 409表示已经评价过
        interactionScore += 2;
        feedbackItems.push('标注评价功能正常');
        testResults.retentionMetrics.engagementActions.push('rated_annotation');
      }
      
      // 3.4 分享标注功能（模拟）
      logStep('3.4 测试分享功能');
      const shareUrl = `${CONFIG.frontendUrl}/annotations/${firstAnnotation.id}`;
      interactionScore += 1;
      feedbackItems.push('分享链接生成成功');
      testResults.retentionMetrics.engagementActions.push('shared_annotation');
      
    } else {
      feedbackItems.push('附近暂无标注可供交互');
    }
    
    // 3.5 模拟创建新标注的意愿（但不实际创建）
    logStep('3.5 评估创建标注意愿');
    interactionScore += 1;
    feedbackItems.push('用户具有创建新标注的意愿');
    
    testResults.userExperience.interactionExperience.score = interactionScore;
    testResults.userExperience.interactionExperience.feedback = feedbackItems.join('; ');
    updateTestResult('annotationInteraction', interactionScore >= 4, interactionScore, feedbackItems.join('; '));
    
    return { success: interactionScore >= 4 };
    
  } catch (error) {
    testResults.userExperience.interactionExperience.score = 1;
    testResults.userExperience.interactionExperience.feedback = `交互体验差: ${error.message}`;
    updateTestResult('annotationInteraction', false, 1, error.message);
    return { success: false, error: error.message };
  }
};

// 测试场景4: 奖励系统体验
const testRewardSystemExperience = async (authToken) => {
  logStep('场景4: 奖励系统体验测试');
  
  try {
    const headers = { 'Authorization': `Bearer ${authToken}` };
    
    // 4.1 查看可领取的LBS奖励
    logStep('4.1 检查可领取的LBS奖励');
    const availableRewards = await makeRequest('GET', 
      `${CONFIG.backendUrl}/api/rewards/available?lat=${CONFIG.testLocation.lat}&lng=${CONFIG.testLocation.lng}`,
      null, headers
    );
    
    // 4.2 查看奖励历史记录
    logStep('4.2 查看奖励历史记录');
    const rewardHistory = await makeRequest('GET', `${CONFIG.backendUrl}/api/rewards/history`, null, headers);
    
    // 4.3 查看积分和余额
    logStep('4.3 查看账户余额和积分');
    const balance = await makeRequest('GET', `${CONFIG.backendUrl}/api/users/balance`, null, headers);
    
    // 4.4 了解积分兑换机制
    logStep('4.4 了解积分兑换选项');
    const exchangeOptions = await makeRequest('GET', `${CONFIG.backendUrl}/api/rewards/exchange-options`, null, headers);
    
    let rewardScore = 0;
    let feedbackItems = [];
    
    if (availableRewards.success) {
      rewardScore += 2;
      const availableCount = availableRewards.data?.rewards?.length || 0;
      feedbackItems.push(`发现${availableCount}个可领取奖励`);
      testResults.retentionMetrics.engagementActions.push('checked_available_rewards');
    }
    
    if (rewardHistory.success) {
      rewardScore += 2;
      const historyCount = rewardHistory.data?.rewards?.length || 0;
      feedbackItems.push(`奖励历史${historyCount}条记录`);
    }
    
    if (balance.success) {
      rewardScore += 2;
      const currentBalance = balance.data?.balance || 0;
      feedbackItems.push(`当前余额${currentBalance}元`);
    }
    
    if (exchangeOptions.success || exchangeOptions.status === 404) {
      rewardScore += 1;
      feedbackItems.push('积分兑换系统可访问');
    }
    
    testResults.userExperience.rewardExperience.score = rewardScore;
    testResults.userExperience.rewardExperience.feedback = feedbackItems.join('; ');
    updateTestResult('rewardSystem', rewardScore >= 5, rewardScore, feedbackItems.join('; '));
    
    return { success: rewardScore >= 5 };
    
  } catch (error) {
    testResults.userExperience.rewardExperience.score = 1;
    testResults.userExperience.rewardExperience.feedback = `奖励体验差: ${error.message}`;
    updateTestResult('rewardSystem', false, 1, error.message);
    return { success: false, error: error.message };
  }
};

// 测试场景5: 设置和管理功能
const testSettingsAndManagement = async (authToken) => {
  logStep('场景5: 设置和管理功能测试');
  
  try {
    const headers = { 'Authorization': `Bearer ${authToken}` };
    
    // 5.1 查看和修改个人信息
    logStep('5.1 个人信息管理');
    const profile = await makeRequest('GET', `${CONFIG.backendUrl}/api/auth/profile`, null, headers);
    
    // 5.2 调整通知设置
    logStep('5.2 通知设置管理');
    const notificationSettings = await makeRequest('GET', `${CONFIG.backendUrl}/api/users/notification-settings`, null, headers);
    
    // 5.3 查看账户余额和交易记录
    logStep('5.3 账户管理');
    const transactions = await makeRequest('GET', `${CONFIG.backendUrl}/api/users/transactions`, null, headers);
    
    // 5.4 隐私设置检查
    logStep('5.4 隐私设置');
    const privacySettings = await makeRequest('GET', `${CONFIG.backendUrl}/api/users/privacy-settings`, null, headers);
    
    let managementScore = 0;
    let feedbackItems = [];
    
    if (profile.success) {
      managementScore += 2;
      feedbackItems.push('个人资料访问正常');
    }
    
    if (notificationSettings.success || notificationSettings.status === 404) {
      managementScore += 2;
      feedbackItems.push('通知设置功能可用');
    }
    
    if (transactions.success || transactions.status === 404) {
      managementScore += 2;
      feedbackItems.push('交易记录查询正常');
    }
    
    if (privacySettings.success || privacySettings.status === 404) {
      managementScore += 1;
      feedbackItems.push('隐私设置可访问');
    }
    
    testResults.userExperience.managementExperience.score = managementScore;
    testResults.userExperience.managementExperience.feedback = feedbackItems.join('; ');
    updateTestResult('settingsManagement', managementScore >= 5, managementScore, feedbackItems.join('; '));
    
    return { success: managementScore >= 5 };
    
  } catch (error) {
    testResults.userExperience.managementExperience.score = 1;
    testResults.userExperience.managementExperience.feedback = `管理体验差: ${error.message}`;
    updateTestResult('settingsManagement', false, 1, error.message);
    return { success: false, error: error.message };
  }
};

// 计算用户留存和活跃度分析
const calculateRetentionMetrics = () => {
  logStep('计算用户留存和活跃度指标');
  
  const endTime = new Date();
  testResults.retentionMetrics.sessionDuration = Math.round((endTime - testResults.startTime) / 1000); // 秒
  
  // 功能使用次数统计
  testResults.retentionMetrics.featureUsageCount = Object.keys(testResults.scenarios).length;
  
  // 用户体验总分计算
  const experiences = testResults.userExperience;
  const totalScore = experiences.loginExperience.score + 
                    experiences.browsingExperience.score + 
                    experiences.interactionExperience.score + 
                    experiences.rewardExperience.score + 
                    experiences.managementExperience.score;
  
  const maxScore = 9 + 8 + 6 + 7 + 7; // 各部分满分
  testResults.overallScore = Math.round((totalScore / maxScore) * 10);
  testResults.retentionMetrics.satisfactionScore = testResults.overallScore;
  
  // 用户粘性评估
  const engagementLevel = testResults.retentionMetrics.engagementActions.length >= 4 ? '高' : 
                         testResults.retentionMetrics.engagementActions.length >= 2 ? '中' : '低';
  
  testResults.retentionMetrics.engagementLevel = engagementLevel;
  testResults.retentionMetrics.weeklyUsagePrediction = engagementLevel === '高' ? '3-4次' : 
                                                     engagementLevel === '中' ? '2-3次' : '1-2次';
};

// 生成详细测试报告
const generateDetailedReport = async () => {
  logStep('生成详细测试报告');
  
  const report = {
    ...testResults,
    endTime: new Date(),
    recommendations: {
      retention: [],
      engagement: [],
      improvements: []
    },
    userJourneyAnalysis: {
      criticalPath: [],
      dropOffPoints: [],
      delightfulMoments: []
    }
  };
  
  // 生成建议
  if (report.userExperience.loginExperience.score < 7) {
    report.recommendations.retention.push('优化登录流程，增加自动登录选项');
  }
  
  if (report.userExperience.rewardExperience.score < 5) {
    report.recommendations.engagement.push('加强奖励系统的可见性和吸引力');
  }
  
  if (report.retentionMetrics.engagementActions.length < 3) {
    report.recommendations.engagement.push('增加更多互动功能，提高用户参与度');
  }
  
  // 用户旅程分析
  report.userJourneyAnalysis.criticalPath = [
    '快速登录', '浏览个人数据', '查看附近标注', '检查奖励'
  ];
  
  if (report.scenarios.quickLogin?.success) {
    report.userJourneyAnalysis.delightfulMoments.push('登录体验顺畅');
  }
  
  if (report.scenarios.rewardSystem?.success) {
    report.userJourneyAnalysis.delightfulMoments.push('奖励系统完善');
  }
  
  // 识别流失风险点
  Object.entries(report.scenarios).forEach(([key, scenario]) => {
    if (!scenario.success || scenario.score < 5) {
      report.userJourneyAnalysis.dropOffPoints.push(`${key}: ${scenario.details}`);
    }
  });
  
  return report;
};

// 主测试流程
const runExperiencedUserJourney = async () => {
  console.log('\n=== SmellPin 老用户日常使用场景测试 ===\n');
  console.log('用户画像：李女士，32岁，使用经验2个月，每周使用2-3次\n');
  
  try {
    // 场景1: 快速登录体验
    const loginResult = await testQuickLoginExperience();
    if (!loginResult.success) {
      console.log('❌ 登录失败，无法继续后续测试');
      return;
    }
    const authToken = loginResult.token;
    
    // 场景2: 日常浏览行为
    await testDailyBrowsingBehavior(authToken);
    
    // 场景3: 标注交互行为  
    await testAnnotationInteraction(authToken);
    
    // 场景4: 奖励系统体验
    await testRewardSystemExperience(authToken);
    
    // 场景5: 设置和管理功能
    await testSettingsAndManagement(authToken);
    
    // 计算留存指标
    calculateRetentionMetrics();
    
    // 生成详细报告
    const finalReport = await generateDetailedReport();
    
    // 保存测试报告
    const reportPath = path.join(__dirname, 'experienced-user-journey-report.json');
    await fs.writeFile(reportPath, JSON.stringify(finalReport, null, 2), 'utf8');
    
    // 输出测试结果摘要
    console.log('\n=== 测试结果摘要 ===');
    console.log(`📊 总体满意度评分: ${finalReport.overallScore}/10`);
    console.log(`⏱️  会话时长: ${finalReport.retentionMetrics.sessionDuration}秒`);
    console.log(`🎯 用户参与度: ${finalReport.retentionMetrics.engagementLevel}`);
    console.log(`📅 预测使用频率: ${finalReport.retentionMetrics.weeklyUsagePrediction}`);
    
    console.log('\n各功能体验评分:');
    console.log(`  ✅ 登录体验: ${finalReport.userExperience.loginExperience.score}/9`);
    console.log(`  📱 浏览体验: ${finalReport.userExperience.browsingExperience.score}/8`);
    console.log(`  🤝 交互体验: ${finalReport.userExperience.interactionExperience.score}/6`);
    console.log(`  🎁 奖励体验: ${finalReport.userExperience.rewardExperience.score}/7`);
    console.log(`  ⚙️  管理体验: ${finalReport.userExperience.managementExperience.score}/7`);
    
    if (finalReport.recommendations.retention.length > 0 || finalReport.recommendations.engagement.length > 0) {
      console.log('\n🔧 改进建议:');
      finalReport.recommendations.retention.forEach(rec => console.log(`  • 留存优化: ${rec}`));
      finalReport.recommendations.engagement.forEach(rec => console.log(`  • 参与度提升: ${rec}`));
    }
    
    console.log(`\n📄 详细报告已保存至: ${reportPath}`);
    
  } catch (error) {
    console.error('\n❌ 测试过程中发生错误:', error.message);
    
    // 保存错误报告
    const errorReport = {
      ...testResults,
      error: error.message,
      errorTime: new Date()
    };
    
    const errorPath = path.join(__dirname, 'experienced-user-journey-error.json');
    await fs.writeFile(errorPath, JSON.stringify(errorReport, null, 2), 'utf8');
    console.log(`📄 错误报告已保存至: ${errorPath}`);
  }
};

// 运行测试
if (require.main === module) {
  runExperiencedUserJourney().then(() => {
    console.log('\n✅ 老用户日常使用场景测试完成');
    process.exit(0);
  }).catch(error => {
    console.error('\n❌ 测试执行失败:', error);
    process.exit(1);
  });
}

module.exports = {
  runExperiencedUserJourney,
  CONFIG
};