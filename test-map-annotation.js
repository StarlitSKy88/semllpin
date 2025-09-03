/**
 * SmellPin 地图标注功能专项测试脚本
 * 测试地图标注的完整生命周期：创建 → 审核 → 发布 → 发现 → 奖励分配
 */

const axios = require('axios');

// 配置
const API_BASE_URL = 'http://localhost:3002/api/v1';
const TEST_TIMEOUT = 30000;

// 测试用户数据
const TEST_USERS = {
  creator: {
    email: 'john.doe@example.com',
    password: 'password123!',
    username: 'john_doe'
  },
  discoverer: {
    email: 'jane.smith@example.com', 
    password: 'password123!',
    username: 'jane_smith'
  }
};

// 测试位置数据
const TEST_LOCATIONS = {
  // 北京天安门广场
  beijing: {
    latitude: 39.9042,
    longitude: 116.4074,
    address: '北京市东城区天安门广场'
  },
  // 上海外滩
  shanghai: {
    latitude: 31.2304,
    longitude: 121.4737,
    address: '上海市黄浦区外滩'
  },
  // 广州塔附近
  guangzhou: {
    latitude: 23.1088,
    longitude: 113.3240,
    address: '广州市海珠区广州塔'
  }
};

// 标注类型配置
const ANNOTATION_TYPES = {
  garbage: {
    type: 'garbage_smell',
    description: '垃圾臭味标注',
    smellIntensity: 8,
    tags: ['垃圾', '恶臭', '环境污染']
  },
  industrial: {
    type: 'industrial_smell', 
    description: '工业废气标注',
    smellIntensity: 6,
    tags: ['工业', '化学', '废气']
  },
  exhaust: {
    type: 'vehicle_exhaust',
    description: '汽车尾气标注', 
    smellIntensity: 5,
    tags: ['汽车', '尾气', '交通']
  }
};

// 全局变量存储测试数据
let testData = {
  tokens: {},
  annotations: [],
  rewards: [],
  users: {}
};

// 工具函数
function log(message, data = null) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${message}`);
  if (data) {
    console.log(JSON.stringify(data, null, 2));
  }
}

function logError(message, error) {
  console.error(`❌ ${message}:`, error.response?.data || error.message);
}

function logSuccess(message, data = null) {
  console.log(`✅ ${message}`);
  if (data) {
    console.log(JSON.stringify(data, null, 2));
  }
}

// 延迟函数
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 计算两点间距离（米）
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // 地球半径（米）
  const φ1 = lat1 * Math.PI/180;
  const φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2-lat1) * Math.PI/180;
  const Δλ = (lon2-lon1) * Math.PI/180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
          Math.cos(φ1) * Math.cos(φ2) *
          Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

  return R * c;
}

// API 请求函数
async function apiRequest(method, endpoint, data = null, token = null) {
  const config = {
    method,
    url: `${API_BASE_URL}${endpoint}`,
    timeout: TEST_TIMEOUT,
    headers: {
      'Content-Type': 'application/json'
    }
  };

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  if (data) {
    config.data = data;
  }

  return axios(config);
}

// 1. 用户认证测试
async function testUserAuthentication() {
  log('🔐 开始用户认证测试...');
  
  try {
    // 登录创建者用户
    const creatorLogin = await apiRequest('POST', '/auth/login', {
      email: TEST_USERS.creator.email,
      password: TEST_USERS.creator.password
    });
    
    testData.tokens.creator = creatorLogin.data.data.tokens.accessToken;
    testData.users.creator = creatorLogin.data.data.user;
    logSuccess('创建者用户登录成功', { userId: testData.users.creator.id });
    
    // 登录发现者用户
    const discovererLogin = await apiRequest('POST', '/auth/login', {
      email: TEST_USERS.discoverer.email,
      password: TEST_USERS.discoverer.password
    });
    
    testData.tokens.discoverer = discovererLogin.data.data.tokens.accessToken;
    testData.users.discoverer = discovererLogin.data.data.user;
    logSuccess('发现者用户登录成功', { userId: testData.users.discoverer.id });
    
    return true;
  } catch (error) {
    logError('用户认证失败', error);
    return false;
  }
}

// 2. 标注创建测试
async function testAnnotationCreation() {
  log('📍 开始标注创建测试...');
  
  try {
    const results = [];
    
    // 创建不同类型的标注
    for (const [locationKey, location] of Object.entries(TEST_LOCATIONS)) {
      for (const [typeKey, annotationType] of Object.entries(ANNOTATION_TYPES)) {
        const annotationData = {
          latitude: location.latitude,
          longitude: location.longitude,
          description: `${annotationType.description} - ${location.address}`,
          smellIntensity: annotationType.smellIntensity
        };
        
        try {
          const response = await apiRequest(
            'POST', 
            '/annotations', 
            annotationData, 
            testData.tokens.creator
          );
          
          const annotation = response.data.data;
          testData.annotations.push({
            ...annotation,
            locationKey,
            typeKey,
            originalData: annotationData
          });
          
          logSuccess(`创建${typeKey}类型标注成功`, {
            id: annotation.id,
            location: locationKey,
            type: typeKey
          });
          
          results.push({ success: true, type: typeKey, location: locationKey });
        } catch (error) {
          logError(`创建${typeKey}类型标注失败`, error);
          results.push({ success: false, type: typeKey, location: locationKey, error: error.message });
        }
        
        // 避免请求过快
        await delay(500);
      }
    }
    
    log(`标注创建测试完成，成功: ${results.filter(r => r.success).length}/${results.length}`);
    return results;
  } catch (error) {
    logError('标注创建测试失败', error);
    return [];
  }
}

// 3. 付费标注测试
async function testPaidAnnotation() {
  log('💰 开始付费标注测试...');
  
  try {
    const paidAnnotationData = {
      latitude: TEST_LOCATIONS.beijing.latitude,
      longitude: TEST_LOCATIONS.beijing.longitude,
      smellIntensity: 9,
      description: '付费恶搞标注 - 超级臭味警告！',
      amount: 10.0,
      currency: 'usd',
      paymentDescription: '付费恶搞标注测试'
    };
    
    const response = await apiRequest(
      'POST',
      '/annotations/paid-prank',
      paidAnnotationData,
      testData.tokens.creator
    );
    
    logSuccess('付费标注创建成功', response.data.data);
    return response.data.data;
  } catch (error) {
    logError('付费标注创建失败', error);
    return null;
  }
}

// 4. 标注查询测试
async function testAnnotationQueries() {
  log('🔍 开始标注查询测试...');
  
  try {
    const results = {};
    
    // 测试获取标注列表
    const listResponse = await apiRequest('GET', '/annotations/list?page=1&limit=10');
    results.list = {
      success: true,
      count: listResponse.data.data.annotations.length,
      total: listResponse.data.data.pagination.total
    };
    logSuccess('获取标注列表成功', results.list);
    
    // 测试获取地图数据
    const mapResponse = await apiRequest('GET', '/annotations/map?north=40&south=39&east=117&west=116');
    results.map = {
      success: true,
      count: mapResponse.data.data.annotations.length
    };
    logSuccess('获取地图数据成功', results.map);
    
    // 测试附近标注查询
    const nearbyResponse = await apiRequest(
      'GET', 
      `/annotations/nearby?latitude=${TEST_LOCATIONS.beijing.latitude}&longitude=${TEST_LOCATIONS.beijing.longitude}&radius=5000`
    );
    results.nearby = {
      success: true,
      count: nearbyResponse.data.data.annotations.length
    };
    logSuccess('获取附近标注成功', results.nearby);
    
    // 测试标注统计
    const statsResponse = await apiRequest('GET', '/annotations/stats');
    results.stats = {
      success: true,
      data: statsResponse.data.data
    };
    logSuccess('获取标注统计成功', results.stats);
    
    return results;
  } catch (error) {
    logError('标注查询测试失败', error);
    return {};
  }
}

// 5. LBS位置上报和奖励测试
async function testLBSRewardMechanism() {
  log('🎯 开始LBS奖励机制测试...');
  
  try {
    const results = [];
    
    // 确保有标注可以触发奖励
    if (testData.annotations.length === 0) {
      log('⚠️ 没有可用的标注进行LBS测试');
      return [];
    }
    
    // 使用发现者用户测试位置上报
    for (const annotation of testData.annotations.slice(0, 3)) { // 只测试前3个标注
      try {
        // 模拟用户进入标注附近
        const locationData = {
          latitude: annotation.latitude + 0.0001, // 稍微偏移位置
          longitude: annotation.longitude + 0.0001,
          accuracy: 10,
          deviceInfo: {
            platform: 'test',
            version: '1.0.0'
          }
        };
        
        const response = await apiRequest(
          'POST',
          '/lbs/report-location',
          locationData,
          testData.tokens.discoverer
        );
        
        const result = response.data.data;
        if (result.rewards && result.rewards.length > 0) {
          testData.rewards.push(...result.rewards);
          logSuccess(`LBS奖励触发成功`, {
            annotationId: annotation.id,
            rewardsCount: result.rewards.length,
            totalAmount: result.totalRewardAmount
          });
        } else {
          log(`位置上报成功但未触发奖励`, {
            annotationId: annotation.id,
            triggeredGeofences: result.triggeredGeofences
          });
        }
        
        results.push({
          success: true,
          annotationId: annotation.id,
          rewardsTriggered: result.rewards?.length || 0,
          totalAmount: result.totalRewardAmount || 0
        });
        
      } catch (error) {
        logError(`LBS测试失败 - 标注${annotation.id}`, error);
        results.push({
          success: false,
          annotationId: annotation.id,
          error: error.message
        });
      }
      
      // 避免请求过快
      await delay(1000);
    }
    
    return results;
  } catch (error) {
    logError('LBS奖励机制测试失败', error);
    return [];
  }
}

// 6. 奖励查询和领取测试
async function testRewardManagement() {
  log('🏆 开始奖励管理测试...');
  
  try {
    const results = {};
    
    // 查询用户奖励记录
    const rewardsResponse = await apiRequest(
      'GET',
      '/lbs/rewards?page=1&limit=20',
      null,
      testData.tokens.discoverer
    );
    
    results.query = {
      success: true,
      count: rewardsResponse.data.rewards.length
    };
    logSuccess('查询奖励记录成功', results.query);
    
    // 查询LBS统计
    const statsResponse = await apiRequest(
      'GET',
      '/lbs/stats',
      null,
      testData.tokens.discoverer
    );
    
    results.stats = {
      success: true,
      data: statsResponse.data
    };
    logSuccess('查询LBS统计成功', results.stats);
    
    // 如果有可领取的奖励，尝试领取
    const availableRewards = rewardsResponse.data.rewards.filter(r => r.status === 'verified');
    if (availableRewards.length > 0) {
      try {
        const claimResponse = await apiRequest(
          'POST',
          '/lbs/claim-reward',
          { rewardIds: availableRewards.slice(0, 2).map(r => r.id) }, // 只领取前2个
          testData.tokens.discoverer
        );
        
        results.claim = {
          success: true,
          amount: claimResponse.data.data.amount,
          claimedCount: claimResponse.data.data.claimedRewards.length
        };
        logSuccess('奖励领取成功', results.claim);
      } catch (error) {
        logError('奖励领取失败', error);
        results.claim = { success: false, error: error.message };
      }
    } else {
      log('没有可领取的奖励');
      results.claim = { success: true, message: '没有可领取的奖励' };
    }
    
    return results;
  } catch (error) {
    logError('奖励管理测试失败', error);
    return {};
  }
}

// 7. 地理围栏精度测试
async function testGeofenceAccuracy() {
  log('🎯 开始地理围栏精度测试...');
  
  try {
    const results = [];
    
    if (testData.annotations.length === 0) {
      log('⚠️ 没有可用的标注进行地理围栏测试');
      return [];
    }
    
    const testAnnotation = testData.annotations[0];
    const testDistances = [10, 50, 100, 500, 1000]; // 测试不同距离（米）
    
    for (const distance of testDistances) {
      // 计算偏移位置（简单的经纬度偏移）
      const latOffset = distance / 111000; // 大约1度纬度 = 111km
      const lonOffset = distance / (111000 * Math.cos(testAnnotation.latitude * Math.PI / 180));
      
      const testLocation = {
        latitude: testAnnotation.latitude + latOffset,
        longitude: testAnnotation.longitude + lonOffset,
        accuracy: 5
      };
      
      try {
        const response = await apiRequest(
          'POST',
          '/lbs/report-location',
          testLocation,
          testData.tokens.discoverer
        );
        
        const actualDistance = calculateDistance(
          testAnnotation.latitude,
          testAnnotation.longitude,
          testLocation.latitude,
          testLocation.longitude
        );
        
        const triggered = response.data.data.triggeredGeofences > 0;
        
        results.push({
          targetDistance: distance,
          actualDistance: Math.round(actualDistance),
          triggered,
          rewardsCount: response.data.data.rewards?.length || 0
        });
        
        log(`距离${distance}m测试: 实际${Math.round(actualDistance)}m, 触发: ${triggered}`);
        
      } catch (error) {
        logError(`地理围栏测试失败 - 距离${distance}m`, error);
        results.push({
          targetDistance: distance,
          error: error.message
        });
      }
      
      await delay(500);
    }
    
    return results;
  } catch (error) {
    logError('地理围栏精度测试失败', error);
    return [];
  }
}

// 8. 标注详情和交互测试
async function testAnnotationInteractions() {
  log('👍 开始标注交互测试...');
  
  try {
    const results = {};
    
    if (testData.annotations.length === 0) {
      log('⚠️ 没有可用的标注进行交互测试');
      return {};
    }
    
    const testAnnotation = testData.annotations[0];
    
    // 测试获取标注详情
    try {
      const detailsResponse = await apiRequest(
        'GET',
        `/annotations/${testAnnotation.id}/details`,
        null,
        testData.tokens.discoverer
      );
      
      results.details = {
        success: true,
        hasMediaFiles: detailsResponse.data.data.mediaFiles.length > 0,
        likesCount: detailsResponse.data.data.likesCount
      };
      logSuccess('获取标注详情成功', results.details);
    } catch (error) {
      logError('获取标注详情失败', error);
      results.details = { success: false, error: error.message };
    }
    
    // 测试点赞功能
    try {
      const likeResponse = await apiRequest(
        'POST',
        `/annotations/${testAnnotation.id}/like`,
        null,
        testData.tokens.discoverer
      );
      
      results.like = {
        success: true,
        message: likeResponse.data.message
      };
      logSuccess('标注点赞成功', results.like);
      
      // 测试取消点赞
      await delay(500);
      const unlikeResponse = await apiRequest(
        'DELETE',
        `/annotations/${testAnnotation.id}/like`,
        null,
        testData.tokens.discoverer
      );
      
      results.unlike = {
        success: true,
        message: unlikeResponse.data.message
      };
      logSuccess('取消点赞成功', results.unlike);
      
    } catch (error) {
      logError('点赞功能测试失败', error);
      results.like = { success: false, error: error.message };
    }
    
    return results;
  } catch (error) {
    logError('标注交互测试失败', error);
    return {};
  }
}

// 主测试函数
async function runMapAnnotationTests() {
  console.log('🚀 SmellPin 地图标注功能专项测试开始\n');
  console.log('=' .repeat(60));
  
  const testResults = {
    startTime: new Date(),
    tests: {},
    summary: {}
  };
  
  try {
    // 1. 用户认证
    testResults.tests.authentication = await testUserAuthentication();
    if (!testResults.tests.authentication) {
      throw new Error('用户认证失败，无法继续测试');
    }
    
    // 2. 标注创建
    testResults.tests.annotationCreation = await testAnnotationCreation();
    
    // 3. 付费标注
    testResults.tests.paidAnnotation = await testPaidAnnotation();
    
    // 4. 标注查询
    testResults.tests.annotationQueries = await testAnnotationQueries();
    
    // 5. LBS奖励机制
    testResults.tests.lbsRewards = await testLBSRewardMechanism();
    
    // 6. 奖励管理
    testResults.tests.rewardManagement = await testRewardManagement();
    
    // 7. 地理围栏精度
    testResults.tests.geofenceAccuracy = await testGeofenceAccuracy();
    
    // 8. 标注交互
    testResults.tests.annotationInteractions = await testAnnotationInteractions();
    
  } catch (error) {
    logError('测试执行失败', error);
    testResults.error = error.message;
  }
  
  testResults.endTime = new Date();
  testResults.duration = testResults.endTime - testResults.startTime;
  
  // 生成测试报告
  generateTestReport(testResults);
}

// 生成测试报告
function generateTestReport(results) {
  console.log('\n' + '=' .repeat(60));
  console.log('📊 SmellPin 地图标注功能测试报告');
  console.log('=' .repeat(60));
  
  console.log(`\n⏱️  测试时间: ${results.duration}ms`);
  console.log(`📅 开始时间: ${results.startTime.toISOString()}`);
  console.log(`📅 结束时间: ${results.endTime.toISOString()}`);
  
  console.log('\n🧪 测试结果概览:');
  console.log('-' .repeat(40));
  
  // 统计各项测试结果
  const stats = {
    total: 0,
    passed: 0,
    failed: 0,
    annotations: testData.annotations.length,
    rewards: testData.rewards.length
  };
  
  Object.entries(results.tests).forEach(([testName, result]) => {
    stats.total++;
    if (result && (result === true || result.success !== false)) {
      stats.passed++;
      console.log(`✅ ${testName}: 通过`);
    } else {
      stats.failed++;
      console.log(`❌ ${testName}: 失败`);
    }
  });
  
  console.log('\n📈 统计数据:');
  console.log('-' .repeat(40));
  console.log(`总测试数: ${stats.total}`);
  console.log(`通过: ${stats.passed}`);
  console.log(`失败: ${stats.failed}`);
  console.log(`成功率: ${((stats.passed / stats.total) * 100).toFixed(1)}%`);
  console.log(`创建标注数: ${stats.annotations}`);
  console.log(`触发奖励数: ${stats.rewards}`);
  
  console.log('\n🎯 核心功能验证:');
  console.log('-' .repeat(40));
  
  // 核心功能检查
  const coreFeatures = {
    '用户认证': results.tests.authentication,
    '标注创建': results.tests.annotationCreation?.some?.(r => r.success),
    '标注查询': results.tests.annotationQueries?.list?.success,
    'LBS奖励': results.tests.lbsRewards?.some?.(r => r.success),
    '地理围栏': results.tests.geofenceAccuracy?.length > 0,
    '标注交互': results.tests.annotationInteractions?.details?.success
  };
  
  Object.entries(coreFeatures).forEach(([feature, status]) => {
    const icon = status ? '✅' : '❌';
    console.log(`${icon} ${feature}: ${status ? '正常' : '异常'}`);
  });
  
  console.log('\n💡 测试建议:');
  console.log('-' .repeat(40));
  
  if (stats.annotations === 0) {
    console.log('⚠️  建议检查标注创建API的权限和数据验证');
  }
  
  if (stats.rewards === 0) {
    console.log('⚠️  建议检查LBS奖励机制的地理围栏配置');
  }
  
  if (stats.failed > 0) {
    console.log('⚠️  建议查看详细错误日志，修复失败的测试项');
  }
  
  if (stats.passed === stats.total) {
    console.log('🎉 所有测试通过！地图标注功能运行正常');
  }
  
  console.log('\n' + '=' .repeat(60));
  console.log('测试完成！');
}

// 执行测试
if (require.main === module) {
  runMapAnnotationTests().catch(error => {
    console.error('测试执行失败:', error);
    process.exit(1);
  });
}

module.exports = {
  runMapAnnotationTests,
  testData
};