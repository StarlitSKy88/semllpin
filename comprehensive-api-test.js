/**
 * SmellPin 核心业务功能综合测试
 * 深度测试标注创建、发现、LBS奖励系统等核心业务流程
 */

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

// 配置
const CONFIG = {
  BASE_URL: 'http://localhost:3004',
  API_VERSION: 'v1',
  TEST_USER: {
    username: 'testuser' + Date.now(),
    email: 'test' + Date.now() + '@example.com',
    password: 'Test123456',
    displayName: '测试用户'
  },
  // 真实测试坐标
  TEST_LOCATIONS: [
    { name: '北京天安门', lat: 39.9042, lng: 116.4074 },
    { name: '上海外滩', lat: 31.2304, lng: 121.4737 },
    { name: '深圳腾讯大厦', lat: 22.5431, lng: 114.0579 },
    { name: '杭州西湖', lat: 30.2741, lng: 120.1551 },
    { name: '成都春熙路', lat: 30.6624, lng: 104.0633 }
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
  success: (msg, data = '') => console.log(`[✓] ${msg}`, data ? JSON.stringify(data, null, 2) : ''),
  warn: (msg, data = '') => console.log(`[WARN] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
};

const httpClient = axios.create({
  baseURL: `${CONFIG.BASE_URL}/api/${CONFIG.API_VERSION}`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// 添加请求拦截器
httpClient.interceptors.request.use(
  (config) => {
    if (authToken) {
      config.headers.Authorization = `Bearer ${authToken}`;
    }
    logger.info(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => Promise.reject(error)
);

// 添加响应拦截器
httpClient.interceptors.response.use(
  (response) => {
    logger.info(`API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    logger.error(`API Error: ${error.response?.status} ${error.config?.url}`, error);
    return Promise.reject(error);
  }
);

/**
 * 用户认证相关测试
 */
class AuthTestSuite {
  static async registerUser() {
    logger.info('🔐 开始用户注册测试...');
    
    try {
      const response = await httpClient.post('/users/register', CONFIG.TEST_USER);
      
      if (response.data.success) {
        testUserId = response.data.data.user.id;
        logger.success('用户注册成功', {
          userId: testUserId,
          username: CONFIG.TEST_USER.username
        });
        return true;
      } else {
        logger.error('用户注册失败', response.data);
        return false;
      }
    } catch (error) {
      // 如果用户已存在，尝试登录
      if (error.response?.status === 409 || error.response?.data?.message?.includes('已存在')) {
        logger.warn('用户已存在，尝试登录...');
        return await this.loginUser();
      }
      
      logger.error('用户注册失败', error);
      return false;
    }
  }

  static async loginUser() {
    logger.info('🔑 开始用户登录测试...');
    
    try {
      const response = await httpClient.post('/users/login', {
        email: CONFIG.TEST_USER.email,
        password: CONFIG.TEST_USER.password
      });
      
      logger.info('登录响应数据结构:', response.data);
      
      if (response.data.success) {
        // 尝试不同的token路径
        authToken = response.data.data?.tokens?.accessToken || 
                   response.data.data?.accessToken || 
                   response.data.data?.token || 
                   response.data.accessToken || 
                   response.data.token;
        
        testUserId = response.data.data?.user?.id || 
                    response.data.data?.id ||
                    response.data.user?.id;
        
        logger.success('用户登录成功', {
          userId: testUserId,
          tokenLength: authToken ? authToken.length : 'undefined',
          dataStructure: Object.keys(response.data.data || {})
        });
        return true;
      } else {
        logger.error('用户登录失败', response.data);
        return false;
      }
    } catch (error) {
      logger.error('用户登录失败', error);
      return false;
    }
  }

  static async getUserProfile() {
    logger.info('👤 测试获取用户资料...');
    
    try {
      const response = await httpClient.get('/users/profile/me');
      
      if (response.data.success) {
        logger.success('获取用户资料成功', response.data.data);
        return response.data.data;
      } else {
        logger.error('获取用户资料失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取用户资料失败', error);
      return null;
    }
  }
}

/**
 * 标注创建API测试套件
 */
class AnnotationTestSuite {
  static async createBasicAnnotation(location, options = {}) {
    logger.info(`📍 创建基础标注测试 - ${location.name}...`);
    
    const annotationData = {
      latitude: location.lat,
      longitude: location.lng,
      smellIntensity: options.intensity || Math.floor(Math.random() * 10) + 1,
      description: options.description || `测试标注 - ${location.name} - ${new Date().toISOString()}`,
      mediaFiles: options.mediaFiles || []
    };
    
    try {
      const response = await httpClient.post('/annotations', annotationData);
      
      if (response.data.success) {
        const annotation = response.data.data.annotation;
        createdAnnotations.push(annotation);
        
        logger.success(`标注创建成功 - ${location.name}`, {
          id: annotation.id,
          latitude: annotation.latitude,
          longitude: annotation.longitude,
          smellIntensity: annotation.smellIntensity,
          status: annotation.status
        });
        
        return annotation;
      } else {
        logger.error('标注创建失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`标注创建失败 - ${location.name}`, error);
      return null;
    }
  }

  static async createPaidPrankAnnotation(location, amount = 5) {
    logger.info(`💰 创建付费恶搞标注测试 - ${location.name}...`);
    
    const annotationData = {
      latitude: location.lat,
      longitude: location.lng,
      smellIntensity: 10, // 最高强度
      description: `付费恶搞标注 - ${location.name} - 超级臭！`,
      mediaFiles: [],
      amount: amount,
      currency: 'usd',
      paymentDescription: `付费恶搞标注创建 - ${location.name}`
    };
    
    try {
      const response = await httpClient.post('/annotations/paid-prank', annotationData);
      
      if (response.data.success) {
        logger.success('付费恶搞标注会话创建成功', {
          sessionId: response.data.data.sessionId,
          paymentUrl: response.data.data.paymentUrl,
          amount: response.data.data.amount,
          currency: response.data.data.currency
        });
        
        return response.data.data;
      } else {
        logger.error('付费恶搞标注创建失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`付费恶搞标注创建失败 - ${location.name}`, error);
      return null;
    }
  }

  static async batchCreateAnnotations() {
    logger.info('🔄 批量创建测试标注...');
    
    const results = [];
    
    for (const location of CONFIG.TEST_LOCATIONS) {
      // 为每个位置创建不同强度的标注
      for (let intensity = 1; intensity <= 5; intensity++) {
        const annotation = await this.createBasicAnnotation(location, {
          intensity: intensity * 2,
          description: `批量测试标注 - ${location.name} - 强度 ${intensity * 2}`
        });
        
        if (annotation) {
          results.push(annotation);
        }
        
        // 避免请求过快
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    logger.success(`批量创建完成，共创建 ${results.length} 个标注`);
    return results;
  }

  static async validateAnnotationData(annotation) {
    logger.info('🔍 验证标注数据完整性...');
    
    const errors = [];
    
    // 必需字段验证
    if (!annotation.id) errors.push('缺少 id 字段');
    if (!annotation.latitude) errors.push('缺少 latitude 字段');
    if (!annotation.longitude) errors.push('缺少 longitude 字段');
    if (!annotation.smellIntensity) errors.push('缺少 smellIntensity 字段');
    if (!annotation.status) errors.push('缺少 status 字段');
    if (!annotation.createdAt) errors.push('缺少 createdAt 字段');
    
    // 数据范围验证
    if (annotation.latitude < -90 || annotation.latitude > 90) {
      errors.push('latitude 超出有效范围 (-90 到 90)');
    }
    if (annotation.longitude < -180 || annotation.longitude > 180) {
      errors.push('longitude 超出有效范围 (-180 到 180)');
    }
    if (annotation.smellIntensity < 1 || annotation.smellIntensity > 10) {
      errors.push('smellIntensity 超出有效范围 (1 到 10)');
    }
    
    // 状态验证
    const validStatuses = ['pending', 'approved', 'rejected'];
    if (!validStatuses.includes(annotation.status)) {
      errors.push(`无效的 status 值: ${annotation.status}`);
    }
    
    if (errors.length > 0) {
      logger.error('标注数据验证失败', errors);
      return false;
    } else {
      logger.success('标注数据验证通过');
      return true;
    }
  }
}

/**
 * 标注查询和发现API测试套件
 */
class AnnotationQueryTestSuite {
  static async getAnnotationsList() {
    logger.info('📋 测试获取标注列表...');
    
    try {
      const response = await httpClient.get('/annotations/list', {
        params: {
          page: 1,
          limit: 20,
          sortBy: 'created_at',
          sortOrder: 'desc'
        }
      });
      
      if (response.data.success) {
        const { annotations, pagination } = response.data.data;
        logger.success('获取标注列表成功', {
          count: annotations.length,
          total: pagination.total,
          pages: pagination.pages
        });
        
        return annotations;
      } else {
        logger.error('获取标注列表失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取标注列表失败', error);
      return null;
    }
  }

  static async getNearbyAnnotations(location, radius = 5000) {
    logger.info(`🌍 测试获取附近标注 - ${location.name}...`);
    
    try {
      const response = await httpClient.get('/annotations/nearby', {
        params: {
          latitude: location.lat,
          longitude: location.lng,
          radius: radius,
          limit: 20
        }
      });
      
      if (response.data.success) {
        const annotations = response.data.data.annotations;
        logger.success(`获取附近标注成功 - ${location.name}`, {
          count: annotations.length,
          radius: radius
        });
        
        // 验证距离计算
        annotations.forEach(annotation => {
          if (annotation.distance) {
            logger.info(`标注距离: ${annotation.distance.toFixed(2)}m`);
          }
        });
        
        return annotations;
      } else {
        logger.error('获取附近标注失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`获取附近标注失败 - ${location.name}`, error);
      return null;
    }
  }

  static async getMapData(bounds) {
    logger.info('🗺️  测试获取地图数据...');
    
    const defaultBounds = bounds || {
      north: 40.0,
      south: 39.5,
      east: 117.0,
      west: 116.0
    };
    
    try {
      const response = await httpClient.get('/annotations/map', {
        params: {
          ...defaultBounds,
          zoom: 12,
          intensityMin: 1,
          intensityMax: 10
        }
      });
      
      if (response.data.success) {
        const annotations = response.data.data.annotations;
        logger.success('获取地图数据成功', {
          count: annotations.length,
          bounds: defaultBounds
        });
        
        return annotations;
      } else {
        logger.error('获取地图数据失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取地图数据失败', error);
      return null;
    }
  }

  static async getAnnotationById(annotationId) {
    logger.info(`🔍 测试获取单个标注详情 - ${annotationId}...`);
    
    try {
      const response = await httpClient.get(`/annotations/${annotationId}`);
      
      if (response.data.success) {
        const annotation = response.data.data.annotation;
        logger.success('获取标注详情成功', {
          id: annotation.id,
          viewCount: annotation.viewCount,
          likeCount: annotation.likeCount
        });
        
        return annotation;
      } else {
        logger.error('获取标注详情失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`获取标注详情失败 - ${annotationId}`, error);
      return null;
    }
  }

  static async testGeographicQueries() {
    logger.info('🌐 测试地理查询功能...');
    
    const results = [];
    
    for (const location of CONFIG.TEST_LOCATIONS.slice(0, 3)) {
      // 测试不同半径的查询
      const radiusTests = [1000, 5000, 10000];
      
      for (const radius of radiusTests) {
        const nearby = await this.getNearbyAnnotations(location, radius);
        if (nearby) {
          results.push({
            location: location.name,
            radius: radius,
            count: nearby.length
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    logger.success('地理查询测试完成', results);
    return results;
  }
}

/**
 * LBS奖励系统测试套件
 */
class LBSRewardTestSuite {
  static async checkRewards(location) {
    logger.info(`🎁 测试LBS奖励检查 - ${location.name}...`);
    
    try {
      const response = await httpClient.get('/lbs/check-rewards', {
        params: {
          lat: location.lat,
          lng: location.lng
        }
      });
      
      if (response.data.success) {
        logger.success(`LBS奖励检查成功 - ${location.name}`, response.data.data);
        return response.data.data;
      } else {
        logger.error('LBS奖励检查失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`LBS奖励检查失败 - ${location.name}`, error);
      return null;
    }
  }

  static async claimReward(rewardId) {
    logger.info(`💎 测试奖励领取 - ${rewardId}...`);
    
    try {
      const response = await httpClient.post(`/lbs/claim-reward/${rewardId}`);
      
      if (response.data.success) {
        logger.success('奖励领取成功', response.data.data);
        return response.data.data;
      } else {
        logger.error('奖励领取失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error(`奖励领取失败 - ${rewardId}`, error);
      return null;
    }
  }

  static async getRewardHistory() {
    logger.info('📜 测试获取奖励历史...');
    
    try {
      const response = await httpClient.get('/lbs/rewards/history');
      
      if (response.data.success) {
        logger.success('获取奖励历史成功', {
          count: response.data.data.rewards?.length || 0
        });
        return response.data.data;
      } else {
        logger.error('获取奖励历史失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取奖励历史失败', error);
      return null;
    }
  }
}

/**
 * 支付系统测试套件
 */
class PaymentTestSuite {
  static async getWalletBalance() {
    logger.info('💰 测试获取钱包余额...');
    
    try {
      const response = await httpClient.get('/wallet/balance');
      
      if (response.data.success) {
        logger.success('获取钱包余额成功', response.data.data);
        return response.data.data;
      } else {
        logger.error('获取钱包余额失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取钱包余额失败', error);
      return null;
    }
  }

  static async getPaymentHistory() {
    logger.info('💳 测试获取支付历史...');
    
    try {
      const response = await httpClient.get('/payments/history');
      
      if (response.data.success) {
        logger.success('获取支付历史成功', {
          count: response.data.data.payments?.length || 0
        });
        return response.data.data;
      } else {
        logger.error('获取支付历史失败', response.data);
        return null;
      }
    } catch (error) {
      logger.error('获取支付历史失败', error);
      return null;
    }
  }
}

/**
 * 并发和性能测试套件
 */
class PerformanceTestSuite {
  static async concurrentAnnotationCreation(concurrency = 5) {
    logger.info(`⚡ 测试并发创建标注 (并发数: ${concurrency})...`);
    
    const promises = [];
    const startTime = Date.now();
    
    for (let i = 0; i < concurrency; i++) {
      const location = CONFIG.TEST_LOCATIONS[i % CONFIG.TEST_LOCATIONS.length];
      const promise = AnnotationTestSuite.createBasicAnnotation(location, {
        description: `并发测试标注 #${i + 1}`
      });
      promises.push(promise);
    }
    
    try {
      const results = await Promise.allSettled(promises);
      const endTime = Date.now();
      
      const successful = results.filter(r => r.status === 'fulfilled' && r.value).length;
      const failed = results.length - successful;
      
      logger.success(`并发创建标注测试完成`, {
        total: results.length,
        successful: successful,
        failed: failed,
        timeMs: endTime - startTime,
        avgTimeMs: Math.round((endTime - startTime) / results.length)
      });
      
      return {
        total: results.length,
        successful,
        failed,
        timeMs: endTime - startTime
      };
    } catch (error) {
      logger.error('并发创建标注测试失败', error);
      return null;
    }
  }

  static async loadTestAnnotationQueries(iterations = 10) {
    logger.info(`🔄 负载测试标注查询 (迭代次数: ${iterations})...`);
    
    const results = [];
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
      const location = CONFIG.TEST_LOCATIONS[i % CONFIG.TEST_LOCATIONS.length];
      const iterationStart = Date.now();
      
      try {
        await AnnotationQueryTestSuite.getNearbyAnnotations(location);
        const iterationTime = Date.now() - iterationStart;
        results.push({ iteration: i + 1, timeMs: iterationTime, success: true });
      } catch (error) {
        const iterationTime = Date.now() - iterationStart;
        results.push({ iteration: i + 1, timeMs: iterationTime, success: false });
        logger.error(`查询迭代 ${i + 1} 失败`, error);
      }
      
      // 短暂延迟避免过载
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    const totalTime = Date.now() - startTime;
    const successfulQueries = results.filter(r => r.success).length;
    const avgTime = results.reduce((sum, r) => sum + r.timeMs, 0) / results.length;
    
    logger.success(`负载测试完成`, {
      totalQueries: iterations,
      successful: successfulQueries,
      failed: iterations - successfulQueries,
      totalTimeMs: totalTime,
      avgQueryTimeMs: Math.round(avgTime),
      queriesPerSecond: Math.round((successfulQueries * 1000) / totalTime)
    });
    
    return {
      totalQueries: iterations,
      successful: successfulQueries,
      avgQueryTimeMs: avgTime,
      queriesPerSecond: Math.round((successfulQueries * 1000) / totalTime)
    };
  }
}

/**
 * 数据完整性验证套件
 */
class DataIntegrityTestSuite {
  static async validateDatabaseConsistency() {
    logger.info('🔒 验证数据库数据一致性...');
    
    try {
      // 获取用户自己的标注
      const userAnnotations = await httpClient.get('/annotations/user/me');
      
      if (!userAnnotations.data.success) {
        logger.error('无法获取用户标注进行一致性验证');
        return false;
      }
      
      const annotations = userAnnotations.data.data.annotations;
      logger.info(`验证 ${annotations.length} 个用户标注的一致性`);
      
      let consistencyErrors = 0;
      
      for (const annotation of annotations.slice(0, 5)) { // 只验证前5个避免过多请求
        try {
          // 通过ID重新获取标注
          const detailResponse = await httpClient.get(`/annotations/${annotation.id}`);
          
          if (detailResponse.data.success) {
            const detailAnnotation = detailResponse.data.data.annotation;
            
            // 验证关键字段一致性
            if (annotation.latitude !== detailAnnotation.latitude ||
                annotation.longitude !== detailAnnotation.longitude ||
                annotation.smellIntensity !== detailAnnotation.smellIntensity) {
              consistencyErrors++;
              logger.error(`标注 ${annotation.id} 数据不一致`, {
                list: {
                  lat: annotation.latitude,
                  lng: annotation.longitude,
                  intensity: annotation.smellIntensity
                },
                detail: {
                  lat: detailAnnotation.latitude,
                  lng: detailAnnotation.longitude,
                  intensity: detailAnnotation.smellIntensity
                }
              });
            }
          } else {
            consistencyErrors++;
            logger.error(`无法获取标注详情 ${annotation.id}`);
          }
        } catch (error) {
          consistencyErrors++;
          logger.error(`验证标注 ${annotation.id} 时出错`, error);
        }
        
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      
      if (consistencyErrors === 0) {
        logger.success('数据一致性验证通过');
        return true;
      } else {
        logger.error(`发现 ${consistencyErrors} 个数据一致性问题`);
        return false;
      }
    } catch (error) {
      logger.error('数据一致性验证失败', error);
      return false;
    }
  }

  static async validateGeographicData() {
    logger.info('🌍 验证地理数据精度...');
    
    try {
      // 创建一个已知位置的标注
      const testLocation = CONFIG.TEST_LOCATIONS[0];
      const testAnnotation = await AnnotationTestSuite.createBasicAnnotation(testLocation, {
        description: '地理数据精度测试标注'
      });
      
      if (!testAnnotation) {
        logger.error('无法创建测试标注进行地理数据验证');
        return false;
      }
      
      // 查询该位置附近的标注
      const nearby = await AnnotationQueryTestSuite.getNearbyAnnotations(testLocation, 100); // 100米内
      
      if (!nearby) {
        logger.error('无法查询附近标注进行地理数据验证');
        return false;
      }
      
      // 验证刚创建的标注是否在结果中
      const foundAnnotation = nearby.find(a => a.id === testAnnotation.id);
      
      if (foundAnnotation) {
        logger.success('地理数据精度验证通过', {
          created: {
            lat: testAnnotation.latitude,
            lng: testAnnotation.longitude
          },
          found: {
            lat: foundAnnotation.latitude,
            lng: foundAnnotation.longitude,
            distance: foundAnnotation.distance
          }
        });
        return true;
      } else {
        logger.error('地理数据精度验证失败 - 未找到刚创建的标注');
        return false;
      }
    } catch (error) {
      logger.error('地理数据精度验证失败', error);
      return false;
    }
  }
}

/**
 * 主测试流程
 */
class MainTestRunner {
  static async runAllTests() {
    logger.info('🚀 开始SmellPin核心业务功能深度测试...');
    
    const testResults = {
      startTime: new Date().toISOString(),
      tests: {},
      summary: {
        total: 0,
        passed: 0,
        failed: 0
      }
    };

    try {
      // 1. 用户认证测试
      logger.info('\n=== 📋 用户认证测试 ===');
      testResults.tests.auth = {};
      
      testResults.tests.auth.register = await this.runTest('用户注册', AuthTestSuite.registerUser);
      testResults.tests.auth.login = await this.runTest('用户登录', AuthTestSuite.loginUser);
      testResults.tests.auth.profile = await this.runTest('获取用户资料', AuthTestSuite.getUserProfile);
      
      if (!authToken) {
        logger.error('❌ 认证失败，无法继续测试');
        return testResults;
      }

      // 2. 标注创建API测试
      logger.info('\n=== 📍 标注创建API测试 ===');
      testResults.tests.annotation_creation = {};
      
      testResults.tests.annotation_creation.basic = await this.runTest('基础标注创建', 
        async () => await AnnotationTestSuite.createBasicAnnotation(CONFIG.TEST_LOCATIONS[0])
      );
      
      testResults.tests.annotation_creation.batch = await this.runTest('批量标注创建', 
        AnnotationTestSuite.batchCreateAnnotations
      );
      
      testResults.tests.annotation_creation.paid_prank = await this.runTest('付费恶搞标注', 
        async () => await AnnotationTestSuite.createPaidPrankAnnotation(CONFIG.TEST_LOCATIONS[1])
      );

      // 3. 标注查询和发现测试
      logger.info('\n=== 🔍 标注查询和发现测试 ===');
      testResults.tests.annotation_query = {};
      
      testResults.tests.annotation_query.list = await this.runTest('获取标注列表', 
        AnnotationQueryTestSuite.getAnnotationsList
      );
      
      testResults.tests.annotation_query.nearby = await this.runTest('获取附近标注', 
        async () => await AnnotationQueryTestSuite.getNearbyAnnotations(CONFIG.TEST_LOCATIONS[0])
      );
      
      testResults.tests.annotation_query.map_data = await this.runTest('获取地图数据', 
        AnnotationQueryTestSuite.getMapData
      );
      
      testResults.tests.annotation_query.geographic = await this.runTest('地理查询功能', 
        AnnotationQueryTestSuite.testGeographicQueries
      );

      // 4. LBS奖励系统测试
      logger.info('\n=== 🎁 LBS奖励系统测试 ===');
      testResults.tests.lbs_rewards = {};
      
      testResults.tests.lbs_rewards.check = await this.runTest('检查奖励', 
        async () => await LBSRewardTestSuite.checkRewards(CONFIG.TEST_LOCATIONS[0])
      );
      
      testResults.tests.lbs_rewards.history = await this.runTest('获取奖励历史', 
        LBSRewardTestSuite.getRewardHistory
      );

      // 5. 支付系统测试
      logger.info('\n=== 💰 支付系统测试 ===');
      testResults.tests.payment = {};
      
      testResults.tests.payment.wallet = await this.runTest('获取钱包余额', 
        PaymentTestSuite.getWalletBalance
      );
      
      testResults.tests.payment.history = await this.runTest('获取支付历史', 
        PaymentTestSuite.getPaymentHistory
      );

      // 6. 性能和并发测试
      logger.info('\n=== ⚡ 性能和并发测试 ===');
      testResults.tests.performance = {};
      
      testResults.tests.performance.concurrent_creation = await this.runTest('并发标注创建', 
        async () => await PerformanceTestSuite.concurrentAnnotationCreation(3)
      );
      
      testResults.tests.performance.load_test_queries = await this.runTest('查询负载测试', 
        async () => await PerformanceTestSuite.loadTestAnnotationQueries(5)
      );

      // 7. 数据完整性验证
      logger.info('\n=== 🔒 数据完整性验证 ===');
      testResults.tests.data_integrity = {};
      
      testResults.tests.data_integrity.consistency = await this.runTest('数据一致性验证', 
        DataIntegrityTestSuite.validateDatabaseConsistency
      );
      
      testResults.tests.data_integrity.geographic = await this.runTest('地理数据精度验证', 
        DataIntegrityTestSuite.validateGeographicData
      );

      // 生成测试报告
      testResults.endTime = new Date().toISOString();
      testResults.summary = this.generateSummary(testResults.tests);
      
      await this.generateReport(testResults);
      
      logger.info('\n🎉 测试完成！');
      logger.success('测试总结', testResults.summary);
      
      return testResults;
      
    } catch (error) {
      logger.error('测试运行过程中发生严重错误', error);
      testResults.error = error.message;
      testResults.endTime = new Date().toISOString();
      return testResults;
    }
  }

  static async runTest(testName, testFunction) {
    try {
      logger.info(`🧪 运行测试: ${testName}`);
      const startTime = Date.now();
      const result = await testFunction();
      const endTime = Date.now();
      
      if (result !== null && result !== false) {
        logger.success(`✅ ${testName} 通过 (${endTime - startTime}ms)`);
        return {
          passed: true,
          result: result,
          timeMs: endTime - startTime,
          error: null
        };
      } else {
        logger.error(`❌ ${testName} 失败`);
        return {
          passed: false,
          result: null,
          timeMs: endTime - startTime,
          error: '测试函数返回失败结果'
        };
      }
    } catch (error) {
      logger.error(`❌ ${testName} 异常:`, error);
      return {
        passed: false,
        result: null,
        timeMs: 0,
        error: error.message
      };
    }
  }

  static generateSummary(tests) {
    let total = 0;
    let passed = 0;
    let failed = 0;
    
    const countTests = (testGroup) => {
      for (const testKey in testGroup) {
        const test = testGroup[testKey];
        if (typeof test === 'object' && test.hasOwnProperty('passed')) {
          total++;
          if (test.passed) {
            passed++;
          } else {
            failed++;
          }
        } else if (typeof test === 'object') {
          countTests(test);
        }
      }
    };
    
    countTests(tests);
    
    return {
      total,
      passed,
      failed,
      passRate: total > 0 ? Math.round((passed / total) * 100) : 0
    };
  }

  static async generateReport(testResults) {
    const reportPath = '/Users/xiaoyang/Downloads/臭味/comprehensive-api-test-report.json';
    
    try {
      fs.writeFileSync(reportPath, JSON.stringify(testResults, null, 2));
      logger.success(`测试报告已保存: ${reportPath}`);
    } catch (error) {
      logger.error('保存测试报告失败', error);
    }
  }
}

// 运行测试
if (require.main === module) {
  MainTestRunner.runAllTests()
    .then(results => {
      process.exit(results.summary.failed > 0 ? 1 : 0);
    })
    .catch(error => {
      logger.error('测试运行失败', error);
      process.exit(1);
    });
}

module.exports = {
  AuthTestSuite,
  AnnotationTestSuite,
  AnnotationQueryTestSuite,
  LBSRewardTestSuite,
  PaymentTestSuite,
  PerformanceTestSuite,
  DataIntegrityTestSuite,
  MainTestRunner,
  CONFIG
};