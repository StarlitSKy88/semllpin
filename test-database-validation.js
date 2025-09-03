const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 配置
const API_BASE_URL = 'http://localhost:8787';
const TEST_USER = {
  email: `test_validation_${Date.now()}@example.com`,
  password: 'TestPassword123!',
  username: `testuser_validation_${Date.now()}`
};

// 全局变量
let authToken = null;
let userId = null;
const testResults = [];
const databaseValidations = [];

// 工具函数
function recordTest(name, success, details, duration, validationData = null) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
    validationData
  };
  testResults.push(result);
  
  const status = success ? '[PASS]' : '[FAIL]';
  console.log(`${status} ${name}`);
  console.log(`   详情: ${details}`);
  console.log(`   耗时: ${duration}ms`);
  if (validationData) {
    console.log(`   验证数据: ${JSON.stringify(validationData, null, 2)}`);
  }
  console.log('');
}

function recordDatabaseValidation(operation, tableName, recordId, beforeState, afterState, isValid) {
  const validation = {
    operation,
    tableName,
    recordId,
    beforeState,
    afterState,
    isValid,
    timestamp: new Date().toISOString()
  };
  databaseValidations.push(validation);
  
  const status = isValid ? '[DB-VALID]' : '[DB-INVALID]';
  console.log(`${status} ${operation} on ${tableName} (ID: ${recordId})`);
  console.log(`   前状态: ${JSON.stringify(beforeState)}`);
  console.log(`   后状态: ${JSON.stringify(afterState)}`);
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
      timeout: 15000
    });
    return response;
  } catch (error) {
    if (error.response) {
      return error.response;
    }
    throw error;
  }
}

// 数据库状态验证函数
async function validateDatabaseState(operation, tableName, recordId, expectedChanges) {
  try {
    // 获取数据库记录状态
    const response = await makeRequest(`${API_BASE_URL}/api/debug/table-record/${tableName}/${recordId}`, {
      headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
    });
    
    if (response.status === 200) {
      const currentState = response.data.data || response.data;
      
      // 验证预期变化
      let isValid = true;
      const validationDetails = {};
      
      for (const [field, expectedValue] of Object.entries(expectedChanges)) {
        const actualValue = currentState[field];
        const fieldValid = actualValue === expectedValue;
        isValid = isValid && fieldValid;
        
        validationDetails[field] = {
          expected: expectedValue,
          actual: actualValue,
          valid: fieldValid
        };
      }
      
      recordDatabaseValidation(operation, tableName, recordId, null, currentState, isValid);
      return { isValid, currentState, validationDetails };
    } else {
      recordDatabaseValidation(operation, tableName, recordId, null, null, false);
      return { isValid: false, error: `无法获取数据库状态: ${response.status}` };
    }
  } catch (error) {
    recordDatabaseValidation(operation, tableName, recordId, null, null, false);
    return { isValid: false, error: error.message };
  }
}

// 检查数据是否为模拟数据
function detectMockData(data) {
  const mockIndicators = [
    'mock', 'test', 'fake', 'dummy', 'sample',
    'example', 'placeholder', 'temp', 'demo'
  ];
  
  const dataString = JSON.stringify(data).toLowerCase();
  const foundIndicators = mockIndicators.filter(indicator => 
    dataString.includes(indicator)
  );
  
  return {
    isMock: foundIndicators.length > 0,
    indicators: foundIndicators
  };
}

// 测试函数
async function testDatabaseConnectionWithValidation() {
  console.log('=== 测试1: 数据库连接验证 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/health`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const data = response.data;
      const dbStatus = data.database || data.db;
      
      // 验证数据库连接的真实性
      const validationData = {
        hasRealConnection: dbStatus === 'connected' || dbStatus === 'healthy',
        responseTime: duration,
        connectionDetails: data
      };
      
      const isValid = validationData.hasRealConnection && duration < 5000;
      recordTest('数据库连接验证', isValid, 
        `状态码: ${response.status}, 数据库状态: ${dbStatus}, 连接真实性: ${isValid}`, 
        duration, validationData);
      return isValid;
    } else {
      recordTest('数据库连接验证', false, 
        `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据库连接验证', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUserRegistrationWithValidation() {
  console.log('=== 测试2: 用户注册数据验证 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USER
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201) {
      const responseData = response.data.data || response.data;
      authToken = responseData.token;
      userId = responseData.user?.id || responseData.id;
      
      // 检测模拟数据
      const mockDetection = detectMockData(responseData);
      
      // 验证数据库中的用户记录
      const dbValidation = await validateDatabaseState(
        'CREATE_USER', 'users', userId, 
        { email: TEST_USER.email, username: TEST_USER.username }
      );
      
      const validationData = {
        mockDetection,
        databaseValidation: dbValidation,
        hasToken: !!authToken,
        hasUserId: !!userId
      };
      
      const isValid = !mockDetection.isMock && dbValidation.isValid && authToken && userId;
      recordTest('用户注册数据验证', isValid, 
        `状态码: ${response.status}, 数据真实性: ${!mockDetection.isMock}, 数据库验证: ${dbValidation.isValid}`, 
        duration, validationData);
      return isValid;
    } else {
      recordTest('用户注册数据验证', false, 
        `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册数据验证', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testAnnotationCreationWithValidation() {
  console.log('=== 测试3: 标注创建数据验证 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('标注创建数据验证', false, '没有可用的认证Token', 0);
    return false;
  }
  
  const annotationData = {
    title: '数据验证测试标注',
    description: '用于验证数据库真实性的测试标注',
    latitude: 39.9042,
    longitude: 116.4074,
    category: 'test',
    severity: 3
  };
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/annotations`, {
      method: 'POST',
      body: annotationData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 201) {
      const responseData = response.data.data || response.data;
      const annotationId = responseData.id;
      
      // 检测模拟数据
      const mockDetection = detectMockData(responseData);
      
      // 验证数据库中的标注记录
      const dbValidation = await validateDatabaseState(
        'CREATE_ANNOTATION', 'annotations', annotationId,
        { 
          title: annotationData.title,
          user_id: userId,
          latitude: annotationData.latitude,
          longitude: annotationData.longitude
        }
      );
      
      const validationData = {
        mockDetection,
        databaseValidation: dbValidation,
        annotationId,
        createdByUser: responseData.user_id === userId
      };
      
      const isValid = !mockDetection.isMock && dbValidation.isValid && annotationId;
      recordTest('标注创建数据验证', isValid, 
        `状态码: ${response.status}, 数据真实性: ${!mockDetection.isMock}, 数据库验证: ${dbValidation.isValid}`, 
        duration, validationData);
      return { success: isValid, annotationId };
    } else {
      recordTest('标注创建数据验证', false, 
        `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return { success: false };
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('标注创建数据验证', false, `网络错误: ${error.message}`, duration);
    return { success: false };
  }
}

async function testDataConsistencyValidation() {
  console.log('=== 测试4: 数据一致性验证 ===\n');
  const startTime = Date.now();
  
  try {
    // 获取用户的标注列表
    const response = await makeRequest(`${API_BASE_URL}/annotations?user_id=${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const annotations = response.data.data || response.data;
      
      // 验证数据一致性
      const consistencyChecks = {
        isArray: Array.isArray(annotations),
        hasUserAnnotations: annotations.some(ann => ann.user_id === userId),
        allHaveIds: annotations.every(ann => ann.id),
        allHaveCoordinates: annotations.every(ann => ann.latitude && ann.longitude)
      };
      
      // 检测模拟数据
      const mockDetection = detectMockData(annotations);
      
      const validationData = {
        annotationCount: annotations.length,
        consistencyChecks,
        mockDetection
      };
      
      const isValid = consistencyChecks.isArray && 
                     consistencyChecks.hasUserAnnotations && 
                     consistencyChecks.allHaveIds && 
                     !mockDetection.isMock;
      
      recordTest('数据一致性验证', isValid, 
        `状态码: ${response.status}, 数据一致性: ${isValid}, 标注数量: ${annotations.length}`, 
        duration, validationData);
      return isValid;
    } else {
      recordTest('数据一致性验证', false, 
        `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('数据一致性验证', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testTransactionIntegrityValidation() {
  console.log('=== 测试5: 事务完整性验证 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('事务完整性验证', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 尝试执行一个需要事务的操作（比如更新用户资料）
    const updateData = {
      bio: `测试事务完整性 - ${Date.now()}`,
      location: '北京市'
    };
    
    const response = await makeRequest(`${API_BASE_URL}/users/me`, {
      method: 'PUT',
      body: updateData,
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      // 验证数据库中的更新
      const dbValidation = await validateDatabaseState(
        'UPDATE_USER', 'users', userId,
        { bio: updateData.bio, location: updateData.location }
      );
      
      const validationData = {
        databaseValidation: dbValidation,
        updateData
      };
      
      recordTest('事务完整性验证', dbValidation.isValid, 
        `状态码: ${response.status}, 事务完整性: ${dbValidation.isValid}`, 
        duration, validationData);
      return dbValidation.isValid;
    } else {
      recordTest('事务完整性验证', false, 
        `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('事务完整性验证', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

// 生成详细报告
function generateValidationReport() {
  const passedTests = testResults.filter(test => test.success).length;
  const totalTests = testResults.length;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(2) : 0;
  
  const validDatabaseOps = databaseValidations.filter(val => val.isValid).length;
  const totalDatabaseOps = databaseValidations.length;
  const dbValidationRate = totalDatabaseOps > 0 ? ((validDatabaseOps / totalDatabaseOps) * 100).toFixed(2) : 0;
  
  const report = {
    summary: {
      timestamp: new Date().toISOString(),
      totalTests,
      passedTests,
      failedTests: totalTests - passedTests,
      successRate: `${successRate}%`,
      totalDatabaseOperations: totalDatabaseOps,
      validDatabaseOperations: validDatabaseOps,
      databaseValidationRate: `${dbValidationRate}%`
    },
    testResults,
    databaseValidations,
    recommendations: generateRecommendations()
  };
  
  // 保存报告到文件
  const reportPath = path.join(__dirname, 'database-validation-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  console.log('\n=== 数据库验证测试报告 ===');
  console.log(`测试总数: ${totalTests}`);
  console.log(`通过测试: ${passedTests}`);
  console.log(`失败测试: ${totalTests - passedTests}`);
  console.log(`成功率: ${successRate}%`);
  console.log(`数据库操作总数: ${totalDatabaseOps}`);
  console.log(`有效数据库操作: ${validDatabaseOps}`);
  console.log(`数据库验证率: ${dbValidationRate}%`);
  console.log(`\n详细报告已保存到: ${reportPath}`);
  
  return report;
}

function generateRecommendations() {
  const recommendations = [];
  
  // 基于测试结果生成建议
  const failedTests = testResults.filter(test => !test.success);
  const invalidDbOps = databaseValidations.filter(val => !val.isValid);
  
  if (failedTests.length > 0) {
    recommendations.push({
      type: 'test_failures',
      message: `有 ${failedTests.length} 个测试失败，需要检查相关功能`,
      details: failedTests.map(test => test.name)
    });
  }
  
  if (invalidDbOps.length > 0) {
    recommendations.push({
      type: 'database_validation',
      message: `有 ${invalidDbOps.length} 个数据库操作验证失败，可能存在数据一致性问题`,
      details: invalidDbOps.map(op => `${op.operation} on ${op.tableName}`)
    });
  }
  
  // 检查是否有模拟数据
  const testsWithMockData = testResults.filter(test => 
    test.validationData?.mockDetection?.isMock
  );
  
  if (testsWithMockData.length > 0) {
    recommendations.push({
      type: 'mock_data_detected',
      message: '检测到模拟数据，建议替换为真实的业务逻辑',
      details: testsWithMockData.map(test => ({
        test: test.name,
        indicators: test.validationData.mockDetection.indicators
      }))
    });
  }
  
  return recommendations;
}

// 主测试函数
async function runDatabaseValidationTests() {
  console.log('开始数据库验证测试...\n');
  
  try {
    await testDatabaseConnectionWithValidation();
    await testUserRegistrationWithValidation();
    const annotationResult = await testAnnotationCreationWithValidation();
    await testDataConsistencyValidation();
    await testTransactionIntegrityValidation();
    
    const report = generateValidationReport();
    
    console.log('\n数据库验证测试完成！');
    return report;
  } catch (error) {
    console.error('测试过程中发生错误:', error);
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  runDatabaseValidationTests()
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
  runDatabaseValidationTests,
  validateDatabaseState,
  detectMockData
};