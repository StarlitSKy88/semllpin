#!/usr/bin/env node

/**
 * SmellPin 使用现有用户的真实API功能验证测试
 * 此脚本绕过频率限制，使用预先存在的用户或手动提供的token进行测试
 */

const axios = require('axios');
const colors = {
  red: (text) => `\x1b[31m${text}\x1b[0m`,
  green: (text) => `\x1b[32m${text}\x1b[0m`,
  yellow: (text) => `\x1b[33m${text}\x1b[0m`,
  blue: (text) => `\x1b[34m${text}\x1b[0m`,
  cyan: (text) => `\x1b[36m${text}\x1b[0m`,
  magenta: (text) => `\x1b[35m${text}\x1b[0m`
};

// 配置
const config = {
  baseURL: 'http://localhost:3000',
  timeout: 10000
};

// 测试结果统计
const testResults = {
  total: 0,
  passed: 0,
  failed: 0,
  details: []
};

// 记录测试结果
function recordTest(testName, success, error = null, data = null) {
  testResults.total++;
  if (success) {
    testResults.passed++;
    console.log(colors.green(`✅ ${testName}`));
    if (data) {
      console.log(colors.cyan(`   数据: ${JSON.stringify(data, null, 2).substring(0, 200)}...`));
    }
  } else {
    testResults.failed++;
    console.log(colors.red(`❌ ${testName}`));
    if (error) {
      let errorMessage = '';
      if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.message) {
        errorMessage = error.message;
      } else if (error.response?.data) {
        errorMessage = JSON.stringify(error.response.data);
      } else {
        errorMessage = String(error);
      }
      console.log(colors.red(`   错误: ${errorMessage}`));
    }
  }
  
  testResults.details.push({
    name: testName,
    success,
    error: error ? String(error) : null,
    data,
    timestamp: new Date().toISOString()
  });
}

// 延迟函数
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 生成真实地理坐标（北京市范围内）
function generateRealCoordinates() {
  const beijingBounds = {
    north: 40.2,
    south: 39.7,
    east: 116.7,
    west: 115.9
  };
  
  const latitude = beijingBounds.south + Math.random() * (beijingBounds.north - beijingBounds.south);
  const longitude = beijingBounds.west + Math.random() * (beijingBounds.east - beijingBounds.west);
  
  return {
    latitude: parseFloat(latitude.toFixed(6)),
    longitude: parseFloat(longitude.toFixed(6))
  };
}

// 测试服务器连接
async function testServerConnection() {
  try {
    const response = await axios.get(`${config.baseURL}/api/v1/health`, {
      timeout: config.timeout
    });
    recordTest('服务器连接测试', true, null, response.data);
    return true;
  } catch (error) {
    recordTest('服务器连接测试', false, error);
    return false;
  }
}

// 验证token有效性
async function validateToken(token) {
  try {
    const response = await axios.get(`${config.baseURL}/api/v1/auth/profile`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    recordTest('Token验证测试', true, null, { userId: response.data.data?.id, email: response.data.data?.email });
    return response.data.data;
  } catch (error) {
    recordTest('Token验证测试', false, error);
    return null;
  }
}

// 测试创建标注
async function testCreateAnnotation(token) {
  try {
    const coordinates = generateRealCoordinates();
    const annotationData = {
      title: `测试标注_${Date.now()}`,
      content: '这是一个真实的API测试标注，用于验证系统功能',
      latitude: coordinates.latitude,
      longitude: coordinates.longitude,
      price: 10.00,
      category: 'funny'
    };
    
    const response = await axios.post(`${config.baseURL}/api/v1/annotations`, annotationData, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    
    recordTest('创建标注测试', true, null, {
      id: response.data.data?.id,
      title: response.data.data?.title,
      coordinates: `${coordinates.latitude}, ${coordinates.longitude}`
    });
    return response.data.data;
  } catch (error) {
    recordTest('创建标注测试', false, error);
    return null;
  }
}

// 测试查询标注列表
async function testGetAnnotations(token) {
  try {
    const coordinates = generateRealCoordinates();
    const response = await axios.get(`${config.baseURL}/api/v1/annotations`, {
      params: {
        latitude: coordinates.latitude,
        longitude: coordinates.longitude,
        radius: 5000, // 5km范围
        page: 1,
        limit: 10
      },
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    
    recordTest('查询标注列表测试', true, null, {
      total: response.data.data?.total || 0,
      count: response.data.data?.annotations?.length || 0
    });
    return response.data.data;
  } catch (error) {
    recordTest('查询标注列表测试', false, error);
    return null;
  }
}

// 测试LBS功能（模拟用户进入标注范围）
async function testLBSFunction(token, annotationId) {
  if (!annotationId) {
    recordTest('LBS功能测试', false, new Error('没有可用的标注ID'));
    return null;
  }
  
  try {
    const coordinates = generateRealCoordinates();
    const response = await axios.post(`${config.baseURL}/api/v1/annotations/${annotationId}/discover`, {
      latitude: coordinates.latitude,
      longitude: coordinates.longitude
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    
    recordTest('LBS功能测试', true, null, {
      discovered: response.data.data?.discovered || false,
      reward: response.data.data?.reward || 0
    });
    return response.data.data;
  } catch (error) {
    recordTest('LBS功能测试', false, error);
    return null;
  }
}

// 测试用户钱包查询
async function testWalletQuery(token) {
  try {
    const response = await axios.get(`${config.baseURL}/api/v1/wallet/balance`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    
    recordTest('钱包查询测试', true, null, {
      balance: response.data.data?.balance || 0,
      currency: response.data.data?.currency || 'CNY'
    });
    return response.data.data;
  } catch (error) {
    recordTest('钱包查询测试', false, error);
    return null;
  }
}

// 生成详细测试报告
function generateTestReport() {
  const report = {
    summary: {
      total: testResults.total,
      passed: testResults.passed,
      failed: testResults.failed,
      successRate: testResults.total > 0 ? ((testResults.passed / testResults.total) * 100).toFixed(2) + '%' : '0%',
      timestamp: new Date().toISOString()
    },
    details: testResults.details,
    recommendations: []
  };
  
  // 基于测试结果生成建议
  if (testResults.failed > 0) {
    report.recommendations.push('检查失败的测试项目，确认API实现是否正确');
  }
  if (testResults.passed === testResults.total) {
    report.recommendations.push('所有测试通过，系统功能正常');
  }
  
  return report;
}

// 主测试函数
async function runTestsWithExistingUser() {
  console.log(colors.cyan('🚀 开始SmellPin使用现有用户的真实API功能验证测试\n'));
  console.log(colors.yellow('⚠️  注意：此测试使用真实API调用，需要有效的用户token\n'));
  
  // 1. 测试服务器连接
  console.log(colors.blue('🔗 测试服务器连接...'));
  const serverConnected = await testServerConnection();
  if (!serverConnected) {
    console.log(colors.red('\n❌ 服务器连接失败，终止测试'));
    return;
  }
  
  await delay(1000);
  
  // 2. 获取用户token
  console.log(colors.blue('\n🔑 请提供有效的用户token:'));
  console.log(colors.yellow('   选项1: 使用预设测试token（如果有的话）'));
  console.log(colors.yellow('   选项2: 手动输入token'));
  console.log(colors.yellow('   选项3: 等待15分钟后运行完整注册/登录测试'));
  
  // 这里我们使用一个示例token，实际使用时需要替换
  const testToken = process.env.TEST_USER_TOKEN || 'your-valid-token-here';
  
  if (testToken === 'your-valid-token-here') {
    console.log(colors.red('\n❌ 未提供有效的测试token'));
    console.log(colors.yellow('请设置环境变量 TEST_USER_TOKEN 或修改脚本中的testToken值'));
    console.log(colors.cyan('\n💡 获取token的方法:'));
    console.log('   1. 等待15分钟后运行 test-real-functionality.js');
    console.log('   2. 使用浏览器开发者工具从网页中获取token');
    console.log('   3. 直接调用登录API获取token');
    return;
  }
  
  // 3. 验证token
  console.log(colors.blue('\n🔐 验证用户token...'));
  const userProfile = await validateToken(testToken);
  if (!userProfile) {
    console.log(colors.red('\n❌ Token验证失败，请检查token是否有效'));
    return;
  }
  
  await delay(1000);
  
  // 4. 测试创建标注
  console.log(colors.blue('\n📍 测试创建标注...'));
  const annotation = await testCreateAnnotation(testToken);
  
  await delay(2000);
  
  // 5. 测试查询标注
  console.log(colors.blue('\n🔍 测试查询标注列表...'));
  const annotations = await testGetAnnotations(testToken);
  
  await delay(2000);
  
  // 6. 测试LBS功能
  console.log(colors.blue('\n📡 测试LBS功能...'));
  await testLBSFunction(testToken, annotation?.id);
  
  await delay(2000);
  
  // 7. 测试钱包查询
  console.log(colors.blue('\n💰 测试钱包查询...'));
  await testWalletQuery(testToken);
  
  // 8. 生成测试报告
  console.log(colors.cyan('\n📋 生成测试报告...'));
  const report = generateTestReport();
  
  console.log(colors.cyan('\n' + '='.repeat(60)));
  console.log(colors.cyan('📋 SmellPin API真实功能测试报告'));
  console.log(colors.cyan('='.repeat(60)));
  
  console.log(colors.blue('\n📊 测试统计:'));
  console.log(`   总测试数: ${report.summary.total}`);
  console.log(`   通过数: ${colors.green(report.summary.passed)}`);
  console.log(`   失败数: ${colors.red(report.summary.failed)}`);
  console.log(`   成功率: ${report.summary.successRate}`);
  
  console.log(colors.blue('\n🔍 测试详情:'));
  report.details.forEach(detail => {
    const status = detail.success ? colors.green('✅') : colors.red('❌');
    console.log(`   ${status} ${detail.name}`);
    if (!detail.success && detail.error) {
      console.log(colors.red(`      错误: ${detail.error.substring(0, 100)}...`));
    }
  });
  
  if (report.recommendations.length > 0) {
    console.log(colors.yellow('\n💡 建议:'));
    report.recommendations.forEach(rec => {
      console.log(`   • ${rec}`);
    });
  }
  
  console.log(colors.green('\n🎯 测试完成!'));
  
  // 保存报告到文件
  const fs = require('fs');
  const reportPath = `./test-report-${Date.now()}.json`;
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(colors.cyan(`📄 详细报告已保存到: ${reportPath}`));
}

// 运行测试
if (require.main === module) {
  runTestsWithExistingUser().catch(error => {
    console.error(colors.red('\n💥 测试执行出错:'), error.message);
    process.exit(1);
  });
}

module.exports = {
  runTestsWithExistingUser,
  testServerConnection,
  validateToken,
  testCreateAnnotation,
  testGetAnnotations,
  testLBSFunction,
  testWalletQuery
};