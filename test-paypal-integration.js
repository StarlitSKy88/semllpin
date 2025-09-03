#!/usr/bin/env node

/**
 * PayPal支付集成测试脚本
 * 测试PayPal支付功能的基本流程
 */

const axios = require('axios');
const dotenv = require('dotenv');

// 加载环境变量
dotenv.config();

const API_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3002';
const TEST_USER_TOKEN = 'test_jwt_token_here'; // 需要替换为有效的测试用户token

// 测试配置
const testConfig = {
  baseURL: `${API_BASE_URL}/api`,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${TEST_USER_TOKEN}`
  }
};

// 测试数据
const testPaymentData = {
  amount: 5.99,
  currency: 'USD',
  description: 'SmellPin测试标注支付',
  annotationId: 'test-annotation-001',
  paymentMethod: 'paypal'
};

/**
 * 执行API请求
 */
async function makeRequest(method, endpoint, data = null) {
  try {
    const response = await axios({
      method,
      url: `${testConfig.baseURL}${endpoint}`,
      data,
      headers: testConfig.headers,
      timeout: testConfig.timeout
    });
    return { success: true, data: response.data };
  } catch (error) {
    const errorMessage = error.response?.data?.message || error.message;
    const statusCode = error.response?.status;
    return { 
      success: false, 
      error: errorMessage,
      statusCode,
      fullError: error.response?.data
    };
  }
}

/**
 * 测试PayPal支付创建
 */
async function testPayPalPaymentCreation() {
  console.log('\n🧪 测试PayPal支付创建...');
  
  const result = await makeRequest('POST', '/payments/create', testPaymentData);
  
  if (result.success) {
    console.log('✅ PayPal支付创建成功');
    console.log(`   - 支付ID: ${result.data.data?.paymentId}`);
    console.log(`   - PayPal订单ID: ${result.data.data?.orderId}`);
    console.log(`   - 状态: ${result.data.data?.status}`);
    console.log(`   - 批准URL: ${result.data.data?.approvalUrl || '未提供'}`);
    return result.data.data;
  } else {
    console.log('❌ PayPal支付创建失败');
    console.log(`   - 错误: ${result.error}`);
    console.log(`   - 状态码: ${result.statusCode}`);
    if (result.fullError) {
      console.log(`   - 详细错误:`, JSON.stringify(result.fullError, null, 2));
    }
    return null;
  }
}

/**
 * 测试PayPal支付捕获（模拟）
 */
async function testPayPalPaymentCapture(orderId) {
  console.log('\n🧪 测试PayPal支付捕获...');
  
  // 模拟PayPal回调的数据
  const captureData = {
    orderId: orderId,
    payerId: 'TEST_PAYER_ID_123',
    paymentMethod: 'paypal'
  };
  
  const result = await makeRequest('POST', '/payments/capture', captureData);
  
  if (result.success) {
    console.log('✅ PayPal支付捕获成功（模拟）');
    console.log(`   - 捕获ID: ${result.data.data?.orderId}`);
    console.log(`   - 状态: ${result.data.data?.status}`);
    console.log(`   - 捕获时间: ${result.data.data?.capturedAt || '未记录'}`);
    return result.data.data;
  } else {
    console.log('❌ PayPal支付捕获失败');
    console.log(`   - 错误: ${result.error}`);
    console.log(`   - 状态码: ${result.statusCode}`);
    return null;
  }
}

/**
 * 测试服务器健康状态
 */
async function testServerHealth() {
  console.log('\n🧪 测试服务器健康状态...');
  
  try {
    const response = await axios.get(`${API_BASE_URL}/health`, { timeout: 5000 });
    console.log('✅ 服务器运行正常');
    console.log(`   - 状态: ${response.data.data?.status}`);
    console.log(`   - 环境: ${response.data.data?.environment}`);
    console.log(`   - 运行时间: ${Math.round(response.data.data?.uptime || 0)}秒`);
    return true;
  } catch (error) {
    console.log('❌ 服务器连接失败');
    console.log(`   - 错误: ${error.message}`);
    return false;
  }
}

/**
 * 测试PayPal配置
 */
async function testPayPalConfiguration() {
  console.log('\n🧪 检查PayPal配置...');
  
  const requiredEnvVars = [
    'PAYPAL_CLIENT_ID',
    'PAYPAL_CLIENT_SECRET',
    'PAYPAL_MODE'
  ];
  
  let configValid = true;
  
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      console.log(`❌ 缺少环境变量: ${envVar}`);
      configValid = false;
    } else {
      console.log(`✅ ${envVar}: ${envVar === 'PAYPAL_CLIENT_SECRET' ? '***' : process.env[envVar]}`);
    }
  }
  
  if (configValid) {
    console.log('✅ PayPal配置完整');
  } else {
    console.log('❌ PayPal配置不完整');
  }
  
  return configValid;
}

/**
 * 主测试函数
 */
async function runTests() {
  console.log('🚀 开始PayPal支付集成测试');
  console.log('='.repeat(50));
  
  // 测试结果统计
  const results = {
    serverHealth: false,
    paypalConfig: false,
    paymentCreation: false,
    paymentCapture: false
  };
  
  try {
    // 1. 测试服务器健康状态
    results.serverHealth = await testServerHealth();
    
    // 2. 检查PayPal配置
    results.paypalConfig = await testPayPalConfiguration();
    
    // 3. 测试PayPal支付创建
    if (results.serverHealth) {
      const paymentData = await testPayPalPaymentCreation();
      results.paymentCreation = !!paymentData;
      
      // 4. 测试PayPal支付捕获（如果创建成功）
      if (paymentData && paymentData.orderId) {
        const captureData = await testPayPalPaymentCapture(paymentData.orderId);
        results.paymentCapture = !!captureData;
      }
    }
    
    // 输出测试结果汇总
    console.log('\n' + '='.repeat(50));
    console.log('📊 测试结果汇总:');
    console.log(`   服务器健康: ${results.serverHealth ? '✅' : '❌'}`);
    console.log(`   PayPal配置: ${results.paypalConfig ? '✅' : '❌'}`);
    console.log(`   支付创建: ${results.paymentCreation ? '✅' : '❌'}`);
    console.log(`   支付捕获: ${results.paymentCapture ? '✅' : '❌'}`);
    
    const passedTests = Object.values(results).filter(Boolean).length;
    const totalTests = Object.keys(results).length;
    
    console.log(`\n通过测试: ${passedTests}/${totalTests}`);
    
    if (passedTests === totalTests) {
      console.log('🎉 所有测试通过！PayPal集成功能正常。');
      process.exit(0);
    } else {
      console.log('⚠️  部分测试失败，请检查配置和实现。');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('\n💥 测试过程中发生未知错误:', error.message);
    process.exit(1);
  }
}

/**
 * 显示使用说明
 */
function showUsage() {
  console.log(`
🔧 PayPal支付集成测试使用说明:

1. 确保环境变量已配置:
   - PAYPAL_CLIENT_ID
   - PAYPAL_CLIENT_SECRET  
   - PAYPAL_MODE (sandbox/live)
   - APP_BASE_URL (可选，默认: http://localhost:3002)

2. 确保后端服务正在运行:
   npm run dev

3. 运行测试:
   node test-paypal-integration.js

⚠️  注意: 这是基础集成测试，不包含实际的PayPal支付流程。
   实际支付需要通过PayPal的前端SDK完成用户授权。
`);
}

// 检查命令行参数
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  showUsage();
  process.exit(0);
}

// 运行测试
runTests().catch(error => {
  console.error('测试执行失败:', error.message);
  process.exit(1);
});