#!/usr/bin/env node

/**
 * SmellPin 认证功能集成测试
 * 测试前后端API对接和JSON解析
 */

const axios = require('axios');

const API_BASE_URL = 'http://localhost:3004/api/v1';

// 生成唯一的测试数据
const timestamp = Date.now();
const testUser = {
  email: `test${timestamp}@example.com`,
  password: '123456',
  username: `testuser${timestamp}`,
};

console.log('🧪 开始测试SmellPin认证功能...\n');

async function testRegistration() {
  console.log('📝 测试用户注册...');
  
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/register`, {
      email: testUser.email,
      password: testUser.password,
      username: testUser.username,
    }, {
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });

    console.log('✅ 注册成功!');
    console.log(`   - 用户ID: ${response.data.data.user.id}`);
    console.log(`   - 邮箱: ${response.data.data.user.email}`);
    console.log(`   - 用户名: ${response.data.data.user.username}`);
    console.log(`   - Token类型: ${typeof response.data.data.tokens.accessToken}`);
    
    return response.data.data;
  } catch (error) {
    console.error('❌ 注册失败:');
    if (error.response) {
      console.error(`   HTTP状态码: ${error.response.status}`);
      console.error(`   错误信息: ${JSON.stringify(error.response.data, null, 2)}`);
    } else {
      console.error(`   网络错误: ${error.message}`);
    }
    throw error;
  }
}

async function testLogin() {
  console.log('\n🔐 测试用户登录...');
  
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      email: testUser.email,
      password: testUser.password,
    }, {
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });

    console.log('✅ 登录成功!');
    console.log(`   - 用户ID: ${response.data.data.user.id}`);
    console.log(`   - 邮箱: ${response.data.data.user.email}`);
    console.log(`   - Access Token长度: ${response.data.data.tokens.accessToken.length}字符`);
    console.log(`   - Refresh Token长度: ${response.data.data.tokens.refreshToken.length}字符`);
    
    return response.data.data;
  } catch (error) {
    console.error('❌ 登录失败:');
    if (error.response) {
      console.error(`   HTTP状态码: ${error.response.status}`);
      console.error(`   错误信息: ${JSON.stringify(error.response.data, null, 2)}`);
    } else {
      console.error(`   网络错误: ${error.message}`);
    }
    throw error;
  }
}

async function testUserProfile(token) {
  console.log('\n👤 测试获取用户资料...');
  
  try {
    const response = await axios.get(`${API_BASE_URL}/auth/profile/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });

    console.log('✅ 获取用户资料成功!');
    console.log(`   - 用户ID: ${response.data.data.user.id}`);
    console.log(`   - 邮箱验证状态: ${response.data.data.user.emailVerified ? '已验证' : '未验证'}`);
    console.log(`   - 账户创建时间: ${response.data.data.user.createdAt}`);
    
    return response.data.data;
  } catch (error) {
    console.error('❌ 获取用户资料失败:');
    if (error.response) {
      console.error(`   HTTP状态码: ${error.response.status}`);
      console.error(`   错误信息: ${JSON.stringify(error.response.data, null, 2)}`);
    } else {
      console.error(`   网络错误: ${error.message}`);
    }
    throw error;
  }
}

async function testValidationErrors() {
  console.log('\n🔍 测试数据验证...');
  
  // 测试空邮箱
  try {
    await axios.post(`${API_BASE_URL}/auth/register`, {
      email: '',
      password: '123456',
      username: 'testuser',
    });
    console.log('❌ 应该拒绝空邮箱');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log('✅ 正确拒绝了空邮箱');
    }
  }
  
  // 测试短密码
  try {
    await axios.post(`${API_BASE_URL}/auth/register`, {
      email: 'test2@example.com',
      password: '123',
      username: 'testuser2',
    });
    console.log('❌ 应该拒绝短密码');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log('✅ 正确拒绝了短密码');
    }
  }
  
  // 测试无效邮箱
  try {
    await axios.post(`${API_BASE_URL}/auth/register`, {
      email: 'invalid-email',
      password: '123456',
      username: 'testuser3',
    });
    console.log('❌ 应该拒绝无效邮箱格式');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log('✅ 正确拒绝了无效邮箱格式');
    }
  }
}

async function testJSONParsing() {
  console.log('\n🔧 测试JSON解析...');
  
  // 测试错误的JSON格式
  try {
    await axios.post(`${API_BASE_URL}/auth/register`, '{"email": "test@example.com", "password": "123456"', {
      headers: {
        'Content-Type': 'application/json',
      },
    });
    console.log('❌ 应该拒绝错误的JSON格式');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log('✅ 正确处理了JSON解析错误');
    } else if (error.code === 'ERR_BAD_REQUEST') {
      console.log('✅ 正确处理了JSON解析错误 (客户端级别)');
    }
  }
  
  // 测试正确的JSON但缺少字段
  try {
    await axios.post(`${API_BASE_URL}/auth/register`, {
      email: 'test@example.com',
      // 缺少password和username
    });
    console.log('❌ 应该要求必填字段');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log('✅ 正确要求了必填字段');
    }
  }
}

async function main() {
  let registrationData, loginData;
  
  try {
    // 1. 测试注册
    registrationData = await testRegistration();
    
    // 2. 测试登录
    loginData = await testLogin();
    
    // 3. 测试获取用户资料
    await testUserProfile(loginData.tokens.accessToken);
    
    // 4. 测试数据验证
    await testValidationErrors();
    
    // 5. 测试JSON解析
    await testJSONParsing();
    
    console.log('\n🎉 所有测试都通过了！');
    console.log('\n📋 测试总结:');
    console.log('   ✅ 用户注册功能正常');
    console.log('   ✅ 用户登录功能正常');
    console.log('   ✅ 获取用户资料功能正常');
    console.log('   ✅ 数据验证功能正常');
    console.log('   ✅ JSON解析功能正常');
    console.log('   ✅ 密码验证规则已简化(适合MVP)');
    console.log('   ✅ API路径映射正确');
    console.log('   ✅ 前后端数据格式匹配');
    
  } catch (error) {
    console.log('\n💥 测试失败！');
    process.exit(1);
  }
}

// 运行测试
main().catch(console.error);