#!/usr/bin/env node

const axios = require('axios');

const API_BASE_URL = 'http://localhost:3003';

async function testAPI() {
  console.log('🔍 开始API调试测试\n');
  
  // Test 1: 检查健康状态
  try {
    console.log('1. 健康检查');
    const health = await axios.get(`${API_BASE_URL}/health`);
    console.log('✅ Health Status:', health.status);
    console.log('   Response:', JSON.stringify(health.data, null, 2));
  } catch (error) {
    console.log('❌ Health check failed:', error.message);
  }

  // Test 2: 用户注册
  try {
    console.log('\n2. 用户注册测试');
    const userData = {
      username: 'testuser123',
      email: 'test123@example.com',
      password: 'Test123!@#',
      displayName: 'Test User'
    };
    console.log('   请求数据:', JSON.stringify(userData, null, 2));
    
    const register = await axios.post(`${API_BASE_URL}/api/v1/users/register`, userData);
    console.log('✅ Register Status:', register.status);
    console.log('   Response:', JSON.stringify(register.data, null, 2));
    
    if (register.data.token) {
      console.log('   Token获取成功:', register.data.token.substring(0, 20) + '...');
    }
  } catch (error) {
    console.log('❌ Register failed:', error.response?.status, error.response?.data?.message || error.message);
    if (error.response?.data) {
      console.log('   错误详情:', JSON.stringify(error.response.data, null, 2));
    }
  }

  // Test 3: 检查API路由
  try {
    console.log('\n3. API路由文档');
    const docs = await axios.get(`${API_BASE_URL}/api/v1/docs`);
    console.log('✅ Docs Status:', docs.status);
    console.log('   用户相关路由:', JSON.stringify(docs.data.endpoints.users, null, 2));
  } catch (error) {
    console.log('❌ Docs failed:', error.response?.status, error.message);
  }

  // Test 4: 检查路由匹配问题
  console.log('\n4. 路由测试');
  const testRoutes = [
    '/api/v1/auth/register',
    '/api/v1/users/register', 
    '/api/v1/health',
    '/api/v1/users/profile/me'
  ];

  for (const route of testRoutes) {
    try {
      const response = await axios.get(`${API_BASE_URL}${route}`);
      console.log(`✅ ${route}: ${response.status}`);
    } catch (error) {
      console.log(`❌ ${route}: ${error.response?.status} - ${error.response?.data?.message || error.message}`);
    }
  }
}

testAPI().catch(console.error);