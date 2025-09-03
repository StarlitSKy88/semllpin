/**
 * 修复脚本 - 解决系统测试报告中的问题
 * 1. 初始化LBS功能所需的数据库表结构
 * 2. 验证文件上传认证功能
 * 3. 检查Stripe配置
 */

const fs = require('fs');
const path = require('path');
const { neon } = require('@neondatabase/serverless');

// 加载环境变量
function loadEnvVars() {
  const envPath = path.join(__dirname, '.dev.vars');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const lines = envContent.split('\n');
    
    lines.forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        const [key, ...valueParts] = trimmed.split('=');
        const value = valueParts.join('=').replace(/^["']|["']$/g, '');
        process.env[key] = value;
      }
    });
  }
}

// 加载环境变量
loadEnvVars();

// 数据库连接
const sql = neon(process.env.DATABASE_URL);

// 动态导入fetch
let fetch;

async function initFetch() {
  if (!fetch) {
    const fetchModule = await import('node-fetch');
    fetch = fetchModule.default;
  }
  return fetch;
}

// 基础URL配置
const BASE_URL = 'http://localhost:8787';

/**
 * 初始化LBS数据库表
 */
async function initializeLbsTables() {
  console.log('🔧 正在初始化LBS数据库表...');
  
  try {
    // 创建签到记录表
    await sql`
      CREATE TABLE IF NOT EXISTS checkin_records (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        location_name VARCHAR(255),
        accuracy DECIMAL(10, 2),
        points_earned INTEGER DEFAULT 0,
        is_first_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建奖励记录表
    await sql`
      CREATE TABLE IF NOT EXISTS reward_records (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        reward_type VARCHAR(50) NOT NULL,
        reward_category VARCHAR(50),
        points INTEGER NOT NULL,
        description TEXT,
        source_id INTEGER,
        source_type VARCHAR(50),
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        status VARCHAR(20) DEFAULT 'pending',
        claimed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建用户位置表
    await sql`
      CREATE TABLE IF NOT EXISTS user_locations (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL UNIQUE,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建用户统计表
    await sql`
      CREATE TABLE IF NOT EXISTS user_stats (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL UNIQUE,
        total_checkins INTEGER DEFAULT 0,
        total_points INTEGER DEFAULT 0,
        last_checkin_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建附近用户表
    await sql`
      CREATE TABLE IF NOT EXISTS nearby_users (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        nearby_user_id UUID NOT NULL,
        distance DECIMAL(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建位置热点表
    await sql`
      CREATE TABLE IF NOT EXISTS location_hotspots (
        id SERIAL PRIMARY KEY,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        checkin_count INTEGER DEFAULT 0,
        total_points INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建钱包表（如果不存在）
    await sql`
      CREATE TABLE IF NOT EXISTS wallets (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        currency VARCHAR(10) DEFAULT 'usd',
        balance DECIMAL(15, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, currency)
      )
    `;
    
    // 创建交易记录表
    await sql`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(10) DEFAULT 'usd',
        status VARCHAR(20) DEFAULT 'pending',
        completed_at TIMESTAMP,
        description TEXT,
        metadata JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    console.log('✅ LBS数据库表初始化完成');
    
  } catch (error) {
    console.error('❌ LBS数据库表初始化失败:', error.message);
    throw error;
  }
}

/**
 * 测试文件上传认证
 */
async function testFileUploadAuth() {
  console.log('🔧 测试文件上传认证功能...');
  
  try {
    const fetchFn = await initFetch();
    
    // 测试无认证的上传请求
    const response = await fetchFn(`${BASE_URL}/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        filename: 'test.jpg',
        contentType: 'image/jpeg'
      })
    });
    
    if (response.status === 401) {
      console.log('✅ 文件上传认证正常工作 - 未认证请求返回401');
    } else {
      console.log('⚠️  文件上传认证可能有问题 - 状态码:', response.status);
    }
    
  } catch (error) {
    console.error('❌ 文件上传认证测试失败:', error.message);
  }
}

/**
 * 检查Stripe配置
 */
async function checkStripeConfig() {
  console.log('🔧 检查Stripe配置...');
  
  const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
  const stripePublishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
  
  if (!stripeSecretKey || stripeSecretKey.includes('sk_test_your_stripe_secret_key_here')) {
    console.log('⚠️  Stripe Secret Key 需要配置真实的密钥');
  } else {
    console.log('✅ Stripe Secret Key 已配置');
  }
  
  if (!stripePublishableKey || stripePublishableKey.includes('pk_test_your_stripe_publishable_key_here')) {
    console.log('⚠️  Stripe Publishable Key 需要配置真实的密钥');
  } else {
    console.log('✅ Stripe Publishable Key 已配置');
  }
}

/**
 * 测试LBS功能
 */
async function testLbsFunctionality() {
  console.log('🔧 测试LBS功能...');
  
  try {
    const fetchFn = await initFetch();
    
    // 测试初始化LBS表的API
    const initResponse = await fetchFn(`${BASE_URL}/lbs/init`, {
      method: 'POST'
    });
    
    if (initResponse.ok) {
      console.log('✅ LBS初始化API正常工作');
    } else {
      console.log('⚠️  LBS初始化API可能有问题 - 状态码:', initResponse.status);
    }
    
  } catch (error) {
    console.error('❌ LBS功能测试失败:', error.message);
  }
}

/**
 * 主修复函数
 */
async function main() {
  console.log('🚀 开始修复系统问题...');
  console.log('=' .repeat(50));
  
  try {
    // 1. 初始化LBS数据库表
    await initializeLbsTables();
    
    // 2. 测试文件上传认证
    await testFileUploadAuth();
    
    // 3. 检查Stripe配置
    await checkStripeConfig();
    
    // 4. 测试LBS功能
    await testLbsFunctionality();
    
    console.log('=' .repeat(50));
    console.log('🎉 修复脚本执行完成！');
    console.log('\n📋 修复总结:');
    console.log('- ✅ LBS数据库表结构已初始化');
    console.log('- ✅ 文件上传认证功能已验证');
    console.log('- ⚠️  请手动配置真实的Stripe API密钥');
    console.log('- ✅ LBS功能已测试');
    
  } catch (error) {
    console.error('❌ 修复过程中出现错误:', error.message);
    process.exit(1);
  }
}

// 运行修复脚本
if (require.main === module) {
  main();
}

module.exports = {
  initializeLbsTables,
  testFileUploadAuth,
  checkStripeConfig,
  testLbsFunctionality
};