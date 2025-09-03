const { execSync } = require('child_process');
const path = require('path');

// 在模块加载之前设置环境变量
process.env.NODE_ENV = 'test';
process.env.PORT = '3003'; // 使用不同的端口避免冲突
// 强制使用SQLite数据库进行测试
delete process.env.DB_TYPE;
delete process.env.DATABASE_URL;
delete process.env.TEST_DATABASE_URL;

// 禁用可能导致问题的服务
process.env.DISABLE_REDIS = 'true';
process.env.DISABLE_CACHE = 'true';
process.env.DISABLE_WEBSOCKET = 'true';
process.env.DISABLE_HEALTH_SERVICE = 'true';

module.exports = async () => {
  console.log('🚀 Setting up E2E test environment...');
  
  // 等待数据库连接
  console.log('📊 Waiting for database connection...');
  
  // 运行数据库迁移
  try {
    console.log('🔄 Running database migrations...');
    const { db } = require('../../src/config/database');
    
    // 运行迁移
    await db.migrate.latest();
    console.log('✅ Database migrations completed!');
    
    // 测试数据库连接
    await db.raw('SELECT 1');
    console.log('✅ Database connection verified!');
  } catch (error) {
    console.error('❌ Database setup failed:', error);
    throw error;
  }
  
  console.log('✅ E2E test environment ready!');
};