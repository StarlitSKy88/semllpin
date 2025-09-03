module.exports = async () => {
  console.log('🧹 Cleaning up E2E test environment...');
  
  // 清理测试数据
  try {
    const { db } = require('../../src/config/database');
    
    // 清理所有测试数据
    console.log('🗑️ Cleaning test data...');
    await db('media_files').del();
    await db('payments').del();
    await db('comments').del();
    await db('annotations').del();
    await db('users').del();
    
    // 关闭数据库连接
    await db.destroy();
    console.log('✅ Database cleaned and disconnected!');
  } catch (error) {
    console.error('❌ Database cleanup failed:', error);
  }
  
  console.log('✅ E2E test environment cleaned up!');
};