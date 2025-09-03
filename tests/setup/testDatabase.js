// Test database configuration
// 导入源文件数据库配置
const { db, connectDatabase, disconnectDatabase } = require('../../src/config/database.ts');

// Export database utilities for tests
module.exports = {
  db,
  connectDatabase,
  disconnectDatabase,
  // Helper function to setup test database
  async setupTestDatabase() {
    try {
      await connectDatabase();
      console.log('Test database connected successfully');
    } catch (error) {
      console.error('Failed to connect test database:', error);
      throw error;
    }
  },
  
  // Helper function to cleanup test database
  async cleanupTestDatabase() {
    try {
      await disconnectDatabase();
      console.log('Test database disconnected successfully');
    } catch (error) {
      console.error('Failed to disconnect test database:', error);
      throw error;
    }
  }
};