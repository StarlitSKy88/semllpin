const path = require('path');
const knexLib = require('knex');

// 导入knex配置
const knexConfig = require('../knexfile');

// 创建测试数据库配置
const testDbConfig = {
  client: 'sqlite3',
  connection: {
    filename: ':memory:',
  },
  useNullAsDefault: true,
  migrations: {
    directory: path.resolve('./migrations'),
    tableName: 'knex_migrations',
  },
  seeds: {
    directory: path.resolve('./seeds'),
  },
  pool: {
    afterCreate: (conn, cb) => {
      conn.run('PRAGMA foreign_keys = ON', cb);
    }
  }
};

// 创建测试数据库连接
const testDb = knexLib(testDbConfig);
global.testDb = testDb;

// 全局测试工具
let expect, sinon;

beforeAll(async () => {
  try {
    // 导入sinon
    sinon = require('sinon');
    
    // 设置全局变量
    global.sinon = sinon;
    
    // 运行数据库迁移
    await testDb.migrate.latest();
    
    console.log('测试环境初始化完成');
  } catch (error) {
    console.error('测试环境初始化失败:', error);
    throw error;
  }
});

afterAll(async () => {
  try {
    if (testDb) {
      await testDb.destroy();
    }
    console.log('测试环境清理完成');
  } catch (error) {
    console.error('测试环境清理失败:', error);
  }
});

// 每个测试后清理数据
afterEach(async () => {
  try {
    if (testDb) {
      // 清理测试数据但保持表结构
      const tables = ['anti_fraud_logs', 'lbs_rewards', 'location_reports', 'users', 'annotations'];
      for (const table of tables) {
        await testDb(table).del().catch(() => {}); // 忽略表不存在的错误
      }
    }
  } catch (error) {
    // 测试数据清理失败不应该中断测试
    console.warn('测试数据清理警告:', error.message);
  }
});

module.exports = {
  testDb,
  testDbConfig,
};