// 数据库测试设置 - SmellPin自动化测试方案2.0
import knex, { Knex } from 'knex';
import { config } from '../../src/config/config';

let testDb: Knex | null = null;
const dbConnections: Map<string, Knex> = new Map();

// 获取测试数据库连接
export function getTestDb(): Knex {
  if (!testDb) {
    throw new Error('Test database not initialized. Call setupTestDatabase() first.');
  }
  return testDb;
}

// 为每个测试套件创建隔离的数据库连接
export async function createIsolatedDbConnection(testSuiteName: string): Promise<Knex> {
  const dbName = `smellpin_test_${testSuiteName}_${Date.now()}`;
  
  // 创建测试数据库
  const adminDb = knex({
    client: 'postgresql',
    connection: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5433'),
      user: process.env.DB_USER || 'test',
      password: process.env.DB_PASSWORD || 'test',
      database: 'postgres', // 连接到默认数据库来创建新数据库
    },
  });

  try {
    await adminDb.raw(`DROP DATABASE IF EXISTS "${dbName}"`);
    await adminDb.raw(`CREATE DATABASE "${dbName}"`);
    await adminDb.destroy();
    
    // 创建连接到新数据库
    const isolatedDb = knex({
      client: 'postgresql',
      connection: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5433'),
        user: process.env.DB_USER || 'test',
        password: process.env.DB_PASSWORD || 'test',
        database: dbName,
      },
      pool: {
        min: 1,
        max: 5,
      },
    });

    // 运行迁移
    await isolatedDb.migrate.latest({
      directory: './migrations'
    });

    // 启用PostGIS扩展（如果可用）
    try {
      await isolatedDb.raw('CREATE EXTENSION IF NOT EXISTS postgis');
      console.log(`✅ PostGIS extension enabled for ${dbName}`);
    } catch (error) {
      console.warn(`⚠️ PostGIS not available for ${dbName}:`, error);
    }

    dbConnections.set(testSuiteName, isolatedDb);
    return isolatedDb;
    
  } catch (error) {
    await adminDb.destroy();
    throw error;
  }
}

// 清理隔离的数据库连接
export async function cleanupIsolatedDbConnection(testSuiteName: string): Promise<void> {
  const db = dbConnections.get(testSuiteName);
  if (db) {
    const dbName = db.client.config.connection.database;
    
    // 关闭连接
    await db.destroy();
    dbConnections.delete(testSuiteName);
    
    // 删除测试数据库
    const adminDb = knex({
      client: 'postgresql',
      connection: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5433'),
        user: process.env.DB_USER || 'test',
        password: process.env.DB_PASSWORD || 'test',
        database: 'postgres',
      },
    });

    try {
      // 终止所有连接到测试数据库的会话
      await adminDb.raw(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = ? AND pid <> pg_backend_pid()
      `, [dbName]);
      
      await adminDb.raw(`DROP DATABASE IF EXISTS "${dbName}"`);
      console.log(`🗑️ Cleaned up test database: ${dbName}`);
    } finally {
      await adminDb.destroy();
    }
  }
}

// 设置主测试数据库
export async function setupTestDatabase(): Promise<void> {
  const testDbUrl = process.env.TEST_DATABASE_URL || 'postgres://test:test@localhost:5433/smellpin_test';
  
  testDb = knex({
    client: 'postgresql',
    connection: testDbUrl,
    pool: {
      min: 2,
      max: 10,
    },
  });

  try {
    // 检查数据库连接
    await testDb.raw('SELECT 1');
    console.log('✅ Test database connection established');
    
    // 运行迁移
    await testDb.migrate.latest({
      directory: './migrations'
    });
    console.log('✅ Test database migrations completed');
    
    // 启用PostGIS扩展（如果可用）
    try {
      await testDb.raw('CREATE EXTENSION IF NOT EXISTS postgis');
      console.log('✅ PostGIS extension enabled');
    } catch (error) {
      console.warn('⚠️ PostGIS not available, continuing without spatial features');
    }
    
  } catch (error) {
    console.error('❌ Test database setup failed:', error);
    throw error;
  }
}

// 清理测试数据库
export async function cleanupTestDatabase(): Promise<void> {
  if (!testDb) return;
  
  try {
    // 获取所有表名
    const tables = await testDb
      .select('tablename')
      .from('pg_tables')
      .where('schemaname', 'public')
      .whereNotIn('tablename', ['knex_migrations', 'knex_migrations_lock']);
    
    if (tables.length > 0) {
      // 清空所有数据表但保留结构
      const tableNames = tables.map(t => `"${t.tablename}"`).join(', ');
      await testDb.raw(`TRUNCATE TABLE ${tableNames} RESTART IDENTITY CASCADE`);
      console.log('🧹 Test database tables cleaned');
    }
    
  } catch (error) {
    console.warn('⚠️ Database cleanup warning:', error);
  }
}

// 关闭所有数据库连接
export async function teardownTestDatabase(): Promise<void> {
  // 清理所有隔离连接
  for (const [testSuiteName] of dbConnections.entries()) {
    await cleanupIsolatedDbConnection(testSuiteName);
  }
  
  // 关闭主测试数据库连接
  if (testDb) {
    await testDb.destroy();
    testDb = null;
    console.log('🔌 Test database connections closed');
  }
}

// Jest钩子函数
beforeAll(async () => {
  await setupTestDatabase();
});

afterEach(async () => {
  await cleanupTestDatabase();
});

afterAll(async () => {
  await teardownTestDatabase();
});

// 数据库健康检查
export async function checkTestDatabaseHealth(): Promise<boolean> {
  try {
    if (!testDb) return false;
    await testDb.raw('SELECT 1');
    return true;
  } catch (error) {
    console.error('❌ Test database health check failed:', error);
    return false;
  }
}