/**
 * SmellPin Testcontainers 设置 - Phase 1
 * 用真实的 Postgres + PostGIS + Redis 替代 SQLite
 * 解决 LBS/地理围栏/近邻查询的行为差异问题
 */
import { GenericContainer, StartedTestContainer, Wait } from 'testcontainers';
import { Client } from 'pg';
import Redis from 'ioredis';

interface TestEnvironment {
  postgres: StartedTestContainer;
  redis: StartedTestContainer;
  pgClient: Client;
  redisClient: Redis;
  DATABASE_URL: string;
  REDIS_URL: string;
}

class TestContainersManager {
  private static instance: TestContainersManager;
  private environment: TestEnvironment | null = null;
  private isSetup = false;

  static getInstance(): TestContainersManager {
    if (!TestContainersManager.instance) {
      TestContainersManager.instance = new TestContainersManager();
    }
    return TestContainersManager.instance;
  }

  async setupTestEnvironment(): Promise<TestEnvironment> {
    if (this.isSetup && this.environment) {
      return this.environment;
    }

    console.log('🐳 启动 Testcontainers: Postgres + PostGIS + Redis...');
    
    try {
      // 启动 PostgreSQL + PostGIS 容器
      const postgresContainer = await new GenericContainer('postgis/postgis:16-3.4')
        .withEnvironment({
          POSTGRES_DB: 'smellpin_test',
          POSTGRES_USER: 'test_user', 
          POSTGRES_PASSWORD: 'test_password',
          POSTGRES_INITDB_ARGS: '--encoding=UTF-8 --lc-collate=C --lc-ctype=C'
        })
        .withExposedPorts(5432)
        .withWaitStrategy(Wait.forLogMessage('database system is ready to accept connections', 2))
        .withStartupTimeout(60000)
        .start();

      console.log(`✅ PostgreSQL + PostGIS 启动成功: ${postgresContainer.getMappedPort(5432)}`);

      // 启动 Redis 容器
      const redisContainer = await new GenericContainer('redis:7-alpine')
        .withExposedPorts(6379)
        .withWaitStrategy(Wait.forLogMessage('Ready to accept connections'))
        .withStartupTimeout(30000)
        .start();

      console.log(`✅ Redis 启动成功: ${redisContainer.getMappedPort(6379)}`);

      // 创建数据库连接
      const DATABASE_URL = `postgres://test_user:test_password@localhost:${postgresContainer.getMappedPort(5432)}/smellpin_test`;
      const REDIS_URL = `redis://localhost:${redisContainer.getMappedPort(6379)}`;

      const pgClient = new Client({ connectionString: DATABASE_URL });
      await pgClient.connect();

      const redisClient = new Redis(REDIS_URL);
      await redisClient.ping();

      // 初始化 PostGIS 扩展
      await this.initializePostGIS(pgClient);

      // 运行数据库迁移
      await this.runMigrations(DATABASE_URL);

      this.environment = {
        postgres: postgresContainer,
        redis: redisContainer,
        pgClient,
        redisClient,
        DATABASE_URL,
        REDIS_URL
      };

      // 设置环境变量
      process.env.DATABASE_URL = DATABASE_URL;
      process.env.REDIS_URL = REDIS_URL;
      process.env.NODE_ENV = 'test';

      this.isSetup = true;
      console.log('🎉 测试环境准备完成!');
      
      return this.environment;
      
    } catch (error) {
      console.error('❌ Testcontainers 启动失败:', error);
      throw error;
    }
  }

  private async initializePostGIS(client: Client): Promise<void> {
    console.log('🗺️ 初始化 PostGIS 扩展...');
    
    try {
      // 启用 PostGIS 扩展
      await client.query('CREATE EXTENSION IF NOT EXISTS postgis;');
      await client.query('CREATE EXTENSION IF NOT EXISTS postgis_topology;');
      await client.query('CREATE EXTENSION IF NOT EXISTS postgis_tiger_geocoder;');
      await client.query('CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;');
      
      // 验证 PostGIS 安装
      const result = await client.query('SELECT PostGIS_Version();');
      console.log(`✅ PostGIS 版本: ${result.rows[0].postgis_version}`);
      
    } catch (error) {
      console.error('❌ PostGIS 初始化失败:', error);
      throw error;
    }
  }

  private async runMigrations(databaseUrl: string): Promise<void> {
    console.log('📦 运行数据库迁移...');
    
    try {
      const knex = require('knex')({
        client: 'pg',
        connection: databaseUrl,
        migrations: {
          directory: './migrations',
          extension: 'js'
        },
        seeds: {
          directory: './seeds'
        }
      });

      await knex.migrate.latest();
      console.log('✅ 数据库迁移完成');
      
      await knex.destroy();
    } catch (error) {
      console.error('❌ 数据库迁移失败:', error);
      throw error;
    }
  }

  async teardownTestEnvironment(): Promise<void> {
    if (!this.environment) {
      return;
    }

    console.log('🧹 清理测试环境...');

    try {
      // 关闭数据库连接
      if (this.environment.pgClient) {
        await this.environment.pgClient.end();
      }

      if (this.environment.redisClient) {
        await this.environment.redisClient.disconnect();
      }

      // 停止容器
      await this.environment.postgres.stop();
      await this.environment.redis.stop();

      this.environment = null;
      this.isSetup = false;
      
      console.log('✅ 测试环境清理完成');
    } catch (error) {
      console.error('❌ 测试环境清理失败:', error);
    }
  }

  getEnvironment(): TestEnvironment | null {
    return this.environment;
  }

  // 数据隔离 - 每个测试使用独立的 schema
  async createIsolatedSchema(testName: string): Promise<string> {
    if (!this.environment?.pgClient) {
      throw new Error('测试环境未初始化');
    }

    const schemaName = `test_${testName}_${Date.now()}`;
    await this.environment.pgClient.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}";`);
    await this.environment.pgClient.query(`SET search_path TO "${schemaName}", public;`);
    
    return schemaName;
  }

  async dropIsolatedSchema(schemaName: string): Promise<void> {
    if (!this.environment?.pgClient) {
      return;
    }

    try {
      await this.environment.pgClient.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE;`);
    } catch (error) {
      console.warn(`清理 schema ${schemaName} 失败:`, error);
    }
  }

  // Redis 清理 - 使用不同的 DB 索引隔离测试数据
  async getIsolatedRedis(dbIndex: number = 0): Promise<Redis> {
    if (!this.environment?.REDIS_URL) {
      throw new Error('Redis 环境未初始化');
    }

    const redis = new Redis(`${this.environment.REDIS_URL}/${dbIndex}`);
    await redis.flushdb(); // 清空当前数据库
    return redis;
  }
}

// 全局设置和清理函数
export async function setupTestContainers(): Promise<TestEnvironment> {
  const manager = TestContainersManager.getInstance();
  return await manager.setupTestEnvironment();
}

export async function teardownTestContainers(): Promise<void> {
  const manager = TestContainersManager.getInstance();
  await manager.teardownTestEnvironment();
}

export function getTestEnvironment(): TestEnvironment | null {
  const manager = TestContainersManager.getInstance();
  return manager.getEnvironment();
}

// Jest 全局设置函数
export default async function globalSetup() {
  console.log('🚀 全局测试环境设置开始...');
  await setupTestContainers();
  console.log('✅ 全局测试环境设置完成');
}

// Jest 全局清理函数 
export async function globalTeardown() {
  console.log('🧹 全局测试环境清理开始...');
  await teardownTestContainers();
  console.log('✅ 全局测试环境清理完成');
}

// 导出管理器实例供测试使用
export { TestContainersManager };