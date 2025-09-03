"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestContainersManager = void 0;
exports.setupTestContainers = setupTestContainers;
exports.teardownTestContainers = teardownTestContainers;
exports.getTestEnvironment = getTestEnvironment;
exports.default = globalSetup;
exports.globalTeardown = globalTeardown;
const testcontainers_1 = require("testcontainers");
const pg_1 = require("pg");
const ioredis_1 = __importDefault(require("ioredis"));
class TestContainersManager {
    constructor() {
        this.environment = null;
        this.isSetup = false;
    }
    static getInstance() {
        if (!TestContainersManager.instance) {
            TestContainersManager.instance = new TestContainersManager();
        }
        return TestContainersManager.instance;
    }
    async setupTestEnvironment() {
        if (this.isSetup && this.environment) {
            return this.environment;
        }
        console.log('🐳 启动 Testcontainers: Postgres + PostGIS + Redis...');
        try {
            const postgresContainer = await new testcontainers_1.GenericContainer('postgis/postgis:16-3.4')
                .withEnvironment({
                POSTGRES_DB: 'smellpin_test',
                POSTGRES_USER: 'test_user',
                POSTGRES_PASSWORD: 'test_password',
                POSTGRES_INITDB_ARGS: '--encoding=UTF-8 --lc-collate=C --lc-ctype=C'
            })
                .withExposedPorts(5432)
                .withWaitStrategy(testcontainers_1.Wait.forLogMessage('database system is ready to accept connections', 2))
                .withStartupTimeout(60000)
                .start();
            console.log(`✅ PostgreSQL + PostGIS 启动成功: ${postgresContainer.getMappedPort(5432)}`);
            const redisContainer = await new testcontainers_1.GenericContainer('redis:7-alpine')
                .withExposedPorts(6379)
                .withWaitStrategy(testcontainers_1.Wait.forLogMessage('Ready to accept connections'))
                .withStartupTimeout(30000)
                .start();
            console.log(`✅ Redis 启动成功: ${redisContainer.getMappedPort(6379)}`);
            const DATABASE_URL = `postgres://test_user:test_password@localhost:${postgresContainer.getMappedPort(5432)}/smellpin_test`;
            const REDIS_URL = `redis://localhost:${redisContainer.getMappedPort(6379)}`;
            const pgClient = new pg_1.Client({ connectionString: DATABASE_URL });
            await pgClient.connect();
            const redisClient = new ioredis_1.default(REDIS_URL);
            await redisClient.ping();
            await this.initializePostGIS(pgClient);
            await this.runMigrations(DATABASE_URL);
            this.environment = {
                postgres: postgresContainer,
                redis: redisContainer,
                pgClient,
                redisClient,
                DATABASE_URL,
                REDIS_URL
            };
            process.env.DATABASE_URL = DATABASE_URL;
            process.env.REDIS_URL = REDIS_URL;
            process.env.NODE_ENV = 'test';
            this.isSetup = true;
            console.log('🎉 测试环境准备完成!');
            return this.environment;
        }
        catch (error) {
            console.error('❌ Testcontainers 启动失败:', error);
            throw error;
        }
    }
    async initializePostGIS(client) {
        console.log('🗺️ 初始化 PostGIS 扩展...');
        try {
            await client.query('CREATE EXTENSION IF NOT EXISTS postgis;');
            await client.query('CREATE EXTENSION IF NOT EXISTS postgis_topology;');
            await client.query('CREATE EXTENSION IF NOT EXISTS postgis_tiger_geocoder;');
            await client.query('CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;');
            const result = await client.query('SELECT PostGIS_Version();');
            console.log(`✅ PostGIS 版本: ${result.rows[0].postgis_version}`);
        }
        catch (error) {
            console.error('❌ PostGIS 初始化失败:', error);
            throw error;
        }
    }
    async runMigrations(databaseUrl) {
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
        }
        catch (error) {
            console.error('❌ 数据库迁移失败:', error);
            throw error;
        }
    }
    async teardownTestEnvironment() {
        if (!this.environment) {
            return;
        }
        console.log('🧹 清理测试环境...');
        try {
            if (this.environment.pgClient) {
                await this.environment.pgClient.end();
            }
            if (this.environment.redisClient) {
                await this.environment.redisClient.disconnect();
            }
            await this.environment.postgres.stop();
            await this.environment.redis.stop();
            this.environment = null;
            this.isSetup = false;
            console.log('✅ 测试环境清理完成');
        }
        catch (error) {
            console.error('❌ 测试环境清理失败:', error);
        }
    }
    getEnvironment() {
        return this.environment;
    }
    async createIsolatedSchema(testName) {
        if (!this.environment?.pgClient) {
            throw new Error('测试环境未初始化');
        }
        const schemaName = `test_${testName}_${Date.now()}`;
        await this.environment.pgClient.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}";`);
        await this.environment.pgClient.query(`SET search_path TO "${schemaName}", public;`);
        return schemaName;
    }
    async dropIsolatedSchema(schemaName) {
        if (!this.environment?.pgClient) {
            return;
        }
        try {
            await this.environment.pgClient.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE;`);
        }
        catch (error) {
            console.warn(`清理 schema ${schemaName} 失败:`, error);
        }
    }
    async getIsolatedRedis(dbIndex = 0) {
        if (!this.environment?.REDIS_URL) {
            throw new Error('Redis 环境未初始化');
        }
        const redis = new ioredis_1.default(`${this.environment.REDIS_URL}/${dbIndex}`);
        await redis.flushdb();
        return redis;
    }
}
exports.TestContainersManager = TestContainersManager;
async function setupTestContainers() {
    const manager = TestContainersManager.getInstance();
    return await manager.setupTestEnvironment();
}
async function teardownTestContainers() {
    const manager = TestContainersManager.getInstance();
    await manager.teardownTestEnvironment();
}
function getTestEnvironment() {
    const manager = TestContainersManager.getInstance();
    return manager.getEnvironment();
}
async function globalSetup() {
    console.log('🚀 全局测试环境设置开始...');
    await setupTestContainers();
    console.log('✅ 全局测试环境设置完成');
}
async function globalTeardown() {
    console.log('🧹 全局测试环境清理开始...');
    await teardownTestContainers();
    console.log('✅ 全局测试环境清理完成');
}
//# sourceMappingURL=testcontainers-setup.js.map