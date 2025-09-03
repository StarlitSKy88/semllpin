"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTestDb = getTestDb;
exports.createIsolatedDbConnection = createIsolatedDbConnection;
exports.cleanupIsolatedDbConnection = cleanupIsolatedDbConnection;
exports.setupTestDatabase = setupTestDatabase;
exports.cleanupTestDatabase = cleanupTestDatabase;
exports.teardownTestDatabase = teardownTestDatabase;
exports.checkTestDatabaseHealth = checkTestDatabaseHealth;
const knex_1 = __importDefault(require("knex"));
let testDb = null;
const dbConnections = new Map();
function getTestDb() {
    if (!testDb) {
        throw new Error('Test database not initialized. Call setupTestDatabase() first.');
    }
    return testDb;
}
async function createIsolatedDbConnection(testSuiteName) {
    const dbName = `smellpin_test_${testSuiteName}_${Date.now()}`;
    const adminDb = (0, knex_1.default)({
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
        await adminDb.raw(`DROP DATABASE IF EXISTS "${dbName}"`);
        await adminDb.raw(`CREATE DATABASE "${dbName}"`);
        await adminDb.destroy();
        const isolatedDb = (0, knex_1.default)({
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
        await isolatedDb.migrate.latest({
            directory: './migrations'
        });
        try {
            await isolatedDb.raw('CREATE EXTENSION IF NOT EXISTS postgis');
            console.log(`✅ PostGIS extension enabled for ${dbName}`);
        }
        catch (error) {
            console.warn(`⚠️ PostGIS not available for ${dbName}:`, error);
        }
        dbConnections.set(testSuiteName, isolatedDb);
        return isolatedDb;
    }
    catch (error) {
        await adminDb.destroy();
        throw error;
    }
}
async function cleanupIsolatedDbConnection(testSuiteName) {
    const db = dbConnections.get(testSuiteName);
    if (db) {
        const dbName = db.client.config.connection.database;
        await db.destroy();
        dbConnections.delete(testSuiteName);
        const adminDb = (0, knex_1.default)({
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
            await adminDb.raw(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = ? AND pid <> pg_backend_pid()
      `, [dbName]);
            await adminDb.raw(`DROP DATABASE IF EXISTS "${dbName}"`);
            console.log(`🗑️ Cleaned up test database: ${dbName}`);
        }
        finally {
            await adminDb.destroy();
        }
    }
}
async function setupTestDatabase() {
    const testDbUrl = process.env.TEST_DATABASE_URL || 'postgres://test:test@localhost:5433/smellpin_test';
    testDb = (0, knex_1.default)({
        client: 'postgresql',
        connection: testDbUrl,
        pool: {
            min: 2,
            max: 10,
        },
    });
    try {
        await testDb.raw('SELECT 1');
        console.log('✅ Test database connection established');
        await testDb.migrate.latest({
            directory: './migrations'
        });
        console.log('✅ Test database migrations completed');
        try {
            await testDb.raw('CREATE EXTENSION IF NOT EXISTS postgis');
            console.log('✅ PostGIS extension enabled');
        }
        catch (error) {
            console.warn('⚠️ PostGIS not available, continuing without spatial features');
        }
    }
    catch (error) {
        console.error('❌ Test database setup failed:', error);
        throw error;
    }
}
async function cleanupTestDatabase() {
    if (!testDb)
        return;
    try {
        const tables = await testDb
            .select('tablename')
            .from('pg_tables')
            .where('schemaname', 'public')
            .whereNotIn('tablename', ['knex_migrations', 'knex_migrations_lock']);
        if (tables.length > 0) {
            const tableNames = tables.map(t => `"${t.tablename}"`).join(', ');
            await testDb.raw(`TRUNCATE TABLE ${tableNames} RESTART IDENTITY CASCADE`);
            console.log('🧹 Test database tables cleaned');
        }
    }
    catch (error) {
        console.warn('⚠️ Database cleanup warning:', error);
    }
}
async function teardownTestDatabase() {
    for (const [testSuiteName] of dbConnections.entries()) {
        await cleanupIsolatedDbConnection(testSuiteName);
    }
    if (testDb) {
        await testDb.destroy();
        testDb = null;
        console.log('🔌 Test database connections closed');
    }
}
beforeAll(async () => {
    await setupTestDatabase();
});
afterEach(async () => {
    await cleanupTestDatabase();
});
afterAll(async () => {
    await teardownTestDatabase();
});
async function checkTestDatabaseHealth() {
    try {
        if (!testDb)
            return false;
        await testDb.raw('SELECT 1');
        return true;
    }
    catch (error) {
        console.error('❌ Test database health check failed:', error);
        return false;
    }
}
//# sourceMappingURL=databaseSetup.js.map