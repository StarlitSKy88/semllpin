"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.monitorQuery = exports.buildBoundsQuery = exports.buildLocationQuery = exports.buildSortQuery = exports.buildSearchQuery = exports.buildPaginationQuery = exports.withTransaction = exports.checkDatabaseHealth = exports.disconnectDatabase = exports.connectDatabase = exports.db = void 0;
const knex_1 = __importDefault(require("knex"));
const config_1 = require("./config");
const logger_1 = require("../utils/logger");
const dbConfig = process.env['DB_TYPE'] === 'sqlite' || (!process.env['DATABASE_URL'] && process.env['NODE_ENV'] === 'test') ? {
    client: 'sqlite3',
    connection: {
        filename: process.env['NODE_ENV'] === 'test' ? './test.sqlite' : './smellpin.sqlite',
    },
    useNullAsDefault: true,
    pool: {
        min: 1,
        max: 1,
    },
    migrations: {
        directory: './migrations',
        tableName: 'knex_migrations',
    },
    seeds: {
        directory: './seeds',
    },
    debug: config_1.config.NODE_ENV === 'development',
} : {
    client: 'postgresql',
    connection: config_1.config.DATABASE_URL ? {
        connectionString: config_1.config.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    } : {
        host: config_1.config.database.host,
        port: config_1.config.database.port,
        user: config_1.config.database.username,
        password: config_1.config.database.password,
        database: config_1.config.database.database,
        ssl: config_1.config.database.ssl ? { rejectUnauthorized: false } : false,
    },
    pool: {
        min: config_1.config.NODE_ENV === 'production' ? 8 : 3,
        max: config_1.config.NODE_ENV === 'production' ? 50 : 15,
        createTimeoutMillis: 8000,
        acquireTimeoutMillis: 10000,
        idleTimeoutMillis: config_1.config.NODE_ENV === 'production' ? 300000 : 180000,
        destroyTimeoutMillis: 3000,
        propagateCreateError: false,
        afterCreate: async (conn, done) => {
            try {
                logger_1.logger.debug('🔗 New database connection created');
                if (conn.raw) {
                    await conn.raw("SET statement_timeout = '8s'");
                    await conn.raw("SET lock_timeout = '5s'");
                    await conn.raw("SET client_encoding TO 'UTF8'");
                    await conn.raw("SET timezone TO 'UTC'");
                }
                done(null, conn);
            }
            catch (error) {
                logger_1.logger.error('❌ Failed to configure new connection:', error);
                done(error instanceof Error ? error : new Error(String(error)));
            }
        }
    },
    migrations: {
        directory: './migrations',
        tableName: 'knex_migrations',
    },
    seeds: {
        directory: './seeds',
    },
    debug: config_1.config.NODE_ENV === 'development',
};
exports.db = (0, knex_1.default)(dbConfig);
const connectDatabase = async () => {
    const maxRetries = 3;
    const retryDelay = 2000;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            logger_1.logger.info(`🔄 Attempting database connection (attempt ${attempt}/${maxRetries})...`);
            const result = await Promise.race([
                exports.db.raw('SELECT 1+1 as result'),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Database connection timeout after 10 seconds')), 10000))
            ]);
            logger_1.logger.info('✅ 数据库连接成功', {
                result: result.rows?.[0] || result,
                attempt,
                connectionPool: {
                    min: dbConfig.pool?.min || 0,
                    max: dbConfig.pool?.max || 0
                }
            });
            if (config_1.config.NODE_ENV === 'production') {
                try {
                    await exports.db.raw('SELECT PostGIS_Version()');
                    logger_1.logger.info('✅ PostGIS extension verified');
                }
                catch (error) {
                    logger_1.logger.warn('⚠️ PostGIS extension not available, spatial queries will be limited');
                }
                await exports.db.migrate.latest();
                logger_1.logger.info('✅ 数据库迁移完成');
            }
            return;
        }
        catch (error) {
            logger_1.logger.error(`❌ 数据库连接失败 (attempt ${attempt}/${maxRetries}):`, {
                error: error instanceof Error ? error.message : error,
                stack: error instanceof Error ? error.stack : undefined
            });
            if (attempt === maxRetries) {
                const errorMessage = `Database connection failed after ${maxRetries} attempts. Server will not start.`;
                logger_1.logger.error(`🚨 ${errorMessage}`);
                throw new Error(errorMessage);
            }
            const delay = retryDelay * attempt;
            logger_1.logger.info(`⏳ Waiting ${delay}ms before retry...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
};
exports.connectDatabase = connectDatabase;
const disconnectDatabase = async () => {
    try {
        await exports.db.destroy();
        logger_1.logger.info('数据库连接已关闭');
    }
    catch (error) {
        logger_1.logger.error('关闭数据库连接时发生错误:', error);
        throw error;
    }
};
exports.disconnectDatabase = disconnectDatabase;
const checkDatabaseHealth = async () => {
    const startTime = Date.now();
    let connectionTest = false;
    let poolStatus = {};
    let error;
    try {
        await exports.db.raw('SELECT 1');
        connectionTest = true;
        const pool = exports.db.client?.pool;
        if (pool) {
            poolStatus = {
                size: pool.size || 0,
                available: pool.available || 0,
                borrowed: pool.borrowed || 0,
                pending: pool.pending || 0,
                max: pool.max || 0,
                min: pool.min || 0
            };
        }
        const responseTime = Date.now() - startTime;
        const healthy = connectionTest && responseTime < 1000;
        if (!healthy && responseTime >= 1000) {
            logger_1.logger.warn('⚠️ Database response time is high:', { responseTime });
        }
        return {
            healthy,
            details: {
                connectionTest,
                poolStatus,
                responseTime
            }
        };
    }
    catch (err) {
        error = err instanceof Error ? err.message : String(err);
        logger_1.logger.error('❌ 数据库健康检查失败:', error);
        return {
            healthy: false,
            details: {
                connectionTest: false,
                poolStatus,
                responseTime: Date.now() - startTime,
                error
            }
        };
    }
};
exports.checkDatabaseHealth = checkDatabaseHealth;
const withTransaction = async (callback) => {
    const trx = await exports.db.transaction();
    try {
        const result = await callback(trx);
        await trx.commit();
        return result;
    }
    catch (error) {
        await trx.rollback();
        throw error;
    }
};
exports.withTransaction = withTransaction;
const buildPaginationQuery = (query, page = 1, limit = 20) => {
    const offset = (page - 1) * limit;
    return query.limit(limit).offset(offset);
};
exports.buildPaginationQuery = buildPaginationQuery;
const buildSearchQuery = (query, searchTerm, searchColumns) => {
    if (!searchTerm || searchColumns.length === 0) {
        return query;
    }
    return query.where((builder) => {
        searchColumns.forEach((column, index) => {
            const method = index === 0 ? 'where' : 'orWhere';
            builder[method](column, 'ILIKE', `%${searchTerm}%`);
        });
    });
};
exports.buildSearchQuery = buildSearchQuery;
const buildSortQuery = (query, sortBy = 'created_at', sortOrder = 'desc') => {
    return query.orderBy(sortBy, sortOrder);
};
exports.buildSortQuery = buildSortQuery;
const buildLocationQuery = (query, latitude, longitude, radiusInMeters = 1000) => {
    return query.whereRaw('ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)', [`POINT(${longitude} ${latitude})`, radiusInMeters]);
};
exports.buildLocationQuery = buildLocationQuery;
const buildBoundsQuery = (query, bounds) => {
    return query.whereRaw('ST_Within(location_point, ST_GeomFromText(?, 4326))', [
        `POLYGON((${bounds.west} ${bounds.south}, ${bounds.east} ${bounds.south}, ${bounds.east} ${bounds.north}, ${bounds.west} ${bounds.north}, ${bounds.west} ${bounds.south}))`,
    ]);
};
exports.buildBoundsQuery = buildBoundsQuery;
const monitorQuery = (queryName, queryFn) => {
    const startTime = Date.now();
    return queryFn()
        .then((result) => {
        const duration = Date.now() - startTime;
        if (duration > 1000) {
            logger_1.logger.warn(`慢查询检测: ${queryName} 耗时 ${duration}ms`);
        }
        return result;
    })
        .catch((error) => {
        const duration = Date.now() - startTime;
        logger_1.logger.error(`查询失败: ${queryName} 耗时 ${duration}ms`, error);
        throw error;
    });
};
exports.monitorQuery = monitorQuery;
exports.default = exports.db;
//# sourceMappingURL=database.js.map