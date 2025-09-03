"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.monitorQuery = exports.buildBoundsQuery = exports.buildLocationQuery = exports.buildSortQuery = exports.buildSearchQuery = exports.buildPaginationQuery = exports.withTransaction = exports.checkDatabaseHealth = exports.disconnectDatabase = exports.connectDatabase = exports.db = void 0;
const knex_1 = __importDefault(require("knex"));
const config_1 = require("./config");
const logger_1 = require("../utils/logger");
const dbConfig = (process.env['NODE_ENV'] === 'development' || process.env['NODE_ENV'] === 'test') && process.env['DB_TYPE'] !== 'postgresql' ? {
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
    connection: {
        connectionString: config_1.config.DATABASE_URL,
        host: config_1.config.database.host,
        port: config_1.config.database.port,
        user: config_1.config.database.username,
        password: config_1.config.database.password,
        database: config_1.config.database.database,
        ssl: config_1.config.database.ssl ? { rejectUnauthorized: false } : false,
    },
    pool: {
        min: 2,
        max: 10,
        createTimeoutMillis: 3000,
        acquireTimeoutMillis: 30000,
        idleTimeoutMillis: 30000,
        reapIntervalMillis: 1000,
        createRetryIntervalMillis: 100,
        propagateCreateError: false,
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
    try {
        await exports.db.raw('SELECT 1+1 as result');
        logger_1.logger.info('数据库连接成功');
        if (config_1.config.NODE_ENV === 'production') {
            await exports.db.migrate.latest();
            logger_1.logger.info('数据库迁移完成');
        }
    }
    catch (error) {
        logger_1.logger.error('数据库连接失败:', error);
        throw error;
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
    try {
        await exports.db.raw('SELECT 1');
        return true;
    }
    catch (error) {
        logger_1.logger.error('数据库健康检查失败:', error);
        return false;
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
    return query.whereRaw('ST_DWithin(location, ST_GeogFromText(?), ?)', [`POINT(${longitude} ${latitude})`, radiusInMeters]);
};
exports.buildLocationQuery = buildLocationQuery;
const buildBoundsQuery = (query, bounds) => {
    return query.whereRaw('ST_Within(location, ST_GeogFromText(?))', [
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