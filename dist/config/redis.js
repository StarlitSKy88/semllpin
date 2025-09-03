"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rateLimiter = exports.RateLimiter = exports.cacheService = exports.CacheService = exports.checkRedisHealth = exports.getRedisClient = exports.disconnectRedis = exports.connectRedis = exports.createRedisClient = void 0;
const ioredis_1 = __importDefault(require("ioredis"));
const config_1 = require("./config");
const logger_1 = require("@/utils/logger");
const redis_mock_1 = __importDefault(require("@/utils/redis-mock"));
let redisClient = null;
const redisConfig = {
    host: config_1.config.redis.host,
    port: config_1.config.redis.port,
    ...(config_1.config.redis.password && { password: config_1.config.redis.password }),
    db: config_1.config.redis.db,
    retryDelayOnFailover: 100,
    enableReadyCheck: true,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
    keepAlive: 30000,
    connectTimeout: 10000,
    commandTimeout: 5000,
    retryDelayOnClusterDown: 300,
};
const createRedisClient = () => {
    if (redisClient) {
        return redisClient;
    }
    if (process.env['REDIS_MOCK'] === 'true') {
        logger_1.logger.info('使用Redis模拟器 (开发模式)');
        redisClient = redis_mock_1.default;
        return redisClient;
    }
    redisClient = new ioredis_1.default(redisConfig);
    redisClient.on('connect', () => {
        logger_1.logger.info('Redis连接已建立');
    });
    redisClient.on('ready', () => {
        logger_1.logger.info('Redis连接就绪');
    });
    redisClient.on('error', (error) => {
        logger_1.logger.error('Redis连接错误:', error);
    });
    redisClient.on('close', () => {
        logger_1.logger.warn('Redis连接已关闭');
    });
    redisClient.on('reconnecting', () => {
        logger_1.logger.info('Redis正在重新连接...');
    });
    redisClient.on('end', () => {
        logger_1.logger.warn('Redis连接已结束');
    });
    return redisClient;
};
exports.createRedisClient = createRedisClient;
const connectRedis = async () => {
    try {
        const client = (0, exports.createRedisClient)();
        if (process.env['REDIS_MOCK'] !== 'true') {
            await client.connect();
        }
        await client.ping();
        logger_1.logger.info('Redis连接测试成功');
    }
    catch (error) {
        logger_1.logger.error('Redis连接失败:', error);
        throw error;
    }
};
exports.connectRedis = connectRedis;
const disconnectRedis = async () => {
    try {
        if (redisClient) {
            await redisClient.quit();
            logger_1.logger.info('Redis连接已关闭');
        }
    }
    catch (error) {
        logger_1.logger.error('关闭Redis连接时发生错误:', error);
        throw error;
    }
};
exports.disconnectRedis = disconnectRedis;
const getRedisClient = () => {
    if (!redisClient) {
        redisClient = (0, exports.createRedisClient)();
    }
    return redisClient;
};
exports.getRedisClient = getRedisClient;
const checkRedisHealth = async () => {
    try {
        const client = (0, exports.getRedisClient)();
        const result = await client.ping();
        return result === 'PONG';
    }
    catch (error) {
        logger_1.logger.error('Redis健康检查失败:', error);
        return false;
    }
};
exports.checkRedisHealth = checkRedisHealth;
class CacheService {
    constructor(ttl = config_1.config.cache.ttl) {
        this.client = (0, exports.getRedisClient)();
        this.defaultTTL = ttl;
    }
    async set(key, value, ttl = this.defaultTTL) {
        try {
            const serializedValue = typeof value === 'string' ? value : JSON.stringify(value);
            await this.client.setex(key, ttl, serializedValue);
        }
        catch (error) {
            logger_1.logger.error(`缓存设置失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async get(key) {
        try {
            const value = await this.client.get(key);
            if (!value) {
                return null;
            }
            try {
                return JSON.parse(value);
            }
            catch {
                return value;
            }
        }
        catch (error) {
            logger_1.logger.error(`缓存获取失败 - Key: ${key}`, error);
            return null;
        }
    }
    async del(key) {
        try {
            await this.client.del(key);
        }
        catch (error) {
            logger_1.logger.error(`缓存删除失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async exists(key) {
        try {
            const result = await this.client.exists(key);
            return result === 1;
        }
        catch (error) {
            logger_1.logger.error(`缓存检查失败 - Key: ${key}`, error);
            return false;
        }
    }
    async expire(key, ttl) {
        try {
            await this.client.expire(key, ttl);
        }
        catch (error) {
            logger_1.logger.error(`设置缓存过期时间失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async mget(keys) {
        try {
            const values = await this.client.mget(...keys);
            return values.map(value => {
                if (!value) {
                    return null;
                }
                try {
                    return JSON.parse(value);
                }
                catch {
                    return value;
                }
            });
        }
        catch (error) {
            logger_1.logger.error('批量获取缓存失败', error);
            return keys.map(() => null);
        }
    }
    async mset(keyValuePairs) {
        try {
            const pipeline = this.client.pipeline();
            Object.entries(keyValuePairs).forEach(([key, value]) => {
                const serializedValue = typeof value === 'string' ? value : JSON.stringify(value);
                pipeline.set(key, serializedValue);
            });
            await pipeline.exec();
        }
        catch (error) {
            logger_1.logger.error('批量设置缓存失败', error);
            throw error;
        }
    }
    async incr(key) {
        try {
            return await this.client.incr(key);
        }
        catch (error) {
            logger_1.logger.error(`计数器递增失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async decr(key) {
        try {
            return await this.client.decr(key);
        }
        catch (error) {
            logger_1.logger.error(`计数器递减失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async sadd(key, ...members) {
        try {
            return await this.client.sadd(key, ...members);
        }
        catch (error) {
            logger_1.logger.error(`添加到集合失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async smembers(key) {
        try {
            return await this.client.smembers(key);
        }
        catch (error) {
            logger_1.logger.error(`获取集合成员失败 - Key: ${key}`, error);
            return [];
        }
    }
    async srem(key, ...members) {
        try {
            return await this.client.srem(key, ...members);
        }
        catch (error) {
            logger_1.logger.error(`从集合移除失败 - Key: ${key}`, error);
            throw error;
        }
    }
    async sismember(key, member) {
        try {
            const result = await this.client.sismember(key, member);
            return result === 1;
        }
        catch (error) {
            logger_1.logger.error(`检查集合成员失败 - Key: ${key}`, error);
            return false;
        }
    }
    async flushall() {
        try {
            await this.client.flushall();
            logger_1.logger.warn('所有缓存已清空');
        }
        catch (error) {
            logger_1.logger.error('清空缓存失败', error);
            throw error;
        }
    }
    async getStats() {
        try {
            const info = await this.client.info('memory');
            const stats = {};
            info.split('\r\n').forEach(line => {
                const [key, value] = line.split(':');
                if (key && value) {
                    stats[key] = value;
                }
            });
            return stats;
        }
        catch (error) {
            logger_1.logger.error('获取缓存统计失败', error);
            return {};
        }
    }
}
exports.CacheService = CacheService;
exports.cacheService = new CacheService();
class RateLimiter {
    constructor() {
        this.client = (0, exports.getRedisClient)();
    }
    async checkLimit(key, limit, windowMs) {
        try {
            const now = Date.now();
            const window = Math.floor(now / windowMs);
            const redisKey = `rate_limit:${key}:${window}`;
            const current = await this.client.incr(redisKey);
            if (current === 1) {
                await this.client.expire(redisKey, Math.ceil(windowMs / 1000));
            }
            const remaining = Math.max(0, limit - current);
            const resetTime = (window + 1) * windowMs;
            return {
                allowed: current <= limit,
                remaining,
                resetTime,
            };
        }
        catch (error) {
            logger_1.logger.error(`限流检查失败 - Key: ${key}`, error);
            return {
                allowed: true,
                remaining: limit,
                resetTime: Date.now() + windowMs,
            };
        }
    }
}
exports.RateLimiter = RateLimiter;
exports.rateLimiter = new RateLimiter();
exports.default = redisClient;
//# sourceMappingURL=redis.js.map