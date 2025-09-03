"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.cleanupExpiredCache = exports.warmupCache = exports.cache = exports.CacheManager = exports.CACHE_TTL = exports.CACHE_KEYS = exports.redis = void 0;
exports.Cacheable = Cacheable;
exports.CacheEvict = CacheEvict;
const ioredis_1 = __importDefault(require("ioredis"));
const config_1 = require("./config");
const logger_1 = require("@/utils/logger");
const redisConfig = {
    host: config_1.config.redis?.host || 'localhost',
    port: config_1.config.redis?.port || 6379,
    db: config_1.config.redis?.db || 0,
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
    keepAlive: 30000,
    connectTimeout: 10000,
    commandTimeout: 5000,
};
if (config_1.config.redis?.password) {
    redisConfig.password = config_1.config.redis.password;
}
let redis;
if (process.env['NODE_ENV'] === 'test' || process.env['DISABLE_REDIS'] === 'true') {
    exports.redis = redis = {
        status: 'ready',
        get: async () => null,
        set: async () => 'OK',
        setex: async () => 'OK',
        del: async () => 1,
        keys: async () => [],
        exists: async () => 0,
        expire: async () => 1,
        ttl: async () => -1,
        incr: async () => 1,
        decr: async () => 0,
        lpush: async () => 1,
        lrange: async () => [],
        sadd: async () => 1,
        smembers: async () => [],
        zadd: async () => 1,
        zrevrange: async () => [],
        hset: async () => 1,
        hget: async () => null,
        hgetall: async () => ({}),
        info: async () => '',
        on: () => { },
        disconnect: async () => { },
    };
}
else {
    exports.redis = redis = new ioredis_1.default(redisConfig);
}
if (process.env['NODE_ENV'] !== 'test' && process.env['DISABLE_REDIS'] !== 'true') {
    redis.on('connect', () => {
        logger_1.logger.info('Redis connecting...');
    });
    redis.on('ready', () => {
        logger_1.logger.info('Redis connected successfully');
    });
    redis.on('error', (err) => {
        logger_1.logger.error('Redis connection error', { error: err.message });
    });
    redis.on('close', () => {
        logger_1.logger.info('Redis connection closed');
    });
    redis.on('reconnecting', () => {
        logger_1.logger.info('Redis reconnecting...');
    });
}
exports.CACHE_KEYS = {
    USER: 'user:',
    ANNOTATION: 'annotation:',
    COMMENT: 'comment:',
    STATS: 'stats:',
    SEARCH: 'search:',
    LOCATION: 'location:',
    POPULAR: 'popular:',
    TRENDING: 'trending:',
    SESSION: 'session:',
    RATE_LIMIT: 'rate_limit:',
    API_CACHE: 'api:',
};
exports.CACHE_TTL = {
    SHORT: 60,
    MEDIUM: 300,
    LONG: 1800,
    VERY_LONG: 3600,
    DAILY: 86400,
    WEEKLY: 604800,
};
class CacheManager {
    constructor(redisInstance) {
        this.redis = redisInstance;
    }
    async set(key, value, ttl = exports.CACHE_TTL.MEDIUM) {
        try {
            const serializedValue = JSON.stringify(value);
            await this.redis.setex(key, ttl, serializedValue);
            logger_1.logger.debug('Cache set', { key, ttl });
            return true;
        }
        catch (error) {
            logger_1.logger.error('Cache set error', { key, error: error.message });
            return false;
        }
    }
    async get(key) {
        try {
            const value = await this.redis.get(key);
            if (value === null) {
                return null;
            }
            const parsed = JSON.parse(value);
            logger_1.logger.debug('Cache hit', { key });
            return parsed;
        }
        catch (error) {
            logger_1.logger.error('Cache get error', { key, error: error.message });
            return null;
        }
    }
    async del(key) {
        try {
            await this.redis.del(key);
            logger_1.logger.debug('Cache deleted', { key });
            return true;
        }
        catch (error) {
            logger_1.logger.error('Cache delete error', { key, error: error.message });
            return false;
        }
    }
    async delPattern(pattern) {
        try {
            const keys = await this.redis.keys(pattern);
            if (keys.length === 0) {
                return 0;
            }
            await this.redis.del(...keys);
            logger_1.logger.debug('Cache pattern deleted', { pattern, count: keys.length });
            return keys.length;
        }
        catch (error) {
            logger_1.logger.error('Cache pattern delete error', { pattern, error: error.message });
            return 0;
        }
    }
    async exists(key) {
        try {
            const result = await this.redis.exists(key);
            return result === 1;
        }
        catch (error) {
            logger_1.logger.error('Cache exists check error', { key, error: error.message });
            return false;
        }
    }
    async expire(key, ttl) {
        try {
            await this.redis.expire(key, ttl);
            return true;
        }
        catch (error) {
            logger_1.logger.error('Cache expire error', { key, ttl, error: error.message });
            return false;
        }
    }
    async ttl(key) {
        try {
            return await this.redis.ttl(key);
        }
        catch (error) {
            logger_1.logger.error('Cache TTL check error', { key, error: error.message });
            return -1;
        }
    }
    async incr(key, ttl) {
        try {
            const result = await this.redis.incr(key);
            if (ttl && result === 1) {
                await this.redis.expire(key, ttl);
            }
            return result;
        }
        catch (error) {
            logger_1.logger.error('Cache incr error', { key, error: error.message });
            return 0;
        }
    }
    async decr(key) {
        try {
            return await this.redis.decr(key);
        }
        catch (error) {
            logger_1.logger.error('Cache decr error', { key, error: error.message });
            return 0;
        }
    }
    async lpush(key, ...values) {
        try {
            const serializedValues = values.map(v => JSON.stringify(v));
            return await this.redis.lpush(key, ...serializedValues);
        }
        catch (error) {
            logger_1.logger.error('Cache lpush error', { key, error: error.message });
            return 0;
        }
    }
    async lrange(key, start, stop) {
        try {
            const values = await this.redis.lrange(key, start, stop);
            return values.map(v => JSON.parse(v));
        }
        catch (error) {
            logger_1.logger.error('Cache lrange error', { key, error: error.message });
            return [];
        }
    }
    async sadd(key, ...members) {
        try {
            return await this.redis.sadd(key, ...members);
        }
        catch (error) {
            logger_1.logger.error('Cache sadd error', { key, error: error.message });
            return 0;
        }
    }
    async smembers(key) {
        try {
            return await this.redis.smembers(key);
        }
        catch (error) {
            logger_1.logger.error('Cache smembers error', { key, error: error.message });
            return [];
        }
    }
    async zadd(key, score, member) {
        try {
            return await this.redis.zadd(key, score, member);
        }
        catch (error) {
            logger_1.logger.error('Cache zadd error', { key, error: error.message });
            return 0;
        }
    }
    async zrevrange(key, start, stop, withScores = false) {
        try {
            if (withScores) {
                return await this.redis.zrevrange(key, start, stop, 'WITHSCORES');
            }
            return await this.redis.zrevrange(key, start, stop);
        }
        catch (error) {
            logger_1.logger.error('Cache zrevrange error', { key, error: error.message });
            return [];
        }
    }
    async hset(key, field, value) {
        try {
            const serializedValue = JSON.stringify(value);
            return await this.redis.hset(key, field, serializedValue);
        }
        catch (error) {
            logger_1.logger.error('Cache hset error', { key, field, error: error.message });
            return 0;
        }
    }
    async hget(key, field) {
        try {
            const value = await this.redis.hget(key, field);
            if (value === null) {
                return null;
            }
            return JSON.parse(value);
        }
        catch (error) {
            logger_1.logger.error('Cache hget error', { key, field, error: error.message });
            return null;
        }
    }
    async hgetall(key) {
        try {
            const hash = await this.redis.hgetall(key);
            const result = {};
            for (const [field, value] of Object.entries(hash)) {
                result[field] = JSON.parse(value);
            }
            return result;
        }
        catch (error) {
            logger_1.logger.error('Cache hgetall error', { key, error: error.message });
            return {};
        }
    }
    async getStats() {
        try {
            const info = await this.redis.info('memory');
            const keyspace = await this.redis.info('keyspace');
            return {
                memory: info,
                keyspace,
                connected: this.redis.status === 'ready',
            };
        }
        catch (error) {
            logger_1.logger.error('Cache stats error', { error: error.message });
            return null;
        }
    }
}
exports.CacheManager = CacheManager;
exports.cache = new CacheManager(redis);
function Cacheable(key, ttl = exports.CACHE_TTL.MEDIUM) {
    return function (_target, _propertyName, descriptor) {
        const method = descriptor.value;
        descriptor.value = async function (...args) {
            const cacheKey = `${key}:${JSON.stringify(args)}`;
            const cached = await exports.cache.get(cacheKey);
            if (cached !== null) {
                return cached;
            }
            const result = await method.apply(this, args);
            await exports.cache.set(cacheKey, result, ttl);
            return result;
        };
    };
}
function CacheEvict(pattern) {
    return function (_target, _propertyName, descriptor) {
        const method = descriptor.value;
        descriptor.value = async function (...args) {
            const result = await method.apply(this, args);
            await exports.cache.delPattern(pattern);
            return result;
        };
    };
}
const warmupCache = async () => {
    try {
        logger_1.logger.info('Starting cache warmup...');
        logger_1.logger.info('Cache warmup completed');
    }
    catch (error) {
        logger_1.logger.error('Cache warmup failed', { error: error.message });
    }
};
exports.warmupCache = warmupCache;
const cleanupExpiredCache = async () => {
    try {
        const stats = await exports.cache.getStats();
        logger_1.logger.info('Cache cleanup check completed', { stats });
    }
    catch (error) {
        logger_1.logger.error('Cache cleanup failed', { error: error.message });
    }
};
exports.cleanupExpiredCache = cleanupExpiredCache;
if (process.env['NODE_ENV'] !== 'test' && process.env['DISABLE_CACHE'] !== 'true') {
    setInterval(exports.cleanupExpiredCache, 60000);
}
exports.default = exports.cache;
//# sourceMappingURL=cache.js.map