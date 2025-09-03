import Redis from 'ioredis';
declare let redisClient: Redis | null;
export declare const createRedisClient: () => Redis;
export declare const connectRedis: () => Promise<void>;
export declare const disconnectRedis: () => Promise<void>;
export declare const getRedisClient: () => Redis;
export declare const checkRedisHealth: () => Promise<boolean>;
export declare class CacheService {
    private client;
    private defaultTTL;
    constructor(ttl?: number);
    set(key: string, value: string | number | object, ttl?: number): Promise<void>;
    get<T = string>(key: string): Promise<T | null>;
    del(key: string): Promise<void>;
    exists(key: string): Promise<boolean>;
    expire(key: string, ttl: number): Promise<void>;
    mget<T = string>(keys: string[]): Promise<(T | null)[]>;
    mset(keyValuePairs: Record<string, string | number | object>): Promise<void>;
    incr(key: string): Promise<number>;
    decr(key: string): Promise<number>;
    sadd(key: string, ...members: string[]): Promise<number>;
    smembers(key: string): Promise<string[]>;
    srem(key: string, ...members: string[]): Promise<number>;
    sismember(key: string, member: string): Promise<boolean>;
    flushall(): Promise<void>;
    getStats(): Promise<Record<string, string>>;
}
export declare const cacheService: CacheService;
export declare class RateLimiter {
    private client;
    constructor();
    checkLimit(key: string, limit: number, windowMs: number): Promise<{
        allowed: boolean;
        remaining: number;
        resetTime: number;
    }>;
}
export declare const rateLimiter: RateLimiter;
export default redisClient;
//# sourceMappingURL=redis.d.ts.map