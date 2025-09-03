import Redis from 'ioredis';
declare let redis: any;
export { redis };
export declare const CACHE_KEYS: {
    readonly USER: "user:";
    readonly ANNOTATION: "annotation:";
    readonly COMMENT: "comment:";
    readonly STATS: "stats:";
    readonly SEARCH: "search:";
    readonly LOCATION: "location:";
    readonly POPULAR: "popular:";
    readonly TRENDING: "trending:";
    readonly SESSION: "session:";
    readonly RATE_LIMIT: "rate_limit:";
    readonly API_CACHE: "api:";
};
export declare const CACHE_TTL: {
    readonly SHORT: 60;
    readonly MEDIUM: 300;
    readonly LONG: 1800;
    readonly VERY_LONG: 3600;
    readonly DAILY: 86400;
    readonly WEEKLY: 604800;
};
export declare class CacheManager {
    private redis;
    constructor(redisInstance: Redis);
    set(key: string, value: any, ttl?: number): Promise<boolean>;
    get<T>(key: string): Promise<T | null>;
    del(key: string): Promise<boolean>;
    delPattern(pattern: string): Promise<number>;
    exists(key: string): Promise<boolean>;
    expire(key: string, ttl: number): Promise<boolean>;
    ttl(key: string): Promise<number>;
    incr(key: string, ttl?: number): Promise<number>;
    decr(key: string): Promise<number>;
    lpush(key: string, ...values: any[]): Promise<number>;
    lrange<T>(key: string, start: number, stop: number): Promise<T[]>;
    sadd(key: string, ...members: string[]): Promise<number>;
    smembers(key: string): Promise<string[]>;
    zadd(key: string, score: number, member: string): Promise<number>;
    zrevrange(key: string, start: number, stop: number, withScores?: boolean): Promise<string[]>;
    hset(key: string, field: string, value: any): Promise<number>;
    hget<T>(key: string, field: string): Promise<T | null>;
    hgetall<T>(key: string): Promise<Record<string, T>>;
    getStats(): Promise<any>;
}
export declare const cache: CacheManager;
export declare function Cacheable(key: string, ttl?: number): (_target: any, _propertyName: string, descriptor: PropertyDescriptor) => void;
export declare function CacheEvict(pattern: string): (_target: any, _propertyName: string, descriptor: PropertyDescriptor) => void;
export declare const warmupCache: () => Promise<void>;
export declare const cleanupExpiredCache: () => Promise<void>;
export default cache;
//# sourceMappingURL=cache.d.ts.map