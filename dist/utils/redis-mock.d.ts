export interface RedisClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttl?: number): Promise<void>;
    del(key: string): Promise<number>;
    exists(key: string): Promise<number>;
    ping(): Promise<string>;
    info(section?: string): Promise<string>;
    quit(): Promise<void>;
    incr(key: string): Promise<number>;
    decr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    ttl(key: string): Promise<number>;
    setex(key: string, seconds: number, value: string): Promise<string>;
}
declare class RedisMock implements RedisClient {
    private store;
    private connected;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttl?: number): Promise<void>;
    del(key: string): Promise<number>;
    exists(key: string): Promise<number>;
    ping(): Promise<string>;
    info(section?: string): Promise<string>;
    quit(): Promise<void>;
    isConnected(): boolean;
    getKeyCount(): number;
    cleanup(): void;
    incr(key: string): Promise<number>;
    decr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    ttl(key: string): Promise<number>;
    setex(key: string, seconds: number, value: string): Promise<string>;
}
declare const redisMock: RedisMock;
export default redisMock;
export { RedisMock };
//# sourceMappingURL=redis-mock.d.ts.map