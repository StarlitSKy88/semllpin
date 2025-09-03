import { StartedTestContainer } from 'testcontainers';
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
declare class TestContainersManager {
    private static instance;
    private environment;
    private isSetup;
    static getInstance(): TestContainersManager;
    setupTestEnvironment(): Promise<TestEnvironment>;
    private initializePostGIS;
    private runMigrations;
    teardownTestEnvironment(): Promise<void>;
    getEnvironment(): TestEnvironment | null;
    createIsolatedSchema(testName: string): Promise<string>;
    dropIsolatedSchema(schemaName: string): Promise<void>;
    getIsolatedRedis(dbIndex?: number): Promise<Redis>;
}
export declare function setupTestContainers(): Promise<TestEnvironment>;
export declare function teardownTestContainers(): Promise<void>;
export declare function getTestEnvironment(): TestEnvironment | null;
export default function globalSetup(): Promise<void>;
export declare function globalTeardown(): Promise<void>;
export { TestContainersManager };
//# sourceMappingURL=testcontainers-setup.d.ts.map