import { Knex } from 'knex';
export declare function getTestDb(): Knex;
export declare function createIsolatedDbConnection(testSuiteName: string): Promise<Knex>;
export declare function cleanupIsolatedDbConnection(testSuiteName: string): Promise<void>;
export declare function setupTestDatabase(): Promise<void>;
export declare function cleanupTestDatabase(): Promise<void>;
export declare function teardownTestDatabase(): Promise<void>;
export declare function checkTestDatabaseHealth(): Promise<boolean>;
//# sourceMappingURL=databaseSetup.d.ts.map