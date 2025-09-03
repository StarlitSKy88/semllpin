import { TestContainersManager } from './testcontainers-setup';
import 'jest-extended';
declare global {
    var testManager: TestContainersManager;
    var testSchema: string;
    var testDbIndex: number;
}
export declare const testUtils: {
    waitFor: (ms: number) => Promise<unknown>;
    generateBeijingCoordinate: () => {
        lat: number;
        lng: number;
    };
    generateGlobalCoordinate: () => {
        lat: number;
        lng: number;
    };
    createTestDbConnection(): Promise<any>;
    createTestRedisConnection(): Promise<import("ioredis").default>;
};
declare global {
    namespace jest {
        interface Matchers<R> {
            toBeWithinDistance(expected: {
                lat: number;
                lng: number;
            }, maxDistance: number): R;
            toRespondWithin(maxTime: number): R;
            toBeValidGeometry(): R;
        }
    }
}
//# sourceMappingURL=jest-setup.d.ts.map