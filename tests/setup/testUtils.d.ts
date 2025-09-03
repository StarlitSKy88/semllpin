export declare class TestDataFactory {
    static createUser(overrides?: Partial<any>): {
        id: string;
        email: string;
        username: string;
        password: string;
        firstName: string;
        lastName: string;
        avatar: string;
        isVerified: boolean;
        createdAt: Date;
        updatedAt: Date;
    };
    static createAnnotation(overrides?: Partial<any>): {
        id: string;
        userId: string;
        latitude: number;
        longitude: number;
        smellType: "industrial" | "chemical" | "sewage" | "garbage" | "cooking";
        intensity: number;
        description: string;
        amount: number;
        status: string;
        tags: ("industrial" | "chemical" | "environment" | "pollution")[];
        photos: never[];
        createdAt: Date;
        updatedAt: Date;
    };
    static createLocationReport(overrides?: Partial<any>): {
        latitude: number;
        longitude: number;
        accuracy: number;
        stayDuration: number;
        timestamp: Date;
        deviceInfo: {
            platform: "Android" | "iOS";
            version: string;
            deviceId: string;
            userAgent: string;
        };
    };
    static createPayment(overrides?: Partial<any>): {
        id: string;
        userId: string;
        annotationId: string;
        amount: number;
        currency: string;
        paymentMethod: string;
        status: "failed" | "pending" | "completed" | "refunded";
        stripeSessionId: string;
        stripePaymentIntentId: string;
        metadata: {
            annotationType: string;
            location: string;
        };
        createdAt: Date;
        updatedAt: Date;
    };
    static createLBSReward(overrides?: Partial<any>): {
        id: string;
        userId: string;
        annotationId: string;
        rewardType: "first_finder" | "combo" | "regular";
        amount: number;
        status: "pending" | "verified" | "claimed" | "expired";
        locationData: {
            latitude: number;
            longitude: number;
            accuracy: number;
            stayDuration: number;
            timestamp: Date;
            deviceInfo: {
                platform: "Android" | "iOS";
                version: string;
                deviceId: string;
                userAgent: string;
            };
        };
        fraudScore: number;
        claimedAt: Date;
        verifiedAt: Date;
    };
    static createBatch<T>(factory: () => T, count: number): T[];
}
export declare class DatabaseTestUtils {
    static cleanup(): Promise<void>;
    static createTestUser(userData?: Partial<any>): Promise<any>;
    static createTestAnnotation(annotationData?: Partial<any>): Promise<any>;
    static seedTestData(): Promise<{
        users: any[];
        annotations: any[];
        payments: {
            id: string;
            userId: string;
            annotationId: string;
            amount: number;
            currency: string;
            paymentMethod: string;
            status: "failed" | "pending" | "completed" | "refunded";
            stripeSessionId: string;
            stripePaymentIntentId: string;
            metadata: {
                annotationType: string;
                location: string;
            };
            createdAt: Date;
            updatedAt: Date;
        }[];
    }>;
}
export declare class APITestUtils {
    static createAuthHeaders(token: string): {
        Authorization: string;
        'Content-Type': string;
    };
    static generateTestToken(payload?: any): any;
    static waitFor(condition: () => boolean | Promise<boolean>, timeout?: number): Promise<boolean>;
    static mockStripeAPI(): {
        checkout: {
            sessions: {
                create: jest.Mock<any, any, any>;
                retrieve: jest.Mock<any, any, any>;
            };
        };
        paymentIntents: {
            retrieve: jest.Mock<any, any, any>;
        };
    };
}
export declare class PerformanceTestUtils {
    static measureTime<T>(operation: () => Promise<T>): Promise<{
        result: T;
        time: number;
    }>;
    static measureConcurrency<T>(operation: () => Promise<T>, concurrency?: number): Promise<{
        results: T[];
        totalTime: number;
        averageTime: number;
        maxTime: number;
        minTime: number;
    }>;
    static measureMemory(): {
        rss: number;
        heapTotal: number;
        heapUsed: number;
        external: number;
    };
}
export declare class SecurityTestUtils {
    static getMaliciousPayloads(): {
        sqlInjection: string[];
        xss: string[];
        pathTraversal: string[];
        commandInjection: string[];
    };
    static testInputValidation(endpoint: string, payload: any): Promise<string[]>;
    static generateSpoofedLocations(): ({
        from: {
            lat: number;
            lon: number;
        };
        to: {
            lat: number;
            lon: number;
        };
        timeGap: number;
        coordinates?: undefined;
    } | {
        coordinates: {
            lat: number;
            lon: number;
            timestamp: Date;
        }[];
        from?: undefined;
        to?: undefined;
        timeGap?: undefined;
    })[];
}
export declare class TestEnvironmentUtils {
    static setup(): Promise<void>;
    static cleanup(): Promise<void>;
    static initializeTestDatabase(): Promise<void>;
    static resetTestDatabase(): Promise<void>;
}
export { TestDataFactory, DatabaseTestUtils, APITestUtils, PerformanceTestUtils, SecurityTestUtils, TestEnvironmentUtils, };
export declare const setupGlobalTests: () => Promise<void>;
export declare const teardownGlobalTests: () => Promise<void>;
//# sourceMappingURL=testUtils.d.ts.map