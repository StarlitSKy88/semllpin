export declare class TestDataFactory {
    createUser(overrides?: any): any;
    createUserRegistrationData(overrides?: any): any;
    createAnnotationData(overrides?: any): any;
    createLocationData(overrides?: any): any;
    createSuspiciousLocationData(overrides?: any): {
        latitude: number;
        longitude: number;
        accuracy: number;
        speed?: undefined;
    } | {
        latitude: number;
        longitude: number;
        speed: number;
        accuracy?: undefined;
    };
    createLocationAtDistance(baseLat: number, baseLng: number, distanceMeters: number): {
        latitude: number;
        longitude: number;
        accuracy: number;
        timestamp: number;
    };
    createPaymentData(overrides?: any): any;
    createCommentData(overrides?: any): any;
    createChatMessageData(overrides?: any): any;
    createFileData(overrides?: any): any;
    createMaliciousFileData(type?: 'executable' | 'script' | 'oversized' | 'path_traversal'): {
        filename: string;
        mimetype: string;
        buffer: Buffer<ArrayBuffer>;
    } | {
        filename: string;
        mimetype: string;
        buffer: Buffer<ArrayBuffer>;
    } | {
        filename: string;
        mimetype: string;
        size: number;
        buffer: Buffer<ArrayBuffer>;
    } | {
        filename: string;
        mimetype: string;
        buffer: Buffer<ArrayBuffer>;
    };
    createSQLInjectionPayloads(): string[];
    createXSSPayloads(): string[];
    createNoSQLInjectionPayloads(): ({
        $ne: null;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $gt: string;
        $ne?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $where: string;
        $ne?: undefined;
        $gt?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $regex: string;
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $or: ({
            password: {
                $regex: string;
            };
            username?: undefined;
        } | {
            username: {
                $regex: string;
            };
            password?: undefined;
        })[];
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $nin: never[];
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $exists: boolean;
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $type?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $type: number;
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $mod?: undefined;
        $all?: undefined;
    } | {
        $mod: number[];
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $all?: undefined;
    } | {
        $all: never[];
        $ne?: undefined;
        $gt?: undefined;
        $where?: undefined;
        $regex?: undefined;
        $or?: undefined;
        $nin?: undefined;
        $exists?: undefined;
        $type?: undefined;
        $mod?: undefined;
    })[];
    createCSRFTestData(): {
        maliciousOrigins: string[];
        maliciousReferers: string[];
    };
    createPerformanceTestData(count?: number): {
        annotations: any;
        user: any;
        comment: any;
        location: any;
    }[];
    createLoadTestScenarios(): {
        lightLoad: {
            duration: number;
            concurrentUsers: number;
            requestsPerSecond: number;
        };
        mediumLoad: {
            duration: number;
            concurrentUsers: number;
            requestsPerSecond: number;
        };
        heavyLoad: {
            duration: number;
            concurrentUsers: number;
            requestsPerSecond: number;
        };
        spikeLoad: {
            duration: number;
            concurrentUsers: number;
            requestsPerSecond: number;
        };
        stressTest: {
            duration: number;
            concurrentUsers: number;
            requestsPerSecond: number;
        };
    };
    createBoundaryTestData(): {
        coordinates: {
            valid: {
                latitude: number;
                longitude: number;
            }[];
            invalid: ({
                latitude: number;
                longitude: number;
            } | {
                latitude: string;
                longitude: string;
            } | {
                latitude: null;
                longitude: null;
            })[];
        };
        strings: {
            empty: string;
            short: string;
            medium: string;
            long: string;
            veryLong: string;
            unicode: string;
            special: string;
            null: null;
            undefined: undefined;
        };
        numbers: {
            zero: number;
            negative: number;
            positive: number;
            float: number;
            largeInt: number;
            smallInt: number;
            infinity: number;
            negativeInfinity: number;
            nan: number;
        };
    };
    createTimezoneTestData(): {
        timezone: string;
        timestamp: string;
        offset: number;
    }[];
    createMultiLanguageTestData(): {
        chinese: string;
        english: string;
        japanese: string;
        korean: string;
        arabic: string;
        emoji: string;
        mixed: string;
    };
    createConcurrencyTestData(scenarios?: number): {
        scenarioId: number;
        users: any[];
        annotations: any[];
        requests: {
            endpoint: "/api/v1/annotations" | "/api/v1/annotations/list" | "/api/v1/annotations/nearby" | "/api/v1/users/profile/me" | "/api/v1/users/stats";
            method: "GET" | "DELETE" | "POST" | "PUT";
            delay: number;
        }[];
    }[];
}
//# sourceMappingURL=test-data-factory.d.ts.map