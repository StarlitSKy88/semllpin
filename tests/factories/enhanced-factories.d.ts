declare const BEIJING_HOTSPOTS: {
    name: string;
    lat: number;
    lng: number;
    category: string;
}[];
declare const SMELL_CATEGORIES: {
    industrial: {
        types: string[];
        intensities: number[];
        descriptions: string[];
    };
    sewage: {
        types: string[];
        intensities: number[];
        descriptions: string[];
    };
    garbage: {
        types: string[];
        intensities: number[];
        descriptions: string[];
    };
    food: {
        types: string[];
        intensities: number[];
        descriptions: string[];
    };
};
declare const USER_PATTERNS: {
    NewUser: {
        sessionDuration: {
            min: number;
            max: number;
        };
        actionsPerSession: {
            min: number;
            max: number;
        };
        errorProbability: number;
        helpSeekingProbability: number;
    };
    ActiveUser: {
        sessionDuration: {
            min: number;
            max: number;
        };
        actionsPerSession: {
            min: number;
            max: number;
        };
        errorProbability: number;
        helpSeekingProbability: number;
    };
    PowerUser: {
        sessionDuration: {
            min: number;
            max: number;
        };
        actionsPerSession: {
            min: number;
            max: number;
        };
        errorProbability: number;
        helpSeekingProbability: number;
    };
    MobileUser: {
        sessionDuration: {
            min: number;
            max: number;
        };
        actionsPerSession: {
            min: number;
            max: number;
        };
        errorProbability: number;
        locationChangeProbability: number;
    };
    StressUser: {
        sessionDuration: {
            min: number;
            max: number;
        };
        actionsPerSession: {
            min: number;
            max: number;
        };
        errorProbability: number;
        maliciousProbability: number;
    };
};
export declare class UserFactory {
    static create(overrides?: Partial<any>): {
        id: string;
        username: string;
        email: string;
        password: string;
        nickname: string;
        avatar: string;
        phoneNumber: string;
        location: {
            lat: number;
            lng: number;
        };
        isVerified: boolean;
        level: 1 | 2 | 3 | 5 | 4;
        points: number;
        joinedAt: Date;
        lastActiveAt: Date;
        preferences: {
            notifications: boolean;
            privacyLevel: "public" | "private" | "friends";
            language: "zh-CN" | "en-US";
        };
        stats: {
            annotationsCreated: number;
            likesReceived: number;
            commentsReceived: number;
        };
    };
    static createBatch(count: number, overrides?: Partial<any>): {
        id: string;
        username: string;
        email: string;
        password: string;
        nickname: string;
        avatar: string;
        phoneNumber: string;
        location: {
            lat: number;
            lng: number;
        };
        isVerified: boolean;
        level: 1 | 2 | 3 | 5 | 4;
        points: number;
        joinedAt: Date;
        lastActiveAt: Date;
        preferences: {
            notifications: boolean;
            privacyLevel: "public" | "private" | "friends";
            language: "zh-CN" | "en-US";
        };
        stats: {
            annotationsCreated: number;
            likesReceived: number;
            commentsReceived: number;
        };
    }[];
    static createByType(userType: keyof typeof USER_PATTERNS, overrides?: Partial<any>): {
        id: string;
        username: string;
        email: string;
        password: string;
        nickname: string;
        avatar: string;
        phoneNumber: string;
        location: {
            lat: number;
            lng: number;
        };
        isVerified: boolean;
        level: 1 | 2 | 3 | 5 | 4;
        points: number;
        joinedAt: Date;
        lastActiveAt: Date;
        preferences: {
            notifications: boolean;
            privacyLevel: "public" | "private" | "friends";
            language: "zh-CN" | "en-US";
        };
        stats: {
            annotationsCreated: number;
            likesReceived: number;
            commentsReceived: number;
        };
    };
}
export declare class AnnotationFactory {
    static create(overrides?: Partial<any>): {
        id: string;
        title: string;
        description: string;
        location: {
            lat: number;
            lng: number;
        };
        category: string;
        smellType: string;
        intensity: number;
        tags: string[];
        userId: string;
        media: {
            id: string;
            type: string;
            url: string;
            thumbnailUrl: string;
        }[];
        status: "active" | "flagged" | "verified" | "resolved";
        visibility: "public" | "private" | "friends";
        likesCount: number;
        commentsCount: number;
        reportsCount: number;
        createdAt: Date;
        updatedAt: Date;
        expiresAt: Date;
        geohash: string;
        nearbyHotspot: string;
        distanceFromCenter: number;
    };
    static createBatch(count: number, overrides?: Partial<any>): {
        id: string;
        title: string;
        description: string;
        location: {
            lat: number;
            lng: number;
        };
        category: string;
        smellType: string;
        intensity: number;
        tags: string[];
        userId: string;
        media: {
            id: string;
            type: string;
            url: string;
            thumbnailUrl: string;
        }[];
        status: "active" | "flagged" | "verified" | "resolved";
        visibility: "public" | "private" | "friends";
        likesCount: number;
        commentsCount: number;
        reportsCount: number;
        createdAt: Date;
        updatedAt: Date;
        expiresAt: Date;
        geohash: string;
        nearbyHotspot: string;
        distanceFromCenter: number;
    }[];
    static createForHotspot(hotspotName: string, count?: number): {
        id: string;
        title: string;
        description: string;
        location: {
            lat: number;
            lng: number;
        };
        category: string;
        smellType: string;
        intensity: number;
        tags: string[];
        userId: string;
        media: {
            id: string;
            type: string;
            url: string;
            thumbnailUrl: string;
        }[];
        status: "active" | "flagged" | "verified" | "resolved";
        visibility: "public" | "private" | "friends";
        likesCount: number;
        commentsCount: number;
        reportsCount: number;
        createdAt: Date;
        updatedAt: Date;
        expiresAt: Date;
        geohash: string;
        nearbyHotspot: string;
        distanceFromCenter: number;
    }[];
}
export declare class PaymentFactory {
    static create(overrides?: Partial<any>): {
        id: string;
        userId: string;
        annotationId: string;
        amount: number;
        currency: string;
        method: string;
        status: string;
        transactionId: string;
        platformTransactionId: string;
        description: string;
        metadata: {
            annotationType: "basic" | "premium" | "emergency";
            userLevel: number;
            discount: number;
        };
        createdAt: Date;
        updatedAt: Date;
        completedAt: Date;
    };
    static createBatch(count: number, overrides?: Partial<any>): {
        id: string;
        userId: string;
        annotationId: string;
        amount: number;
        currency: string;
        method: string;
        status: string;
        transactionId: string;
        platformTransactionId: string;
        description: string;
        metadata: {
            annotationType: "basic" | "premium" | "emergency";
            userLevel: number;
            discount: number;
        };
        createdAt: Date;
        updatedAt: Date;
        completedAt: Date;
    }[];
}
export declare class GeoFactory {
    static createGeofence(center?: {
        lat: number;
        lng: number;
    }, radius?: number): {
        id: string;
        name: string;
        center: {
            lat: number;
            lng: number;
        };
        radius: number;
        type: "circle" | "polygon";
        isActive: boolean;
        createdAt: Date;
    };
    static createTrajectory(startPoint?: {
        lat: number;
        lng: number;
    }, pointsCount?: number): {
        id: string;
        userId: string;
        points: {
            lat: number;
            lng: number;
        }[];
        totalDistance: number;
        duration: number;
        createdAt: Date;
    };
    static createSpatialQuery(): {
        type: string;
        center: {
            lat: number;
            lng: number;
        };
        radius: number;
        bbox: {
            north: number;
            south: number;
            east: number;
            west: number;
        };
        expectedResultCount: number;
    };
}
export declare class DataGenerator {
    static seedTestDatabase(): Promise<{
        users: {
            id: string;
            username: string;
            email: string;
            password: string;
            nickname: string;
            avatar: string;
            phoneNumber: string;
            location: {
                lat: number;
                lng: number;
            };
            isVerified: boolean;
            level: 1 | 2 | 3 | 5 | 4;
            points: number;
            joinedAt: Date;
            lastActiveAt: Date;
            preferences: {
                notifications: boolean;
                privacyLevel: "public" | "private" | "friends";
                language: "zh-CN" | "en-US";
            };
            stats: {
                annotationsCreated: number;
                likesReceived: number;
                commentsReceived: number;
            };
        }[];
        annotations: {
            id: string;
            title: string;
            description: string;
            location: {
                lat: number;
                lng: number;
            };
            category: string;
            smellType: string;
            intensity: number;
            tags: string[];
            userId: string;
            media: {
                id: string;
                type: string;
                url: string;
                thumbnailUrl: string;
            }[];
            status: "active" | "flagged" | "verified" | "resolved";
            visibility: "public" | "private" | "friends";
            likesCount: number;
            commentsCount: number;
            reportsCount: number;
            createdAt: Date;
            updatedAt: Date;
            expiresAt: Date;
            geohash: string;
            nearbyHotspot: string;
            distanceFromCenter: number;
        }[];
        payments: {
            id: string;
            userId: string;
            annotationId: string;
            amount: number;
            currency: string;
            method: string;
            status: string;
            transactionId: string;
            platformTransactionId: string;
            description: string;
            metadata: {
                annotationType: "basic" | "premium" | "emergency";
                userLevel: number;
                discount: number;
            };
            createdAt: Date;
            updatedAt: Date;
            completedAt: Date;
        }[];
    }>;
    static createRealisticScenario(): {
        name: string;
        location: {
            name: string;
            lat: number;
            lng: number;
            category: string;
        };
        users: {
            id: string;
            username: string;
            email: string;
            password: string;
            nickname: string;
            avatar: string;
            phoneNumber: string;
            location: {
                lat: number;
                lng: number;
            };
            isVerified: boolean;
            level: 1 | 2 | 3 | 5 | 4;
            points: number;
            joinedAt: Date;
            lastActiveAt: Date;
            preferences: {
                notifications: boolean;
                privacyLevel: "public" | "private" | "friends";
                language: "zh-CN" | "en-US";
            };
            stats: {
                annotationsCreated: number;
                likesReceived: number;
                commentsReceived: number;
            };
        }[];
        annotations: never[];
        timespan: {
            start: Date;
            end: Date;
        };
    };
}
export declare function resetSeed(seed?: number): void;
export { BEIJING_HOTSPOTS, SMELL_CATEGORIES, USER_PATTERNS };
//# sourceMappingURL=enhanced-factories.d.ts.map