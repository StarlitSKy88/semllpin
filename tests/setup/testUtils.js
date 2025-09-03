"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.teardownGlobalTests = exports.setupGlobalTests = exports.TestEnvironmentUtils = exports.SecurityTestUtils = exports.PerformanceTestUtils = exports.APITestUtils = exports.DatabaseTestUtils = exports.TestDataFactory = void 0;
const faker_1 = require("@faker-js/faker");
const uuid_1 = require("uuid");
const database_1 = require("../../src/config/database");
class TestDataFactory {
    static createUser(overrides = {}) {
        return {
            id: (0, uuid_1.v4)(),
            email: faker_1.faker.internet.email(),
            username: faker_1.faker.internet.userName(),
            password: 'TestPassword123!',
            firstName: faker_1.faker.person.firstName(),
            lastName: faker_1.faker.person.lastName(),
            avatar: faker_1.faker.image.avatar(),
            isVerified: true,
            createdAt: new Date(),
            updatedAt: new Date(),
            ...overrides,
        };
    }
    static createAnnotation(overrides = {}) {
        return {
            id: (0, uuid_1.v4)(),
            userId: (0, uuid_1.v4)(),
            latitude: faker_1.faker.location.latitude(),
            longitude: faker_1.faker.location.longitude(),
            smellType: faker_1.faker.helpers.arrayElement(['chemical', 'sewage', 'garbage', 'industrial', 'cooking']),
            intensity: faker_1.faker.number.int({ min: 1, max: 10 }),
            description: faker_1.faker.lorem.sentence(),
            amount: faker_1.faker.number.float({ min: 10, max: 100, fractionDigits: 2 }),
            status: 'active',
            tags: faker_1.faker.helpers.arrayElements(['pollution', 'industrial', 'chemical', 'environment']),
            photos: [],
            createdAt: new Date(),
            updatedAt: new Date(),
            ...overrides,
        };
    }
    static createLocationReport(overrides = {}) {
        return {
            latitude: faker_1.faker.location.latitude(),
            longitude: faker_1.faker.location.longitude(),
            accuracy: faker_1.faker.number.float({ min: 5, max: 50 }),
            stayDuration: faker_1.faker.number.int({ min: 30, max: 300 }),
            timestamp: new Date(),
            deviceInfo: {
                platform: faker_1.faker.helpers.arrayElement(['iOS', 'Android']),
                version: faker_1.faker.system.semver(),
                deviceId: (0, uuid_1.v4)(),
                userAgent: faker_1.faker.internet.userAgent(),
            },
            ...overrides,
        };
    }
    static createPayment(overrides = {}) {
        return {
            id: (0, uuid_1.v4)(),
            userId: (0, uuid_1.v4)(),
            annotationId: (0, uuid_1.v4)(),
            amount: faker_1.faker.number.float({ min: 10, max: 100, fractionDigits: 2 }),
            currency: 'USD',
            paymentMethod: 'stripe',
            status: faker_1.faker.helpers.arrayElement(['pending', 'completed', 'failed', 'refunded']),
            stripeSessionId: `cs_${faker_1.faker.string.alphanumeric(10)}`,
            stripePaymentIntentId: `pi_${faker_1.faker.string.alphanumeric(10)}`,
            metadata: {
                annotationType: 'smell_report',
                location: faker_1.faker.location.city(),
            },
            createdAt: new Date(),
            updatedAt: new Date(),
            ...overrides,
        };
    }
    static createLBSReward(overrides = {}) {
        return {
            id: (0, uuid_1.v4)(),
            userId: (0, uuid_1.v4)(),
            annotationId: (0, uuid_1.v4)(),
            rewardType: faker_1.faker.helpers.arrayElement(['first_finder', 'combo', 'regular']),
            amount: faker_1.faker.number.float({ min: 1, max: 50, fractionDigits: 2 }),
            status: faker_1.faker.helpers.arrayElement(['pending', 'verified', 'claimed', 'expired']),
            locationData: this.createLocationReport(),
            fraudScore: faker_1.faker.number.float({ min: 0, max: 1, fractionDigits: 3 }),
            claimedAt: new Date(),
            verifiedAt: new Date(),
            ...overrides,
        };
    }
    static createBatch(factory, count) {
        return Array.from({ length: count }, factory);
    }
}
exports.TestDataFactory = TestDataFactory;
class DatabaseTestUtils {
    static async cleanup() {
        const tables = [
            'lbs_rewards',
            'payments',
            'annotations',
            'location_reports',
            'anti_fraud_logs',
            'user_sessions',
            'users',
        ];
        for (const table of tables.reverse()) {
            await (0, database_1.db)(table).whereRaw('email LIKE ?', ['%test%']).del();
        }
    }
    static async createTestUser(userData) {
        const user = TestDataFactory.createUser(userData);
        const [createdUser] = await (0, database_1.db)('users').insert(user).returning('*');
        return createdUser;
    }
    static async createTestAnnotation(annotationData) {
        const annotation = TestDataFactory.createAnnotation(annotationData);
        const [createdAnnotation] = await (0, database_1.db)('annotations').insert(annotation).returning('*');
        return createdAnnotation;
    }
    static async seedTestData() {
        const users = TestDataFactory.createBatch(() => TestDataFactory.createUser(), 5);
        const createdUsers = await (0, database_1.db)('users').insert(users).returning('*');
        const annotations = TestDataFactory.createBatch(() => TestDataFactory.createAnnotation({
            userId: faker_1.faker.helpers.arrayElement(createdUsers).id,
        }), 10);
        const createdAnnotations = await (0, database_1.db)('annotations').insert(annotations).returning('*');
        const payments = TestDataFactory.createBatch(() => TestDataFactory.createPayment({
            userId: faker_1.faker.helpers.arrayElement(createdUsers).id,
            annotationId: faker_1.faker.helpers.arrayElement(createdAnnotations).id,
        }), 8);
        await (0, database_1.db)('payments').insert(payments);
        return {
            users: createdUsers,
            annotations: createdAnnotations,
            payments,
        };
    }
}
exports.DatabaseTestUtils = DatabaseTestUtils;
class APITestUtils {
    static createAuthHeaders(token) {
        return {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        };
    }
    static generateTestToken(payload = {}) {
        const jwt = require('jsonwebtoken');
        return jwt.sign({
            userId: (0, uuid_1.v4)(),
            email: 'test@example.com',
            ...payload,
        }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
    }
    static async waitFor(condition, timeout = 5000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            if (await condition()) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        throw new Error(`Timeout waiting for condition after ${timeout}ms`);
    }
    static mockStripeAPI() {
        return {
            checkout: {
                sessions: {
                    create: jest.fn().mockResolvedValue({
                        id: 'cs_test_session_123',
                        url: 'https://checkout.stripe.com/test',
                    }),
                    retrieve: jest.fn().mockResolvedValue({
                        id: 'cs_test_session_123',
                        payment_status: 'paid',
                        payment_intent: 'pi_test_intent_123',
                    }),
                },
            },
            paymentIntents: {
                retrieve: jest.fn().mockResolvedValue({
                    id: 'pi_test_intent_123',
                    status: 'succeeded',
                    amount: 5000,
                }),
            },
        };
    }
}
exports.APITestUtils = APITestUtils;
class PerformanceTestUtils {
    static async measureTime(operation) {
        const start = process.hrtime.bigint();
        const result = await operation();
        const end = process.hrtime.bigint();
        const time = Number(end - start) / 1000000;
        return { result, time };
    }
    static async measureConcurrency(operation, concurrency = 10) {
        const start = process.hrtime.bigint();
        const promises = Array.from({ length: concurrency }, async () => {
            const { result, time } = await this.measureTime(operation);
            return { result, time };
        });
        const outcomes = await Promise.all(promises);
        const end = process.hrtime.bigint();
        const times = outcomes.map(o => o.time);
        const results = outcomes.map(o => o.result);
        return {
            results,
            totalTime: Number(end - start) / 1000000,
            averageTime: times.reduce((a, b) => a + b, 0) / times.length,
            maxTime: Math.max(...times),
            minTime: Math.min(...times),
        };
    }
    static measureMemory() {
        const usage = process.memoryUsage();
        return {
            rss: usage.rss / 1024 / 1024,
            heapTotal: usage.heapTotal / 1024 / 1024,
            heapUsed: usage.heapUsed / 1024 / 1024,
            external: usage.external / 1024 / 1024,
        };
    }
}
exports.PerformanceTestUtils = PerformanceTestUtils;
class SecurityTestUtils {
    static getMaliciousPayloads() {
        return {
            sqlInjection: [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM users --",
                "admin'--",
                "admin' /*",
            ],
            xss: [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
            ],
            pathTraversal: [
                "../../etc/passwd",
                "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../proc/version",
                "....//....//....//etc/passwd",
            ],
            commandInjection: [
                "; cat /etc/passwd",
                "| whoami",
                "& dir",
                "`id`",
                "$(cat /etc/passwd)",
            ],
        };
    }
    static async testInputValidation(endpoint, payload) {
        const maliciousInputs = this.getMaliciousPayloads();
        const vulnerabilities = [];
        for (const [category, payloads] of Object.entries(maliciousInputs)) {
            for (const maliciousPayload of payloads) {
                const testPayload = { ...payload };
                Object.keys(testPayload).forEach(key => {
                    if (typeof testPayload[key] === 'string') {
                        testPayload[key] = maliciousPayload;
                    }
                });
                try {
                    vulnerabilities.push(`${category}: ${maliciousPayload}`);
                }
                catch (error) {
                }
            }
        }
        return vulnerabilities;
    }
    static generateSpoofedLocations() {
        return [
            {
                from: { lat: 39.9042, lon: 116.4074 },
                to: { lat: 40.7128, lon: -74.0060 },
                timeGap: 60000,
            },
            {
                from: { lat: 31.2304, lon: 121.4737 },
                to: { lat: 22.3193, lon: 114.1694 },
                timeGap: 300000,
            },
            {
                coordinates: [
                    { lat: 39.9042, lon: 116.4074, timestamp: new Date('2024-01-01T10:00:00Z') },
                    { lat: 39.9043, lon: 116.4075, timestamp: new Date('2024-01-01T10:00:01Z') },
                    { lat: 39.9044, lon: 116.4076, timestamp: new Date('2024-01-01T10:00:02Z') },
                ],
            },
        ];
    }
}
exports.SecurityTestUtils = SecurityTestUtils;
class TestEnvironmentUtils {
    static async setup() {
        process.env.NODE_ENV = 'test';
        process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/smellpin_test';
        process.env.REDIS_URL = process.env.TEST_REDIS_URL || 'redis://localhost:6379/1';
        await this.initializeTestDatabase();
    }
    static async cleanup() {
        await DatabaseTestUtils.cleanup();
        await database_1.db.destroy();
    }
    static async initializeTestDatabase() {
        try {
            await database_1.db.migrate.latest();
        }
        catch (error) {
            console.error('Migration failed:', error);
            throw error;
        }
    }
    static async resetTestDatabase() {
        await database_1.db.migrate.rollback();
        await database_1.db.migrate.latest();
    }
}
exports.TestEnvironmentUtils = TestEnvironmentUtils;
const setupGlobalTests = async () => {
    await TestEnvironmentUtils.setup();
};
exports.setupGlobalTests = setupGlobalTests;
const teardownGlobalTests = async () => {
    await TestEnvironmentUtils.cleanup();
};
exports.teardownGlobalTests = teardownGlobalTests;
//# sourceMappingURL=testUtils.js.map