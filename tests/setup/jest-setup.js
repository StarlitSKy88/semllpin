"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.testUtils = void 0;
const testcontainers_setup_1 = require("./testcontainers-setup");
const faker_1 = require("@faker-js/faker");
require("jest-extended");
jest.setTimeout(30000);
faker_1.faker.seed(12345);
beforeAll(async () => {
    global.testManager = testcontainers_setup_1.TestContainersManager.getInstance();
    const env = global.testManager.getEnvironment();
    if (!env) {
        await global.testManager.setupTestEnvironment();
    }
});
beforeEach(async () => {
    const testName = expect.getState().currentTestName?.replace(/\s+/g, '_') || 'unknown';
    global.testSchema = await global.testManager.createIsolatedSchema(testName);
    global.testDbIndex = Math.floor(Math.random() * 15) + 1;
    jest.clearAllMocks();
    jest.restoreAllMocks();
});
afterEach(async () => {
    if (global.testSchema) {
        await global.testManager.dropIsolatedSchema(global.testSchema);
    }
    if (global.testDbIndex && global.testManager.getEnvironment()) {
        try {
            const redis = await global.testManager.getIsolatedRedis(global.testDbIndex);
            await redis.flushdb();
            await redis.disconnect();
        }
        catch (error) {
            console.warn('Redis 清理失败:', error);
        }
    }
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
expect.extend({
    toBeWithinDistance(received, expected, maxDistance) {
        const distance = calculateDistance(received, expected);
        const pass = distance <= maxDistance;
        return {
            message: () => `expected ${JSON.stringify(received)} to be within ${maxDistance}m of ${JSON.stringify(expected)}, but was ${distance.toFixed(2)}m away`,
            pass,
        };
    },
    toRespondWithin(received, maxTime) {
        const pass = received <= maxTime;
        return {
            message: () => `expected response time ${received}ms to be within ${maxTime}ms`,
            pass,
        };
    },
    toBeValidGeometry(received) {
        const pass = received &&
            typeof received.type === 'string' &&
            Array.isArray(received.coordinates);
        return {
            message: () => `expected ${JSON.stringify(received)} to be a valid GeoJSON geometry`,
            pass,
        };
    }
});
function calculateDistance(point1, point2) {
    const R = 6371000;
    const φ1 = (point1.lat * Math.PI) / 180;
    const φ2 = (point2.lat * Math.PI) / 180;
    const Δφ = ((point2.lat - point1.lat) * Math.PI) / 180;
    const Δλ = ((point2.lng - point1.lng) * Math.PI) / 180;
    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}
jest.mock('node-cron', () => ({
    schedule: jest.fn(),
    destroy: jest.fn(),
    getTasks: jest.fn(() => new Map())
}));
jest.mock('winston', () => ({
    createLogger: jest.fn(() => ({
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn()
    })),
    format: {
        combine: jest.fn(),
        timestamp: jest.fn(),
        errors: jest.fn(),
        printf: jest.fn(),
        json: jest.fn()
    },
    transports: {
        Console: jest.fn(),
        File: jest.fn()
    }
}));
jest.mock('nodemailer', () => ({
    createTransporter: jest.fn(() => ({
        sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' })
    }))
}));
if (process.env.NODE_ENV === 'test') {
    jest.mock('stripe', () => ({
        Stripe: jest.fn(() => ({
            paymentIntents: {
                create: jest.fn().mockResolvedValue({ id: 'pi_test_12345', status: 'succeeded' }),
                retrieve: jest.fn().mockResolvedValue({ id: 'pi_test_12345', status: 'succeeded' })
            },
            webhooks: {
                constructEvent: jest.fn().mockReturnValue({ type: 'payment_intent.succeeded', data: { object: { id: 'pi_test_12345' } } })
            }
        }))
    }));
}
jest.mock('aws-sdk', () => ({
    S3: jest.fn(() => ({
        upload: jest.fn(() => ({
            promise: jest.fn().mockResolvedValue({ Location: 'https://test-bucket.s3.amazonaws.com/test-file.jpg' })
        })),
        deleteObject: jest.fn(() => ({
            promise: jest.fn().mockResolvedValue({})
        }))
    })),
    config: {
        update: jest.fn()
    }
}));
exports.testUtils = {
    waitFor: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
    generateBeijingCoordinate: () => ({
        lat: faker_1.faker.number.float({ min: 39.8, max: 40.2 }),
        lng: faker_1.faker.number.float({ min: 116.2, max: 116.6 })
    }),
    generateGlobalCoordinate: () => ({
        lat: faker_1.faker.location.latitude(),
        lng: faker_1.faker.location.longitude()
    }),
    async createTestDbConnection() {
        const env = global.testManager.getEnvironment();
        if (!env)
            throw new Error('测试环境未初始化');
        const { Client } = require('pg');
        const client = new Client({ connectionString: env.DATABASE_URL });
        await client.connect();
        return client;
    },
    async createTestRedisConnection() {
        return await global.testManager.getIsolatedRedis(global.testDbIndex);
    }
};
//# sourceMappingURL=jest-setup.js.map