/**
 * Test Utilities and Helpers
 * Common utilities for testing across the SmellPin application
 */

import { faker } from '@faker-js/faker';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../../src/config/database';

// Test Data Factories
export class TestDataFactory {
  /**
   * Create mock user data
   */
  static createUser(overrides: Partial<any> = {}) {
    return {
      id: uuidv4(),
      email: faker.internet.email(),
      username: faker.internet.userName(),
      password: 'TestPassword123!',
      firstName: faker.person.firstName(),
      lastName: faker.person.lastName(),
      avatar: faker.image.avatar(),
      isVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  /**
   * Create mock annotation data
   */
  static createAnnotation(overrides: Partial<any> = {}) {
    return {
      id: uuidv4(),
      userId: uuidv4(),
      latitude: faker.location.latitude(),
      longitude: faker.location.longitude(),
      smellType: faker.helpers.arrayElement(['chemical', 'sewage', 'garbage', 'industrial', 'cooking']),
      intensity: faker.number.int({ min: 1, max: 10 }),
      description: faker.lorem.sentence(),
      amount: faker.number.float({ min: 10, max: 100, fractionDigits: 2 }),
      status: 'active',
      tags: faker.helpers.arrayElements(['pollution', 'industrial', 'chemical', 'environment']),
      photos: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  /**
   * Create mock location report data
   */
  static createLocationReport(overrides: Partial<any> = {}) {
    return {
      latitude: faker.location.latitude(),
      longitude: faker.location.longitude(),
      accuracy: faker.number.float({ min: 5, max: 50 }),
      stayDuration: faker.number.int({ min: 30, max: 300 }),
      timestamp: new Date(),
      deviceInfo: {
        platform: faker.helpers.arrayElement(['iOS', 'Android']),
        version: faker.system.semver(),
        deviceId: uuidv4(),
        userAgent: faker.internet.userAgent(),
      },
      ...overrides,
    };
  }

  /**
   * Create mock payment data
   */
  static createPayment(overrides: Partial<any> = {}) {
    return {
      id: uuidv4(),
      userId: uuidv4(),
      annotationId: uuidv4(),
      amount: faker.number.float({ min: 10, max: 100, fractionDigits: 2 }),
      currency: 'USD',
      paymentMethod: 'stripe',
      status: faker.helpers.arrayElement(['pending', 'completed', 'failed', 'refunded']),
      stripeSessionId: `cs_${faker.string.alphanumeric(10)}`,
      stripePaymentIntentId: `pi_${faker.string.alphanumeric(10)}`,
      metadata: {
        annotationType: 'smell_report',
        location: faker.location.city(),
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  /**
   * Create mock LBS reward data
   */
  static createLBSReward(overrides: Partial<any> = {}) {
    return {
      id: uuidv4(),
      userId: uuidv4(),
      annotationId: uuidv4(),
      rewardType: faker.helpers.arrayElement(['first_finder', 'combo', 'regular']),
      amount: faker.number.float({ min: 1, max: 50, fractionDigits: 2 }),
      status: faker.helpers.arrayElement(['pending', 'verified', 'claimed', 'expired']),
      locationData: this.createLocationReport(),
      fraudScore: faker.number.float({ min: 0, max: 1, fractionDigits: 3 }),
      claimedAt: new Date(),
      verifiedAt: new Date(),
      ...overrides,
    };
  }

  /**
   * Create batch of test data
   */
  static createBatch<T>(factory: () => T, count: number): T[] {
    return Array.from({ length: count }, factory);
  }
}

// Database Test Utilities
export class DatabaseTestUtils {
  /**
   * Clean up test data
   */
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

    // Delete in reverse order to handle foreign key constraints
    for (const table of tables.reverse()) {
      await db(table).whereRaw('email LIKE ?', ['%test%']).del();
    }
  }

  /**
   * Create test user in database
   */
  static async createTestUser(userData?: Partial<any>) {
    const user = TestDataFactory.createUser(userData);
    const [createdUser] = await db('users').insert(user).returning('*');
    return createdUser;
  }

  /**
   * Create test annotation in database
   */
  static async createTestAnnotation(annotationData?: Partial<any>) {
    const annotation = TestDataFactory.createAnnotation(annotationData);
    const [createdAnnotation] = await db('annotations').insert(annotation).returning('*');
    return createdAnnotation;
  }

  /**
   * Seed test database with sample data
   */
  static async seedTestData() {
    // Create test users
    const users = TestDataFactory.createBatch(() => TestDataFactory.createUser(), 5);
    const createdUsers = await db('users').insert(users).returning('*');

    // Create test annotations
    const annotations = TestDataFactory.createBatch(() => 
      TestDataFactory.createAnnotation({
        userId: faker.helpers.arrayElement(createdUsers).id,
      }), 10
    );
    const createdAnnotations = await db('annotations').insert(annotations).returning('*');

    // Create test payments
    const payments = TestDataFactory.createBatch(() =>
      TestDataFactory.createPayment({
        userId: faker.helpers.arrayElement(createdUsers).id,
        annotationId: faker.helpers.arrayElement(createdAnnotations).id,
      }), 8
    );
    await db('payments').insert(payments);

    return {
      users: createdUsers,
      annotations: createdAnnotations,
      payments,
    };
  }
}

// API Test Utilities
export class APITestUtils {
  /**
   * Create authenticated request headers
   */
  static createAuthHeaders(token: string) {
    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }

  /**
   * Generate JWT token for testing
   */
  static generateTestToken(payload: any = {}) {
    const jwt = require('jsonwebtoken');
    return jwt.sign({
      userId: uuidv4(),
      email: 'test@example.com',
      ...payload,
    }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
  }

  /**
   * Wait for async operations
   */
  static async waitFor(condition: () => boolean | Promise<boolean>, timeout = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (await condition()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`Timeout waiting for condition after ${timeout}ms`);
  }

  /**
   * Mock external API responses
   */
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

// Performance Test Utilities
export class PerformanceTestUtils {
  /**
   * Measure execution time
   */
  static async measureTime<T>(operation: () => Promise<T>): Promise<{ result: T; time: number }> {
    const start = process.hrtime.bigint();
    const result = await operation();
    const end = process.hrtime.bigint();
    const time = Number(end - start) / 1_000_000; // Convert to milliseconds
    return { result, time };
  }

  /**
   * Run multiple operations concurrently and measure performance
   */
  static async measureConcurrency<T>(
    operation: () => Promise<T>,
    concurrency: number = 10
  ): Promise<{
    results: T[];
    totalTime: number;
    averageTime: number;
    maxTime: number;
    minTime: number;
  }> {
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
      totalTime: Number(end - start) / 1_000_000,
      averageTime: times.reduce((a, b) => a + b, 0) / times.length,
      maxTime: Math.max(...times),
      minTime: Math.min(...times),
    };
  }

  /**
   * Memory usage measurement
   */
  static measureMemory() {
    const usage = process.memoryUsage();
    return {
      rss: usage.rss / 1024 / 1024, // MB
      heapTotal: usage.heapTotal / 1024 / 1024, // MB
      heapUsed: usage.heapUsed / 1024 / 1024, // MB
      external: usage.external / 1024 / 1024, // MB
    };
  }
}

// Security Test Utilities
export class SecurityTestUtils {
  /**
   * Generate malicious input payloads for testing
   */
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

  /**
   * Test for common vulnerabilities
   */
  static async testInputValidation(endpoint: string, payload: any) {
    const maliciousInputs = this.getMaliciousPayloads();
    const vulnerabilities: string[] = [];

    for (const [category, payloads] of Object.entries(maliciousInputs)) {
      for (const maliciousPayload of payloads) {
        const testPayload = { ...payload };
        // Inject malicious payload into all string fields
        Object.keys(testPayload).forEach(key => {
          if (typeof testPayload[key] === 'string') {
            testPayload[key] = maliciousPayload;
          }
        });

        try {
          // This would be implemented with actual HTTP client
          // const response = await apiClient.post(endpoint, testPayload);
          // Check if malicious payload was reflected or executed
          vulnerabilities.push(`${category}: ${maliciousPayload}`);
        } catch (error) {
          // Expected behavior - input should be rejected
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Generate test coordinates for GPS spoofing detection
   */
  static generateSpoofedLocations() {
    return [
      // Impossible movement (teleportation)
      {
        from: { lat: 39.9042, lon: 116.4074 }, // Beijing
        to: { lat: 40.7128, lon: -74.0060 }, // New York
        timeGap: 60000, // 1 minute
      },
      // Unrealistic speed
      {
        from: { lat: 31.2304, lon: 121.4737 }, // Shanghai
        to: { lat: 22.3193, lon: 114.1694 }, // Hong Kong
        timeGap: 300000, // 5 minutes (would require ~2000 km/h)
      },
      // Pattern detection
      {
        coordinates: [
          { lat: 39.9042, lon: 116.4074, timestamp: new Date('2024-01-01T10:00:00Z') },
          { lat: 39.9043, lon: 116.4075, timestamp: new Date('2024-01-01T10:00:01Z') },
          { lat: 39.9044, lon: 116.4076, timestamp: new Date('2024-01-01T10:00:02Z') },
        ], // Too regular pattern
      },
    ];
  }
}

// Test Environment Utilities
export class TestEnvironmentUtils {
  /**
   * Setup test environment
   */
  static async setup() {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/smellpin_test';
    process.env.REDIS_URL = process.env.TEST_REDIS_URL || 'redis://localhost:6379/1';

    // Initialize test database
    await this.initializeTestDatabase();
  }

  /**
   * Cleanup test environment
   */
  static async cleanup() {
    await DatabaseTestUtils.cleanup();
    await db.destroy();
  }

  /**
   * Initialize test database
   */
  static async initializeTestDatabase() {
    // Run migrations
    try {
      await db.migrate.latest();
    } catch (error) {
      console.error('Migration failed:', error);
      throw error;
    }
  }

  /**
   * Reset test database
   */
  static async resetTestDatabase() {
    await db.migrate.rollback();
    await db.migrate.latest();
  }
}

// Export all utilities
export {
  TestDataFactory,
  DatabaseTestUtils,
  APITestUtils,
  PerformanceTestUtils,
  SecurityTestUtils,
  TestEnvironmentUtils,
};

// Global test setup
export const setupGlobalTests = async () => {
  await TestEnvironmentUtils.setup();
};

export const teardownGlobalTests = async () => {
  await TestEnvironmentUtils.cleanup();
};