/**
 * SmellPin 测试环境 Jest 设置 - Phase 2
 * 集中处理 mock/清理工作，确保测试隔离
 */
import { TestContainersManager } from './testcontainers-setup';
import { faker } from '@faker-js/faker';
import 'jest-extended';

// 设置全局测试超时
jest.setTimeout(30000);

// 设置 faker 随机种子，确保测试可重复
faker.seed(12345);

// 全局变量存储
declare global {
  var testManager: TestContainersManager;
  var testSchema: string;
  var testDbIndex: number;
}

// 在每个测试文件开始前执行
beforeAll(async () => {
  // 获取测试容器管理器
  global.testManager = TestContainersManager.getInstance();
  
  // 确保测试环境已启动
  const env = global.testManager.getEnvironment();
  if (!env) {
    await global.testManager.setupTestEnvironment();
  }
});

// 在每个测试用例开始前执行
beforeEach(async () => {
  // 为每个测试创建独立的数据库 schema
  const testName = expect.getState().currentTestName?.replace(/\s+/g, '_') || 'unknown';
  global.testSchema = await global.testManager.createIsolatedSchema(testName);
  
  // 为每个测试分配独立的 Redis DB 索引
  global.testDbIndex = Math.floor(Math.random() * 15) + 1; // Redis 默认有 16 个数据库 (0-15)
  
  // 清理所有 mocks
  jest.clearAllMocks();
  jest.restoreAllMocks();
  
  // 重置 faker 种子（可选：为每个测试使用不同种子）
  // faker.seed(Date.now());
});

// 在每个测试用例结束后执行
afterEach(async () => {
  // 清理测试用的 schema
  if (global.testSchema) {
    await global.testManager.dropIsolatedSchema(global.testSchema);
  }
  
  // 清理 Redis 测试数据库
  if (global.testDbIndex && global.testManager.getEnvironment()) {
    try {
      const redis = await global.testManager.getIsolatedRedis(global.testDbIndex);
      await redis.flushdb();
      await redis.disconnect();
    } catch (error) {
      console.warn('Redis 清理失败:', error);
    }
  }
});

// 全局错误处理
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// 增强的匹配器
expect.extend({
  // 自定义地理位置匹配器
  toBeWithinDistance(received: { lat: number; lng: number }, expected: { lat: number; lng: number }, maxDistance: number) {
    const distance = calculateDistance(received, expected);
    const pass = distance <= maxDistance;
    
    return {
      message: () => 
        `expected ${JSON.stringify(received)} to be within ${maxDistance}m of ${JSON.stringify(expected)}, but was ${distance.toFixed(2)}m away`,
      pass,
    };
  },
  
  // 响应时间匹配器
  toRespondWithin(received: number, maxTime: number) {
    const pass = received <= maxTime;
    return {
      message: () => `expected response time ${received}ms to be within ${maxTime}ms`,
      pass,
    };
  },
  
  // PostGIS 几何对象匹配器
  toBeValidGeometry(received: any) {
    const pass = received && 
                 typeof received.type === 'string' &&
                 Array.isArray(received.coordinates);
    return {
      message: () => `expected ${JSON.stringify(received)} to be a valid GeoJSON geometry`,
      pass,
    };
  }
});

// 辅助函数：计算两点间距离（Haversine 公式）
function calculateDistance(
  point1: { lat: number; lng: number },
  point2: { lat: number; lng: number }
): number {
  const R = 6371000; // 地球半径（米）
  const φ1 = (point1.lat * Math.PI) / 180;
  const φ2 = (point2.lat * Math.PI) / 180;
  const Δφ = ((point2.lat - point1.lat) * Math.PI) / 180;
  const Δλ = ((point2.lng - point1.lng) * Math.PI) / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

// 全局 mock 设置

// Mock node-cron 以避免在测试中执行定时任务
const mockNodeCron = {
  schedule: jest.fn(),
  destroy: jest.fn(),
  getTasks: jest.fn(() => new Map())
};
jest.doMock('node-cron', () => mockNodeCron);

// Mock winston logger
const mockWinston = {
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
};
jest.doMock('winston', () => mockWinston);

// Mock nodemailer 邮件发送
const mockNodemailer = {
  createTransporter: jest.fn(() => ({
    sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' })
  }))
};
jest.doMock('nodemailer', () => mockNodemailer);

// Mock 支付接口（开发环境下）
if (process.env['NODE_ENV'] === 'test') {
  const mockStripe = {
    Stripe: function() {
      return {
        paymentIntents: {
          create: jest.fn().mockResolvedValue({ id: 'pi_test_12345', status: 'succeeded' }),
          retrieve: jest.fn().mockResolvedValue({ id: 'pi_test_12345', status: 'succeeded' })
        },
        webhooks: {
          constructEvent: jest.fn().mockReturnValue({ type: 'payment_intent.succeeded', data: { object: { id: 'pi_test_12345' } } })
        }
      };
    }
  };
  
  jest.doMock('stripe', () => mockStripe);
}

// Mock AWS S3 文件上传
const mockAwsSdk = {
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
};
jest.doMock('aws-sdk', () => mockAwsSdk);

// 测试工具函数导出
export const testUtils = {
  // 等待异步操作完成
  waitFor: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // 生成测试用的地理坐标（北京范围内）
  generateBeijingCoordinate: () => ({
    lat: faker.number.float({ min: 39.8, max: 40.2 }),
    lng: faker.number.float({ min: 116.2, max: 116.6 })
  }),
  
  // 生成测试用的全球坐标
  generateGlobalCoordinate: () => ({
    lat: faker.location.latitude(),
    lng: faker.location.longitude()
  }),
  
  // 创建测试数据库连接
  async createTestDbConnection() {
    const env = global.testManager.getEnvironment();
    if (!env) throw new Error('测试环境未初始化');
    
    const { Client } = require('pg');
    const client = new Client({ connectionString: env.DATABASE_URL });
    await client.connect();
    return client;
  },
  
  // 创建测试 Redis 连接
  async createTestRedisConnection() {
    return await global.testManager.getIsolatedRedis(global.testDbIndex);
  }
};

// TypeScript 声明增强
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeWithinDistance(expected: { lat: number; lng: number }, maxDistance: number): R;
      toRespondWithin(maxTime: number): R;
      toBeValidGeometry(): R;
    }
  }
}