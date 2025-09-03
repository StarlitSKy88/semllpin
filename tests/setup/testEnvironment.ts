// 测试环境设置 - SmellPin自动化测试方案2.0
import { config } from 'dotenv';
import path from 'path';

// 加载测试环境变量
config({ path: path.resolve(process.cwd(), '.env.test') });

// 设置测试环境变量
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // 减少测试期间的日志噪音

// 数据库配置
if (!process.env.TEST_DATABASE_URL) {
  process.env.TEST_DATABASE_URL = 'postgres://test:test@localhost:5433/smellpin_test';
}

// Redis配置  
if (!process.env.REDIS_URL) {
  process.env.REDIS_URL = 'redis://localhost:6380';
}

// JWT配置
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'test_jwt_secret_key_for_automated_testing_2024';
}

// 测试服务器端口
process.env.PORT = process.env.TEST_PORT || '3001';

// 禁用外部服务
process.env.DISABLE_EXTERNAL_SERVICES = 'true';
process.env.DISABLE_EMAIL_NOTIFICATIONS = 'true';
process.env.DISABLE_SMS_NOTIFICATIONS = 'true';

// Stripe测试密钥
process.env.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_fake_key_for_testing';
process.env.STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_fake_webhook_secret';

// PayPal测试配置
process.env.PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || 'fake_paypal_client_id';
process.env.PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || 'fake_paypal_client_secret';
process.env.PAYPAL_MODE = 'sandbox';

// 文件上传配置
process.env.UPLOAD_PATH = path.join(process.cwd(), 'tests', 'temp', 'uploads');
process.env.MAX_FILE_SIZE = '5MB';

// 地理服务配置
process.env.NOMINATIM_URL = 'https://nominatim.openstreetmap.org';
process.env.DISABLE_RATE_LIMITING = 'true';

// 监控和错误处理
process.env.DISABLE_ERROR_MONITORING = 'true';
process.env.DISABLE_PERFORMANCE_MONITORING = 'false'; // 保持性能监控用于测试

// 缓存配置
process.env.CACHE_TTL = '60'; // 1分钟TTL用于测试
process.env.ENABLE_QUERY_CACHE = 'true';

// 并发配置
process.env.MAX_CONCURRENT_REQUESTS = '50';
process.env.DB_POOL_SIZE = '10';

// 确保测试目录存在
import { mkdirSync } from 'fs';
try {
  mkdirSync(path.join(process.cwd(), 'tests', 'temp'), { recursive: true });
  mkdirSync(path.join(process.cwd(), 'tests', 'temp', 'uploads'), { recursive: true });
  mkdirSync(path.join(process.cwd(), 'test-results'), { recursive: true });
  mkdirSync(path.join(process.cwd(), 'coverage', 'parallel'), { recursive: true });
} catch (error) {
  // 目录可能已存在，忽略错误
}

// 全局测试工具
declare global {
  namespace NodeJS {
    interface Global {
      testMode: boolean;
      testStartTime: number;
    }
  }
}

(global as any).testMode = true;
(global as any).testStartTime = Date.now();

// 测试开始日志
console.log('🧪 SmellPin测试环境初始化完成');
console.log(`📅 测试开始时间: ${new Date().toISOString()}`);
console.log(`🗄️ 测试数据库: ${process.env.TEST_DATABASE_URL?.replace(/:[^:@]*@/, ':***@')}`);
console.log(`🔴 Redis: ${process.env.REDIS_URL}`);
console.log(`🚀 测试服务器端口: ${process.env.PORT}`);