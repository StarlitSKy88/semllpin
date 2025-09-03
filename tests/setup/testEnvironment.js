"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = require("dotenv");
const path_1 = __importDefault(require("path"));
(0, dotenv_1.config)({ path: path_1.default.resolve(process.cwd(), '.env.test') });
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
if (!process.env.TEST_DATABASE_URL) {
    process.env.TEST_DATABASE_URL = 'postgres://test:test@localhost:5433/smellpin_test';
}
if (!process.env.REDIS_URL) {
    process.env.REDIS_URL = 'redis://localhost:6380';
}
if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = 'test_jwt_secret_key_for_automated_testing_2024';
}
process.env.PORT = process.env.TEST_PORT || '3001';
process.env.DISABLE_EXTERNAL_SERVICES = 'true';
process.env.DISABLE_EMAIL_NOTIFICATIONS = 'true';
process.env.DISABLE_SMS_NOTIFICATIONS = 'true';
process.env.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_fake_key_for_testing';
process.env.STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_fake_webhook_secret';
process.env.PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || 'fake_paypal_client_id';
process.env.PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || 'fake_paypal_client_secret';
process.env.PAYPAL_MODE = 'sandbox';
process.env.UPLOAD_PATH = path_1.default.join(process.cwd(), 'tests', 'temp', 'uploads');
process.env.MAX_FILE_SIZE = '5MB';
process.env.NOMINATIM_URL = 'https://nominatim.openstreetmap.org';
process.env.DISABLE_RATE_LIMITING = 'true';
process.env.DISABLE_ERROR_MONITORING = 'true';
process.env.DISABLE_PERFORMANCE_MONITORING = 'false';
process.env.CACHE_TTL = '60';
process.env.ENABLE_QUERY_CACHE = 'true';
process.env.MAX_CONCURRENT_REQUESTS = '50';
process.env.DB_POOL_SIZE = '10';
const fs_1 = require("fs");
try {
    (0, fs_1.mkdirSync)(path_1.default.join(process.cwd(), 'tests', 'temp'), { recursive: true });
    (0, fs_1.mkdirSync)(path_1.default.join(process.cwd(), 'tests', 'temp', 'uploads'), { recursive: true });
    (0, fs_1.mkdirSync)(path_1.default.join(process.cwd(), 'test-results'), { recursive: true });
    (0, fs_1.mkdirSync)(path_1.default.join(process.cwd(), 'coverage', 'parallel'), { recursive: true });
}
catch (error) {
}
global.testMode = true;
global.testStartTime = Date.now();
console.log('🧪 SmellPin测试环境初始化完成');
console.log(`📅 测试开始时间: ${new Date().toISOString()}`);
console.log(`🗄️ 测试数据库: ${process.env.TEST_DATABASE_URL?.replace(/:[^:@]*@/, ':***@')}`);
console.log(`🔴 Redis: ${process.env.REDIS_URL}`);
console.log(`🚀 测试服务器端口: ${process.env.PORT}`);
//# sourceMappingURL=testEnvironment.js.map