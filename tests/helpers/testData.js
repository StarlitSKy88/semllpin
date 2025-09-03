const { faker } = require('@faker-js/faker');

// 生成测试用户数据
function generateTestUser(overrides = {}) {
  return {
    username: faker.internet.userName(),
    email: faker.internet.email(),
    password: 'TestPassword123!',
    first_name: faker.person.firstName(),
    last_name: faker.person.lastName(),
    bio: faker.lorem.sentence(),
    location: faker.location.city(),
    ...overrides,
  };
}

// 生成测试标注数据
function generateTestAnnotation(overrides = {}) {
  return {
    latitude: parseFloat(faker.location.latitude()),
    longitude: parseFloat(faker.location.longitude()),
    smell_intensity: faker.number.int({ min: 1, max: 10 }),
    description: faker.lorem.paragraph(),
    category: faker.helpers.arrayElement([
      'sewage',
      'garbage',
      'industrial',
      'food',
      'chemical',
      'animal',
      'other'
    ]),
    ...overrides,
  };
}

// 生成测试评论数据
function generateTestComment(overrides = {}) {
  return {
    content: faker.lorem.sentence(),
    is_funny: faker.datatype.boolean(),
    ...overrides,
  };
}

// 生成测试支付数据
function generateTestPayment(overrides = {}) {
  return {
    amount: parseFloat(faker.commerce.price({ min: 1, max: 1000 })),
    currency: faker.helpers.arrayElement(['usd', 'cny', 'eur']),
    description: faker.commerce.productDescription(),
    status: faker.helpers.arrayElement(['pending', 'completed', 'failed', 'refunded']),
    stripe_session_id: `cs_test_${faker.string.alphanumeric(24)}`,
    ...overrides,
  };
}

// 生成测试钱包交易数据
function generateTestWalletTransaction(overrides = {}) {
  return {
    amount: parseFloat(faker.commerce.price({ min: 1, max: 500 })),
    transaction_type: faker.helpers.arrayElement(['credit', 'debit']),
    description: faker.lorem.sentence(),
    reference_id: faker.string.uuid(),
    ...overrides,
  };
}

// 生成测试通知数据
function generateTestNotification(overrides = {}) {
  return {
    type: faker.helpers.arrayElement(['follow', 'like', 'comment', 'share', 'system']),
    title: faker.lorem.words(3),
    message: faker.lorem.sentence(),
    is_read: faker.datatype.boolean(),
    ...overrides,
  };
}

// 生成测试媒体文件数据
function generateTestMediaFile(overrides = {}) {
  return {
    filename: faker.system.fileName(),
    file_type: faker.helpers.arrayElement(['image', 'video', 'audio']),
    file_size: faker.number.int({ min: 1024, max: 10485760 }), // 1KB to 10MB
    mime_type: faker.helpers.arrayElement([
      'image/jpeg',
      'image/png',
      'image/gif',
      'video/mp4',
      'video/webm',
      'audio/mp3'
    ]),
    file_url: faker.internet.url(),
    ...overrides,
  };
}

// 生成测试管理员日志数据
function generateTestAdminLog(overrides = {}) {
  return {
    action: faker.helpers.arrayElement([
      'user_ban',
      'user_unban',
      'content_delete',
      'content_approve',
      'system_config_update'
    ]),
    target_type: faker.helpers.arrayElement(['user', 'annotation', 'comment', 'system']),
    target_id: faker.string.uuid(),
    details: faker.lorem.sentence(),
    ip_address: faker.internet.ip(),
    user_agent: faker.internet.userAgent(),
    ...overrides,
  };
}

// 生成批量测试数据
function generateBulkTestData(generator, count = 10, overrides = {}) {
  const data = [];
  for (let i = 0; i < count; i++) {
    data.push(generator(overrides));
  }
  return data;
}

// 生成测试坐标（在指定区域内）
function generateTestCoordinates(center = { lat: 40.7128, lng: -74.0060 }, radiusKm = 10) {
  const radiusInDegrees = radiusKm / 111; // 大约每度111km
  
  const lat = center.lat + (Math.random() - 0.5) * 2 * radiusInDegrees;
  const lng = center.lng + (Math.random() - 0.5) * 2 * radiusInDegrees;
  
  return {
    latitude: parseFloat(lat.toFixed(6)),
    longitude: parseFloat(lng.toFixed(6)),
  };
}

// 生成测试时间范围
function generateTestDateRange(daysBack = 30) {
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - daysBack * 24 * 60 * 60 * 1000);
  
  return {
    start_date: startDate.toISOString(),
    end_date: endDate.toISOString(),
  };
}

// 生成测试搜索查询
function generateTestSearchQuery() {
  return {
    q: faker.lorem.words(faker.number.int({ min: 1, max: 3 })),
    category: faker.helpers.arrayElement(['sewage', 'garbage', 'industrial', 'food']),
    min_intensity: faker.number.int({ min: 1, max: 5 }),
    max_intensity: faker.number.int({ min: 6, max: 10 }),
    radius: faker.number.int({ min: 100, max: 5000 }),
    ...generateTestCoordinates(),
  };
}

// 生成测试分页参数
function generateTestPagination() {
  return {
    page: faker.number.int({ min: 1, max: 10 }),
    limit: faker.helpers.arrayElement([10, 20, 50, 100]),
    sort_by: faker.helpers.arrayElement(['created_at', 'updated_at', 'smell_intensity', 'like_count']),
    sort_order: faker.helpers.arrayElement(['asc', 'desc']),
  };
}

// 生成测试API响应
function generateTestApiResponse(data = null, success = true, error = null) {
  const response = {
    success,
    timestamp: new Date().toISOString(),
  };
  
  if (success) {
    response.data = data;
  } else {
    response.error = error || {
      code: 'TEST_ERROR',
      message: 'Test error message',
    };
  }
  
  return response;
}

// 生成测试错误
function generateTestError(code = 'TEST_ERROR', message = null) {
  return {
    code,
    message: message || faker.lorem.sentence(),
    details: faker.lorem.paragraph(),
    timestamp: new Date().toISOString(),
  };
}

// 生成测试JWT载荷
function generateTestJWTPayload(overrides = {}) {
  return {
    user_id: faker.string.uuid(),
    username: faker.internet.userName(),
    email: faker.internet.email(),
    role: faker.helpers.arrayElement(['user', 'admin', 'moderator']),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1小时后过期
    ...overrides,
  };
}

// 生成测试文件上传数据
function generateTestFileUpload(type = 'image') {
  const fileTypes = {
    image: {
      filename: 'test-image.jpg',
      mimetype: 'image/jpeg',
      size: faker.number.int({ min: 10240, max: 5242880 }), // 10KB to 5MB
    },
    video: {
      filename: 'test-video.mp4',
      mimetype: 'video/mp4',
      size: faker.number.int({ min: 1048576, max: 52428800 }), // 1MB to 50MB
    },
    audio: {
      filename: 'test-audio.mp3',
      mimetype: 'audio/mpeg',
      size: faker.number.int({ min: 102400, max: 10485760 }), // 100KB to 10MB
    },
  };
  
  return fileTypes[type] || fileTypes.image;
}

// 生成测试性能指标
function generateTestPerformanceMetrics() {
  return {
    response_time: faker.number.int({ min: 50, max: 2000 }),
    memory_usage: faker.number.int({ min: 50, max: 500 }),
    cpu_usage: faker.number.float({ min: 0.1, max: 100.0, precision: 0.1 }),
    database_queries: faker.number.int({ min: 1, max: 20 }),
    cache_hits: faker.number.int({ min: 0, max: 100 }),
    cache_misses: faker.number.int({ min: 0, max: 50 }),
  };
}

// 生成测试安全事件
function generateTestSecurityEvent() {
  return {
    event_type: faker.helpers.arrayElement([
      'login_attempt',
      'failed_login',
      'suspicious_activity',
      'rate_limit_exceeded',
      'invalid_token',
      'sql_injection_attempt',
      'xss_attempt'
    ]),
    ip_address: faker.internet.ip(),
    user_agent: faker.internet.userAgent(),
    severity: faker.helpers.arrayElement(['low', 'medium', 'high', 'critical']),
    details: faker.lorem.sentence(),
    timestamp: faker.date.recent(),
  };
}

// 清理测试数据的辅助函数
function cleanupTestData(db, tables = []) {
  const defaultTables = [
    'wallet_transactions',
    'payments',
    'notifications',
    'media_files',
    'comments',
    'annotation_likes',
    'user_follows',
    'annotations',
    'admin_logs',
    'users',
  ];
  
  const tablesToClean = tables.length > 0 ? tables : defaultTables;
  
  return Promise.all(
    tablesToClean.map(table => db(table).del())
  );
}

// 创建测试数据库事务
function withTestTransaction(db, callback) {
  return db.transaction(async (trx) => {
    try {
      const result = await callback(trx);
      await trx.rollback(); // 总是回滚测试事务
      return result;
    } catch (error) {
      await trx.rollback();
      throw error;
    }
  });
}

// 等待异步操作完成的辅助函数
function waitFor(condition, timeout = 5000, interval = 100) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    
    const check = async () => {
      try {
        if (await condition()) {
          resolve(true);
          return;
        }
      } catch (error) {
        // 忽略条件检查中的错误，继续等待
      }
      
      if (Date.now() - startTime >= timeout) {
        reject(new Error(`Timeout waiting for condition after ${timeout}ms`));
        return;
      }
      
      setTimeout(check, interval);
    };
    
    check();
  });
}

// 模拟网络延迟
function simulateNetworkDelay(min = 100, max = 500) {
  const delay = faker.number.int({ min, max });
  return new Promise(resolve => setTimeout(resolve, delay));
}

module.exports = {
  // 数据生成器
  generateTestUser,
  generateTestAnnotation,
  generateTestComment,
  generateTestPayment,
  generateTestWalletTransaction,
  generateTestNotification,
  generateTestMediaFile,
  generateTestAdminLog,
  generateBulkTestData,
  
  // 特殊数据生成器
  generateTestCoordinates,
  generateTestDateRange,
  generateTestSearchQuery,
  generateTestPagination,
  generateTestApiResponse,
  generateTestError,
  generateTestJWTPayload,
  generateTestFileUpload,
  generateTestPerformanceMetrics,
  generateTestSecurityEvent,
  
  // 辅助工具
  cleanupTestData,
  withTestTransaction,
  waitFor,
  simulateNetworkDelay,
};