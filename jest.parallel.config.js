// 优化的并行测试配置 - SmellPin自动化测试方案2.0
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  maxWorkers: '75%', // 使用75%的CPU核心进行并行测试
  
  // 测试文件匹配
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: [
    // 仅运行单元测试与服务层稳定快速用例
    '**/tests/unit/**/*.test.ts',
    '<rootDir>/src/services/__tests__/antiFraudService.test.ts',
    '<rootDir>/src/services/__tests__/rewardCalculationService.test.ts'
  ],
  
  // 忽略前端组件测试
  testPathIgnorePatterns: [
    '<rootDir>/frontend/',
    '<rootDir>/node_modules/',
    '<rootDir>/coverage/',
    '<rootDir>/dist/',
    '<rootDir>/src/__tests__/e2e/',
    '<rootDir>/tests/e2e/',
    '/__tests__/e2e/',
    '/tests/e2e/',
    // 新增：忽略集成测试
    '<rootDir>/src/__tests__/integration/',
    '<rootDir>/tests/integration/'
  ],
  
  // TypeScript转换配置
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        module: 'commonjs',
        target: 'es2018',
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true
      }
    }]
  },
  
  transformIgnorePatterns: [
    'node_modules/(?!(.*\\.mjs$))'
  ],
  
  // 覆盖率收集配置
  collectCoverageFrom: [
    'src/controllers/**/*.ts',
    'src/services/**/*.ts',
    'src/models/**/*.ts',
    'src/middleware/**/*.ts',
    'src/routes/**/*.ts',
    'src/utils/**/*.ts',
    '!src/**/*.d.ts',
    '!src/server.ts',
    '!src/migrations/**',
    '!src/seeds/**',
    '!src/__mocks__/**',
    '!src/types/**'
  ],
  
  coverageDirectory: 'coverage/parallel',
  coverageReporters: ['text-summary', 'lcov', 'html', 'json'],
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 75, 
      lines: 75,
      statements: 75
    }
  },
  
  // 模块路径映射
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    'node-cron': '<rootDir>/tests/mocks/node-cron.ts'
  },
  
  // 测试超时和性能配置
  testTimeout: 45000, // 45秒超时，适合数据库操作
  verbose: true,
  clearMocks: true,
  restoreMocks: true,
  resetMocks: true,
  
  // 测试环境设置
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup/testEnvironment.ts'
  ],
  
  // 全局变量
  globals: {
    'ts-jest': {
      useESM: false,
      isolatedModules: true
    }
  },
  
  // 测试序列化配置，支持数据库隔离
  runner: 'jest-runner',
  testSequencer: '<rootDir>/tests/setup/testSequencer.js',
  
  // 缓存配置
  cache: true,
  cacheDirectory: '<rootDir>/node_modules/.cache/jest',
  
  // 错误报告配置
  errorOnDeprecated: true,
  notify: false,
  notifyMode: 'failure-change',
  
  // 测试结果报告
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'test-results',
      outputName: 'parallel-test-results.xml',
      suiteName: 'SmellPin Parallel Tests'
    }],
    ['jest-html-reporters', {
      publicPath: 'test-results',
      filename: 'parallel-test-report.html',
      pageTitle: 'SmellPin Parallel Test Report',
      expand: true,
      hideIcon: false
    }]
  ],
  
  // 监控模式配置
  // watchPlugins 已禁用以避免在非交互环境中的依赖冲突
  
  // 强制退出配置
  forceExit: true,
  detectOpenHandles: true,
  
  // 模块解析配置
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  
  // 测试环境变量
  testEnvironmentOptions: {
    NODE_ENV: 'test'
  }
};