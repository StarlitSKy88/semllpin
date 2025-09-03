// SmellPin 生产级测试配置 - 融合优化版
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  maxWorkers: '75%', // 并行执行优化

  // 测试文件匹配 - Level 1-5 层次结构
  projects: [
    {
      displayName: 'Level 1: Unit Tests',
      testMatch: ['**/tests/unit/**/*.test.ts'],
      testEnvironment: 'node'
    },
    {
      displayName: 'Level 2: Integration Tests', 
      testMatch: ['**/tests/integration/**/*.test.ts'],
      testEnvironment: 'node',
      globalSetup: '<rootDir>/tests/setup/testcontainers-setup.ts',
      globalTeardown: '<rootDir>/tests/setup/testcontainers-teardown.ts'
    },
    {
      displayName: 'Level 3: E2E Tests',
      testMatch: ['**/tests/e2e/**/*.test.ts'], 
      testEnvironment: 'node',
      testTimeout: 30000
    },
    {
      displayName: 'Level 4: Performance Tests',
      testMatch: ['**/tests/performance/**/*.test.ts'],
      testEnvironment: 'node',
      testTimeout: 120000
    },
    {
      displayName: 'Level 5: Multi-Agent Simulation',
      testMatch: ['**/tests/multi-agent/**/*.test.ts'],
      testEnvironment: 'node', 
      testTimeout: 300000
    }
  ],

  // 80% 覆盖率阈值 - CI门禁要求
  coverageThreshold: {
    global: {
      statements: 80,
      branches: 80, 
      functions: 80,
      lines: 80
    },
    // 核心模块更严格
    './src/services/**': {
      statements: 90,
      branches: 85,
      functions: 90,
      lines: 90
    },
    './src/controllers/**': {
      statements: 85,
      branches: 80,
      functions: 85, 
      lines: 85
    }
  },

  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/migrations/**',
    '!src/seeds/**',
    '!src/types/**',
    '!src/server.ts'
  ],

  coverageDirectory: 'coverage',
  coverageReporters: [
    'text-summary',
    'lcov', 
    'html',
    'json',
    'cobertura' // Jenkins/Azure DevOps兼容
  ],

  // CI报告输出 - JUnit XML
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'test-results',
      outputName: 'junit.xml',
      ancestorSeparator: ' › ',
      uniqueOutputName: 'false',
      suiteNameTemplate: '{displayName}',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}'
    }],
    ['jest-html-reporters', {
      publicPath: 'test-results',
      filename: 'test-report.html',
      pageTitle: 'SmellPin Test Report',
      logoImgPath: './logo.png',
      expand: true,
      hideIcon: false,
      dateFormat: 'yyyy/mm/dd HH:MM:ss'
    }]
  ],

  // 模块路径映射
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1'
  },

  // TypeScript 转换配置
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        module: 'commonjs',
        target: 'es2020',
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true
      }
    }]
  },

  // 测试环境设置
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup/jest-setup.ts'
  ],

  // 测试数据库配置
  testEnvironmentOptions: {
    NODE_ENV: 'test'
  },

  // 错误处理配置
  errorOnDeprecated: true,
  clearMocks: true,
  restoreMocks: true,
  resetMocks: true,

  // 缓存配置
  cache: true,
  cacheDirectory: '<rootDir>/node_modules/.cache/jest',

  // 性能配置
  detectOpenHandles: true,
  forceExit: false,
  
  // 模块文件扩展名
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],

  // 忽略模式
  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/dist/',
    '<rootDir>/coverage/'
  ],

  transformIgnorePatterns: [
    'node_modules/(?!(.*\\.mjs$))'
  ],

  // 全局变量
  globals: {
    'ts-jest': {
      useESM: false,
      isolatedModules: true
    }
  }
};