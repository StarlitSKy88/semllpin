module.exports = {
  preset: 'ts-jest',
  displayName: 'E2E Tests',
  testEnvironment: 'node',
  testMatch: [
    '<rootDir>/tests/e2e/**/*.spec.ts',
    '<rootDir>/tests/e2e/**/*.test.js',
    '<rootDir>/frontend/e2e/**/*.spec.ts'
  ],
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup.js'
  ],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      useESM: true,
      isolatedModules: true
    }],
  },
  maxWorkers: 1, // E2E tests should run serially
  testTimeout: 120000, // 2 minutes for E2E tests
  slowTestThreshold: 30000,
  detectOpenHandles: true,
  forceExit: true,
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.test.{ts,tsx}',
  ],
};