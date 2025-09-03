module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: [
    '**/tests/**/*.+(ts|js)',
    '**/src/**/*.test.+(ts|js)',
    '!**/src/components/**',
    '!**/src/hooks/**',
    '!**/src/pages/**'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  transformIgnorePatterns: [
    'node_modules/(?!(.*\\.mjs$))'
  ],
  collectCoverageFrom: [
    'src/controllers/**/*.{ts,js}',
    'src/services/**/*.{ts,js}',
    'src/models/**/*.{ts,js}',
    'src/middleware/**/*.{ts,js}',
    'src/routes/**/*.{ts,js}',
    '!src/**/*.d.ts',
    '!src/server.ts',
    '!src/migrations/**',
    '!src/__mocks__/**',
    '!src/types/**'
  ],
  coverageDirectory: 'coverage/backend',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  testTimeout: 30000,
  verbose: true,
  clearMocks: true,
  restoreMocks: true,
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js']
};