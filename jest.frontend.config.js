module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src'],
  testMatch: [
    '**/components/**/*.test.+(ts|tsx)',
    '**/hooks/**/*.test.+(ts|tsx)',
    '**/pages/**/*.test.+(ts|tsx)',
    '**/utils/**/*.test.+(ts|tsx)',
    '**/__tests__/**/*.(test|spec).+(ts|tsx)'
  ],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      tsconfig: {
        jsx: 'react-jsx'
      }
    }]
  },
  collectCoverageFrom: [
    'src/components/**/*.{ts,tsx}',
    'src/hooks/**/*.{ts,tsx}',
    'src/pages/**/*.{ts,tsx}',
    'src/utils/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/__mocks__/**',
    '!src/types/**'
  ],
  coverageDirectory: 'coverage/frontend',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy'
  },
  testTimeout: 10000,
  verbose: true,
  clearMocks: true,
  restoreMocks: true
};