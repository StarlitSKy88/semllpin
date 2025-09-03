const request = require('supertest');

describe('Simple Module Import Test', () => {
  test('should be able to import basic modules', () => {
    expect(1 + 1).toBe(2);
  });

  test('should be able to require testDatabase', () => {
    const { db } = require('../setup/testDatabase');
    expect(db).toBeDefined();
  });

  test('should be able to require testServer', () => {
    const app = require('../setup/testServer');
    expect(app).toBeDefined();
  });
});