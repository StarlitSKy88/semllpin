// 测试模块导入功能，不启动服务器
describe('Module Import Tests', () => {
  test('should import basic Node.js modules', () => {
    const path = require('path');
    const fs = require('fs');
    expect(path).toBeDefined();
    expect(fs).toBeDefined();
  });

  test('should import ts-node', () => {
    // 注册ts-node
    require('ts-node/register');
    expect(true).toBe(true);
  });

  test('should import database config without connecting', () => {
    // 只测试模块导入，不实际连接数据库
    require('ts-node/register');
    const databaseModule = require('../../src/config/database.ts');
    expect(databaseModule).toBeDefined();
    expect(typeof databaseModule.connectDatabase).toBe('function');
  });

  test('should import server class without instantiating', () => {
    // 只测试模块导入，不实例化服务器
    require('ts-node/register');
    const ServerClass = require('../../src/server.ts').default;
    expect(ServerClass).toBeDefined();
    expect(typeof ServerClass).toBe('function');
  });
});