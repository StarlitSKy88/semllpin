// 测试序列化器 - 管理数据库并发隔离
const TestSequencer = require('@jest/test-sequencer').default;

class DatabaseTestSequencer extends TestSequencer {
  sort(tests) {
    // 将测试按优先级分组
    const unitTests = [];
    const integrationTests = [];
    const e2eTests = [];
    const databaseTests = [];

    tests.forEach(test => {
      const testPath = test.path;
      
      if (testPath.includes('/unit/') || testPath.includes('.unit.test.')) {
        unitTests.push(test);
      } else if (testPath.includes('/integration/') || testPath.includes('.integration.test.')) {
        integrationTests.push(test);
      } else if (testPath.includes('/e2e/') || testPath.includes('.e2e.test.')) {
        e2eTests.push(test);
      } else if (testPath.includes('database') || testPath.includes('model')) {
        databaseTests.push(test);
      } else {
        unitTests.push(test); // 默认作为单元测试
      }
    });

    // 按执行顺序返回：单元测试 -> 数据库测试 -> 集成测试 -> E2E测试
    return [
      ...this.sortByModificationTime(unitTests),
      ...this.sortByModificationTime(databaseTests), 
      ...this.sortByModificationTime(integrationTests),
      ...this.sortByModificationTime(e2eTests)
    ];
  }

  sortByModificationTime(tests) {
    // 按文件修改时间排序，最新的文件优先测试
    return tests.sort((a, b) => {
      const aStats = require('fs').statSync(a.path);
      const bStats = require('fs').statSync(b.path);
      return bStats.mtime - aStats.mtime;
    });
  }
}

module.exports = DatabaseTestSequencer;