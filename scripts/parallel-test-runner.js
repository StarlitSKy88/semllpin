#!/usr/bin/env node

/**
 * 并行测试执行器
 * 用于管理多个测试套件的并行执行，优化测试性能
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

// 测试套件配置
const TEST_SUITES = {
  // 快速单元测试 - 高优先级
  unit_fast: {
    name: 'Unit Tests (Fast)',
    pattern: 'src/**/__tests__/**/*.test.ts',
    exclude: ['integration', 'e2e', 'performance'],
    maxWorkers: Math.ceil(os.cpus().length / 2),
    timeout: 30000,
    priority: 1
  },
  
  // 集成测试 - 中等优先级
  integration: {
    name: 'Integration Tests',
    pattern: 'src/__tests__/integration/**/*.test.ts',
    exclude: [],
    maxWorkers: 2, // 数据库访问限制
    timeout: 60000,
    priority: 2
  },
  
  // 服务单元测试
  services: {
    name: 'Service Tests',
    pattern: 'tests/unit/services/**/*.test.ts',
    exclude: [],
    maxWorkers: 4,
    timeout: 45000,
    priority: 1
  },
  
  // 控制器测试
  controllers: {
    name: 'Controller Tests', 
    pattern: 'src/controllers/__tests__/**/*.test.ts',
    exclude: [],
    maxWorkers: 3,
    timeout: 30000,
    priority: 2
  },
  
  // 工具函数测试
  utils: {
    name: 'Utility Tests',
    pattern: 'src/utils/__tests__/**/*.test.ts', 
    exclude: [],
    maxWorkers: 4,
    timeout: 20000,
    priority: 1
  },
  
  // 前端测试
  frontend: {
    name: 'Frontend Tests',
    pattern: 'frontend/lib/services/__tests__/**/*.test.ts',
    exclude: [],
    maxWorkers: 3,
    timeout: 30000,
    priority: 2
  },
  
  // E2E测试 - 低优先级，串行执行
  e2e: {
    name: 'E2E Tests',
    pattern: 'tests/e2e/**/*.spec.ts',
    exclude: ['performance'],
    maxWorkers: 1, // E2E测试串行执行
    timeout: 120000,
    priority: 3
  },
  
  // 性能测试 - 最低优先级
  performance: {
    name: 'Performance Tests',
    pattern: 'tests/**/*performance*.test.ts',
    exclude: [],
    maxWorkers: 1,
    timeout: 180000,
    priority: 4
  }
};

class ParallelTestRunner {
  constructor() {
    this.results = {};
    this.runningTests = new Map();
    this.failedSuites = [];
    this.totalTests = 0;
    this.passedTests = 0;
    this.failedTests = 0;
    this.startTime = Date.now();
  }

  /**
   * 执行单个测试套件
   */
  async runTestSuite(suiteKey, suite) {
    return new Promise((resolve, reject) => {
      console.log(`🚀 Starting ${suite.name}...`);
      
      // 构建Jest命令
      const args = [
        '--config', this.getConfigForSuite(suiteKey),
        '--testPathPattern', suite.pattern,
        '--maxWorkers', suite.maxWorkers.toString(),
        '--testTimeout', suite.timeout.toString(),
        '--verbose',
        '--coverage=false', // 禁用覆盖率以提高速度
        '--passWithNoTests',
        ...this.getExcludeArgs(suite.exclude)
      ];
      
      // 如果是集成测试，使用串行模式
      if (suiteKey === 'integration' || suiteKey === 'e2e') {
        args.push('--runInBand');
      }
      
      const testProcess = spawn('npx', ['jest', ...args], {
        stdio: 'pipe',
        env: { 
          ...process.env,
          NODE_ENV: 'test',
          JEST_WORKER_ID: suiteKey,
          // 为不同套件分配不同的数据库
          TEST_DB_SUFFIX: `_${suiteKey}`
        }
      });
      
      let stdout = '';
      let stderr = '';
      
      testProcess.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      testProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      testProcess.on('close', (code) => {
        const result = {
          suite: suite.name,
          code,
          stdout,
          stderr,
          success: code === 0
        };
        
        this.results[suiteKey] = result;
        
        if (code === 0) {
          console.log(`✅ ${suite.name} completed successfully`);
          this.extractTestCounts(stdout);
        } else {
          console.log(`❌ ${suite.name} failed`);
          this.failedSuites.push(suiteKey);
        }
        
        resolve(result);
      });
      
      testProcess.on('error', (error) => {
        console.error(`💥 Failed to start ${suite.name}:`, error.message);
        reject(error);
      });
      
      this.runningTests.set(suiteKey, testProcess);
    });
  }

  /**
   * 获取测试套件的Jest配置文件
   */
  getConfigForSuite(suiteKey) {
    switch(suiteKey) {
      case 'frontend':
        return 'jest.frontend.config.js';
      case 'e2e':
        return 'jest.e2e.config.js';
      case 'integration':
        return 'jest.backend.config.js';
      default:
        return 'jest.backend.config.js';
    }
  }

  /**
   * 构建排除参数
   */
  getExcludeArgs(excludePatterns) {
    if (!excludePatterns.length) return [];
    
    return excludePatterns.flatMap(pattern => [
      '--testPathIgnorePatterns', pattern
    ]);
  }

  /**
   * 提取测试计数信息
   */
  extractTestCounts(stdout) {
    const passedMatch = stdout.match(/(\d+) passed/);
    const failedMatch = stdout.match(/(\d+) failed/);
    const totalMatch = stdout.match(/(\d+) total/);
    
    if (passedMatch) this.passedTests += parseInt(passedMatch[1]);
    if (failedMatch) this.failedTests += parseInt(failedMatch[1]);
    if (totalMatch) this.totalTests += parseInt(totalMatch[1]);
  }

  /**
   * 按优先级排序套件
   */
  getSortedSuites() {
    return Object.entries(TEST_SUITES).sort(([, a], [, b]) => {
      return a.priority - b.priority;
    });
  }

  /**
   * 并行执行测试
   */
  async runParallel() {
    console.log('🎯 Starting Parallel Test Execution\n');
    
    const sortedSuites = this.getSortedSuites();
    const maxConcurrency = Math.min(4, os.cpus().length); // 最多4个并行套件
    
    // 分批执行，高优先级先执行
    const batches = [];
    for (let i = 0; i < sortedSuites.length; i += maxConcurrency) {
      batches.push(sortedSuites.slice(i, i + maxConcurrency));
    }
    
    for (const batch of batches) {
      console.log(`📦 Executing batch: ${batch.map(([key, suite]) => suite.name).join(', ')}\n`);
      
      const promises = batch.map(([suiteKey, suite]) => 
        this.runTestSuite(suiteKey, suite)
      );
      
      await Promise.allSettled(promises);
      console.log(''); // 空行分隔
    }
  }

  /**
   * 串行执行测试（回退模式）
   */
  async runSerial() {
    console.log('🔄 Running tests in serial mode (fallback)\n');
    
    const sortedSuites = this.getSortedSuites();
    
    for (const [suiteKey, suite] of sortedSuites) {
      try {
        await this.runTestSuite(suiteKey, suite);
      } catch (error) {
        console.error(`Failed to run ${suite.name}:`, error.message);
        this.failedSuites.push(suiteKey);
      }
    }
  }

  /**
   * 生成执行报告
   */
  generateReport() {
    const duration = Date.now() - this.startTime;
    const minutes = Math.floor(duration / 60000);
    const seconds = Math.floor((duration % 60000) / 1000);
    
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST EXECUTION SUMMARY');
    console.log('='.repeat(60));
    console.log(`⏱️  Total Duration: ${minutes}m ${seconds}s`);
    console.log(`📈 Total Tests: ${this.totalTests}`);
    console.log(`✅ Passed: ${this.passedTests}`);
    console.log(`❌ Failed: ${this.failedTests}`);
    console.log(`📦 Test Suites: ${Object.keys(this.results).length}`);
    
    const successfulSuites = Object.values(this.results).filter(r => r.success).length;
    console.log(`✅ Successful Suites: ${successfulSuites}`);
    console.log(`❌ Failed Suites: ${this.failedSuites.length}`);
    
    if (this.failedSuites.length > 0) {
      console.log('\n❌ FAILED SUITES:');
      this.failedSuites.forEach(suite => {
        const result = this.results[suite];
        console.log(`   • ${result?.suite || suite}`);
        if (result?.stderr) {
          console.log(`     Error: ${result.stderr.split('\n')[0]}`);
        }
      });
    }
    
    console.log('\n📋 SUITE DETAILS:');
    Object.entries(this.results).forEach(([key, result]) => {
      const status = result.success ? '✅' : '❌';
      console.log(`   ${status} ${result.suite}`);
    });
    
    console.log('='.repeat(60));
    
    return this.failedSuites.length === 0;
  }

  /**
   * 清理资源
   */
  cleanup() {
    // 终止所有运行中的测试进程
    this.runningTests.forEach((process, suiteKey) => {
      if (!process.killed) {
        console.log(`🛑 Terminating ${suiteKey}...`);
        process.kill('SIGTERM');
      }
    });
    
    this.runningTests.clear();
  }
}

// 主执行函数
async function main() {
  const runner = new ParallelTestRunner();
  
  // 处理中断信号
  process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT, cleaning up...');
    runner.cleanup();
    process.exit(1);
  });
  
  process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM, cleaning up...');
    runner.cleanup();
    process.exit(1);
  });
  
  try {
    const mode = process.argv.includes('--serial') ? 'serial' : 'parallel';
    
    if (mode === 'parallel') {
      await runner.runParallel();
    } else {
      await runner.runSerial();
    }
    
    const success = runner.generateReport();
    
    // 返回适当的退出码
    process.exit(success ? 0 : 1);
    
  } catch (error) {
    console.error('💥 Fatal error:', error.message);
    runner.cleanup();
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { ParallelTestRunner, TEST_SUITES };