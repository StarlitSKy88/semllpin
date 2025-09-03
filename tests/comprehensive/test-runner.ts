/**
 * SmellPin API全面测试运行器
 * 
 * 统一运行所有测试套件并生成详细报告
 */

import { spawn } from 'child_process';
import { TestMetrics } from '../utils/test-metrics';
import fs from 'fs';
import path from 'path';

interface TestSuite {
  name: string;
  file: string;
  timeout: number;
  priority: number;
  dependencies?: string[];
}

class ComprehensiveTestRunner {
  private testMetrics: TestMetrics;
  private suites: TestSuite[];
  private results: Map<string, any> = new Map();

  constructor() {
    this.testMetrics = new TestMetrics();
    this.suites = [
      {
        name: 'API基础测试',
        file: './tests/comprehensive/api-test-suite.ts',
        timeout: 300000, // 5分钟
        priority: 1,
      },
      {
        name: '支付API测试',
        file: './tests/comprehensive/payment-api-tests.ts',
        timeout: 180000, // 3分钟
        priority: 2,
        dependencies: ['API基础测试']
      },
      {
        name: '数据库操作测试',
        file: './tests/comprehensive/database-tests.ts',
        timeout: 240000, // 4分钟
        priority: 1,
      },
      {
        name: 'WebSocket测试',
        file: './tests/comprehensive/websocket-tests.ts',
        timeout: 180000, // 3分钟
        priority: 2,
        dependencies: ['API基础测试']
      },
      {
        name: '安全性测试',
        file: './tests/comprehensive/security-tests.ts',
        timeout: 600000, // 10分钟
        priority: 3,
        dependencies: ['API基础测试', '数据库操作测试']
      },
      {
        name: '性能测试',
        file: './tests/comprehensive/performance-tests.ts',
        timeout: 900000, // 15分钟
        priority: 4,
        dependencies: ['API基础测试', '数据库操作测试']
      }
    ];
  }

  async runAllTests(): Promise<void> {
    console.log('🚀 开始运行SmellPin API全面测试套件...\n');
    
    this.testMetrics.recordPerformanceMetric('test_suite_start');

    try {
      // 按优先级排序测试套件
      const sortedSuites = this.suites.sort((a, b) => a.priority - b.priority);
      
      // 运行每个测试套件
      for (const suite of sortedSuites) {
        await this.runTestSuite(suite);
      }

      // 生成综合报告
      await this.generateComprehensiveReport();

    } catch (error) {
      console.error('❌ 测试套件执行失败:', error);
      process.exit(1);
    } finally {
      this.testMetrics.recordPerformanceMetric('test_suite_end');
    }
  }

  private async runTestSuite(suite: TestSuite): Promise<void> {
    console.log(`\n📋 运行测试套件: ${suite.name}`);
    console.log(`⏱️  超时设置: ${suite.timeout / 1000}秒`);
    
    if (suite.dependencies) {
      console.log(`📦 依赖: ${suite.dependencies.join(', ')}`);
      
      // 检查依赖是否已完成
      for (const dep of suite.dependencies) {
        if (!this.results.has(dep)) {
          throw new Error(`依赖测试套件 "${dep}" 未完成`);
        }
        
        const depResult = this.results.get(dep);
        if (!depResult.success) {
          console.log(`⚠️  依赖测试 "${dep}" 失败，跳过 "${suite.name}"`);
          this.results.set(suite.name, {
            success: false,
            skipped: true,
            reason: `依赖测试失败: ${dep}`,
            timestamp: new Date().toISOString()
          });
          return;
        }
      }
    }

    const startTime = Date.now();
    this.testMetrics.recordPerformanceMetric(`${suite.name}_start`);

    try {
      const result = await this.executeJestTest(suite.file, suite.timeout);
      const duration = Date.now() - startTime;

      this.results.set(suite.name, {
        success: result.success,
        duration,
        testCount: result.numTotalTests,
        passedTests: result.numPassedTests,
        failedTests: result.numFailedTests,
        coverage: result.coverageMap,
        timestamp: new Date().toISOString()
      });

      if (result.success) {
        console.log(`✅ ${suite.name} 完成 (${duration}ms)`);
        console.log(`   通过: ${result.numPassedTests}, 失败: ${result.numFailedTests}`);
      } else {
        console.log(`❌ ${suite.name} 失败 (${duration}ms)`);
        console.log(`   通过: ${result.numPassedTests}, 失败: ${result.numFailedTests}`);
        if (result.failureMessage) {
          console.log(`   错误信息: ${result.failureMessage}`);
        }
      }

    } catch (error) {
      const duration = Date.now() - startTime;
      console.log(`💥 ${suite.name} 执行异常 (${duration}ms):`, error);
      
      this.results.set(suite.name, {
        success: false,
        duration,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString()
      });
    } finally {
      this.testMetrics.recordPerformanceMetric(`${suite.name}_end`);
    }
  }

  private executeJestTest(testFile: string, timeout: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const jestArgs = [
        testFile,
        '--coverage',
        '--json',
        '--outputFile=temp-test-results.json',
        `--testTimeout=${timeout}`,
        '--verbose'
      ];

      const jestProcess = spawn('npx', ['jest', ...jestArgs], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, NODE_ENV: 'test' }
      });

      let stdout = '';
      let stderr = '';

      jestProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        // 实时输出测试进度
        const lines = data.toString().split('\n');
        lines.forEach((line: string) => {
          if (line.trim() && (line.includes('PASS') || line.includes('FAIL') || line.includes('●'))) {
            console.log(`    ${line.trim()}`);
          }
        });
      });

      jestProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      jestProcess.on('close', (code) => {
        try {
          // 尝试读取Jest输出的JSON结果
          let result: any = {};
          
          if (fs.existsSync('temp-test-results.json')) {
            const resultData = fs.readFileSync('temp-test-results.json', 'utf8');
            result = JSON.parse(resultData);
            fs.unlinkSync('temp-test-results.json'); // 清理临时文件
          }

          resolve({
            success: code === 0,
            exitCode: code,
            stdout,
            stderr,
            numTotalTests: result.numTotalTests || 0,
            numPassedTests: result.numPassedTests || 0,
            numFailedTests: result.numFailedTests || 0,
            testResults: result.testResults || [],
            coverageMap: result.coverageMap,
            failureMessage: result.testResults?.[0]?.message
          });
        } catch (error) {
          resolve({
            success: false,
            exitCode: code,
            stdout,
            stderr,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      });

      jestProcess.on('error', (error) => {
        reject(error);
      });

      // 处理超时
      setTimeout(() => {
        jestProcess.kill('SIGKILL');
        reject(new Error(`测试超时 (${timeout}ms)`));
      }, timeout + 10000); // 额外10秒缓冲时间
    });
  }

  private async generateComprehensiveReport(): Promise<void> {
    console.log('\n📊 生成综合测试报告...');

    // 计算总体统计
    const totalSuites = this.suites.length;
    const completedSuites = Array.from(this.results.values()).filter(r => !r.skipped);
    const successfulSuites = completedSuites.filter(r => r.success);
    const failedSuites = completedSuites.filter(r => !r.success);
    const skippedSuites = Array.from(this.results.values()).filter(r => r.skipped);

    const totalTests = completedSuites.reduce((sum, r) => sum + (r.testCount || 0), 0);
    const totalPassed = completedSuites.reduce((sum, r) => sum + (r.passedTests || 0), 0);
    const totalFailed = completedSuites.reduce((sum, r) => sum + (r.failedTests || 0), 0);
    const totalDuration = completedSuites.reduce((sum, r) => sum + (r.duration || 0), 0);

    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalSuites,
        completedSuites: completedSuites.length,
        successfulSuites: successfulSuites.length,
        failedSuites: failedSuites.length,
        skippedSuites: skippedSuites.length,
        successRate: completedSuites.length > 0 ? (successfulSuites.length / completedSuites.length * 100) : 0,
        totalTests,
        totalPassed,
        totalFailed,
        testPassRate: totalTests > 0 ? (totalPassed / totalTests * 100) : 0,
        totalDuration: totalDuration,
        averageSuiteDuration: completedSuites.length > 0 ? totalDuration / completedSuites.length : 0
      },
      suiteResults: Object.fromEntries(this.results),
      performanceMetrics: this.testMetrics.generateReport(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        memory: process.memoryUsage(),
        cwd: process.cwd(),
        env: process.env.NODE_ENV
      },
      recommendations: this.generateRecommendations(successfulSuites, failedSuites, completedSuites)
    };

    // 保存JSON报告
    const reportsDir = path.join(process.cwd(), 'tests', 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const jsonReportPath = path.join(reportsDir, `comprehensive-report-${timestamp}.json`);
    fs.writeFileSync(jsonReportPath, JSON.stringify(report, null, 2));

    // 生成HTML报告
    const htmlReportPath = await this.generateHtmlReport(report, reportsDir, timestamp);

    // 打印控制台摘要
    this.printConsoleSummary(report);

    console.log(`\n📋 详细报告已保存:`);
    console.log(`   JSON: ${jsonReportPath}`);
    console.log(`   HTML: ${htmlReportPath}`);
  }

  private generateRecommendations(successful: any[], failed: any[], all: any[]): string[] {
    const recommendations: string[] = [];

    // 基于测试结果生成建议
    const successRate = successful.length / all.length * 100;
    if (successRate < 80) {
      recommendations.push('测试成功率较低，建议检查代码质量和测试环境配置');
    }

    const avgDuration = all.reduce((sum, r) => sum + (r.duration || 0), 0) / all.length;
    if (avgDuration > 60000) { // 1分钟
      recommendations.push('测试执行时间较长，建议优化测试用例或并行执行');
    }

    if (failed.some(f => f.error && f.error.includes('timeout'))) {
      recommendations.push('存在超时测试，建议检查网络连接和服务器性能');
    }

    if (all.some(r => r.coverage && r.coverage.summary?.total?.lines?.pct < 80)) {
      recommendations.push('代码覆盖率不足80%，建议增加测试用例');
    }

    return recommendations;
  }

  private async generateHtmlReport(report: any, reportsDir: string, timestamp: string): Promise<string> {
    const htmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin API 综合测试报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin: 0 0 10px 0; font-size: 2.5em; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .summary-card h3 { margin: 0 0 15px 0; color: #333; font-size: 1.1em; }
        .metric { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .metric-value { font-weight: bold; font-size: 1.2em; }
        .success { color: #4CAF50; }
        .warning { color: #ff9800; }
        .error { color: #f44336; }
        .section { background: white; margin-bottom: 20px; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #f8f9fa; padding: 20px; border-bottom: 1px solid #dee2e6; }
        .section-content { padding: 20px; }
        .suite-result { border: 1px solid #dee2e6; border-radius: 5px; margin-bottom: 15px; overflow: hidden; }
        .suite-header { padding: 15px; background: #f8f9fa; display: flex; justify-content: space-between; align-items: center; }
        .suite-details { padding: 15px; background: white; }
        .status-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .status-success { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-skipped { background: #fff3cd; color: #856404; }
        .progress-bar { width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: #4CAF50; transition: width 0.3s ease; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; font-weight: 600; }
        .recommendations { background: #e3f2fd; border-left: 4px solid #2196F3; padding: 20px; margin: 20px 0; }
        .recommendations h3 { margin: 0 0 15px 0; color: #1976D2; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SmellPin API 综合测试报告</h1>
            <p>生成时间: ${report.timestamp}</p>
            <p>总耗时: ${Math.round(report.summary.totalDuration / 1000)}秒</p>
            <p>环境: Node.js ${report.environment.nodeVersion} on ${report.environment.platform}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>测试套件概览</h3>
                <div class="metric">
                    <span>总套件数</span>
                    <span class="metric-value">${report.summary.totalSuites}</span>
                </div>
                <div class="metric">
                    <span>成功套件</span>
                    <span class="metric-value success">${report.summary.successfulSuites}</span>
                </div>
                <div class="metric">
                    <span>失败套件</span>
                    <span class="metric-value error">${report.summary.failedSuites}</span>
                </div>
                <div class="metric">
                    <span>跳过套件</span>
                    <span class="metric-value warning">${report.summary.skippedSuites}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${report.summary.successRate}%"></div>
                </div>
                <p style="text-align: center; margin: 10px 0 0 0; font-size: 0.9em; color: #666;">
                    成功率: ${report.summary.successRate.toFixed(1)}%
                </p>
            </div>

            <div class="summary-card">
                <h3>测试用例统计</h3>
                <div class="metric">
                    <span>总测试数</span>
                    <span class="metric-value">${report.summary.totalTests}</span>
                </div>
                <div class="metric">
                    <span>通过测试</span>
                    <span class="metric-value success">${report.summary.totalPassed}</span>
                </div>
                <div class="metric">
                    <span>失败测试</span>
                    <span class="metric-value error">${report.summary.totalFailed}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${report.summary.testPassRate}%"></div>
                </div>
                <p style="text-align: center; margin: 10px 0 0 0; font-size: 0.9em; color: #666;">
                    通过率: ${report.summary.testPassRate.toFixed(1)}%
                </p>
            </div>

            <div class="summary-card">
                <h3>性能指标</h3>
                <div class="metric">
                    <span>总耗时</span>
                    <span class="metric-value">${Math.round(report.summary.totalDuration / 1000)}s</span>
                </div>
                <div class="metric">
                    <span>平均耗时</span>
                    <span class="metric-value">${Math.round(report.summary.averageSuiteDuration / 1000)}s</span>
                </div>
                <div class="metric">
                    <span>内存使用</span>
                    <span class="metric-value">${Math.round(report.environment.memory.heapUsed / 1024 / 1024)}MB</span>
                </div>
            </div>
        </div>

        ${report.recommendations.length > 0 ? `
        <div class="recommendations">
            <h3>优化建议</h3>
            <ul>
                ${report.recommendations.map((rec: string) => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
        ` : ''}

        <div class="section">
            <div class="section-header">
                <h2>测试套件详情</h2>
            </div>
            <div class="section-content">
                ${Object.entries(report.suiteResults).map(([name, result]: [string, any]) => `
                <div class="suite-result">
                    <div class="suite-header">
                        <span style="font-weight: bold;">${name}</span>
                        <span class="status-badge ${result.skipped ? 'status-skipped' : result.success ? 'status-success' : 'status-failed'}">
                            ${result.skipped ? '跳过' : result.success ? '通过' : '失败'}
                        </span>
                    </div>
                    <div class="suite-details">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                            ${result.duration ? `<div>耗时: ${Math.round(result.duration / 1000)}秒</div>` : ''}
                            ${result.testCount ? `<div>测试数: ${result.testCount}</div>` : ''}
                            ${result.passedTests ? `<div class="success">通过: ${result.passedTests}</div>` : ''}
                            ${result.failedTests ? `<div class="error">失败: ${result.failedTests}</div>` : ''}
                        </div>
                        ${result.error ? `<div style="margin-top: 10px; color: #f44336;">错误: ${result.error}</div>` : ''}
                        ${result.reason ? `<div style="margin-top: 10px; color: #ff9800;">原因: ${result.reason}</div>` : ''}
                    </div>
                </div>
                `).join('')}
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>系统环境信息</h2>
            </div>
            <div class="section-content">
                <table>
                    <tr><td>Node.js版本</td><td>${report.environment.nodeVersion}</td></tr>
                    <tr><td>操作系统</td><td>${report.environment.platform} (${report.environment.arch})</td></tr>
                    <tr><td>内存使用</td><td>${Math.round(report.environment.memory.heapUsed / 1024 / 1024)}MB / ${Math.round(report.environment.memory.heapTotal / 1024 / 1024)}MB</td></tr>
                    <tr><td>工作目录</td><td>${report.environment.cwd}</td></tr>
                    <tr><td>测试环境</td><td>${report.environment.env}</td></tr>
                </table>
            </div>
        </div>
    </div>
</body>
</html>`;

    const htmlPath = path.join(reportsDir, `comprehensive-report-${timestamp}.html`);
    fs.writeFileSync(htmlPath, htmlContent);
    return htmlPath;
  }

  private printConsoleSummary(report: any): void {
    console.log('\n' + '='.repeat(60));
    console.log('📊 测试套件执行摘要');
    console.log('='.repeat(60));

    console.log(`\n🧪 测试套件: ${report.summary.successfulSuites}/${report.summary.totalSuites} 成功 (${report.summary.successRate.toFixed(1)}%)`);
    console.log(`🔬 测试用例: ${report.summary.totalPassed}/${report.summary.totalTests} 通过 (${report.summary.testPassRate.toFixed(1)}%)`);
    console.log(`⏱️  总耗时: ${Math.round(report.summary.totalDuration / 1000)}秒`);
    console.log(`💾 内存使用: ${Math.round(report.environment.memory.heapUsed / 1024 / 1024)}MB`);

    if (report.summary.failedSuites > 0) {
      console.log(`\n❌ 失败的测试套件:`);
      Object.entries(report.suiteResults).forEach(([name, result]: [string, any]) => {
        if (!result.success && !result.skipped) {
          console.log(`   • ${name}: ${result.error || '测试失败'}`);
        }
      });
    }

    if (report.summary.skippedSuites > 0) {
      console.log(`\n⏭️  跳过的测试套件:`);
      Object.entries(report.suiteResults).forEach(([name, result]: [string, any]) => {
        if (result.skipped) {
          console.log(`   • ${name}: ${result.reason}`);
        }
      });
    }

    if (report.recommendations.length > 0) {
      console.log(`\n💡 优化建议:`);
      report.recommendations.forEach((rec: string, index: number) => {
        console.log(`   ${index + 1}. ${rec}`);
      });
    }

    const overallResult = report.summary.successRate >= 80 ? '✅ 通过' : '❌ 需要改进';
    console.log(`\n🏆 总体评价: ${overallResult}`);
    console.log('='.repeat(60));
  }
}

// 如果直接运行此文件，执行测试套件
if (require.main === module) {
  const runner = new ComprehensiveTestRunner();
  runner.runAllTests().catch(error => {
    console.error('测试运行器执行失败:', error);
    process.exit(1);
  });
}

export default ComprehensiveTestRunner;