import fs from 'fs';
import path from 'path';

/**
 * SmellPin前端E2E测试报告生成器
 * 
 * 功能：
 * 1. 收集测试执行结果
 * 2. 分析性能指标
 * 3. 生成详细的HTML报告
 * 4. 提供改进建议
 * 
 * @author E2E Test Report Generator
 * @version 1.0.0
 */

interface TestResult {
  title: string;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  screenshots: string[];
  performanceMetrics?: any;
}

interface TestSuite {
  name: string;
  results: TestResult[];
  totalDuration: number;
  passRate: number;
}

interface PerformanceMetrics {
  pageLoad: {
    coldStart: number;
    hotStart: number;
    fcp: number;
    lcp: number;
    cls: number;
  };
  interactions: {
    averageResponseTime: number;
    maxResponseTime: number;
  };
  memory: {
    initialUsage: number;
    finalUsage: number;
    growthPercentage: number;
  };
  network: {
    apiRequestCount: number;
    totalDataTransferred: number;
    cacheHitRate: number;
  };
}

export class TestReportGenerator {
  private testSuites: TestSuite[] = [];
  private overallMetrics: PerformanceMetrics;
  private startTime: Date;
  private endTime: Date;
  private reportDir: string;

  constructor(reportDir = './test-results') {
    this.reportDir = reportDir;
    this.startTime = new Date();
    this.initializeReportDirectory();
  }

  private initializeReportDirectory(): void {
    if (!fs.existsSync(this.reportDir)) {
      fs.mkdirSync(this.reportDir, { recursive: true });
    }

    // 创建子目录
    const subDirs = ['screenshots', 'videos', 'performance-data', 'raw-data'];
    subDirs.forEach(dir => {
      const dirPath = path.join(this.reportDir, dir);
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }
    });
  }

  public addTestSuite(suite: TestSuite): void {
    this.testSuites.push(suite);
  }

  public setOverallMetrics(metrics: PerformanceMetrics): void {
    this.overallMetrics = metrics;
  }

  public finalize(): void {
    this.endTime = new Date();
  }

  public generateReport(): string {
    const reportPath = path.join(this.reportDir, 'e2e-test-report.html');
    const reportHtml = this.buildReportHtml();
    
    fs.writeFileSync(reportPath, reportHtml, 'utf8');
    
    // 生成JSON数据文件供其他工具使用
    this.generateJsonReport();
    
    // 生成性能摘要
    this.generatePerformanceSummary();
    
    console.log(`📊 测试报告已生成: ${reportPath}`);
    return reportPath;
  }

  private buildReportHtml(): string {
    const totalTests = this.testSuites.reduce((sum, suite) => sum + suite.results.length, 0);
    const passedTests = this.testSuites.reduce((sum, suite) => 
      sum + suite.results.filter(r => r.status === 'passed').length, 0);
    const failedTests = this.testSuites.reduce((sum, suite) => 
      sum + suite.results.filter(r => r.status === 'failed').length, 0);
    const skippedTests = this.testSuites.reduce((sum, suite) => 
      sum + suite.results.filter(r => r.status === 'skipped').length, 0);
    
    const overallPassRate = totalTests > 0 ? (passedTests / totalTests * 100).toFixed(2) : '0';
    const totalDuration = (this.endTime.getTime() - this.startTime.getTime()) / 1000;

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 前端 E2E 测试报告</title>
    <style>
        ${this.getReportStyles()}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🌸 SmellPin 前端 E2E 测试报告</h1>
            <div class="meta-info">
                <p><strong>生成时间：</strong> ${this.endTime.toLocaleString('zh-CN')}</p>
                <p><strong>测试持续时间：</strong> ${totalDuration.toFixed(2)} 秒</p>
                <p><strong>测试环境：</strong> Playwright + TypeScript</p>
            </div>
        </header>

        <section class="summary">
            <h2>📈 测试摘要</h2>
            <div class="stats-grid">
                <div class="stat-card ${overallPassRate === '100.00' ? 'success' : failedTests > 0 ? 'danger' : 'warning'}">
                    <h3>总体通过率</h3>
                    <div class="stat-value">${overallPassRate}%</div>
                </div>
                <div class="stat-card info">
                    <h3>总测试数</h3>
                    <div class="stat-value">${totalTests}</div>
                </div>
                <div class="stat-card success">
                    <h3>通过</h3>
                    <div class="stat-value">${passedTests}</div>
                </div>
                <div class="stat-card danger">
                    <h3>失败</h3>
                    <div class="stat-value">${failedTests}</div>
                </div>
                <div class="stat-card warning">
                    <h3>跳过</h3>
                    <div class="stat-value">${skippedTests}</div>
                </div>
            </div>
            
            <div class="chart-container">
                <canvas id="testResultsChart"></canvas>
            </div>
        </section>

        ${this.buildPerformanceSection()}
        ${this.buildTestSuitesSection()}
        ${this.buildRecommendationsSection()}
        ${this.buildAppendixSection()}
    </div>

    <script>
        ${this.getReportScripts()}
    </script>
</body>
</html>`;
  }

  private buildPerformanceSection(): string {
    if (!this.overallMetrics) return '';

    const metrics = this.overallMetrics;
    
    return `
        <section class="performance">
            <h2>⚡ 性能指标分析</h2>
            
            <div class="performance-grid">
                <div class="performance-card">
                    <h3>页面加载性能</h3>
                    <div class="metric-list">
                        <div class="metric-item">
                            <span class="metric-label">冷启动加载时间:</span>
                            <span class="metric-value ${metrics.pageLoad.coldStart < 3000 ? 'good' : metrics.pageLoad.coldStart < 5000 ? 'warning' : 'poor'}">${metrics.pageLoad.coldStart}ms</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">热启动加载时间:</span>
                            <span class="metric-value ${metrics.pageLoad.hotStart < 1000 ? 'good' : metrics.pageLoad.hotStart < 2000 ? 'warning' : 'poor'}">${metrics.pageLoad.hotStart}ms</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">首次内容绘制 (FCP):</span>
                            <span class="metric-value ${metrics.pageLoad.fcp < 1800 ? 'good' : metrics.pageLoad.fcp < 3000 ? 'warning' : 'poor'}">${metrics.pageLoad.fcp}ms</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">最大内容绘制 (LCP):</span>
                            <span class="metric-value ${metrics.pageLoad.lcp < 2500 ? 'good' : metrics.pageLoad.lcp < 4000 ? 'warning' : 'poor'}">${metrics.pageLoad.lcp}ms</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">累计布局偏移 (CLS):</span>
                            <span class="metric-value ${metrics.pageLoad.cls < 0.1 ? 'good' : metrics.pageLoad.cls < 0.25 ? 'warning' : 'poor'}">${metrics.pageLoad.cls}</span>
                        </div>
                    </div>
                </div>

                <div class="performance-card">
                    <h3>交互响应性能</h3>
                    <div class="metric-list">
                        <div class="metric-item">
                            <span class="metric-label">平均响应时间:</span>
                            <span class="metric-value ${metrics.interactions.averageResponseTime < 100 ? 'good' : metrics.interactions.averageResponseTime < 300 ? 'warning' : 'poor'}">${metrics.interactions.averageResponseTime}ms</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">最大响应时间:</span>
                            <span class="metric-value ${metrics.interactions.maxResponseTime < 500 ? 'good' : metrics.interactions.maxResponseTime < 1000 ? 'warning' : 'poor'}">${metrics.interactions.maxResponseTime}ms</span>
                        </div>
                    </div>
                </div>

                <div class="performance-card">
                    <h3>内存使用情况</h3>
                    <div class="metric-list">
                        <div class="metric-item">
                            <span class="metric-label">初始内存使用:</span>
                            <span class="metric-value">${(metrics.memory.initialUsage / 1024 / 1024).toFixed(2)}MB</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">最终内存使用:</span>
                            <span class="metric-value">${(metrics.memory.finalUsage / 1024 / 1024).toFixed(2)}MB</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">内存增长:</span>
                            <span class="metric-value ${metrics.memory.growthPercentage < 20 ? 'good' : metrics.memory.growthPercentage < 50 ? 'warning' : 'poor'}">${metrics.memory.growthPercentage.toFixed(2)}%</span>
                        </div>
                    </div>
                </div>

                <div class="performance-card">
                    <h3>网络性能</h3>
                    <div class="metric-list">
                        <div class="metric-item">
                            <span class="metric-label">API请求总数:</span>
                            <span class="metric-value">${metrics.network.apiRequestCount}</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">数据传输总量:</span>
                            <span class="metric-value">${(metrics.network.totalDataTransferred / 1024).toFixed(2)}KB</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-label">缓存命中率:</span>
                            <span class="metric-value ${metrics.network.cacheHitRate > 80 ? 'good' : metrics.network.cacheHitRate > 60 ? 'warning' : 'poor'}">${metrics.network.cacheHitRate.toFixed(2)}%</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="chart-container">
                <canvas id="performanceChart"></canvas>
            </div>
        </section>`;
  }

  private buildTestSuitesSection(): string {
    let suitesHtml = `
        <section class="test-suites">
            <h2>🧪 测试套件详情</h2>`;

    this.testSuites.forEach((suite, index) => {
      const passedCount = suite.results.filter(r => r.status === 'passed').length;
      const failedCount = suite.results.filter(r => r.status === 'failed').length;
      const skippedCount = suite.results.filter(r => r.status === 'skipped').length;
      
      suitesHtml += `
            <div class="test-suite">
                <h3 class="suite-title">${suite.name}</h3>
                <div class="suite-stats">
                    <span class="stat">通过: ${passedCount}</span>
                    <span class="stat">失败: ${failedCount}</span>
                    <span class="stat">跳过: ${skippedCount}</span>
                    <span class="stat">通过率: ${suite.passRate.toFixed(2)}%</span>
                    <span class="stat">总时长: ${(suite.totalDuration / 1000).toFixed(2)}s</span>
                </div>
                
                <div class="test-results">
                    ${suite.results.map(result => this.buildTestResultHtml(result)).join('')}
                </div>
            </div>`;
    });

    suitesHtml += '</section>';
    return suitesHtml;
  }

  private buildTestResultHtml(result: TestResult): string {
    const statusClass = {
      'passed': 'success',
      'failed': 'danger',
      'skipped': 'warning'
    }[result.status];

    const statusIcon = {
      'passed': '✅',
      'failed': '❌',
      'skipped': '⏭️'
    }[result.status];

    let screenshotsHtml = '';
    if (result.screenshots && result.screenshots.length > 0) {
      screenshotsHtml = `
                <div class="screenshots">
                    <h5>📸 截图:</h5>
                    <div class="screenshot-gallery">
                        ${result.screenshots.map(screenshot => `
                            <img src="${screenshot}" alt="Test Screenshot" class="screenshot-thumb" onclick="openModal('${screenshot}')">
                        `).join('')}
                    </div>
                </div>`;
    }

    let performanceHtml = '';
    if (result.performanceMetrics) {
      performanceHtml = `
                <div class="test-performance">
                    <h5>⚡ 性能指标:</h5>
                    <pre>${JSON.stringify(result.performanceMetrics, null, 2)}</pre>
                </div>`;
    }

    return `
            <div class="test-result ${statusClass}">
                <div class="test-header">
                    <span class="test-status">${statusIcon}</span>
                    <span class="test-title">${result.title}</span>
                    <span class="test-duration">${result.duration}ms</span>
                </div>
                ${result.error ? `<div class="test-error"><strong>错误:</strong> ${result.error}</div>` : ''}
                ${screenshotsHtml}
                ${performanceHtml}
            </div>`;
  }

  private buildRecommendationsSection(): string {
    const recommendations = this.generateRecommendations();
    
    return `
        <section class="recommendations">
            <h2>💡 改进建议</h2>
            <div class="recommendation-grid">
                ${recommendations.map(rec => `
                    <div class="recommendation-card ${rec.priority}">
                        <div class="rec-header">
                            <span class="rec-icon">${rec.icon}</span>
                            <h4>${rec.title}</h4>
                            <span class="rec-priority">${rec.priority.toUpperCase()}</span>
                        </div>
                        <p class="rec-description">${rec.description}</p>
                        <div class="rec-actions">
                            <strong>建议行动:</strong>
                            <ul>
                                ${rec.actions.map(action => `<li>${action}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `).join('')}
            </div>
        </section>`;
  }

  private buildAppendixSection(): string {
    return `
        <section class="appendix">
            <h2>📋 附录</h2>
            
            <div class="appendix-grid">
                <div class="appendix-card">
                    <h3>🔧 测试环境信息</h3>
                    <ul>
                        <li><strong>浏览器:</strong> Chromium, Firefox, WebKit</li>
                        <li><strong>测试框架:</strong> Playwright ${this.getPlaywrightVersion()}</li>
                        <li><strong>Node.js版本:</strong> ${process.version}</li>
                        <li><strong>操作系统:</strong> ${process.platform} ${process.arch}</li>
                        <li><strong>CPU核心数:</strong> ${require('os').cpus().length}</li>
                        <li><strong>总内存:</strong> ${(require('os').totalmem() / 1024 / 1024 / 1024).toFixed(2)}GB</li>
                    </ul>
                </div>

                <div class="appendix-card">
                    <h3>📊 测试数据说明</h3>
                    <ul>
                        <li><strong>性能基准:</strong> 基于Web Vitals标准</li>
                        <li><strong>响应时间:</strong> 从用户操作到UI反馈的时间</li>
                        <li><strong>内存增长:</strong> 长时间使用后的内存变化</li>
                        <li><strong>缓存命中率:</strong> 重复访问时的缓存利用率</li>
                    </ul>
                </div>

                <div class="appendix-card">
                    <h3>🚨 已知问题</h3>
                    <ul>
                        <li>Safari WebKit在某些API上存在兼容性差异</li>
                        <li>移动端设备的性能指标会因设备而异</li>
                        <li>网络条件会显著影响加载性能测试结果</li>
                        <li>某些第三方服务可能影响测试稳定性</li>
                    </ul>
                </div>

                <div class="appendix-card">
                    <h3>🔍 如何阅读报告</h3>
                    <ul>
                        <li><span class="good">绿色</span>: 性能优秀，符合最佳实践</li>
                        <li><span class="warning">橙色</span>: 性能可接受，但有改进空间</li>
                        <li><span class="poor">红色</span>: 性能不佳，需要优化</li>
                        <li>点击截图可以查看大图</li>
                        <li>性能数据基于多次测试的平均值</li>
                    </ul>
                </div>
            </div>
        </section>`;
  }

  private generateRecommendations(): any[] {
    const recommendations = [];
    
    if (!this.overallMetrics) return recommendations;

    const metrics = this.overallMetrics;
    
    // 页面加载性能建议
    if (metrics.pageLoad.coldStart > 5000) {
      recommendations.push({
        title: '优化页面加载时间',
        description: '首次加载时间超过5秒，严重影响用户体验',
        priority: 'high',
        icon: '🚀',
        actions: [
          '实施代码分割和懒加载',
          '优化图片和静态资源压缩',
          '使用CDN加速资源分发',
          '减少关键渲染路径阻塞资源'
        ]
      });
    }

    if (metrics.pageLoad.fcp > 3000) {
      recommendations.push({
        title: '改善首次内容绘制时间',
        description: 'FCP时间过长，用户会感到页面响应缓慢',
        priority: 'medium',
        icon: '🎨',
        actions: [
          '优化关键CSS的内联',
          '预加载关键字体和资源',
          '使用服务端渲染(SSR)',
          '减少JavaScript执行时间'
        ]
      });
    }

    // 交互性能建议
    if (metrics.interactions.averageResponseTime > 300) {
      recommendations.push({
        title: '提高交互响应速度',
        description: '用户交互响应时间超过300ms，影响操作流畅度',
        priority: 'medium',
        icon: '⚡',
        actions: [
          '优化事件处理器性能',
          '使用防抖和节流技术',
          '减少主线程阻塞操作',
          '实施虚拟滚动优化长列表'
        ]
      });
    }

    // 内存使用建议
    if (metrics.memory.growthPercentage > 50) {
      recommendations.push({
        title: '修复内存泄漏问题',
        description: '内存增长超过50%，可能存在内存泄漏',
        priority: 'high',
        icon: '🧠',
        actions: [
          '检查事件监听器是否正确移除',
          '清理未使用的DOM引用',
          '优化图片和媒体资源管理',
          '使用内存分析工具定位泄漏源'
        ]
      });
    }

    // 网络性能建议
    if (metrics.network.cacheHitRate < 60) {
      recommendations.push({
        title: '优化缓存策略',
        description: '缓存命中率低于60%，重复请求过多',
        priority: 'medium',
        icon: '💾',
        actions: [
          '设置合适的HTTP缓存头',
          '实施应用层缓存策略',
          '使用Service Worker缓存',
          '优化API请求合并和批处理'
        ]
      });
    }

    // 移动端优化建议
    const failedTests = this.testSuites.reduce((sum, suite) => 
      sum + suite.results.filter(r => r.status === 'failed').length, 0);
    
    if (failedTests > 0) {
      recommendations.push({
        title: '提高测试稳定性',
        description: `${failedTests}个测试失败，需要提高测试可靠性`,
        priority: failedTests > 5 ? 'high' : 'medium',
        icon: '🔧',
        actions: [
          '增加测试用例的等待和重试机制',
          '优化选择器策略提高稳定性',
          '完善错误处理和异常恢复',
          '添加更多的断言验证'
        ]
      });
    }

    return recommendations;
  }

  private generateJsonReport(): void {
    const jsonReport = {
      metadata: {
        generatedAt: this.endTime.toISOString(),
        testDuration: this.endTime.getTime() - this.startTime.getTime(),
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch
        }
      },
      summary: {
        totalTests: this.testSuites.reduce((sum, suite) => sum + suite.results.length, 0),
        passedTests: this.testSuites.reduce((sum, suite) => 
          sum + suite.results.filter(r => r.status === 'passed').length, 0),
        failedTests: this.testSuites.reduce((sum, suite) => 
          sum + suite.results.filter(r => r.status === 'failed').length, 0),
        skippedTests: this.testSuites.reduce((sum, suite) => 
          sum + suite.results.filter(r => r.status === 'skipped').length, 0)
      },
      performanceMetrics: this.overallMetrics,
      testSuites: this.testSuites,
      recommendations: this.generateRecommendations()
    };

    const jsonPath = path.join(this.reportDir, 'raw-data', 'test-results.json');
    fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2), 'utf8');
    console.log(`📄 JSON报告已生成: ${jsonPath}`);
  }

  private generatePerformanceSummary(): void {
    if (!this.overallMetrics) return;

    const summary = `# SmellPin前端性能测试摘要

## 测试时间
- 开始: ${this.startTime.toLocaleString('zh-CN')}
- 结束: ${this.endTime.toLocaleString('zh-CN')}
- 持续: ${((this.endTime.getTime() - this.startTime.getTime()) / 1000).toFixed(2)}秒

## 核心性能指标

### 页面加载性能
- 冷启动加载: ${this.overallMetrics.pageLoad.coldStart}ms
- 热启动加载: ${this.overallMetrics.pageLoad.hotStart}ms  
- 首次内容绘制(FCP): ${this.overallMetrics.pageLoad.fcp}ms
- 最大内容绘制(LCP): ${this.overallMetrics.pageLoad.lcp}ms
- 累计布局偏移(CLS): ${this.overallMetrics.pageLoad.cls}

### 交互性能
- 平均响应时间: ${this.overallMetrics.interactions.averageResponseTime}ms
- 最大响应时间: ${this.overallMetrics.interactions.maxResponseTime}ms

### 资源使用
- 初始内存: ${(this.overallMetrics.memory.initialUsage / 1024 / 1024).toFixed(2)}MB
- 最终内存: ${(this.overallMetrics.memory.finalUsage / 1024 / 1024).toFixed(2)}MB
- 内存增长: ${this.overallMetrics.memory.growthPercentage.toFixed(2)}%

### 网络性能
- API请求总数: ${this.overallMetrics.network.apiRequestCount}
- 数据传输量: ${(this.overallMetrics.network.totalDataTransferred / 1024).toFixed(2)}KB
- 缓存命中率: ${this.overallMetrics.network.cacheHitRate.toFixed(2)}%

## 性能评级

${this.getPerformanceGrade()}

## 关键建议

${this.generateRecommendations().slice(0, 3).map(rec => 
  `- **${rec.title}**: ${rec.description}`).join('\n')}
`;

    const summaryPath = path.join(this.reportDir, 'performance-summary.md');
    fs.writeFileSync(summaryPath, summary, 'utf8');
    console.log(`📈 性能摘要已生成: ${summaryPath}`);
  }

  private getPerformanceGrade(): string {
    if (!this.overallMetrics) return 'N/A';

    let score = 0;
    const metrics = this.overallMetrics;

    // FCP评分 (30分)
    if (metrics.pageLoad.fcp < 1800) score += 30;
    else if (metrics.pageLoad.fcp < 3000) score += 20;
    else score += 10;

    // LCP评分 (30分)
    if (metrics.pageLoad.lcp < 2500) score += 30;
    else if (metrics.pageLoad.lcp < 4000) score += 20;
    else score += 10;

    // CLS评分 (20分)
    if (metrics.pageLoad.cls < 0.1) score += 20;
    else if (metrics.pageLoad.cls < 0.25) score += 15;
    else score += 5;

    // 交互性评分 (20分)
    if (metrics.interactions.averageResponseTime < 100) score += 20;
    else if (metrics.interactions.averageResponseTime < 300) score += 15;
    else score += 5;

    if (score >= 85) return '🏆 优秀 (A级)';
    if (score >= 70) return '😊 良好 (B级)';
    if (score >= 55) return '😐 一般 (C级)';
    return '😟 需要改进 (D级)';
  }

  private getPlaywrightVersion(): string {
    try {
      const packageJson = require('@playwright/test/package.json');
      return packageJson.version;
    } catch {
      return 'Unknown';
    }
  }

  private getReportStyles(): string {
    return `
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; line-height: 1.6; color: #333; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }
        .header h1 { font-size: 2.5rem; margin-bottom: 20px; }
        .meta-info p { margin: 5px 0; opacity: 0.9; }
        
        .summary { background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { padding: 20px; border-radius: 8px; text-align: center; color: white; }
        .stat-card.success { background: linear-gradient(135deg, #4CAF50, #45a049); }
        .stat-card.danger { background: linear-gradient(135deg, #f44336, #da190b); }
        .stat-card.warning { background: linear-gradient(135deg, #ff9800, #f57c00); }
        .stat-card.info { background: linear-gradient(135deg, #2196F3, #0b7dda); }
        .stat-card h3 { font-size: 1rem; margin-bottom: 10px; opacity: 0.9; }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        
        .performance { background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .performance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .performance-card { padding: 20px; border: 1px solid #e0e6ed; border-radius: 8px; background: #fafbfc; }
        .metric-list { }
        .metric-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #f0f0f0; }
        .metric-item:last-child { border-bottom: none; }
        .metric-label { font-weight: 500; }
        .metric-value { font-weight: bold; padding: 4px 8px; border-radius: 4px; }
        .metric-value.good { color: #4CAF50; background: #e8f5e8; }
        .metric-value.warning { color: #ff9800; background: #fff3e0; }
        .metric-value.poor { color: #f44336; background: #ffebee; }
        
        .test-suites { background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .test-suite { margin-bottom: 30px; padding: 20px; border: 1px solid #e0e6ed; border-radius: 8px; }
        .suite-title { color: #667eea; margin-bottom: 10px; }
        .suite-stats { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
        .suite-stats .stat { padding: 4px 12px; background: #f0f2f5; border-radius: 20px; font-size: 0.9rem; }
        
        .test-result { margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 4px solid; }
        .test-result.success { border-color: #4CAF50; background: #f1f8e9; }
        .test-result.danger { border-color: #f44336; background: #ffebee; }
        .test-result.warning { border-color: #ff9800; background: #fff3e0; }
        .test-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
        .test-status { font-size: 1.2rem; }
        .test-title { flex: 1; font-weight: 500; }
        .test-duration { font-size: 0.9rem; color: #666; }
        .test-error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 4px; margin: 10px 0; }
        
        .screenshots { margin-top: 15px; }
        .screenshot-gallery { display: flex; gap: 10px; flex-wrap: wrap; }
        .screenshot-thumb { width: 100px; height: 60px; object-fit: cover; border-radius: 4px; cursor: pointer; transition: transform 0.2s; }
        .screenshot-thumb:hover { transform: scale(1.1); }
        
        .recommendations { background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .recommendation-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        .recommendation-card { padding: 20px; border-radius: 8px; border: 1px solid; }
        .recommendation-card.high { border-color: #f44336; background: #ffebee; }
        .recommendation-card.medium { border-color: #ff9800; background: #fff3e0; }
        .recommendation-card.low { border-color: #4CAF50; background: #e8f5e8; }
        .rec-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
        .rec-icon { font-size: 1.5rem; }
        .rec-priority { padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; color: white; }
        .rec-priority { background: #666; }
        .recommendation-card.high .rec-priority { background: #f44336; }
        .recommendation-card.medium .rec-priority { background: #ff9800; }
        .recommendation-card.low .rec-priority { background: #4CAF50; }
        .rec-actions ul { margin-top: 10px; padding-left: 20px; }
        
        .appendix { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .appendix-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .appendix-card { padding: 20px; border: 1px solid #e0e6ed; border-radius: 8px; background: #fafbfc; }
        .appendix-card h3 { color: #667eea; margin-bottom: 15px; }
        .appendix-card ul { padding-left: 20px; }
        
        .chart-container { max-width: 600px; margin: 30px auto; }
        
        .good { color: #4CAF50; }
        .warning { color: #ff9800; }
        .poor { color: #f44336; }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header { padding: 20px; }
            .header h1 { font-size: 2rem; }
            .stats-grid, .performance-grid, .recommendation-grid, .appendix-grid { grid-template-columns: 1fr; }
            .suite-stats { flex-direction: column; gap: 10px; }
            .test-header { flex-direction: column; align-items: flex-start; gap: 5px; }
        }`;
  }

  private getReportScripts(): string {
    return `
        // 测试结果饼图
        const ctx1 = document.getElementById('testResultsChart');
        if (ctx1) {
            new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: ['通过', '失败', '跳过'],
                    datasets: [{
                        data: [
                            ${this.testSuites.reduce((sum, suite) => sum + suite.results.filter(r => r.status === 'passed').length, 0)},
                            ${this.testSuites.reduce((sum, suite) => sum + suite.results.filter(r => r.status === 'failed').length, 0)},
                            ${this.testSuites.reduce((sum, suite) => sum + suite.results.filter(r => r.status === 'skipped').length, 0)}
                        ],
                        backgroundColor: ['#4CAF50', '#f44336', '#ff9800']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: '测试结果分布'
                        }
                    }
                }
            });
        }

        // 性能指标雷达图
        const ctx2 = document.getElementById('performanceChart');
        if (ctx2 && ${JSON.stringify(this.overallMetrics)}) {
            const metrics = ${JSON.stringify(this.overallMetrics)};
            new Chart(ctx2, {
                type: 'radar',
                data: {
                    labels: ['页面加载', '交互响应', '内存使用', '网络性能', '视觉稳定性'],
                    datasets: [{
                        label: '性能得分',
                        data: [
                            Math.max(0, 100 - metrics.pageLoad.coldStart / 50),
                            Math.max(0, 100 - metrics.interactions.averageResponseTime / 3),
                            Math.max(0, 100 - metrics.memory.growthPercentage),
                            metrics.network.cacheHitRate,
                            Math.max(0, 100 - metrics.pageLoad.cls * 100)
                        ],
                        backgroundColor: 'rgba(102, 126, 234, 0.2)',
                        borderColor: '#667eea',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: '性能指标雷达图'
                        }
                    },
                    scales: {
                        r: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
        }

        // 截图模态框
        function openModal(imageSrc) {
            const modal = document.createElement('div');
            modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:10000;';
            
            const img = document.createElement('img');
            img.src = imageSrc;
            img.style.cssText = 'max-width:90%;max-height:90%;border-radius:8px;';
            
            modal.appendChild(img);
            modal.onclick = () => document.body.removeChild(modal);
            document.body.appendChild(modal);
        }

        // 页面加载完成后的处理
        document.addEventListener('DOMContentLoaded', function() {
            console.log('📊 SmellPin E2E测试报告已加载');
            
            // 添加平滑滚动
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });
        });`;
  }
}