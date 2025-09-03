/**
 * Comprehensive Compatibility Test Report Generator
 * 全面兼容性测试报告生成器
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 报告配置
const REPORT_CONFIG = {
  title: 'SmellPin 移动端和跨设备兼容性测试报告',
  version: process.env.npm_package_version || '1.0.0',
  testDate: new Date().toISOString().split('T')[0],
  environment: process.env.NODE_ENV || 'test',
  resultsPath: process.env.TEST_RESULTS_PATH || './test-results',
};

// 兼容性标准
const COMPATIBILITY_STANDARDS = {
  performance: {
    loadTime: 3000,
    interactionDelay: 200,
    scrollFPS: 50,
    memoryUsage: 100
  },
  coverage: {
    deviceCoverage: 95,
    browserCoverage: 95,
    featureCoverage: 90
  },
  stability: {
    maxFailures: 5,
    crashRate: 0.01,
    errorRate: 0.05
  }
};

class CompatibilityReportGenerator {
  constructor() {
    this.testResults = {};
    this.summary = {
      totalTests: 0,
      passedTests: 0,
      failedTests: 0,
      skippedTests: 0,
      devicesCovered: new Set(),
      browsersCovered: new Set(),
      networkConditions: new Set(),
      performanceMetrics: {},
      compatibilityIssues: [],
      recommendations: []
    };
  }

  /**
   * 主要报告生成流程
   */
  async generateReport() {
    console.log('🔄 生成兼容性测试报告...');
    
    try {
      // 1. 收集所有测试结果
      await this.collectTestResults();
      
      // 2. 分析测试数据
      await this.analyzeTestResults();
      
      // 3. 生成性能分析
      await this.analyzePerformanceMetrics();
      
      // 4. 识别兼容性问题
      await this.identifyCompatibilityIssues();
      
      // 5. 生成建议
      await this.generateRecommendations();
      
      // 6. 创建报告文件
      await this.createReportFiles();
      
      console.log('✅ 兼容性测试报告生成完成');
      
    } catch (error) {
      console.error('❌ 报告生成失败:', error);
      process.exit(1);
    }
  }

  /**
   * 收集所有测试结果
   */
  async collectTestResults() {
    console.log('📊 收集测试结果...');
    
    const resultsDir = REPORT_CONFIG.resultsPath;
    
    if (!fs.existsSync(resultsDir)) {
      console.warn('⚠️  测试结果目录不存在:', resultsDir);
      return;
    }

    // 递归搜索所有测试结果文件
    const resultFiles = this.findResultFiles(resultsDir);
    
    for (const file of resultFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        
        if (file.endsWith('.json')) {
          const data = JSON.parse(content);
          this.processJsonResults(data, file);
        } else if (file.endsWith('.xml')) {
          this.processXmlResults(content, file);
        }
        
      } catch (error) {
        console.warn(`⚠️  无法处理结果文件 ${file}:`, error.message);
      }
    }
    
    console.log(`📈 收集到 ${Object.keys(this.testResults).length} 组测试结果`);
  }

  /**
   * 查找所有结果文件
   */
  findResultFiles(dir, files = []) {
    const items = fs.readdirSync(dir, { withFileTypes: true });
    
    for (const item of items) {
      const fullPath = path.join(dir, item.name);
      
      if (item.isDirectory()) {
        this.findResultFiles(fullPath, files);
      } else if (item.name.match(/\.(json|xml)$/)) {
        files.push(fullPath);
      }
    }
    
    return files;
  }

  /**
   * 处理JSON格式的测试结果
   */
  processJsonResults(data, filePath) {
    const testSuite = path.basename(filePath, '.json');
    
    if (data.suites) {
      // Playwright格式
      this.testResults[testSuite] = {
        type: 'playwright',
        summary: {
          total: data.stats?.total || 0,
          passed: data.stats?.expected || 0,
          failed: data.stats?.failed || 0,
          skipped: data.stats?.skipped || 0,
          duration: data.stats?.duration || 0
        },
        tests: data.suites.flatMap(suite => 
          suite.specs?.map(spec => ({
            title: spec.title,
            outcome: spec.tests?.[0]?.results?.[0]?.status || 'unknown',
            duration: spec.tests?.[0]?.results?.[0]?.duration || 0,
            error: spec.tests?.[0]?.results?.[0]?.error || null,
            browser: this.extractBrowser(spec),
            device: this.extractDevice(spec),
            network: this.extractNetwork(spec)
          })) || []
        )
      };
    } else if (data.testResults) {
      // Jest格式
      this.testResults[testSuite] = {
        type: 'jest',
        summary: {
          total: data.numTotalTests,
          passed: data.numPassedTests,
          failed: data.numFailedTests,
          skipped: data.numPendingTests,
          duration: data.testResults.reduce((sum, r) => sum + r.perfStats.end - r.perfStats.start, 0)
        },
        tests: data.testResults.flatMap(result => 
          result.assertionResults.map(assertion => ({
            title: assertion.title,
            outcome: assertion.status,
            duration: assertion.duration || 0,
            error: assertion.failureMessages?.join('\n') || null
          }))
        )
      };
    }
    
    // 更新摘要统计
    const suite = this.testResults[testSuite];
    if (suite) {
      this.summary.totalTests += suite.summary.total;
      this.summary.passedTests += suite.summary.passed;
      this.summary.failedTests += suite.summary.failed;
      this.summary.skippedTests += suite.summary.skipped;
      
      // 收集覆盖的设备和浏览器
      suite.tests.forEach(test => {
        if (test.device) this.summary.devicesCovered.add(test.device);
        if (test.browser) this.summary.browsersCovered.add(test.browser);
        if (test.network) this.summary.networkConditions.add(test.network);
      });
    }
  }

  /**
   * 处理XML格式的测试结果
   */
  processXmlResults(content, filePath) {
    // 简单的XML解析 - 在实际项目中可能需要使用xml2js等库
    const testSuite = path.basename(filePath, '.xml');
    console.log(`处理XML结果: ${testSuite}`);
  }

  /**
   * 从测试名称中提取浏览器信息
   */
  extractBrowser(spec) {
    const title = spec.title || '';
    const browsers = ['chromium', 'firefox', 'webkit', 'chrome', 'safari', 'edge'];
    
    for (const browser of browsers) {
      if (title.toLowerCase().includes(browser)) {
        return browser;
      }
    }
    
    return 'unknown';
  }

  /**
   * 从测试名称中提取设备信息
   */
  extractDevice(spec) {
    const title = spec.title || '';
    
    if (title.includes('iPhone') || title.includes('iPad')) return 'iOS';
    if (title.includes('Android') || title.includes('Galaxy') || title.includes('Pixel')) return 'Android';
    if (title.includes('Mobile') || title.includes('mobile')) return 'Mobile';
    if (title.includes('Desktop') || title.includes('desktop')) return 'Desktop';
    
    return 'unknown';
  }

  /**
   * 从测试名称中提取网络信息
   */
  extractNetwork(spec) {
    const title = spec.title || '';
    const networks = ['WiFi', '4G', '3G', 'Slow WiFi'];
    
    for (const network of networks) {
      if (title.includes(network)) {
        return network;
      }
    }
    
    return null;
  }

  /**
   * 分析测试结果
   */
  async analyzeTestResults() {
    console.log('🔍 分析测试结果...');
    
    const analysis = {
      overallStatus: this.summary.failedTests === 0 ? 'PASS' : 'FAIL',
      successRate: (this.summary.passedTests / this.summary.totalTests * 100).toFixed(2),
      deviceCoverage: this.summary.devicesCovered.size,
      browserCoverage: this.summary.browsersCovered.size,
      networkCoverage: this.summary.networkConditions.size,
      testCategorization: this.categorizeTests()
    };
    
    this.summary.analysis = analysis;
    
    console.log(`📊 测试成功率: ${analysis.successRate}%`);
    console.log(`📱 设备覆盖: ${analysis.deviceCoverage} 种设备`);
    console.log(`🌐 浏览器覆盖: ${analysis.browserCoverage} 种浏览器`);
    console.log(`📶 网络条件: ${analysis.networkCoverage} 种网络`);
  }

  /**
   * 测试分类
   */
  categorizeTests() {
    const categories = {
      responsive: 0,
      touchGestures: 0,
      deviceFeatures: 0,
      performance: 0,
      crossBrowser: 0,
      network: 0
    };
    
    Object.values(this.testResults).forEach(suite => {
      suite.tests.forEach(test => {
        const title = test.title.toLowerCase();
        
        if (title.includes('responsive') || title.includes('layout')) {
          categories.responsive++;
        } else if (title.includes('touch') || title.includes('gesture')) {
          categories.touchGestures++;
        } else if (title.includes('gps') || title.includes('camera') || title.includes('sensor')) {
          categories.deviceFeatures++;
        } else if (title.includes('performance') || title.includes('load') || title.includes('fps')) {
          categories.performance++;
        } else if (title.includes('browser') || title.includes('cross')) {
          categories.crossBrowser++;
        } else if (title.includes('network') || title.includes('3g') || title.includes('wifi')) {
          categories.network++;
        }
      });
    });
    
    return categories;
  }

  /**
   * 分析性能指标
   */
  async analyzePerformanceMetrics() {
    console.log('⚡ 分析性能指标...');
    
    const performanceData = {
      loadTimes: [],
      interactionDelays: [],
      memoryUsage: [],
      frameRates: [],
      networkPerformance: {}
    };
    
    // 从测试结果中提取性能数据
    Object.values(this.testResults).forEach(suite => {
      suite.tests.forEach(test => {
        if (test.duration) {
          if (test.title.includes('load')) {
            performanceData.loadTimes.push(test.duration);
          } else if (test.title.includes('interaction')) {
            performanceData.interactionDelays.push(test.duration);
          }
        }
      });
    });
    
    // 计算性能统计
    this.summary.performanceMetrics = {
      averageLoadTime: this.calculateAverage(performanceData.loadTimes),
      maxLoadTime: Math.max(...performanceData.loadTimes, 0),
      averageInteractionDelay: this.calculateAverage(performanceData.interactionDelays),
      loadTimeCompliance: this.calculateCompliance(performanceData.loadTimes, COMPATIBILITY_STANDARDS.performance.loadTime),
      interactionCompliance: this.calculateCompliance(performanceData.interactionDelays, COMPATIBILITY_STANDARDS.performance.interactionDelay)
    };
    
    console.log(`📈 平均加载时间: ${this.summary.performanceMetrics.averageLoadTime.toFixed(0)}ms`);
    console.log(`⚡ 平均交互延迟: ${this.summary.performanceMetrics.averageInteractionDelay.toFixed(0)}ms`);
  }

  /**
   * 计算平均值
   */
  calculateAverage(values) {
    if (values.length === 0) return 0;
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  /**
   * 计算合规率
   */
  calculateCompliance(values, threshold) {
    if (values.length === 0) return 100;
    const compliantCount = values.filter(val => val <= threshold).length;
    return (compliantCount / values.length * 100).toFixed(2);
  }

  /**
   * 识别兼容性问题
   */
  async identifyCompatibilityIssues() {
    console.log('🔍 识别兼容性问题...');
    
    const issues = [];
    
    // 检查失败的测试
    Object.values(this.testResults).forEach(suite => {
      suite.tests.filter(test => test.outcome === 'failed' || test.outcome === 'timedOut').forEach(test => {
        issues.push({
          type: 'test-failure',
          severity: 'high',
          title: test.title,
          browser: test.browser,
          device: test.device,
          network: test.network,
          error: test.error,
          category: this.categorizeIssue(test.title)
        });
      });
    });
    
    // 检查性能问题
    if (this.summary.performanceMetrics.averageLoadTime > COMPATIBILITY_STANDARDS.performance.loadTime) {
      issues.push({
        type: 'performance',
        severity: 'medium',
        title: '页面加载时间超标',
        description: `平均加载时间 ${this.summary.performanceMetrics.averageLoadTime.toFixed(0)}ms 超过标准 ${COMPATIBILITY_STANDARDS.performance.loadTime}ms`,
        category: 'performance'
      });
    }
    
    // 检查覆盖率
    const deviceCoverageRate = (this.summary.devicesCovered.size / 10 * 100); // 假设目标覆盖10种设备
    if (deviceCoverageRate < COMPATIBILITY_STANDARDS.coverage.deviceCoverage) {
      issues.push({
        type: 'coverage',
        severity: 'low',
        title: '设备覆盖率不足',
        description: `设备覆盖率 ${deviceCoverageRate.toFixed(1)}% 低于标准 ${COMPATIBILITY_STANDARDS.coverage.deviceCoverage}%`,
        category: 'coverage'
      });
    }
    
    this.summary.compatibilityIssues = issues;
    
    console.log(`⚠️  发现 ${issues.length} 个兼容性问题`);
    issues.forEach(issue => {
      console.log(`   - [${issue.severity.toUpperCase()}] ${issue.title}`);
    });
  }

  /**
   * 问题分类
   */
  categorizeIssue(title) {
    const categories = {
      'responsive': 'layout',
      'touch': 'interaction',
      'gps|camera|sensor': 'device-features',
      'performance|load|fps': 'performance',
      'browser|cross': 'compatibility',
      'network|3g|wifi': 'network'
    };
    
    for (const [pattern, category] of Object.entries(categories)) {
      if (new RegExp(pattern, 'i').test(title)) {
        return category;
      }
    }
    
    return 'other';
  }

  /**
   * 生成建议
   */
  async generateRecommendations() {
    console.log('💡 生成改进建议...');
    
    const recommendations = [];
    
    // 基于问题生成建议
    const issuesByCategory = this.groupIssuesByCategory();
    
    if (issuesByCategory.layout && issuesByCategory.layout.length > 0) {
      recommendations.push({
        category: 'layout',
        priority: 'high',
        title: '优化响应式布局',
        description: '修复移动端布局适配问题，确保在不同屏幕尺寸下的显示效果',
        actions: [
          '检查CSS断点设置',
          '优化flexbox和grid布局',
          '测试极端屏幕尺寸',
          '验证横竖屏切换'
        ]
      });
    }
    
    if (issuesByCategory.performance && issuesByCategory.performance.length > 0) {
      recommendations.push({
        category: 'performance',
        priority: 'high',
        title: '改善性能表现',
        description: '优化页面加载速度和交互响应时间',
        actions: [
          '压缩和优化图片资源',
          '实施代码分割和懒加载',
          '优化API请求和缓存策略',
          '减少JavaScript包大小'
        ]
      });
    }
    
    if (issuesByCategory.interaction && issuesByCategory.interaction.length > 0) {
      recommendations.push({
        category: 'interaction',
        priority: 'medium',
        title: '优化触摸交互',
        description: '改善移动端触摸手势和交互体验',
        actions: [
          '增大触摸目标区域',
          '优化手势识别算法',
          '添加触觉反馈',
          '改善滚动性能'
        ]
      });
    }
    
    // 基于覆盖率生成建议
    if (this.summary.devicesCovered.size < 5) {
      recommendations.push({
        category: 'coverage',
        priority: 'medium',
        title: '扩展设备测试覆盖',
        description: '增加更多设备和浏览器的测试覆盖',
        actions: [
          '添加更多iOS设备测试',
          '增加Android设备变体',
          '测试低端设备性能',
          '验证新版本浏览器兼容性'
        ]
      });
    }
    
    this.summary.recommendations = recommendations;
    
    console.log(`💡 生成 ${recommendations.length} 条改进建议`);
  }

  /**
   * 按类别分组问题
   */
  groupIssuesByCategory() {
    const grouped = {};
    
    this.summary.compatibilityIssues.forEach(issue => {
      if (!grouped[issue.category]) {
        grouped[issue.category] = [];
      }
      grouped[issue.category].push(issue);
    });
    
    return grouped;
  }

  /**
   * 创建报告文件
   */
  async createReportFiles() {
    console.log('📄 创建报告文件...');
    
    // 1. HTML报告
    const htmlReport = this.generateHtmlReport();
    fs.writeFileSync('compatibility-report.html', htmlReport, 'utf8');
    
    // 2. JSON报告
    const jsonReport = {
      meta: {
        title: REPORT_CONFIG.title,
        version: REPORT_CONFIG.version,
        date: REPORT_CONFIG.testDate,
        environment: REPORT_CONFIG.environment,
        generatedAt: new Date().toISOString()
      },
      summary: {
        ...this.summary,
        devicesCovered: Array.from(this.summary.devicesCovered),
        browsersCovered: Array.from(this.summary.browsersCovered),
        networkConditions: Array.from(this.summary.networkConditions)
      },
      results: this.testResults
    };
    fs.writeFileSync('compatibility-report.json', JSON.stringify(jsonReport, null, 2), 'utf8');
    
    // 3. Markdown摘要
    const markdownSummary = this.generateMarkdownSummary();
    fs.writeFileSync('compatibility-summary.md', markdownSummary, 'utf8');
    
    console.log('✅ 报告文件创建完成');
    console.log('   - compatibility-report.html (详细HTML报告)');
    console.log('   - compatibility-report.json (原始数据)');
    console.log('   - compatibility-summary.md (摘要)');
  }

  /**
   * 生成HTML报告
   */
  generateHtmlReport() {
    const successRate = (this.summary.passedTests / this.summary.totalTests * 100).toFixed(1);
    const statusColor = successRate >= 95 ? 'green' : successRate >= 80 ? 'orange' : 'red';
    
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${REPORT_CONFIG.title}</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 28px; }
        .header .meta { opacity: 0.9; margin-top: 10px; }
        .content { padding: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; border: 1px solid #e1e5e9; border-radius: 6px; padding: 20px; }
        .card h3 { margin-top: 0; color: #2c3e50; }
        .metric { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; }
        .metric-value { font-weight: bold; font-size: 18px; }
        .success { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        .progress-bar { width: 100%; height: 8px; background: #ecf0f1; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: ${statusColor}; }
        .issues { margin: 20px 0; }
        .issue { background: #fff5f5; border: 1px solid #fed7d7; border-radius: 4px; padding: 15px; margin: 10px 0; }
        .issue-high { border-color: #fc8181; }
        .issue-medium { border-color: #f6ad55; background: #fffaf0; }
        .issue-low { border-color: #68d391; background: #f0fff4; }
        .recommendations { margin: 20px 0; }
        .recommendation { background: #ebf8ff; border: 1px solid #bee3f8; border-radius: 4px; padding: 15px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e1e5e9; }
        th { background: #f8f9fa; font-weight: 600; }
        .status-pass { color: #27ae60; font-weight: bold; }
        .status-fail { color: #e74c3c; font-weight: bold; }
        .status-skip { color: #f39c12; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>${REPORT_CONFIG.title}</h1>
            <div class="meta">
                版本: ${REPORT_CONFIG.version} | 测试日期: ${REPORT_CONFIG.testDate} | 环境: ${REPORT_CONFIG.environment}
            </div>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="card">
                    <h3>测试概览</h3>
                    <div class="metric">
                        <span>总测试数</span>
                        <span class="metric-value">${this.summary.totalTests}</span>
                    </div>
                    <div class="metric">
                        <span>通过</span>
                        <span class="metric-value success">${this.summary.passedTests}</span>
                    </div>
                    <div class="metric">
                        <span>失败</span>
                        <span class="metric-value error">${this.summary.failedTests}</span>
                    </div>
                    <div class="metric">
                        <span>跳过</span>
                        <span class="metric-value warning">${this.summary.skippedTests}</span>
                    </div>
                    <div class="metric">
                        <span>成功率</span>
                        <span class="metric-value" style="color: ${statusColor}">${successRate}%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${successRate}%; background: ${statusColor};"></div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>覆盖范围</h3>
                    <div class="metric">
                        <span>设备类型</span>
                        <span class="metric-value">${this.summary.devicesCovered.size}</span>
                    </div>
                    <div class="metric">
                        <span>浏览器</span>
                        <span class="metric-value">${this.summary.browsersCovered.size}</span>
                    </div>
                    <div class="metric">
                        <span>网络条件</span>
                        <span class="metric-value">${this.summary.networkConditions.size}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>性能指标</h3>
                    <div class="metric">
                        <span>平均加载时间</span>
                        <span class="metric-value">${this.summary.performanceMetrics.averageLoadTime?.toFixed(0) || 0}ms</span>
                    </div>
                    <div class="metric">
                        <span>平均交互延迟</span>
                        <span class="metric-value">${this.summary.performanceMetrics.averageInteractionDelay?.toFixed(0) || 0}ms</span>
                    </div>
                    <div class="metric">
                        <span>加载时间合规率</span>
                        <span class="metric-value">${this.summary.performanceMetrics.loadTimeCompliance || 0}%</span>
                    </div>
                </div>
            </div>
            
            ${this.summary.compatibilityIssues.length > 0 ? `
            <h2>兼容性问题</h2>
            <div class="issues">
                ${this.summary.compatibilityIssues.map(issue => `
                <div class="issue issue-${issue.severity}">
                    <strong>[${issue.severity.toUpperCase()}] ${issue.title}</strong>
                    ${issue.description ? `<p>${issue.description}</p>` : ''}
                    ${issue.browser ? `<small>浏览器: ${issue.browser}</small><br>` : ''}
                    ${issue.device ? `<small>设备: ${issue.device}</small><br>` : ''}
                    ${issue.error ? `<details><summary>错误详情</summary><pre>${issue.error}</pre></details>` : ''}
                </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${this.summary.recommendations.length > 0 ? `
            <h2>改进建议</h2>
            <div class="recommendations">
                ${this.summary.recommendations.map(rec => `
                <div class="recommendation">
                    <strong>[${rec.priority.toUpperCase()}] ${rec.title}</strong>
                    <p>${rec.description}</p>
                    <ul>
                        ${rec.actions.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
                `).join('')}
            </div>
            ` : ''}
            
            <h2>测试详情</h2>
            <table>
                <thead>
                    <tr>
                        <th>测试套件</th>
                        <th>总数</th>
                        <th>通过</th>
                        <th>失败</th>
                        <th>跳过</th>
                        <th>时长</th>
                        <th>状态</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(this.testResults).map(([name, suite]) => `
                    <tr>
                        <td>${name}</td>
                        <td>${suite.summary.total}</td>
                        <td class="success">${suite.summary.passed}</td>
                        <td class="error">${suite.summary.failed}</td>
                        <td class="warning">${suite.summary.skipped}</td>
                        <td>${(suite.summary.duration / 1000).toFixed(1)}s</td>
                        <td class="${suite.summary.failed === 0 ? 'status-pass' : 'status-fail'}">
                            ${suite.summary.failed === 0 ? 'PASS' : 'FAIL'}
                        </td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e1e5e9; color: #666; text-align: center;">
                报告生成时间: ${new Date().toLocaleString('zh-CN')}
            </div>
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * 生成Markdown摘要
   */
  generateMarkdownSummary() {
    const successRate = (this.summary.passedTests / this.summary.totalTests * 100).toFixed(1);
    const statusEmoji = successRate >= 95 ? '✅' : successRate >= 80 ? '⚠️' : '❌';
    
    return `# 兼容性测试摘要

${statusEmoji} **整体状态**: ${this.summary.failedTests === 0 ? 'PASS' : 'FAIL'} (${successRate}% 通过率)

## 📊 测试统计

- **总测试数**: ${this.summary.totalTests}
- **通过**: ${this.summary.passedTests}
- **失败**: ${this.summary.failedTests}
- **跳过**: ${this.summary.skippedTests}

## 📱 覆盖范围

- **设备类型**: ${Array.from(this.summary.devicesCovered).join(', ') || '无'}
- **浏览器**: ${Array.from(this.summary.browsersCovered).join(', ') || '无'}
- **网络条件**: ${Array.from(this.summary.networkConditions).join(', ') || '无'}

## ⚡ 性能指标

- **平均加载时间**: ${this.summary.performanceMetrics.averageLoadTime?.toFixed(0) || 0}ms
- **平均交互延迟**: ${this.summary.performanceMetrics.averageInteractionDelay?.toFixed(0) || 0}ms
- **加载时间合规率**: ${this.summary.performanceMetrics.loadTimeCompliance || 0}%

${this.summary.compatibilityIssues.length > 0 ? `
## ⚠️ 主要问题

${this.summary.compatibilityIssues.slice(0, 5).map(issue => 
  `- **[${issue.severity.toUpperCase()}]** ${issue.title}${issue.browser ? ` (${issue.browser})` : ''}`
).join('\n')}

${this.summary.compatibilityIssues.length > 5 ? `\n*...以及 ${this.summary.compatibilityIssues.length - 5} 个其他问题*` : ''}
` : ''}

${this.summary.recommendations.length > 0 ? `
## 💡 改进建议

${this.summary.recommendations.slice(0, 3).map(rec => 
  `- **${rec.title}**: ${rec.description}`
).join('\n')}
` : ''}

## 📄 详细报告

完整的测试报告请查看 [compatibility-report.html](./compatibility-report.html)

---
*报告生成时间: ${new Date().toLocaleString('zh-CN')}*`;
  }
}

// 主程序入口
if (require.main === module) {
  const generator = new CompatibilityReportGenerator();
  generator.generateReport().catch(console.error);
}

module.exports = CompatibilityReportGenerator;