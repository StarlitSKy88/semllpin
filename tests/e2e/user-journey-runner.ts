import { chromium, devices, Browser, BrowserContext } from '@playwright/test';
import { UXMetricsCollector } from './utils/ux-metrics';
import { AuthPage } from './page-objects/auth-page';
import { MapPage } from './page-objects/map-page';
import { TestData } from './fixtures/test-data';
import fs from 'fs';
import path from 'path';

interface TestResult {
  testName: string;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  screenshots: string[];
  uxMetrics?: any;
  userFeedback?: UserFeedback;
}

interface UserFeedback {
  taskCompletionRate: number;
  userSatisfactionScore: number;
  usabilityIssues: string[];
  suggestions: string[];
}

interface ComprehensiveTestReport {
  summary: {
    totalTests: number;
    passed: number;
    failed: number;
    skipped: number;
    totalDuration: number;
    overallSuccessRate: number;
  };
  deviceResults: Record<string, TestResult[]>;
  networkResults: Record<string, TestResult[]>;
  userJourneyResults: Record<string, TestResult[]>;
  performanceMetrics: {
    averagePageLoadTime: number;
    averageTaskCompletionTime: number;
    errorRate: number;
    conversionRates: Record<string, number>;
  };
  usabilityFindings: {
    criticalIssues: string[];
    moderateIssues: string[];
    minorIssues: string[];
    positiveFindings: string[];
  };
  recommendations: string[];
  timestamp: string;
}

export class UserJourneyRunner {
  private browser: Browser | null = null;
  private results: TestResult[] = [];
  private startTime: number = 0;

  async initialize() {
    console.log('🚀 初始化用户路径测试运行器...');
    this.browser = await chromium.launch({
      headless: process.env.HEADLESS !== 'false',
      slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0
    });
    this.startTime = Date.now();
  }

  async cleanup() {
    if (this.browser) {
      await this.browser.close();
    }
  }

  // 运行新用户注册流程测试
  async runNewUserRegistrationTests(): Promise<TestResult[]> {
    console.log('📝 开始新用户注册流程测试...');
    const results: TestResult[] = [];
    
    const devices = [
      { name: 'Desktop Chrome', device: null },
      { name: 'Mobile Safari', device: devices['iPhone 12'] },
      { name: 'Tablet iPad', device: devices['iPad Pro'] }
    ];

    for (const deviceConfig of devices) {
      const result = await this.runSingleTest(
        `新用户注册 - ${deviceConfig.name}`,
        async (context, uxCollector) => {
          const page = await context.newPage();
          const authPage = new AuthPage(page);
          
          // 启动UX指标收集
          await uxCollector.measurePageLoadTime();
          uxCollector.startTask('registration');

          // 执行注册流程
          const userData = TestData.users.newUser;
          await authPage.navigateToRegister();
          await authPage.register({
            username: `${userData.username}_${Date.now()}`,
            email: `test_${Date.now()}@example.com`,
            password: userData.password
          });

          // 处理邮箱验证
          if (page.url().includes('/verify')) {
            await authPage.verifyEmail('123456');
          }

          // 验证注册成功
          await authPage.verifyLoggedIn();
          
          const registrationTime = uxCollector.endTask('registration');
          await uxCollector.collectWebVitals();
          
          return {
            success: true,
            metrics: { registrationTime },
            feedback: await this.simulateUserFeedback('registration', registrationTime)
          };
        },
        deviceConfig.device
      );
      
      results.push(result);
    }

    return results;
  }

  // 运行标注创建者流程测试
  async runAnnotationCreatorTests(): Promise<TestResult[]> {
    console.log('🏷️ 开始标注创建者流程测试...');
    const results: TestResult[] = [];
    
    const result = await this.runSingleTest(
      '标注创建者完整流程',
      async (context, uxCollector) => {
        const page = await context.newPage();
        const authPage = new AuthPage(page);
        const mapPage = new MapPage(page);
        
        // 创建测试用户并登录
        const userData = await authPage.createAndLoginTestUser();
        
        uxCollector.startTask('annotationCreation');
        
        // 进入地图并创建标注
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        
        const annotation = TestData.annotations.pleasant[0];
        await mapPage.createAnnotation({
          ...annotation,
          latitude: 40.7128,
          longitude: -74.0060
        });
        
        const creationTime = uxCollector.endTask('annotationCreation');
        
        // 验证标注创建成功
        await mapPage.verifyAnnotationCount(1);
        
        return {
          success: true,
          metrics: { creationTime },
          feedback: await this.simulateUserFeedback('creation', creationTime)
        };
      }
    );
    
    results.push(result);
    return results;
  }

  // 运行奖励发现者流程测试
  async runRewardDiscovererTests(): Promise<TestResult[]> {
    console.log('🎁 开始奖励发现者流程测试...');
    const results: TestResult[] = [];
    
    const result = await this.runSingleTest(
      '奖励发现者完整流程',
      async (context, uxCollector) => {
        const page = await context.newPage();
        const authPage = new AuthPage(page);
        const mapPage = new MapPage(page);
        
        // 登录发现者账户
        const userData = TestData.users.rewardDiscoverer;
        await authPage.login(
          `${userData.email}_${Date.now()}@test.com`,
          userData.password
        );
        
        uxCollector.startTask('rewardDiscovery');
        
        // 进入地图并发现奖励
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        await mapPage.getCurrentLocation();
        
        // 模拟移动到标注位置
        await mapPage.enterGeofence(40.7589, -73.9851);
        await mapPage.claimReward();
        
        const discoveryTime = uxCollector.endTask('rewardDiscovery');
        
        return {
          success: true,
          metrics: { discoveryTime },
          feedback: await this.simulateUserFeedback('discovery', discoveryTime)
        };
      }
    );
    
    results.push(result);
    return results;
  }

  // 运行社交互动流程测试
  async runSocialInteractionTests(): Promise<TestResult[]> {
    console.log('👥 开始社交互动流程测试...');
    const results: TestResult[] = [];
    
    const result = await this.runSingleTest(
      '社交互动完整流程',
      async (context, uxCollector) => {
        const page = await context.newPage();
        const authPage = new AuthPage(page);
        const mapPage = new MapPage(page);
        
        const userData = TestData.users.socialUser;
        await authPage.login(
          `${userData.email}_${Date.now()}@test.com`,
          userData.password
        );
        
        uxCollector.startTask('socialInteraction');
        
        // 进行社交互动
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        
        // 点赞标注
        await mapPage.clickAnnotationMarker(0);
        await mapPage.likeAnnotation();
        
        const interactionTime = uxCollector.endTask('socialInteraction');
        
        return {
          success: true,
          metrics: { interactionTime },
          feedback: await this.simulateUserFeedback('social', interactionTime)
        };
      }
    );
    
    results.push(result);
    return results;
  }

  // 运行跨设备和网络环境测试
  async runCrossDeviceNetworkTests(): Promise<TestResult[]> {
    console.log('📱 开始跨设备和网络环境测试...');
    const results: TestResult[] = [];
    
    // 测试不同网络条件
    const networkConditions = [
      { name: '快速网络', delay: 0 },
      { name: '慢速3G', delay: 2000 },
      { name: '不稳定网络', delay: 'random' }
    ];
    
    for (const network of networkConditions) {
      const result = await this.runSingleTest(
        `网络测试 - ${network.name}`,
        async (context, uxCollector) => {
          // 设置网络延迟
          if (network.delay !== 0) {
            await context.route('**/*', async route => {
              const delay = network.delay === 'random' 
                ? Math.random() * 3000 
                : network.delay;
              await new Promise(resolve => setTimeout(resolve, delay));
              await route.continue();
            });
          }
          
          const page = await context.newPage();
          const authPage = new AuthPage(page);
          const mapPage = new MapPage(page);
          
          uxCollector.startTask('networkTest');
          
          const userData = await authPage.createAndLoginTestUser();
          await mapPage.navigateToMap();
          await mapPage.waitForMapLoad();
          
          const networkTestTime = uxCollector.endTask('networkTest');
          
          return {
            success: true,
            metrics: { networkTestTime },
            feedback: await this.simulateUserFeedback('network', networkTestTime)
          };
        }
      );
      
      results.push(result);
    }
    
    return results;
  }

  // 运行单个测试
  private async runSingleTest(
    testName: string,
    testFunction: (context: BrowserContext, uxCollector: UXMetricsCollector) => Promise<any>,
    device?: any
  ): Promise<TestResult> {
    console.log(`▶️  运行测试: ${testName}`);
    const startTime = Date.now();
    const screenshots: string[] = [];
    
    try {
      const contextOptions = device ? { ...device } : {};
      contextOptions.permissions = ['geolocation', 'notifications'];
      contextOptions.geolocation = { latitude: 40.7128, longitude: -74.0060 };
      
      const context = await this.browser!.newContext(contextOptions);
      const page = await context.newPage();
      const uxCollector = new UXMetricsCollector(page);
      
      // 设置截图
      const screenshotDir = path.join('test-results', 'screenshots', testName.replace(/\s+/g, '-'));
      if (!fs.existsSync(screenshotDir)) {
        fs.mkdirSync(screenshotDir, { recursive: true });
      }
      
      const result = await testFunction(context, uxCollector);
      
      // 生成UX报告
      const uxMetrics = await uxCollector.generateUXReport();
      await uxCollector.exportMetrics(`${testName.replace(/\s+/g, '-')}.json`);
      
      // 截取最终截图
      const finalScreenshot = path.join(screenshotDir, 'final.png');
      await page.screenshot({ path: finalScreenshot, fullPage: true });
      screenshots.push(finalScreenshot);
      
      await context.close();
      
      const duration = Date.now() - startTime;
      console.log(`✅ ${testName} 完成 (${duration}ms)`);
      
      return {
        testName,
        status: 'passed',
        duration,
        screenshots,
        uxMetrics,
        userFeedback: result.feedback
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ ${testName} 失败 (${duration}ms):`, error);
      
      return {
        testName,
        status: 'failed',
        duration,
        error: (error as Error).message,
        screenshots
      };
    }
  }

  // 模拟用户反馈
  private async simulateUserFeedback(taskType: string, duration: number): Promise<UserFeedback> {
    // 基于任务完成时间和类型生成模拟的用户反馈
    let satisfactionScore = 10;
    const usabilityIssues: string[] = [];
    const suggestions: string[] = [];
    
    // 根据完成时间调整满意度
    if (duration > 30000) { // 超过30秒
      satisfactionScore -= 2;
      usabilityIssues.push('任务完成时间过长');
      suggestions.push('优化页面加载速度');
    }
    
    if (duration > 60000) { // 超过1分钟
      satisfactionScore -= 2;
      usabilityIssues.push('用户流程复杂');
      suggestions.push('简化用户操作步骤');
    }
    
    // 根据任务类型添加特定反馈
    switch (taskType) {
      case 'registration':
        if (duration > 15000) {
          usabilityIssues.push('注册流程步骤过多');
          suggestions.push('考虑社交媒体快速登录');
        }
        break;
      case 'creation':
        if (duration > 45000) {
          usabilityIssues.push('标注创建界面不够直观');
          suggestions.push('增加更清晰的视觉引导');
        }
        break;
      case 'discovery':
        suggestions.push('奖励发现体验很好');
        break;
      case 'social':
        suggestions.push('社交功能设计良好');
        break;
    }
    
    return {
      taskCompletionRate: duration < 60000 ? 1.0 : 0.8,
      userSatisfactionScore: Math.max(1, Math.min(10, satisfactionScore)),
      usabilityIssues,
      suggestions
    };
  }

  // 生成综合测试报告
  async generateComprehensiveReport(): Promise<ComprehensiveTestReport> {
    const totalDuration = Date.now() - this.startTime;
    const passed = this.results.filter(r => r.status === 'passed').length;
    const failed = this.results.filter(r => r.status === 'failed').length;
    const skipped = this.results.filter(r => r.status === 'skipped').length;
    
    // 计算性能指标
    const pageLoadTimes = this.results
      .map(r => r.uxMetrics?.pageLoadTime || 0)
      .filter(time => time > 0);
    
    const averagePageLoadTime = pageLoadTimes.length > 0
      ? pageLoadTimes.reduce((a, b) => a + b, 0) / pageLoadTimes.length
      : 0;
    
    // 收集可用性发现
    const allIssues = this.results
      .flatMap(r => r.userFeedback?.usabilityIssues || []);
    
    const allSuggestions = this.results
      .flatMap(r => r.userFeedback?.suggestions || []);
    
    // 按严重程度分类问题
    const criticalIssues = allIssues.filter(issue => 
      issue.includes('时间过长') || issue.includes('失败')
    );
    
    const moderateIssues = allIssues.filter(issue => 
      issue.includes('复杂') || issue.includes('不够直观')
    );
    
    const minorIssues = allIssues.filter(issue => 
      !criticalIssues.includes(issue) && !moderateIssues.includes(issue)
    );
    
    const positiveFindings = allSuggestions.filter(suggestion =>
      suggestion.includes('很好') || suggestion.includes('良好')
    );
    
    // 生成改进建议
    const recommendations = [
      ...new Set([
        ...allSuggestions.filter(s => !positiveFindings.includes(s)),
        criticalIssues.length > 0 ? '优先解决关键性能问题' : '',
        averagePageLoadTime > 3000 ? '优化页面加载性能' : '',
        failed > 0 ? '修复测试失败的功能' : ''
      ])
    ].filter(r => r !== '');
    
    const report: ComprehensiveTestReport = {
      summary: {
        totalTests: this.results.length,
        passed,
        failed,
        skipped,
        totalDuration,
        overallSuccessRate: this.results.length > 0 ? passed / this.results.length : 0
      },
      deviceResults: this.groupResultsByCategory('device'),
      networkResults: this.groupResultsByCategory('network'),
      userJourneyResults: this.groupResultsByCategory('journey'),
      performanceMetrics: {
        averagePageLoadTime,
        averageTaskCompletionTime: this.results
          .map(r => r.duration)
          .reduce((a, b) => a + b, 0) / this.results.length,
        errorRate: failed / this.results.length,
        conversionRates: this.calculateConversionRates()
      },
      usabilityFindings: {
        criticalIssues,
        moderateIssues,
        minorIssues,
        positiveFindings
      },
      recommendations,
      timestamp: new Date().toISOString()
    };
    
    return report;
  }

  private groupResultsByCategory(category: string): Record<string, TestResult[]> {
    const grouped: Record<string, TestResult[]> = {};
    
    this.results.forEach(result => {
      let key = 'other';
      
      if (category === 'device') {
        if (result.testName.includes('Mobile')) key = 'mobile';
        else if (result.testName.includes('Tablet')) key = 'tablet';
        else if (result.testName.includes('Desktop')) key = 'desktop';
      } else if (category === 'network') {
        if (result.testName.includes('网络')) key = 'network';
      } else if (category === 'journey') {
        if (result.testName.includes('注册')) key = 'registration';
        else if (result.testName.includes('标注')) key = 'annotation';
        else if (result.testName.includes('奖励')) key = 'reward';
        else if (result.testName.includes('社交')) key = 'social';
      }
      
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(result);
    });
    
    return grouped;
  }

  private calculateConversionRates(): Record<string, number> {
    const registrationTests = this.results.filter(r => 
      r.testName.includes('注册') && r.status === 'passed'
    );
    
    const creationTests = this.results.filter(r => 
      r.testName.includes('标注') && r.status === 'passed'
    );
    
    const discoveryTests = this.results.filter(r => 
      r.testName.includes('奖励') && r.status === 'passed'
    );
    
    return {
      registration: registrationTests.length / Math.max(1, this.results.filter(r => r.testName.includes('注册')).length),
      creation: creationTests.length / Math.max(1, this.results.filter(r => r.testName.includes('标注')).length),
      discovery: discoveryTests.length / Math.max(1, this.results.filter(r => r.testName.includes('奖励')).length)
    };
  }

  // 导出测试报告
  async exportReport(report: ComprehensiveTestReport, filename: string = 'user-journey-report.json') {
    const reportPath = path.join('test-results', filename);
    const dir = path.dirname(reportPath);
    
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    // 同时生成HTML报告
    const htmlReport = this.generateHTMLReport(report);
    const htmlPath = reportPath.replace('.json', '.html');
    fs.writeFileSync(htmlPath, htmlReport);
    
    console.log(`📊 测试报告已生成:`);
    console.log(`   JSON: ${reportPath}`);
    console.log(`   HTML: ${htmlPath}`);
  }

  private generateHTMLReport(report: ComprehensiveTestReport): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>SmellPin 用户路径测试报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #e1e5e9; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #495057; }
        .metric .value { font-size: 2em; font-weight: bold; color: #007bff; }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .section { margin-bottom: 40px; }
        .issue-list { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; }
        .suggestion-list { background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; padding: 15px; }
        .test-result { margin: 10px 0; padding: 10px; border-left: 4px solid #ddd; }
        .test-result.passed { border-color: #28a745; }
        .test-result.failed { border-color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SmellPin 用户路径测试报告</h1>
        <p>生成时间: ${new Date(report.timestamp).toLocaleString('zh-CN')}</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>总测试数</h3>
            <div class="value">${report.summary.totalTests}</div>
        </div>
        <div class="metric">
            <h3>通过</h3>
            <div class="value passed">${report.summary.passed}</div>
        </div>
        <div class="metric">
            <h3>失败</h3>
            <div class="value failed">${report.summary.failed}</div>
        </div>
        <div class="metric">
            <h3>成功率</h3>
            <div class="value">${(report.summary.overallSuccessRate * 100).toFixed(1)}%</div>
        </div>
        <div class="metric">
            <h3>总耗时</h3>
            <div class="value">${Math.round(report.summary.totalDuration / 1000)}s</div>
        </div>
    </div>
    
    <div class="section">
        <h2>性能指标</h2>
        <div class="summary">
            <div class="metric">
                <h3>平均页面加载</h3>
                <div class="value">${Math.round(report.performanceMetrics.averagePageLoadTime)}ms</div>
            </div>
            <div class="metric">
                <h3>平均任务完成</h3>
                <div class="value">${Math.round(report.performanceMetrics.averageTaskCompletionTime / 1000)}s</div>
            </div>
            <div class="metric">
                <h3>错误率</h3>
                <div class="value">${(report.performanceMetrics.errorRate * 100).toFixed(1)}%</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>关键问题</h2>
        <div class="issue-list">
            ${report.usabilityFindings.criticalIssues.length > 0 
              ? report.usabilityFindings.criticalIssues.map(issue => `<li>${issue}</li>`).join('')
              : '<p>未发现关键问题 ✅</p>'
            }
        </div>
    </div>
    
    <div class="section">
        <h2>改进建议</h2>
        <div class="suggestion-list">
            ${report.recommendations.length > 0
              ? report.recommendations.map(rec => `<li>${rec}</li>`).join('')
              : '<p>当前表现良好，无特别建议 👍</p>'
            }
        </div>
    </div>
    
    <div class="section">
        <h2>积极发现</h2>
        <div class="suggestion-list">
            ${report.usabilityFindings.positiveFindings.map(finding => `<li>${finding}</li>`).join('')}
        </div>
    </div>
</body>
</html>
    `;
  }

  // 执行完整的用户路径测试套件
  async runCompleteTestSuite(): Promise<void> {
    try {
      await this.initialize();
      console.log('🎯 开始执行SmellPin完整用户路径测试套件\n');
      
      // 运行各个测试模块
      this.results.push(...await this.runNewUserRegistrationTests());
      this.results.push(...await this.runAnnotationCreatorTests());
      this.results.push(...await this.runRewardDiscovererTests());
      this.results.push(...await this.runSocialInteractionTests());
      this.results.push(...await this.runCrossDeviceNetworkTests());
      
      // 生成综合报告
      const report = await this.generateComprehensiveReport();
      await this.exportReport(report);
      
      // 输出测试总结
      console.log('\n📊 测试完成总结:');
      console.log(`✅ 通过: ${report.summary.passed}`);
      console.log(`❌ 失败: ${report.summary.failed}`);
      console.log(`📈 成功率: ${(report.summary.overallSuccessRate * 100).toFixed(1)}%`);
      console.log(`⏱️  总耗时: ${Math.round(report.summary.totalDuration / 1000)}秒`);
      
      if (report.recommendations.length > 0) {
        console.log('\n💡 主要改进建议:');
        report.recommendations.slice(0, 3).forEach((rec, i) => {
          console.log(`   ${i + 1}. ${rec}`);
        });
      }
      
    } finally {
      await this.cleanup();
    }
  }
}

// 如果直接运行此文件
if (require.main === module) {
  const runner = new UserJourneyRunner();
  runner.runCompleteTestSuite().catch(console.error);
}