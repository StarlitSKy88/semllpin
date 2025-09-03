"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserJourneyRunner = void 0;
const test_1 = require("@playwright/test");
const ux_metrics_1 = require("./utils/ux-metrics");
const auth_page_1 = require("./page-objects/auth-page");
const map_page_1 = require("./page-objects/map-page");
const test_data_1 = require("./fixtures/test-data");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
class UserJourneyRunner {
    constructor() {
        this.browser = null;
        this.results = [];
        this.startTime = 0;
    }
    async initialize() {
        console.log('🚀 初始化用户路径测试运行器...');
        this.browser = await test_1.chromium.launch({
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
    async runNewUserRegistrationTests() {
        console.log('📝 开始新用户注册流程测试...');
        const results = [];
        const devices = [
            { name: 'Desktop Chrome', device: null },
            { name: 'Mobile Safari', device: devices['iPhone 12'] },
            { name: 'Tablet iPad', device: devices['iPad Pro'] }
        ];
        for (const deviceConfig of devices) {
            const result = await this.runSingleTest(`新用户注册 - ${deviceConfig.name}`, async (context, uxCollector) => {
                const page = await context.newPage();
                const authPage = new auth_page_1.AuthPage(page);
                await uxCollector.measurePageLoadTime();
                uxCollector.startTask('registration');
                const userData = test_data_1.TestData.users.newUser;
                await authPage.navigateToRegister();
                await authPage.register({
                    username: `${userData.username}_${Date.now()}`,
                    email: `test_${Date.now()}@example.com`,
                    password: userData.password
                });
                if (page.url().includes('/verify')) {
                    await authPage.verifyEmail('123456');
                }
                await authPage.verifyLoggedIn();
                const registrationTime = uxCollector.endTask('registration');
                await uxCollector.collectWebVitals();
                return {
                    success: true,
                    metrics: { registrationTime },
                    feedback: await this.simulateUserFeedback('registration', registrationTime)
                };
            }, deviceConfig.device);
            results.push(result);
        }
        return results;
    }
    async runAnnotationCreatorTests() {
        console.log('🏷️ 开始标注创建者流程测试...');
        const results = [];
        const result = await this.runSingleTest('标注创建者完整流程', async (context, uxCollector) => {
            const page = await context.newPage();
            const authPage = new auth_page_1.AuthPage(page);
            const mapPage = new map_page_1.MapPage(page);
            const userData = await authPage.createAndLoginTestUser();
            uxCollector.startTask('annotationCreation');
            await mapPage.navigateToMap();
            await mapPage.waitForMapLoad();
            const annotation = test_data_1.TestData.annotations.pleasant[0];
            await mapPage.createAnnotation({
                ...annotation,
                latitude: 40.7128,
                longitude: -74.0060
            });
            const creationTime = uxCollector.endTask('annotationCreation');
            await mapPage.verifyAnnotationCount(1);
            return {
                success: true,
                metrics: { creationTime },
                feedback: await this.simulateUserFeedback('creation', creationTime)
            };
        });
        results.push(result);
        return results;
    }
    async runRewardDiscovererTests() {
        console.log('🎁 开始奖励发现者流程测试...');
        const results = [];
        const result = await this.runSingleTest('奖励发现者完整流程', async (context, uxCollector) => {
            const page = await context.newPage();
            const authPage = new auth_page_1.AuthPage(page);
            const mapPage = new map_page_1.MapPage(page);
            const userData = test_data_1.TestData.users.rewardDiscoverer;
            await authPage.login(`${userData.email}_${Date.now()}@test.com`, userData.password);
            uxCollector.startTask('rewardDiscovery');
            await mapPage.navigateToMap();
            await mapPage.waitForMapLoad();
            await mapPage.getCurrentLocation();
            await mapPage.enterGeofence(40.7589, -73.9851);
            await mapPage.claimReward();
            const discoveryTime = uxCollector.endTask('rewardDiscovery');
            return {
                success: true,
                metrics: { discoveryTime },
                feedback: await this.simulateUserFeedback('discovery', discoveryTime)
            };
        });
        results.push(result);
        return results;
    }
    async runSocialInteractionTests() {
        console.log('👥 开始社交互动流程测试...');
        const results = [];
        const result = await this.runSingleTest('社交互动完整流程', async (context, uxCollector) => {
            const page = await context.newPage();
            const authPage = new auth_page_1.AuthPage(page);
            const mapPage = new map_page_1.MapPage(page);
            const userData = test_data_1.TestData.users.socialUser;
            await authPage.login(`${userData.email}_${Date.now()}@test.com`, userData.password);
            uxCollector.startTask('socialInteraction');
            await mapPage.navigateToMap();
            await mapPage.waitForMapLoad();
            await mapPage.clickAnnotationMarker(0);
            await mapPage.likeAnnotation();
            const interactionTime = uxCollector.endTask('socialInteraction');
            return {
                success: true,
                metrics: { interactionTime },
                feedback: await this.simulateUserFeedback('social', interactionTime)
            };
        });
        results.push(result);
        return results;
    }
    async runCrossDeviceNetworkTests() {
        console.log('📱 开始跨设备和网络环境测试...');
        const results = [];
        const networkConditions = [
            { name: '快速网络', delay: 0 },
            { name: '慢速3G', delay: 2000 },
            { name: '不稳定网络', delay: 'random' }
        ];
        for (const network of networkConditions) {
            const result = await this.runSingleTest(`网络测试 - ${network.name}`, async (context, uxCollector) => {
                if (network.delay !== 0) {
                    await context.route('**/*', async (route) => {
                        const delay = network.delay === 'random'
                            ? Math.random() * 3000
                            : network.delay;
                        await new Promise(resolve => setTimeout(resolve, delay));
                        await route.continue();
                    });
                }
                const page = await context.newPage();
                const authPage = new auth_page_1.AuthPage(page);
                const mapPage = new map_page_1.MapPage(page);
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
            });
            results.push(result);
        }
        return results;
    }
    async runSingleTest(testName, testFunction, device) {
        console.log(`▶️  运行测试: ${testName}`);
        const startTime = Date.now();
        const screenshots = [];
        try {
            const contextOptions = device ? { ...device } : {};
            contextOptions.permissions = ['geolocation', 'notifications'];
            contextOptions.geolocation = { latitude: 40.7128, longitude: -74.0060 };
            const context = await this.browser.newContext(contextOptions);
            const page = await context.newPage();
            const uxCollector = new ux_metrics_1.UXMetricsCollector(page);
            const screenshotDir = path_1.default.join('test-results', 'screenshots', testName.replace(/\s+/g, '-'));
            if (!fs_1.default.existsSync(screenshotDir)) {
                fs_1.default.mkdirSync(screenshotDir, { recursive: true });
            }
            const result = await testFunction(context, uxCollector);
            const uxMetrics = await uxCollector.generateUXReport();
            await uxCollector.exportMetrics(`${testName.replace(/\s+/g, '-')}.json`);
            const finalScreenshot = path_1.default.join(screenshotDir, 'final.png');
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
        }
        catch (error) {
            const duration = Date.now() - startTime;
            console.error(`❌ ${testName} 失败 (${duration}ms):`, error);
            return {
                testName,
                status: 'failed',
                duration,
                error: error.message,
                screenshots
            };
        }
    }
    async simulateUserFeedback(taskType, duration) {
        let satisfactionScore = 10;
        const usabilityIssues = [];
        const suggestions = [];
        if (duration > 30000) {
            satisfactionScore -= 2;
            usabilityIssues.push('任务完成时间过长');
            suggestions.push('优化页面加载速度');
        }
        if (duration > 60000) {
            satisfactionScore -= 2;
            usabilityIssues.push('用户流程复杂');
            suggestions.push('简化用户操作步骤');
        }
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
    async generateComprehensiveReport() {
        const totalDuration = Date.now() - this.startTime;
        const passed = this.results.filter(r => r.status === 'passed').length;
        const failed = this.results.filter(r => r.status === 'failed').length;
        const skipped = this.results.filter(r => r.status === 'skipped').length;
        const pageLoadTimes = this.results
            .map(r => r.uxMetrics?.pageLoadTime || 0)
            .filter(time => time > 0);
        const averagePageLoadTime = pageLoadTimes.length > 0
            ? pageLoadTimes.reduce((a, b) => a + b, 0) / pageLoadTimes.length
            : 0;
        const allIssues = this.results
            .flatMap(r => r.userFeedback?.usabilityIssues || []);
        const allSuggestions = this.results
            .flatMap(r => r.userFeedback?.suggestions || []);
        const criticalIssues = allIssues.filter(issue => issue.includes('时间过长') || issue.includes('失败'));
        const moderateIssues = allIssues.filter(issue => issue.includes('复杂') || issue.includes('不够直观'));
        const minorIssues = allIssues.filter(issue => !criticalIssues.includes(issue) && !moderateIssues.includes(issue));
        const positiveFindings = allSuggestions.filter(suggestion => suggestion.includes('很好') || suggestion.includes('良好'));
        const recommendations = [
            ...new Set([
                ...allSuggestions.filter(s => !positiveFindings.includes(s)),
                criticalIssues.length > 0 ? '优先解决关键性能问题' : '',
                averagePageLoadTime > 3000 ? '优化页面加载性能' : '',
                failed > 0 ? '修复测试失败的功能' : ''
            ])
        ].filter(r => r !== '');
        const report = {
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
    groupResultsByCategory(category) {
        const grouped = {};
        this.results.forEach(result => {
            let key = 'other';
            if (category === 'device') {
                if (result.testName.includes('Mobile'))
                    key = 'mobile';
                else if (result.testName.includes('Tablet'))
                    key = 'tablet';
                else if (result.testName.includes('Desktop'))
                    key = 'desktop';
            }
            else if (category === 'network') {
                if (result.testName.includes('网络'))
                    key = 'network';
            }
            else if (category === 'journey') {
                if (result.testName.includes('注册'))
                    key = 'registration';
                else if (result.testName.includes('标注'))
                    key = 'annotation';
                else if (result.testName.includes('奖励'))
                    key = 'reward';
                else if (result.testName.includes('社交'))
                    key = 'social';
            }
            if (!grouped[key])
                grouped[key] = [];
            grouped[key].push(result);
        });
        return grouped;
    }
    calculateConversionRates() {
        const registrationTests = this.results.filter(r => r.testName.includes('注册') && r.status === 'passed');
        const creationTests = this.results.filter(r => r.testName.includes('标注') && r.status === 'passed');
        const discoveryTests = this.results.filter(r => r.testName.includes('奖励') && r.status === 'passed');
        return {
            registration: registrationTests.length / Math.max(1, this.results.filter(r => r.testName.includes('注册')).length),
            creation: creationTests.length / Math.max(1, this.results.filter(r => r.testName.includes('标注')).length),
            discovery: discoveryTests.length / Math.max(1, this.results.filter(r => r.testName.includes('奖励')).length)
        };
    }
    async exportReport(report, filename = 'user-journey-report.json') {
        const reportPath = path_1.default.join('test-results', filename);
        const dir = path_1.default.dirname(reportPath);
        if (!fs_1.default.existsSync(dir)) {
            fs_1.default.mkdirSync(dir, { recursive: true });
        }
        fs_1.default.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        const htmlReport = this.generateHTMLReport(report);
        const htmlPath = reportPath.replace('.json', '.html');
        fs_1.default.writeFileSync(htmlPath, htmlReport);
        console.log(`📊 测试报告已生成:`);
        console.log(`   JSON: ${reportPath}`);
        console.log(`   HTML: ${htmlPath}`);
    }
    generateHTMLReport(report) {
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
            : '<p>未发现关键问题 ✅</p>'}
        </div>
    </div>
    
    <div class="section">
        <h2>改进建议</h2>
        <div class="suggestion-list">
            ${report.recommendations.length > 0
            ? report.recommendations.map(rec => `<li>${rec}</li>`).join('')
            : '<p>当前表现良好，无特别建议 👍</p>'}
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
    async runCompleteTestSuite() {
        try {
            await this.initialize();
            console.log('🎯 开始执行SmellPin完整用户路径测试套件\n');
            this.results.push(...await this.runNewUserRegistrationTests());
            this.results.push(...await this.runAnnotationCreatorTests());
            this.results.push(...await this.runRewardDiscovererTests());
            this.results.push(...await this.runSocialInteractionTests());
            this.results.push(...await this.runCrossDeviceNetworkTests());
            const report = await this.generateComprehensiveReport();
            await this.exportReport(report);
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
        }
        finally {
            await this.cleanup();
        }
    }
}
exports.UserJourneyRunner = UserJourneyRunner;
if (require.main === module) {
    const runner = new UserJourneyRunner();
    runner.runCompleteTestSuite().catch(console.error);
}
//# sourceMappingURL=user-journey-runner.js.map