/**
 * 测试指标收集和报告工具
 */

import fs from 'fs';
import path from 'path';

export interface ApiMetric {
  timestamp: number;
  endpoint: string;
  method: string;
  responseTime: number;
  status: number;
  payloadSize?: number;
  errorMessage?: string;
}

export interface PerformanceMetric {
  timestamp: number;
  label: string;
  cpuUsage: NodeJS.CpuUsage;
  memoryUsage: NodeJS.MemoryUsage;
  heapStatistics?: any;
}

export interface SecurityTestResult {
  testName: string;
  passed: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  payload?: string;
  response?: any;
}

export class TestMetrics {
  private apiMetrics: ApiMetric[] = [];
  private performanceMetrics: PerformanceMetric[] = [];
  private securityTestResults: SecurityTestResult[] = [];
  private testStartTime: number;

  constructor() {
    this.testStartTime = Date.now();
  }

  // API性能指标记录
  recordApiCall(
    endpoint: string, 
    responseTime: number, 
    status: number, 
    method: string = 'GET',
    payloadSize?: number,
    errorMessage?: string
  ) {
    this.apiMetrics.push({
      timestamp: Date.now(),
      endpoint,
      method,
      responseTime,
      status,
      payloadSize,
      errorMessage
    });
  }

  // 性能指标记录
  recordPerformanceMetric(label: string) {
    this.performanceMetrics.push({
      timestamp: Date.now(),
      label,
      cpuUsage: process.cpuUsage(),
      memoryUsage: process.memoryUsage(),
      heapStatistics: (process as any).getHeapStatistics ? (process as any).getHeapStatistics() : undefined
    });
  }

  // 安全测试结果记录
  recordSecurityTest(result: SecurityTestResult) {
    this.securityTestResults.push(result);
  }

  // 计算API统计信息
  getApiStatistics() {
    if (this.apiMetrics.length === 0) {
      return null;
    }

    const responseTimes = this.apiMetrics.map(m => m.responseTime);
    const successful = this.apiMetrics.filter(m => m.status >= 200 && m.status < 400);
    const clientErrors = this.apiMetrics.filter(m => m.status >= 400 && m.status < 500);
    const serverErrors = this.apiMetrics.filter(m => m.status >= 500);

    // 按端点分组统计
    const endpointStats = this.groupBy(this.apiMetrics, 'endpoint');
    const endpointSummary = Object.entries(endpointStats).reduce((acc, [endpoint, metrics]) => {
      const times = metrics.map(m => m.responseTime);
      acc[endpoint] = {
        count: metrics.length,
        averageTime: this.average(times),
        minTime: Math.min(...times),
        maxTime: Math.max(...times),
        p50: this.percentile(times, 50),
        p95: this.percentile(times, 95),
        p99: this.percentile(times, 99),
        successRate: (metrics.filter(m => m.status >= 200 && m.status < 400).length / metrics.length) * 100
      };
      return acc;
    }, {} as any);

    return {
      totalRequests: this.apiMetrics.length,
      successfulRequests: successful.length,
      clientErrors: clientErrors.length,
      serverErrors: serverErrors.length,
      successRate: (successful.length / this.apiMetrics.length) * 100,
      averageResponseTime: this.average(responseTimes),
      minResponseTime: Math.min(...responseTimes),
      maxResponseTime: Math.max(...responseTimes),
      medianResponseTime: this.percentile(responseTimes, 50),
      p95ResponseTime: this.percentile(responseTimes, 95),
      p99ResponseTime: this.percentile(responseTimes, 99),
      throughput: this.calculateThroughput(),
      endpointSummary
    };
  }

  // 计算性能统计信息
  getPerformanceStatistics() {
    if (this.performanceMetrics.length < 2) {
      return null;
    }

    const first = this.performanceMetrics[0];
    const last = this.performanceMetrics[this.performanceMetrics.length - 1];

    const memoryGrowth = last.memoryUsage.heapUsed - first.memoryUsage.heapUsed;
    const cpuGrowth = {
      user: last.cpuUsage.user - first.cpuUsage.user,
      system: last.cpuUsage.system - first.cpuUsage.system
    };

    const memoryUsages = this.performanceMetrics.map(m => m.memoryUsage.heapUsed);
    const maxMemoryUsage = Math.max(...memoryUsages);
    const avgMemoryUsage = this.average(memoryUsages);

    return {
      testDuration: last.timestamp - first.timestamp,
      memoryGrowth,
      maxMemoryUsage,
      avgMemoryUsage,
      cpuTime: cpuGrowth,
      peakMemoryUsage: maxMemoryUsage,
      memoryGrowthRate: memoryGrowth / (last.timestamp - first.timestamp),
      snapshots: this.performanceMetrics.length
    };
  }

  // 安全测试统计
  getSecurityStatistics() {
    if (this.securityTestResults.length === 0) {
      return null;
    }

    const passed = this.securityTestResults.filter(r => r.passed);
    const failed = this.securityTestResults.filter(r => !r.passed);
    
    const severityCount = this.securityTestResults.reduce((acc, result) => {
      acc[result.severity] = (acc[result.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const vulnerabilities = failed.map(result => ({
      testName: result.testName,
      severity: result.severity,
      description: result.description
    }));

    return {
      totalTests: this.securityTestResults.length,
      passedTests: passed.length,
      failedTests: failed.length,
      passRate: (passed.length / this.securityTestResults.length) * 100,
      severityBreakdown: severityCount,
      vulnerabilities,
      criticalVulnerabilities: failed.filter(r => r.severity === 'critical').length,
      highVulnerabilities: failed.filter(r => r.severity === 'high').length
    };
  }

  // 生成综合报告
  generateReport() {
    const apiStats = this.getApiStatistics();
    const performanceStats = this.getPerformanceStatistics();
    const securityStats = this.getSecurityStatistics();

    const report = {
      timestamp: new Date().toISOString(),
      testDuration: Date.now() - this.testStartTime,
      summary: {
        totalApiCalls: apiStats?.totalRequests || 0,
        overallSuccessRate: apiStats?.successRate || 0,
        averageResponseTime: apiStats?.averageResponseTime || 0,
        securityTestsPassed: securityStats?.passedTests || 0,
        vulnerabilitiesFound: securityStats?.failedTests || 0,
        memoryGrowth: performanceStats?.memoryGrowth || 0
      },
      apiStatistics: apiStats,
      performanceStatistics: performanceStats,
      securityStatistics: securityStats
    };

    return report;
  }

  // 保存报告到文件
  async saveReport(filename?: string) {
    const report = this.generateReport();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = filename || `test-report-${timestamp}.json`;
    const filePath = path.join(process.cwd(), 'tests', 'reports', fileName);

    // 确保报告目录存在
    const reportDir = path.dirname(filePath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    console.log(`Test report saved to: ${filePath}`);
    
    return filePath;
  }

  // 生成HTML报告
  async generateHtmlReport(filename?: string) {
    const report = this.generateReport();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = filename || `test-report-${timestamp}.html`;
    const filePath = path.join(process.cwd(), 'tests', 'reports', fileName);

    const htmlContent = this.generateHtmlContent(report);

    // 确保报告目录存在
    const reportDir = path.dirname(filePath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    fs.writeFileSync(filePath, htmlContent);
    console.log(`HTML test report saved to: ${filePath}`);
    
    return filePath;
  }

  // 辅助方法
  private average(numbers: number[]): number {
    return numbers.reduce((sum, num) => sum + num, 0) / numbers.length;
  }

  private percentile(numbers: number[], percentile: number): number {
    const sorted = numbers.sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[index];
  }

  private groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const groupKey = String(item[key]);
      groups[groupKey] = groups[groupKey] || [];
      groups[groupKey].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }

  private calculateThroughput(): number {
    if (this.apiMetrics.length < 2) return 0;
    
    const firstTimestamp = this.apiMetrics[0].timestamp;
    const lastTimestamp = this.apiMetrics[this.apiMetrics.length - 1].timestamp;
    const durationSeconds = (lastTimestamp - firstTimestamp) / 1000;
    
    return this.apiMetrics.length / durationSeconds;
  }

  private generateHtmlContent(report: any): string {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin API测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: white; border: 1px solid #ddd; border-radius: 5px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; color: #333; }
        .metric-label { font-size: 0.9em; color: #666; margin-top: 5px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .success { color: #4CAF50; }
        .warning { color: #ff9800; }
        .error { color: #f44336; }
        .chart { width: 100%; height: 300px; margin: 20px 0; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>SmellPin API全面测试报告</h1>
        <p>生成时间: ${report.timestamp}</p>
        <p>测试持续时间: ${Math.round(report.testDuration / 1000)}秒</p>
    </div>

    <div class="summary">
        <div class="metric-card">
            <div class="metric-value">${report.summary.totalApiCalls}</div>
            <div class="metric-label">API调用总数</div>
        </div>
        <div class="metric-card">
            <div class="metric-value ${report.summary.overallSuccessRate >= 95 ? 'success' : 'warning'}">${report.summary.overallSuccessRate.toFixed(1)}%</div>
            <div class="metric-label">整体成功率</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">${report.summary.averageResponseTime.toFixed(0)}ms</div>
            <div class="metric-label">平均响应时间</div>
        </div>
        <div class="metric-card">
            <div class="metric-value ${report.summary.vulnerabilitiesFound === 0 ? 'success' : 'error'}">${report.summary.vulnerabilitiesFound}</div>
            <div class="metric-label">发现的漏洞数</div>
        </div>
    </div>

    ${report.apiStatistics ? this.generateApiStatsHtml(report.apiStatistics) : ''}
    ${report.performanceStatistics ? this.generatePerformanceStatsHtml(report.performanceStatistics) : ''}
    ${report.securityStatistics ? this.generateSecurityStatsHtml(report.securityStatistics) : ''}

    <div class="section">
        <h2>详细数据</h2>
        <pre style="background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto;">
${JSON.stringify(report, null, 2)}
        </pre>
    </div>
</body>
</html>`;
  }

  private generateApiStatsHtml(stats: any): string {
    return `
    <div class="section">
        <h2>API性能统计</h2>
        <table>
            <tr>
                <th>指标</th>
                <th>值</th>
            </tr>
            <tr>
                <td>总请求数</td>
                <td>${stats.totalRequests}</td>
            </tr>
            <tr>
                <td>成功请求数</td>
                <td class="success">${stats.successfulRequests}</td>
            </tr>
            <tr>
                <td>客户端错误</td>
                <td class="warning">${stats.clientErrors}</td>
            </tr>
            <tr>
                <td>服务器错误</td>
                <td class="error">${stats.serverErrors}</td>
            </tr>
            <tr>
                <td>平均响应时间</td>
                <td>${stats.averageResponseTime.toFixed(2)}ms</td>
            </tr>
            <tr>
                <td>95%响应时间</td>
                <td>${stats.p95ResponseTime.toFixed(2)}ms</td>
            </tr>
            <tr>
                <td>吞吐量</td>
                <td>${stats.throughput.toFixed(2)} req/sec</td>
            </tr>
        </table>

        <h3>端点性能详情</h3>
        <table>
            <tr>
                <th>端点</th>
                <th>请求数</th>
                <th>平均时间(ms)</th>
                <th>P95时间(ms)</th>
                <th>成功率(%)</th>
            </tr>
            ${Object.entries(stats.endpointSummary).map(([endpoint, data]: [string, any]) => `
            <tr>
                <td>${endpoint}</td>
                <td>${data.count}</td>
                <td>${data.averageTime.toFixed(2)}</td>
                <td>${data.p95.toFixed(2)}</td>
                <td class="${data.successRate >= 95 ? 'success' : 'warning'}">${data.successRate.toFixed(1)}</td>
            </tr>
            `).join('')}
        </table>
    </div>`;
  }

  private generatePerformanceStatsHtml(stats: any): string {
    return `
    <div class="section">
        <h2>性能监控统计</h2>
        <table>
            <tr>
                <th>指标</th>
                <th>值</th>
            </tr>
            <tr>
                <td>测试持续时间</td>
                <td>${Math.round(stats.testDuration / 1000)}秒</td>
            </tr>
            <tr>
                <td>内存增长</td>
                <td>${(stats.memoryGrowth / 1024 / 1024).toFixed(2)} MB</td>
            </tr>
            <tr>
                <td>峰值内存使用</td>
                <td>${(stats.peakMemoryUsage / 1024 / 1024).toFixed(2)} MB</td>
            </tr>
            <tr>
                <td>平均内存使用</td>
                <td>${(stats.avgMemoryUsage / 1024 / 1024).toFixed(2)} MB</td>
            </tr>
            <tr>
                <td>CPU用户时间</td>
                <td>${(stats.cpuTime.user / 1000).toFixed(2)}ms</td>
            </tr>
            <tr>
                <td>CPU系统时间</td>
                <td>${(stats.cpuTime.system / 1000).toFixed(2)}ms</td>
            </tr>
        </table>
    </div>`;
  }

  private generateSecurityStatsHtml(stats: any): string {
    return `
    <div class="section">
        <h2>安全测试统计</h2>
        <table>
            <tr>
                <th>指标</th>
                <th>值</th>
            </tr>
            <tr>
                <td>总测试数</td>
                <td>${stats.totalTests}</td>
            </tr>
            <tr>
                <td>通过测试</td>
                <td class="success">${stats.passedTests}</td>
            </tr>
            <tr>
                <td>失败测试</td>
                <td class="error">${stats.failedTests}</td>
            </tr>
            <tr>
                <td>通过率</td>
                <td class="${stats.passRate >= 95 ? 'success' : 'error'}">${stats.passRate.toFixed(1)}%</td>
            </tr>
            <tr>
                <td>严重漏洞</td>
                <td class="error">${stats.criticalVulnerabilities}</td>
            </tr>
            <tr>
                <td>高危漏洞</td>
                <td class="warning">${stats.highVulnerabilities}</td>
            </tr>
        </table>

        ${stats.vulnerabilities.length > 0 ? `
        <h3>发现的漏洞</h3>
        <table>
            <tr>
                <th>测试名称</th>
                <th>严重级别</th>
                <th>描述</th>
            </tr>
            ${stats.vulnerabilities.map((vuln: any) => `
            <tr>
                <td>${vuln.testName}</td>
                <td class="${vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : ''}">${vuln.severity}</td>
                <td>${vuln.description}</td>
            </tr>
            `).join('')}
        </table>
        ` : '<p class="success">未发现安全漏洞</p>'}
    </div>`;
  }
}