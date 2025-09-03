import { Page } from '@playwright/test';

export interface UXMetrics {
  // 性能指标
  pageLoadTime: number;
  timeToInteractive: number;
  firstContentfulPaint: number;
  largestContentfulPaint: number;
  cumulativeLayoutShift: number;
  
  // 用户交互指标
  clickResponseTime: number[];
  formFillTime: number;
  navigationTime: number;
  
  // 业务指标
  taskCompletionTime: number;
  errorRate: number;
  conversionFunnelMetrics: Record<string, number>;
  
  // 设备和网络指标
  deviceInfo: DeviceInfo;
  networkConditions: NetworkConditions;
  
  // 用户满意度指标（模拟）
  perceivedPerformance: number; // 1-10分
  taskSuccess: boolean;
  userFrustrationEvents: string[];
}

export interface DeviceInfo {
  userAgent: string;
  viewport: { width: number; height: number };
  devicePixelRatio: number;
  isMobile: boolean;
  isTablet: boolean;
  browserName: string;
}

export interface NetworkConditions {
  effectiveType: string;
  downlink: number;
  rtt: number;
  saveData: boolean;
}

export class UXMetricsCollector {
  private page: Page;
  private metrics: Partial<UXMetrics> = {};
  private startTimes: Map<string, number> = new Map();
  private interactionTimes: number[] = [];
  private errorEvents: string[] = [];

  constructor(page: Page) {
    this.page = page;
    this.setupMetricsCollection();
  }

  private async setupMetricsCollection() {
    // 监听页面错误
    this.page.on('pageerror', (error) => {
      this.errorEvents.push(`Page Error: ${error.message}`);
    });

    // 监听网络请求失败
    this.page.on('requestfailed', (request) => {
      this.errorEvents.push(`Request Failed: ${request.url()}`);
    });

    // 监听控制台错误
    this.page.on('console', (msg) => {
      if (msg.type() === 'error') {
        this.errorEvents.push(`Console Error: ${msg.text()}`);
      }
    });

    // 注入性能监控代码
    await this.page.addInitScript(() => {
      // 监听用户交互事件
      let interactionStartTime: number;
      
      document.addEventListener('click', () => {
        interactionStartTime = performance.now();
        
        // 监听下一次DOM更新完成
        requestAnimationFrame(() => {
          const responseTime = performance.now() - interactionStartTime;
          (window as any).__interactionTimes = (window as any).__interactionTimes || [];
          (window as any).__interactionTimes.push(responseTime);
        });
      });

      // 监听表单交互
      document.addEventListener('input', () => {
        if (!(window as any).__formStartTime) {
          (window as any).__formStartTime = performance.now();
        }
      });

      document.addEventListener('submit', () => {
        if ((window as any).__formStartTime) {
          const formFillTime = performance.now() - (window as any).__formStartTime;
          (window as any).__formFillTime = formFillTime;
        }
      });

      // 监听布局偏移
      let clsValue = 0;
      new PerformanceObserver((entryList) => {
        for (const entry of entryList.getEntries()) {
          if (!(entry as any).hadRecentInput) {
            clsValue += (entry as any).value;
          }
        }
        (window as any).__clsValue = clsValue;
      }).observe({ type: 'layout-shift', buffered: true });
    });
  }

  // 开始测量任务
  startTask(taskName: string) {
    this.startTimes.set(taskName, Date.now());
  }

  // 结束测量任务
  endTask(taskName: string): number {
    const startTime = this.startTimes.get(taskName);
    if (!startTime) {
      throw new Error(`Task ${taskName} was not started`);
    }
    
    const duration = Date.now() - startTime;
    this.startTimes.delete(taskName);
    return duration;
  }

  // 收集Web Vitals指标
  async collectWebVitals(): Promise<void> {
    const vitals = await this.page.evaluate(() => {
      return new Promise((resolve) => {
        const vitals = {
          fcp: 0,
          lcp: 0,
          cls: (window as any).__clsValue || 0,
          fid: 0,
          ttfb: 0
        };

        // First Contentful Paint
        new PerformanceObserver((entryList) => {
          for (const entry of entryList.getEntries()) {
            if (entry.name === 'first-contentful-paint') {
              vitals.fcp = entry.startTime;
            }
          }
        }).observe({ type: 'paint', buffered: true });

        // Largest Contentful Paint
        new PerformanceObserver((entryList) => {
          const entries = entryList.getEntries();
          const lastEntry = entries[entries.length - 1];
          vitals.lcp = lastEntry.startTime;
        }).observe({ type: 'largest-contentful-paint', buffered: true });

        // Time to First Byte
        const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
        if (navigation) {
          vitals.ttfb = navigation.responseStart - navigation.fetchStart;
        }

        // 等待一小段时间收集数据
        setTimeout(() => resolve(vitals), 1000);
      });
    });

    this.metrics.firstContentfulPaint = vitals.fcp;
    this.metrics.largestContentfulPaint = vitals.lcp;
    this.metrics.cumulativeLayoutShift = vitals.cls;
  }

  // 收集交互指标
  async collectInteractionMetrics(): Promise<void> {
    const interactions = await this.page.evaluate(() => {
      return {
        interactionTimes: (window as any).__interactionTimes || [],
        formFillTime: (window as any).__formFillTime || 0
      };
    });

    this.metrics.clickResponseTime = interactions.interactionTimes;
    this.metrics.formFillTime = interactions.formFillTime;
  }

  // 收集设备信息
  async collectDeviceInfo(): Promise<void> {
    const deviceInfo = await this.page.evaluate(() => {
      return {
        userAgent: navigator.userAgent,
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight
        },
        devicePixelRatio: window.devicePixelRatio,
        isMobile: /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent),
        isTablet: /iPad|Tablet/i.test(navigator.userAgent)
      };
    });

    this.metrics.deviceInfo = {
      ...deviceInfo,
      browserName: this.getBrowserName(deviceInfo.userAgent)
    };
  }

  // 收集网络条件
  async collectNetworkConditions(): Promise<void> {
    const networkInfo = await this.page.evaluate(() => {
      const connection = (navigator as any).connection;
      if (connection) {
        return {
          effectiveType: connection.effectiveType,
          downlink: connection.downlink,
          rtt: connection.rtt,
          saveData: connection.saveData
        };
      }
      return null;
    });

    this.metrics.networkConditions = networkInfo || {
      effectiveType: 'unknown',
      downlink: 0,
      rtt: 0,
      saveData: false
    };
  }

  // 测量页面加载时间
  async measurePageLoadTime(): Promise<number> {
    const loadTime = await this.page.evaluate(() => {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return navigation ? navigation.loadEventEnd - navigation.fetchStart : 0;
    });

    this.metrics.pageLoadTime = loadTime;
    return loadTime;
  }

  // 测量Time to Interactive
  async measureTimeToInteractive(): Promise<number> {
    // 简化的TTI计算：等待页面稳定且无长任务
    const tti = await this.page.evaluate(() => {
      return new Promise((resolve) => {
        let lastLongTaskEnd = 0;
        
        // 监听长任务
        new PerformanceObserver((entryList) => {
          for (const entry of entryList.getEntries()) {
            lastLongTaskEnd = entry.startTime + entry.duration;
          }
        }).observe({ type: 'longtask', buffered: true });

        // 等待2秒的静默期
        setTimeout(() => {
          const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
          const tti = Math.max(
            navigation.domContentLoadedEventEnd,
            lastLongTaskEnd
          ) - navigation.fetchStart;
          
          resolve(tti);
        }, 2000);
      });
    });

    this.metrics.timeToInteractive = tti;
    return tti;
  }

  // 评估用户体验满意度
  evaluateUserSatisfaction(): number {
    let score = 10;

    // 根据各项指标扣分
    if (this.metrics.pageLoadTime && this.metrics.pageLoadTime > 3000) {
      score -= 2; // 页面加载超过3秒
    }

    if (this.metrics.largestContentfulPaint && this.metrics.largestContentfulPaint > 2500) {
      score -= 1; // LCP超过2.5秒
    }

    if (this.metrics.cumulativeLayoutShift && this.metrics.cumulativeLayoutShift > 0.1) {
      score -= 1; // CLS超过0.1
    }

    if (this.metrics.clickResponseTime && this.metrics.clickResponseTime.length > 0) {
      const avgResponseTime = this.metrics.clickResponseTime.reduce((a, b) => a + b, 0) / this.metrics.clickResponseTime.length;
      if (avgResponseTime > 100) {
        score -= 1; // 平均响应时间超过100ms
      }
    }

    if (this.errorEvents.length > 0) {
      score -= this.errorEvents.length * 0.5; // 每个错误扣0.5分
    }

    return Math.max(1, Math.min(10, score)); // 确保分数在1-10之间
  }

  // 生成转化漏斗指标
  createConversionFunnel(steps: string[]): Record<string, number> {
    const funnel: Record<string, number> = {};
    
    // 这里应该根据实际的用户行为数据来计算
    // 简化示例：假设每一步都有一定的转化率
    let currentUsers = 100;
    
    for (let i = 0; i < steps.length; i++) {
      funnel[steps[i]] = currentUsers;
      currentUsers *= 0.8; // 每步80%的转化率（示例）
    }
    
    return funnel;
  }

  // 获取完整的UX指标报告
  async generateUXReport(): Promise<UXMetrics> {
    await this.collectWebVitals();
    await this.collectInteractionMetrics();
    await this.collectDeviceInfo();
    await this.collectNetworkConditions();

    const report: UXMetrics = {
      // 性能指标
      pageLoadTime: this.metrics.pageLoadTime || 0,
      timeToInteractive: this.metrics.timeToInteractive || 0,
      firstContentfulPaint: this.metrics.firstContentfulPaint || 0,
      largestContentfulPaint: this.metrics.largestContentfulPaint || 0,
      cumulativeLayoutShift: this.metrics.cumulativeLayoutShift || 0,
      
      // 交互指标
      clickResponseTime: this.metrics.clickResponseTime || [],
      formFillTime: this.metrics.formFillTime || 0,
      navigationTime: 0, // 可以通过路由变化时间来测量
      
      // 业务指标
      taskCompletionTime: 0, // 需要在具体任务中设置
      errorRate: this.errorEvents.length,
      conversionFunnelMetrics: {},
      
      // 设备和网络
      deviceInfo: this.metrics.deviceInfo!,
      networkConditions: this.metrics.networkConditions!,
      
      // 用户满意度
      perceivedPerformance: this.evaluateUserSatisfaction(),
      taskSuccess: this.errorEvents.length === 0,
      userFrustrationEvents: this.errorEvents
    };

    return report;
  }

  // 导出指标到文件
  async exportMetrics(filename: string): Promise<void> {
    const report = await this.generateUXReport();
    const fs = require('fs');
    const path = require('path');
    
    const reportPath = path.join('test-results', 'ux-metrics', filename);
    const dir = path.dirname(reportPath);
    
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`UX指标报告已导出到: ${reportPath}`);
  }

  private getBrowserName(userAgent: string): string {
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    return 'Unknown';
  }

  // 创建性能预算检查
  checkPerformanceBudget(budget: Partial<UXMetrics>): { passed: boolean; violations: string[] } {
    const violations: string[] = [];

    if (budget.pageLoadTime && this.metrics.pageLoadTime! > budget.pageLoadTime) {
      violations.push(`页面加载时间超预算: ${this.metrics.pageLoadTime}ms > ${budget.pageLoadTime}ms`);
    }

    if (budget.largestContentfulPaint && this.metrics.largestContentfulPaint! > budget.largestContentfulPaint) {
      violations.push(`LCP超预算: ${this.metrics.largestContentfulPaint}ms > ${budget.largestContentfulPaint}ms`);
    }

    if (budget.cumulativeLayoutShift && this.metrics.cumulativeLayoutShift! > budget.cumulativeLayoutShift) {
      violations.push(`CLS超预算: ${this.metrics.cumulativeLayoutShift} > ${budget.cumulativeLayoutShift}`);
    }

    return {
      passed: violations.length === 0,
      violations
    };
  }
}