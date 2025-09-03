/**
 * 性能优化工具函数
 * 提供各种性能监控、优化和分析的实用函数
 */

// 性能指标接口
export interface PerformanceMetrics {
  // Core Web Vitals
  LCP?: number; // Largest Contentful Paint
  FID?: number; // First Input Delay
  CLS?: number; // Cumulative Layout Shift
  FCP?: number; // First Contentful Paint
  TTFB?: number; // Time to First Byte
  
  // 自定义指标
  pageLoadTime?: number;
  domContentLoaded?: number;
  firstPaint?: number;
  memoryUsage?: number;
  jsHeapSize?: number;
  
  // 网络指标
  networkType?: string;
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
}

// 性能观察者类
export class PerformanceObserver {
  private observers: Map<string, globalThis.PerformanceObserver> = new Map();
  private metrics: PerformanceMetrics = {};
  private callbacks: Array<(metrics: PerformanceMetrics) => void> = [];

  constructor() {
    this.initObservers();
  }

  // 初始化性能观察者
  private initObservers() {
    // 观察 LCP
    if ('PerformanceObserver' in window) {
      try {
        const lcpObserver = new window.PerformanceObserver((entryList) => {
          const entries = entryList.getEntries();
          const lastEntry = entries[entries.length - 1];
          this.metrics.LCP = lastEntry.startTime;
          this.notifyCallbacks();
        });
        lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
        this.observers.set('lcp', lcpObserver);
      } catch (e) {
        console.warn('LCP observer not supported:', e);
      }

      // 观察 FID
      try {
        const fidObserver = new window.PerformanceObserver((entryList) => {
          const entries = entryList.getEntries();
          entries.forEach((entry) => {
            const fidEntry = entry as PerformanceEntry & { processingStart: number };
            this.metrics.FID = fidEntry.processingStart - fidEntry.startTime;
          });
          this.notifyCallbacks();
        });
        fidObserver.observe({ entryTypes: ['first-input'] });
        this.observers.set('fid', fidObserver);
      } catch (e) {
        console.warn('FID observer not supported:', e);
      }

      // 观察 CLS
      try {
        let clsValue = 0;
        const clsObserver = new window.PerformanceObserver((entryList) => {
          const entries = entryList.getEntries();
          entries.forEach((entry) => {
            const clsEntry = entry as PerformanceEntry & { value: number; hadRecentInput: boolean };
            if (!clsEntry.hadRecentInput) {
              clsValue += clsEntry.value;
            }
          });
          this.metrics.CLS = clsValue;
          this.notifyCallbacks();
        });
        clsObserver.observe({ entryTypes: ['layout-shift'] });
        this.observers.set('cls', clsObserver);
      } catch (e) {
        console.warn('CLS observer not supported:', e);
      }

      // 观察导航时间
      try {
        const navigationObserver = new window.PerformanceObserver((entryList) => {
          const entries = entryList.getEntries();
          entries.forEach((entry) => {
            const navEntry = entry as PerformanceNavigationTiming;
            this.metrics.pageLoadTime = navEntry.loadEventEnd - navEntry.loadEventStart;
            this.metrics.domContentLoaded = navEntry.domContentLoadedEventEnd - navEntry.domContentLoadedEventStart;
            this.metrics.TTFB = navEntry.responseStart - navEntry.requestStart;
          });
          this.notifyCallbacks();
        });
        navigationObserver.observe({ entryTypes: ['navigation'] });
        this.observers.set('navigation', navigationObserver);
      } catch (e) {
        console.warn('Navigation observer not supported:', e);
      }
    }

    // 监控内存使用
    this.monitorMemoryUsage();
    
    // 监控网络信息
    this.monitorNetworkInfo();
  }

  // 监控内存使用
  private monitorMemoryUsage() {
    if ('memory' in performance) {
      const updateMemory = () => {
        const memory = (performance as unknown as { memory: { usedJSHeapSize: number; totalJSHeapSize: number } }).memory;
        this.metrics.memoryUsage = memory.usedJSHeapSize / 1024 / 1024; // MB
        this.metrics.jsHeapSize = memory.totalJSHeapSize / 1024 / 1024; // MB
        this.notifyCallbacks();
      };
      
      updateMemory();
      setInterval(updateMemory, 5000); // 每5秒更新一次
    }
  }

  // 监控网络信息
  private monitorNetworkInfo() {
    if ('connection' in navigator) {
      const connection = (navigator as unknown as { connection: {
        type: string;
        effectiveType: string;
        downlink: number;
        rtt: number;
        addEventListener: (event: string, callback: () => void) => void;
      } }).connection;
      this.metrics.networkType = connection.type;
      this.metrics.effectiveType = connection.effectiveType;
      this.metrics.downlink = connection.downlink;
      this.metrics.rtt = connection.rtt;
      
      connection.addEventListener('change', () => {
        this.metrics.networkType = connection.type;
        this.metrics.effectiveType = connection.effectiveType;
        this.metrics.downlink = connection.downlink;
        this.metrics.rtt = connection.rtt;
        this.notifyCallbacks();
      });
    }
  }

  // 添加回调函数
  public addCallback(callback: (metrics: PerformanceMetrics) => void) {
    this.callbacks.push(callback);
  }

  // 移除回调函数
  public removeCallback(callback: (metrics: PerformanceMetrics) => void) {
    const index = this.callbacks.indexOf(callback);
    if (index > -1) {
      this.callbacks.splice(index, 1);
    }
  }

  // 通知所有回调函数
  private notifyCallbacks() {
    this.callbacks.forEach(callback => callback({ ...this.metrics }));
  }

  // 获取当前指标
  public getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  // 清理观察者
  public cleanup() {
    this.observers.forEach(observer => {
      observer.disconnect();
    });
    this.observers.clear();
    this.callbacks = [];
  }
}

// 全局性能观察者实例
export const globalPerformanceObserver = new PerformanceObserver();

// 性能评分函数
export const calculatePerformanceScore = (metrics: PerformanceMetrics): number => {
  let score = 100;
  
  // LCP 评分 (权重: 25%)
  if (metrics.LCP) {
    if (metrics.LCP > 4000) score -= 25;
    else if (metrics.LCP > 2500) score -= 15;
    else if (metrics.LCP > 1500) score -= 5;
  }
  
  // FID 评分 (权重: 25%)
  if (metrics.FID) {
    if (metrics.FID > 300) score -= 25;
    else if (metrics.FID > 100) score -= 15;
    else if (metrics.FID > 50) score -= 5;
  }
  
  // CLS 评分 (权重: 25%)
  if (metrics.CLS) {
    if (metrics.CLS > 0.25) score -= 25;
    else if (metrics.CLS > 0.1) score -= 15;
    else if (metrics.CLS > 0.05) score -= 5;
  }
  
  // 页面加载时间评分 (权重: 25%)
  if (metrics.pageLoadTime) {
    if (metrics.pageLoadTime > 5000) score -= 25;
    else if (metrics.pageLoadTime > 3000) score -= 15;
    else if (metrics.pageLoadTime > 1500) score -= 5;
  }
  
  return Math.max(0, Math.min(100, score));
};

// 性能等级评定
export const getPerformanceGrade = (score: number): string => {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
};

// 获取性能建议
export const getPerformanceRecommendations = (metrics: PerformanceMetrics): string[] => {
  const recommendations: string[] = [];
  
  if (metrics.LCP && metrics.LCP > 2500) {
    recommendations.push('优化最大内容绘制时间：压缩图片、使用CDN、优化服务器响应时间');
  }
  
  if (metrics.FID && metrics.FID > 100) {
    recommendations.push('减少首次输入延迟：优化JavaScript执行、减少主线程阻塞');
  }
  
  if (metrics.CLS && metrics.CLS > 0.1) {
    recommendations.push('改善累积布局偏移：为图片和广告预留空间、避免动态插入内容');
  }
  
  if (metrics.memoryUsage && metrics.memoryUsage > 100) {
    recommendations.push('优化内存使用：清理未使用的变量、优化图片缓存、减少DOM节点');
  }
  
  if (metrics.pageLoadTime && metrics.pageLoadTime > 3000) {
    recommendations.push('优化页面加载时间：启用代码分割、使用懒加载、优化资源加载顺序');
  }
  
  return recommendations;
};

// 资源加载性能分析
export const analyzeResourcePerformance = (): Array<{
  name: string;
  type: string;
  size: number;
  duration: number;
  startTime: number;
}> => {
  const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
  
  return resources.map(resource => ({
    name: resource.name,
    type: resource.initiatorType,
    size: resource.transferSize || 0,
    duration: resource.duration,
    startTime: resource.startTime,
  })).sort((a, b) => b.duration - a.duration);
};

// 检测性能瓶颈
export const detectPerformanceBottlenecks = (metrics: PerformanceMetrics): Array<{
  type: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
  recommendation: string;
}> => {
  const bottlenecks: Array<{
    type: string;
    severity: 'low' | 'medium' | 'high';
    description: string;
    recommendation: string;
  }> = [];
  
  // 检测LCP问题
  if (metrics.LCP && metrics.LCP > 4000) {
    bottlenecks.push({
      type: 'LCP',
      severity: 'high',
      description: `最大内容绘制时间过长 (${metrics.LCP.toFixed(0)}ms)`,
      recommendation: '优化图片加载、使用CDN、减少服务器响应时间',
    });
  } else if (metrics.LCP && metrics.LCP > 2500) {
    bottlenecks.push({
      type: 'LCP',
      severity: 'medium',
      description: `最大内容绘制时间较长 (${metrics.LCP.toFixed(0)}ms)`,
      recommendation: '压缩图片、优化关键资源加载',
    });
  }
  
  // 检测FID问题
  if (metrics.FID && metrics.FID > 300) {
    bottlenecks.push({
      type: 'FID',
      severity: 'high',
      description: `首次输入延迟过长 (${metrics.FID.toFixed(0)}ms)`,
      recommendation: '减少JavaScript执行时间、优化事件处理器',
    });
  } else if (metrics.FID && metrics.FID > 100) {
    bottlenecks.push({
      type: 'FID',
      severity: 'medium',
      description: `首次输入延迟较长 (${metrics.FID.toFixed(0)}ms)`,
      recommendation: '优化主线程任务、使用Web Workers',
    });
  }
  
  // 检测CLS问题
  if (metrics.CLS && metrics.CLS > 0.25) {
    bottlenecks.push({
      type: 'CLS',
      severity: 'high',
      description: `累积布局偏移过大 (${metrics.CLS.toFixed(3)})`,
      recommendation: '为动态内容预留空间、避免无尺寸的图片',
    });
  } else if (metrics.CLS && metrics.CLS > 0.1) {
    bottlenecks.push({
      type: 'CLS',
      severity: 'medium',
      description: `累积布局偏移较大 (${metrics.CLS.toFixed(3)})`,
      recommendation: '优化字体加载、稳定化动态内容',
    });
  }
  
  // 检测内存问题
  if (metrics.memoryUsage && metrics.memoryUsage > 150) {
    bottlenecks.push({
      type: 'Memory',
      severity: 'high',
      description: `内存使用过高 (${metrics.memoryUsage.toFixed(1)}MB)`,
      recommendation: '检查内存泄漏、优化数据结构、清理未使用的对象',
    });
  } else if (metrics.memoryUsage && metrics.memoryUsage > 100) {
    bottlenecks.push({
      type: 'Memory',
      severity: 'medium',
      description: `内存使用较高 (${metrics.memoryUsage.toFixed(1)}MB)`,
      recommendation: '优化图片缓存、减少DOM节点数量',
    });
  }
  
  return bottlenecks;
};

// 性能数据格式化
export const formatPerformanceData = (metrics: PerformanceMetrics) => {
  return {
    coreWebVitals: {
      LCP: metrics.LCP ? `${metrics.LCP.toFixed(0)}ms` : 'N/A',
      FID: metrics.FID ? `${metrics.FID.toFixed(0)}ms` : 'N/A',
      CLS: metrics.CLS ? metrics.CLS.toFixed(3) : 'N/A',
      FCP: metrics.FCP ? `${metrics.FCP.toFixed(0)}ms` : 'N/A',
      TTFB: metrics.TTFB ? `${metrics.TTFB.toFixed(0)}ms` : 'N/A',
    },
    loadingMetrics: {
      pageLoadTime: metrics.pageLoadTime ? `${metrics.pageLoadTime.toFixed(0)}ms` : 'N/A',
      domContentLoaded: metrics.domContentLoaded ? `${metrics.domContentLoaded.toFixed(0)}ms` : 'N/A',
      firstPaint: metrics.firstPaint ? `${metrics.firstPaint.toFixed(0)}ms` : 'N/A',
    },
    resourceMetrics: {
      memoryUsage: metrics.memoryUsage ? `${metrics.memoryUsage.toFixed(1)}MB` : 'N/A',
      jsHeapSize: metrics.jsHeapSize ? `${metrics.jsHeapSize.toFixed(1)}MB` : 'N/A',
    },
    networkMetrics: {
      networkType: metrics.networkType || 'N/A',
      effectiveType: metrics.effectiveType || 'N/A',
      downlink: metrics.downlink ? `${metrics.downlink.toFixed(1)}Mbps` : 'N/A',
      rtt: metrics.rtt ? `${metrics.rtt}ms` : 'N/A',
    },
  };
};

// 性能数据导出
export const exportPerformanceData = (metrics: PerformanceMetrics, format: 'json' | 'csv' = 'json') => {
  const data = formatPerformanceData(metrics);
  const timestamp = new Date().toISOString();
  
  if (format === 'json') {
    const jsonData = {
      timestamp,
      ...data,
      score: calculatePerformanceScore(metrics),
      grade: getPerformanceGrade(calculatePerformanceScore(metrics)),
      recommendations: getPerformanceRecommendations(metrics),
      bottlenecks: detectPerformanceBottlenecks(metrics),
    };
    
    const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `performance-report-${timestamp.split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } else if (format === 'csv') {
    const csvData = [
      ['Metric', 'Value'],
      ['Timestamp', timestamp],
      ['LCP', data.coreWebVitals.LCP],
      ['FID', data.coreWebVitals.FID],
      ['CLS', data.coreWebVitals.CLS],
      ['FCP', data.coreWebVitals.FCP],
      ['TTFB', data.coreWebVitals.TTFB],
      ['Page Load Time', data.loadingMetrics.pageLoadTime],
      ['DOM Content Loaded', data.loadingMetrics.domContentLoaded],
      ['Memory Usage', data.resourceMetrics.memoryUsage],
      ['JS Heap Size', data.resourceMetrics.jsHeapSize],
      ['Network Type', data.networkMetrics.networkType],
      ['Effective Type', data.networkMetrics.effectiveType],
      ['Downlink', data.networkMetrics.downlink],
      ['RTT', data.networkMetrics.rtt],
    ].map(row => row.join(',')).join('\n');
    
    const blob = new Blob([csvData], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `performance-report-${timestamp.split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }
};

// 性能预警系统
export class PerformanceAlertSystem {
  private thresholds: {
    LCP: number;
    FID: number;
    CLS: number;
    memoryUsage: number;
    pageLoadTime: number;
  };
  
  private alertCallbacks: Array<(alert: {
    type: string;
    severity: 'warning' | 'error';
    message: string;
    value: number;
    threshold: number;
  }) => void> = [];

  constructor(thresholds = {
    LCP: 2500,
    FID: 100,
    CLS: 0.1,
    memoryUsage: 100,
    pageLoadTime: 3000,
  }) {
    this.thresholds = thresholds;
  }

  // 检查性能指标并触发预警
  public checkMetrics(metrics: PerformanceMetrics) {
    // 检查 LCP
    if (metrics.LCP && metrics.LCP > this.thresholds.LCP) {
      this.triggerAlert({
        type: 'LCP',
        severity: metrics.LCP > this.thresholds.LCP * 1.5 ? 'error' : 'warning',
        message: `最大内容绘制时间超过阈值`,
        value: metrics.LCP,
        threshold: this.thresholds.LCP,
      });
    }
    
    // 检查 FID
    if (metrics.FID && metrics.FID > this.thresholds.FID) {
      this.triggerAlert({
        type: 'FID',
        severity: metrics.FID > this.thresholds.FID * 2 ? 'error' : 'warning',
        message: `首次输入延迟超过阈值`,
        value: metrics.FID,
        threshold: this.thresholds.FID,
      });
    }
    
    // 检查 CLS
    if (metrics.CLS && metrics.CLS > this.thresholds.CLS) {
      this.triggerAlert({
        type: 'CLS',
        severity: metrics.CLS > this.thresholds.CLS * 2 ? 'error' : 'warning',
        message: `累积布局偏移超过阈值`,
        value: metrics.CLS,
        threshold: this.thresholds.CLS,
      });
    }
    
    // 检查内存使用
    if (metrics.memoryUsage && metrics.memoryUsage > this.thresholds.memoryUsage) {
      this.triggerAlert({
        type: 'Memory',
        severity: metrics.memoryUsage > this.thresholds.memoryUsage * 1.5 ? 'error' : 'warning',
        message: `内存使用超过阈值`,
        value: metrics.memoryUsage,
        threshold: this.thresholds.memoryUsage,
      });
    }
    
    // 检查页面加载时间
    if (metrics.pageLoadTime && metrics.pageLoadTime > this.thresholds.pageLoadTime) {
      this.triggerAlert({
        type: 'PageLoad',
        severity: metrics.pageLoadTime > this.thresholds.pageLoadTime * 1.5 ? 'error' : 'warning',
        message: `页面加载时间超过阈值`,
        value: metrics.pageLoadTime,
        threshold: this.thresholds.pageLoadTime,
      });
    }
  }

  // 触发预警
  private triggerAlert(alert: {
    type: string;
    severity: 'warning' | 'error';
    message: string;
    value: number;
    threshold: number;
  }) {
    this.alertCallbacks.forEach(callback => callback(alert));
  }

  // 添加预警回调
  public addAlertCallback(callback: (alert: {
    type: string;
    severity: 'warning' | 'error';
    message: string;
    value: number;
    threshold: number;
  }) => void) {
    this.alertCallbacks.push(callback);
  }

  // 移除预警回调
  public removeAlertCallback(callback: (alert: {
    type: string;
    severity: 'warning' | 'error';
    message: string;
    value: number;
    threshold: number;
  }) => void) {
    const index = this.alertCallbacks.indexOf(callback);
    if (index > -1) {
      this.alertCallbacks.splice(index, 1);
    }
  }

  // 更新阈值
  public updateThresholds(newThresholds: Partial<typeof this.thresholds>) {
    this.thresholds = { ...this.thresholds, ...newThresholds };
  }
}

// 全局性能预警系统实例
export const globalPerformanceAlertSystem = new PerformanceAlertSystem();