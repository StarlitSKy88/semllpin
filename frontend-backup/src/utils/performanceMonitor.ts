// 性能监控工具
interface MetricData {
  current: number;
  average: number;
  min: number;
  max: number;
  count: number;
}

interface MemoryInfo {
  usedJSHeapSize: number;
  totalJSHeapSize: number;
  jsHeapSizeLimit: number;
}

interface NetworkConnection {
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
}

interface PerformanceEntryWithProcessing extends PerformanceEntry {
  processingStart: number;
}

interface LayoutShiftEntry extends PerformanceEntry {
  value: number;
  hadRecentInput: boolean;
}

export class PerformanceMonitor {
  private static instance: PerformanceMonitor;
  private metrics: Map<string, number[]> = new Map();
  private observers: PerformanceObserver[] = [];
  private isEnabled: boolean = true;

  private constructor() {
    this.initializeObservers();
  }

  public static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  private initializeObservers(): void {
    if (typeof window === 'undefined' || !('PerformanceObserver' in window)) {
      this.isEnabled = false;
      return;
    }

    try {
      // 监控 LCP (Largest Contentful Paint)
      const lcpObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const lastEntry = entries[entries.length - 1];
        this.recordMetric('LCP', lastEntry.startTime);
      });
      lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
      this.observers.push(lcpObserver);

      // 监控 FID (First Input Delay)
      const fidObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          const fidEntry = entry as PerformanceEntryWithProcessing;
          this.recordMetric('FID', fidEntry.processingStart - fidEntry.startTime);
        });
      });
      fidObserver.observe({ entryTypes: ['first-input'] });
      this.observers.push(fidObserver);

      // 监控 CLS (Cumulative Layout Shift)
      let clsValue = 0;
      const clsObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          const clsEntry = entry as LayoutShiftEntry;
          if (!clsEntry.hadRecentInput) {
            clsValue += clsEntry.value;
            this.recordMetric('CLS', clsValue);
          }
        });
      });
      clsObserver.observe({ entryTypes: ['layout-shift'] });
      this.observers.push(clsObserver);

      // 监控长任务
      const longTaskObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          this.recordMetric('LongTask', entry.duration);
        });
      });
      longTaskObserver.observe({ entryTypes: ['longtask'] });
      this.observers.push(longTaskObserver);

    } catch (error) {
      console.warn('Performance monitoring initialization failed:', error);
      this.isEnabled = false;
    }
  }

  public recordMetric(name: string, value: number): void {
    if (!this.isEnabled) return;
    
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    const values = this.metrics.get(name)!;
    values.push(value);
    
    // 保持最近100个记录
    if (values.length > 100) {
      values.shift();
    }
  }

  public getMetrics(): Record<string, MetricData> {
    if (!this.isEnabled) return {};

    const result: Record<string, MetricData> = {};
    
    this.metrics.forEach((values, name) => {
      if (values.length > 0) {
        result[name] = {
          current: values[values.length - 1],
          average: values.reduce((a, b) => a + b, 0) / values.length,
          min: Math.min(...values),
          max: Math.max(...values),
          count: values.length
        };
      }
    });

    return result;
  }

  public getVitalMetrics(): Record<string, number> {
    const metrics = this.getMetrics();
    return {
      LCP: metrics.LCP?.current || 0,
      FID: metrics.FID?.current || 0,
      CLS: metrics.CLS?.current || 0,
    };
  }

  public getMemoryUsage(): Record<string, number> {
    if (typeof window === 'undefined' || !('performance' in window)) {
      return {};
    }

    const memory = (performance as unknown as { memory?: MemoryInfo }).memory;
    if (!memory) return {};

    return {
      usedJSHeapSize: memory.usedJSHeapSize,
      totalJSHeapSize: memory.totalJSHeapSize,
      jsHeapSizeLimit: memory.jsHeapSizeLimit,
      usagePercentage: (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100
    };
  }

  public getNetworkInfo(): NetworkConnection {
    if (typeof window === 'undefined' || !('navigator' in window)) {
      return {};
    }

    const connection = (navigator as unknown as { connection?: NetworkConnection }).connection;
    if (!connection) return {};

    return {
      effectiveType: connection.effectiveType,
      downlink: connection.downlink,
      rtt: connection.rtt,
      saveData: connection.saveData
    };
  }

  public generateReport(): string {
    const metrics = this.getMetrics();
    const vitals = this.getVitalMetrics();
    const memory = this.getMemoryUsage();
    const network = this.getNetworkInfo();

    const report = {
      timestamp: new Date().toISOString(),
      vitals,
      metrics,
      memory,
      network,
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    return JSON.stringify(report, null, 2);
  }

  public startCustomTimer(name: string): () => void {
    const startTime = performance.now();
    
    return () => {
      const duration = performance.now() - startTime;
      this.recordMetric(name, duration);
    };
  }

  public measureFunction<T extends (...args: unknown[]) => unknown>(
    fn: T,
    name: string
  ): T {
    return ((...args: Parameters<T>) => {
      const endTimer = this.startCustomTimer(name);
      try {
        const result = fn(...args);
        if (result instanceof Promise) {
          return result.finally(() => endTimer());
        }
        endTimer();
        return result;
      } catch (error: unknown) {
        endTimer();
        throw error;
      }
    }) as T;
  }

  public measureComponent(componentName: string) {
    return {
      onMount: this.startCustomTimer(`${componentName}_mount`),
      onUpdate: this.startCustomTimer(`${componentName}_update`),
      onUnmount: this.startCustomTimer(`${componentName}_unmount`)
    };
  }

  public logPerformanceWarnings(): void {
    const vitals = this.getVitalMetrics();
    const memory = this.getMemoryUsage();

    // LCP 警告 (>2.5s)
    if (vitals.LCP > 2500) {
      console.warn(`⚠️ Poor LCP: ${vitals.LCP}ms (should be <2.5s)`);
    }

    // FID 警告 (>100ms)
    if (vitals.FID > 100) {
      console.warn(`⚠️ Poor FID: ${vitals.FID}ms (should be <100ms)`);
    }

    // CLS 警告 (>0.1)
    if (vitals.CLS > 0.1) {
      console.warn(`⚠️ Poor CLS: ${vitals.CLS} (should be <0.1)`);
    }

    // 内存使用警告 (>80%)
    if (memory.usagePercentage && memory.usagePercentage > 80) {
      console.warn(`⚠️ High memory usage: ${memory.usagePercentage.toFixed(1)}%`);
    }
  }

  public dispose(): void {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
    this.metrics.clear();
    this.isEnabled = false;
  }
}

// 导出单例实例
export const performanceMonitor = PerformanceMonitor.getInstance();

// 防抖函数
export function debounce<T extends (...args: unknown[]) => unknown>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

// 节流函数
export function throttle<T extends (...args: unknown[]) => unknown>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// 资源预加载
export function preloadResource(href: string, as: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const link = document.createElement('link');
    link.rel = 'preload';
    link.href = href;
    link.as = as;
    link.onload = () => resolve();
    link.onerror = () => reject(new Error(`Failed to preload ${href}`));
    document.head.appendChild(link);
  });
}

// 批量预加载资源
export async function preloadResources(resources: Array<{href: string, as: string}>): Promise<void> {
  const promises = resources.map(resource => preloadResource(resource.href, resource.as));
  await Promise.allSettled(promises);
}