/**
 * 性能优化工具函数集合
 * 提供各种性能优化相关的实用工具
 */

// 网络连接信息接口
interface NetworkInformation {
  effectiveType?: '2g' | '3g' | '4g' | 'slow-2g';
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
}

// 移除未使用的导入

// 资源预加载工具
export class ResourcePreloader {
  private static preloadedResources = new Set<string>();
  private static preloadPromises = new Map<string, Promise<HTMLImageElement | void>>();

  // 预加载图片
  static preloadImage(src: string): Promise<HTMLImageElement> {
    if (this.preloadedResources.has(src)) {
      return Promise.resolve(new Image());
    }

    if (this.preloadPromises.has(src)) {
      return this.preloadPromises.get(src)! as Promise<HTMLImageElement>;
    }

    const promise = new Promise<HTMLImageElement>((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        this.preloadedResources.add(src);
        resolve(img);
      };
      img.onerror = reject;
      img.src = src;
    });

    this.preloadPromises.set(src, promise);
    return promise;
  }

  // 预加载多个图片
  static preloadImages(srcs: string[]): Promise<HTMLImageElement[]> {
    return Promise.all(srcs.map(src => this.preloadImage(src)));
  }

  // 预加载CSS
  static preloadCSS(href: string): Promise<void> {
    if (this.preloadedResources.has(href)) {
      return Promise.resolve();
    }

    if (this.preloadPromises.has(href)) {
      return this.preloadPromises.get(href)! as Promise<void>;
    }

    const promise = new Promise<void>((resolve, reject) => {
      const link = document.createElement('link');
      link.rel = 'preload';
      link.as = 'style';
      link.href = href;
      link.onload = () => {
        this.preloadedResources.add(href);
        resolve();
      };
      link.onerror = reject;
      document.head.appendChild(link);
    });

    this.preloadPromises.set(href, promise);
    return promise;
  }

  // 预加载JavaScript模块
  static preloadModule(src: string): Promise<void> {
    if (this.preloadedResources.has(src)) {
      return Promise.resolve();
    }

    if (this.preloadPromises.has(src)) {
      return this.preloadPromises.get(src)! as Promise<void>;
    }

    const promise = new Promise<void>((resolve, reject) => {
      const link = document.createElement('link');
      link.rel = 'modulepreload';
      link.href = src;
      link.onload = () => {
        this.preloadedResources.add(src);
        resolve();
      };
      link.onerror = reject;
      document.head.appendChild(link);
    });

    this.preloadPromises.set(src, promise);
    return promise;
  }

  // 清理预加载缓存
  static clearCache(): void {
    this.preloadedResources.clear();
    this.preloadPromises.clear();
  }
}

// 懒加载工具
export class LazyLoader {
  private static observer: IntersectionObserver | null = null;
  private static loadedElements = new WeakSet();

  // 初始化懒加载观察器
  static init(options: IntersectionObserverInit = {}) {
    if (this.observer) {
      this.observer.disconnect();
    }

    this.observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && !this.loadedElements.has(entry.target)) {
          this.loadElement(entry.target as HTMLElement);
          this.loadedElements.add(entry.target);
          this.observer?.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '50px',
      threshold: 0.1,
      ...options,
    });
  }

  // 观察元素
  static observe(element: HTMLElement): void {
    if (!this.observer) {
      this.init();
    }
    this.observer?.observe(element);
  }

  // 加载元素
  private static loadElement(element: HTMLElement): void {
    // 加载图片
    if (element.tagName === 'IMG') {
      const img = element as HTMLImageElement;
      const dataSrc = img.dataset.src;
      if (dataSrc) {
        img.src = dataSrc;
        img.removeAttribute('data-src');
      }
    }

    // 加载背景图片
    const dataBg = element.dataset.bg;
    if (dataBg) {
      element.style.backgroundImage = `url(${dataBg})`;
      element.removeAttribute('data-bg');
    }

    // 触发自定义加载事件
    const loadEvent = new CustomEvent('lazyload', { detail: { element } });
    element.dispatchEvent(loadEvent);
  }

  // 销毁观察器
  static destroy(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}

// 缓存管理工具
export class CacheManager {
  private static caches = new Map<string, Map<string, unknown>>();
  private static cacheTTL = new Map<string, Map<string, number>>();

  // 设置缓存
  static set(namespace: string, key: string, value: unknown, ttl?: number): void {
    if (!this.caches.has(namespace)) {
      this.caches.set(namespace, new Map());
      this.cacheTTL.set(namespace, new Map());
    }

    const cache = this.caches.get(namespace)!;
    const ttlMap = this.cacheTTL.get(namespace)!;

    cache.set(key, value);
    
    if (ttl) {
      ttlMap.set(key, Date.now() + ttl);
    }
  }

  // 获取缓存
  static get<T>(namespace: string, key: string): T | null {
    const cache = this.caches.get(namespace);
    const ttlMap = this.cacheTTL.get(namespace);

    if (!cache || !cache.has(key)) {
      return null;
    }

    // 检查TTL
    if (ttlMap && ttlMap.has(key)) {
      const expiry = ttlMap.get(key)!;
      if (Date.now() > expiry) {
        this.delete(namespace, key);
        return null;
      }
    }

    return cache.get(key) as T | null;
  }

  // 删除缓存
  static delete(namespace: string, key: string): boolean {
    const cache = this.caches.get(namespace);
    const ttlMap = this.cacheTTL.get(namespace);

    let deleted = false;
    if (cache) {
      deleted = cache.delete(key);
    }
    if (ttlMap) {
      ttlMap.delete(key);
    }

    return deleted;
  }

  // 清空命名空间缓存
  static clear(namespace: string): void {
    this.caches.delete(namespace);
    this.cacheTTL.delete(namespace);
  }

  // 清空所有缓存
  static clearAll(): void {
    this.caches.clear();
    this.cacheTTL.clear();
  }

  // 获取缓存统计
  static getStats(namespace?: string) {
    if (namespace) {
      const cache = this.caches.get(namespace);
      return {
        namespace,
        size: cache?.size || 0,
        keys: cache ? Array.from(cache.keys()) : [],
      };
    }

    return Array.from(this.caches.entries()).map(([ns, cache]) => ({
      namespace: ns,
      size: cache.size,
      keys: Array.from(cache.keys()),
    }));
  }
}

// 防抖工具
export function debounce<T extends (...args: unknown[]) => unknown>(
  func: T,
  wait: number,
  immediate = false
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null;
  
  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null;
      if (!immediate) func(...args);
    };
    
    const callNow = immediate && !timeout;
    
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    
    if (callNow) func(...args);
  };
}

// 节流工具
export function throttle<T extends (...args: unknown[]) => unknown>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// 批处理工具
export class BatchProcessor<T> {
  private batch: T[] = [];
  private timer: NodeJS.Timeout | null = null;
  private processor: (items: T[]) => void;
  private batchSize: number;
  private delay: number;

  constructor(
    processor: (items: T[]) => void,
    batchSize = 10,
    delay = 100
  ) {
    this.processor = processor;
    this.batchSize = batchSize;
    this.delay = delay;
  }

  add(item: T): void {
    this.batch.push(item);

    if (this.batch.length >= this.batchSize) {
      this.flush();
    } else if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), this.delay);
    }
  }

  flush(): void {
    if (this.batch.length > 0) {
      this.processor([...this.batch]);
      this.batch = [];
    }

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  destroy(): void {
    this.flush();
  }
}

// 性能测量工具
export class PerformanceMeasurer {
  private static marks = new Map<string, number>();
  private static measures = new Map<string, number>();

  // 标记开始时间
  static mark(name: string): void {
    this.marks.set(name, performance.now());
  }

  // 测量时间差
  static measure(name: string, startMark: string): number {
    const startTime = this.marks.get(startMark);
    if (!startTime) {
      console.warn(`Start mark '${startMark}' not found`);
      return 0;
    }

    const duration = performance.now() - startTime;
    this.measures.set(name, duration);
    return duration;
  }

  // 获取测量结果
  static getMeasure(name: string): number | undefined {
    return this.measures.get(name);
  }

  // 获取所有测量结果
  static getAllMeasures(): Record<string, number> {
    return Object.fromEntries(this.measures);
  }

  // 清空测量数据
  static clear(): void {
    this.marks.clear();
    this.measures.clear();
  }
}

// 内存信息接口
interface MemoryInfo {
  usedJSHeapSize: number;
  totalJSHeapSize: number;
  jsHeapSizeLimit: number;
}

// 内存优化工具
export class MemoryOptimizer {
  private static weakRefs = new Set<WeakRef<object>>();
  private static cleanupRegistry = new FinalizationRegistry((heldValue: string) => {
    console.log(`Object ${heldValue} has been garbage collected`);
  });

  // 创建弱引用
  static createWeakRef<T extends object>(obj: T, label?: string): WeakRef<T> {
    const weakRef = new WeakRef(obj);
    this.weakRefs.add(weakRef);
    
    if (label) {
      this.cleanupRegistry.register(obj, label);
    }
    
    return weakRef;
  }

  // 清理无效的弱引用
  static cleanup(): void {
    const validRefs = new Set<WeakRef<object>>();
    
    for (const ref of this.weakRefs) {
      if (ref.deref()) {
        validRefs.add(ref);
      }
    }
    
    this.weakRefs = validRefs;
  }

  // 获取内存使用情况
  static getMemoryUsage(): MemoryInfo | null {
    if ('memory' in performance) {
      return (performance as unknown as { memory: MemoryInfo }).memory;
    }
    return null;
  }

  // 强制垃圾回收（仅在开发环境）
  static forceGC(): void {
    if (import.meta.env.VITE_NODE_ENV === 'development' && 'gc' in window) {
      (window as unknown as { gc: () => void }).gc();
    }
  }
}

// 网络优化工具
export class NetworkOptimizer {

  // 获取网络连接信息
  static getConnectionInfo(): NetworkInformation | null {
    if ('connection' in navigator) {
      return (navigator as unknown as { connection: NetworkInformation }).connection;
    }
    return null;
  }

  // 检查是否为慢速连接
  static isSlowConnection(): boolean {
    const connection = this.getConnectionInfo();
    if (!connection || !connection.effectiveType) return false;

    const slowConnections = ['slow-2g', '2g', '3g'];
    return slowConnections.includes(connection.effectiveType);
  }

  // 检查是否为快速连接
  static isFastConnection(): boolean {
    const connection = this.getConnectionInfo();
    if (!connection) return true; // 默认假设快速连接

    return connection.effectiveType === '4g';
  }

  // 获取网络延迟
  static async measureLatency(url = '/favicon.ico'): Promise<number> {
    const start = performance.now();
    
    try {
      await fetch(url, { method: 'HEAD', cache: 'no-cache' });
      return performance.now() - start;
    } catch (error) {
      console.warn('Failed to measure network latency:', error);
      return Infinity;
    }
  }

  // 自适应资源加载
  static getOptimalImageQuality(): 'low' | 'medium' | 'high' {
    if (this.isSlowConnection()) {
      return 'low';
    } else if (this.isFastConnection()) {
      return 'high';
    }
    return 'medium';
  }
}

// 代码分割工具
export class CodeSplitter {
  private static loadedChunks = new Set<string>();
  private static loadingChunks = new Map<string, Promise<unknown>>();

  // 动态导入组件
  static async loadComponent<T>(importFn: () => Promise<T>, chunkName?: string): Promise<T> {
    const key = chunkName || importFn.toString();
    
    if (this.loadedChunks.has(key)) {
      return importFn();
    }

    if (this.loadingChunks.has(key)) {
      return this.loadingChunks.get(key)! as Promise<T>;
    }

    const promise = importFn().then(module => {
      this.loadedChunks.add(key);
      this.loadingChunks.delete(key);
      return module;
    }).catch(error => {
      this.loadingChunks.delete(key);
      throw error;
    });

    this.loadingChunks.set(key, promise);
    return promise;
  }

  // 预加载组件
  static preloadComponent(importFn: () => Promise<unknown>, chunkName?: string): void {
    const key = chunkName || importFn.toString();
    
    if (!this.loadedChunks.has(key) && !this.loadingChunks.has(key)) {
      this.loadComponent(importFn, chunkName).catch(() => {
        // 忽略预加载错误
      });
    }
  }

  // 获取加载状态
  static getLoadingStatus(): {
    loaded: string[];
    loading: string[];
  } {
    return {
      loaded: Array.from(this.loadedChunks),
      loading: Array.from(this.loadingChunks.keys()),
    };
  }
}

// 导出所有工具
export const OptimizationUtils = {
  ResourcePreloader,
  LazyLoader,
  CacheManager,
  debounce,
  throttle,
  BatchProcessor,
  PerformanceMeasurer,
  MemoryOptimizer,
  NetworkOptimizer,
  CodeSplitter,
};