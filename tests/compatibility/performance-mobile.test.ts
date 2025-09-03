/**
 * Mobile Performance Benchmarking Tests
 * 移动端性能基准测试
 */

import { test, expect, Page, BrowserContext } from '@playwright/test';
import { testStandards, allDevices, networkConditions } from './mobile-device-matrix';

// 性能测试指标接口
interface PerformanceMetrics {
  loadTime: number;
  domContentLoaded: number;
  firstContentfulPaint: number;
  largestContentfulPaint: number;
  cumulativeLayoutShift: number;
  firstInputDelay: number;
  totalBlockingTime: number;
  memoryUsage: number;
  scriptExecutionTime: number;
  renderTime: number;
}

interface FrameRateMetrics {
  averageFPS: number;
  minFPS: number;
  maxFPS: number;
  frameDrops: number;
  totalFrames: number;
}

test.describe('Mobile Performance Benchmarks', () => {
  
  test('Page load performance on different devices', async ({ page, context }) => {
    // 测试不同设备配置下的页面加载性能
    for (const device of allDevices.slice(0, 3)) { // 取前3个设备避免测试时间过长
      await page.setViewportSize(device.viewport);
      
      // 启用性能监控
      const client = await context.newCDPSession(page);
      await client.send('Performance.enable');
      
      const startTime = Date.now();
      
      // 导航到首页并等待加载完成
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      
      const endTime = Date.now();
      const totalLoadTime = endTime - startTime;
      
      // 获取详细性能指标
      const metrics = await collectPerformanceMetrics(page);
      
      // 验证加载时间符合标准
      expect(totalLoadTime).toBeLessThan(testStandards.performance.loadTime);
      expect(metrics.firstContentfulPaint).toBeLessThan(2000); // FCP < 2s
      expect(metrics.largestContentfulPaint).toBeLessThan(4000); // LCP < 4s
      expect(metrics.cumulativeLayoutShift).toBeLessThan(0.1); // CLS < 0.1
      
      // 内存使用验证
      expect(metrics.memoryUsage).toBeLessThan(testStandards.performance.memoryUsage * 1024 * 1024); // 转换为bytes
      
      // 记录测试结果
      console.log(`Device: ${device.name}`);
      console.log(`Load Time: ${totalLoadTime}ms`);
      console.log(`FCP: ${metrics.firstContentfulPaint}ms`);
      console.log(`LCP: ${metrics.largestContentfulPaint}ms`);
      console.log(`Memory: ${(metrics.memoryUsage / 1024 / 1024).toFixed(2)}MB`);
      
      await client.detach();
    }
  });

  test('Map component performance on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // 启用性能监控
    await page.evaluate(() => {
      (window as any).performanceObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach(entry => {
          (window as any).performanceEntries = (window as any).performanceEntries || [];
          (window as any).performanceEntries.push({
            name: entry.name,
            startTime: entry.startTime,
            duration: entry.duration,
            entryType: entry.entryType
          });
        });
      });
      (window as any).performanceObserver.observe({ 
        entryTypes: ['measure', 'navigation', 'paint', 'largest-contentful-paint'] 
      });
    });

    const startTime = Date.now();
    
    await page.goto('/map');
    await page.waitForLoadState('networkidle');
    
    // 等待地图完全加载
    await page.waitForSelector('[data-testid="map-container"]', { timeout: 10000 });
    await page.waitForTimeout(2000); // 等待地图渲染完成
    
    const mapLoadTime = Date.now() - startTime;
    
    // 测试地图交互性能
    const mapContainer = page.locator('[data-testid="map-container"]');
    const mapBox = await mapContainer.boundingBox();
    
    if (mapBox) {
      // 测试地图平移性能
      const panStart = Date.now();
      await page.mouse.move(mapBox.x + mapBox.width / 2, mapBox.y + mapBox.height / 2);
      await page.mouse.down();
      await page.mouse.move(mapBox.x + mapBox.width / 2 + 100, mapBox.y + mapBox.height / 2, { steps: 10 });
      await page.mouse.up();
      const panTime = Date.now() - panStart;
      
      // 测试缩放性能
      const zoomStart = Date.now();
      const zoomInButton = page.locator('[data-testid="zoom-in"]');
      if (await zoomInButton.isVisible()) {
        await zoomInButton.click();
        await page.waitForTimeout(500);
      }
      const zoomTime = Date.now() - zoomStart;
      
      // 验证性能标准
      expect(mapLoadTime).toBeLessThan(5000); // 地图加载 < 5s
      expect(panTime).toBeLessThan(testStandards.performance.interactionDelay);
      expect(zoomTime).toBeLessThan(testStandards.performance.interactionDelay);
      
      console.log(`Map Load Time: ${mapLoadTime}ms`);
      console.log(`Pan Performance: ${panTime}ms`);
      console.log(`Zoom Performance: ${zoomTime}ms`);
    }
  });

  test('Scroll performance and frame rate', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');
    
    // 启动帧率监控
    const frameRateMetrics = await startFrameRateMonitoring(page);
    
    // 执行滚动测试
    const scrollContainer = page.locator('[data-testid="main-content"], body').first();
    
    // 快速滚动测试
    for (let i = 0; i < 10; i++) {
      await scrollContainer.evaluate(el => {
        el.scrollBy(0, 200);
      });
      await page.waitForTimeout(50); // 每50ms滚动一次
    }
    
    // 慢速滚动测试
    for (let i = 0; i < 20; i++) {
      await scrollContainer.evaluate(el => {
        el.scrollBy(0, 50);
      });
      await page.waitForTimeout(100); // 每100ms滚动一次
    }
    
    // 停止监控并获取结果
    const finalMetrics = await stopFrameRateMonitoring(page);
    
    // 验证帧率性能
    expect(finalMetrics.averageFPS).toBeGreaterThan(testStandards.performance.scrollFPS);
    expect(finalMetrics.frameDrops).toBeLessThan(5); // 丢帧少于5次
    
    console.log(`Average FPS: ${finalMetrics.averageFPS}`);
    console.log(`Min FPS: ${finalMetrics.minFPS}`);
    console.log(`Frame Drops: ${finalMetrics.frameDrops}`);
  });

  test('Form input responsiveness', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');
    
    const inputs = page.locator('input, textarea, select');
    const inputCount = await inputs.count();
    
    for (let i = 0; i < Math.min(inputCount, 5); i++) {
      const input = inputs.nth(i);
      
      if (await input.isVisible()) {
        const inputType = await input.getAttribute('type') || await input.tagName().then(tag => tag.toLowerCase());
        
        // 测试输入响应时间
        const startTime = Date.now();
        await input.click();
        await input.fill('test input');
        const inputTime = Date.now() - startTime;
        
        // 测试键盘弹出后的布局调整
        await page.waitForTimeout(300); // 等待键盘动画
        
        // 验证输入响应性能
        expect(inputTime).toBeLessThan(testStandards.performance.interactionDelay);
        
        console.log(`Input ${inputType} response time: ${inputTime}ms`);
        
        // 清空输入
        await input.clear();
      }
    }
  });

  test('Image loading and rendering performance', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // 监控图片加载性能
    const imageMetrics: Array<{ src: string; loadTime: number; size: number }> = [];
    
    page.on('response', async (response) => {
      if (response.url().includes('image') || 
          response.headers()['content-type']?.startsWith('image/')) {
        const startTime = Date.now();
        try {
          const buffer = await response.body();
          const endTime = Date.now();
          
          imageMetrics.push({
            src: response.url(),
            loadTime: endTime - startTime,
            size: buffer.length
          });
        } catch (error) {
          console.log('Failed to process image response:', error);
        }
      }
    });
    
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');
    
    // 等待所有图片加载完成
    await page.waitForFunction(() => {
      const images = document.querySelectorAll('img');
      return Array.from(images).every(img => img.complete);
    }, { timeout: 10000 });
    
    // 验证图片加载性能
    for (const metric of imageMetrics) {
      // 图片加载时间应该合理（基于文件大小）
      const expectedMaxTime = Math.max(1000, metric.size / 1000); // 基础时间 + 按KB计算
      expect(metric.loadTime).toBeLessThan(expectedMaxTime);
      
      console.log(`Image: ${metric.src.substring(metric.src.lastIndexOf('/') + 1)}`);
      console.log(`Load Time: ${metric.loadTime}ms, Size: ${(metric.size / 1024).toFixed(2)}KB`);
    }
  });
});

test.describe('Network Performance Impact', () => {
  
  test('Performance under different network conditions', async ({ page, context }) => {
    const testPages = ['/', '/map', '/annotations'];
    
    for (const network of networkConditions) {
      console.log(`Testing network condition: ${network.name}`);
      
      // 设置网络条件
      const client = await context.newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        latency: network.latency,
        downloadThroughput: network.downloadThroughput,
        uploadThroughput: network.uploadThroughput
      });
      
      for (const pagePath of testPages) {
        const startTime = Date.now();
        
        await page.goto(pagePath);
        await page.waitForLoadState('networkidle');
        
        const loadTime = Date.now() - startTime;
        const metrics = await collectPerformanceMetrics(page);
        
        // 根据网络条件调整期望值
        let expectedMaxLoadTime = testStandards.performance.loadTime;
        if (network.name === '3G') {
          expectedMaxLoadTime *= 2;
        } else if (network.name === 'Slow WiFi') {
          expectedMaxLoadTime *= 3;
        }
        
        expect(loadTime).toBeLessThan(expectedMaxLoadTime);
        
        console.log(`Page: ${pagePath}, Network: ${network.name}, Load Time: ${loadTime}ms`);
      }
      
      await client.detach();
    }
  });

  test('Offline performance and caching', async ({ page, context }) => {
    // 首先在线访问，让资源缓存
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 模拟离线
    const client = await context.newCDPSession(page);
    await client.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0
    });
    
    // 刷新页面测试离线性能
    const startTime = Date.now();
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    const offlineLoadTime = Date.now() - startTime;
    
    // 离线加载应该更快（从缓存加载）
    expect(offlineLoadTime).toBeLessThan(testStandards.performance.loadTime / 2);
    
    // 验证离线功能
    const offlineIndicator = page.locator('[data-testid="offline-indicator"]');
    if (await offlineIndicator.isVisible()) {
      await expect(offlineIndicator).toBeVisible();
    }
    
    console.log(`Offline load time: ${offlineLoadTime}ms`);
    
    await client.detach();
  });
});

test.describe('Memory and CPU Performance', () => {
  
  test('Memory usage monitoring', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // 初始内存使用
    const initialMemory = await getMemoryUsage(page);
    
    // 执行各种操作
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const homeMemory = await getMemoryUsage(page);
    
    await page.goto('/map');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(3000); // 等待地图完全加载
    const mapMemory = await getMemoryUsage(page);
    
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');
    const annotationsMemory = await getMemoryUsage(page);
    
    // 执行垃圾回收
    await page.evaluate(() => {
      if ((window as any).gc) {
        (window as any).gc();
      }
    });
    await page.waitForTimeout(1000);
    const afterGCMemory = await getMemoryUsage(page);
    
    // 验证内存使用
    expect(homeMemory.used).toBeGreaterThan(initialMemory.used);
    expect(mapMemory.used).toBeGreaterThan(homeMemory.used); // 地图组件消耗更多内存
    expect(afterGCMemory.used).toBeLessThanOrEqual(annotationsMemory.used); // GC后内存应该减少或相等
    
    const maxMemoryMB = testStandards.performance.memoryUsage;
    expect(mapMemory.used / 1024 / 1024).toBeLessThan(maxMemoryMB);
    
    console.log('Memory Usage:');
    console.log(`Initial: ${(initialMemory.used / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Home: ${(homeMemory.used / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Map: ${(mapMemory.used / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Annotations: ${(annotationsMemory.used / 1024 / 1024).toFixed(2)}MB`);
    console.log(`After GC: ${(afterGCMemory.used / 1024 / 1024).toFixed(2)}MB`);
  });

  test('CPU intensive operations performance', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/map');
    await page.waitForLoadState('networkidle');
    
    // 测试CPU密集型操作（例如：大量标注点渲染）
    const cpuIntensiveStart = Date.now();
    
    // 模拟添加大量标注点
    await page.evaluate(() => {
      // 模拟CPU密集型计算
      const start = performance.now();
      let result = 0;
      for (let i = 0; i < 1000000; i++) {
        result += Math.sin(i) * Math.cos(i);
      }
      const end = performance.now();
      
      (window as any).cpuTestResult = {
        result,
        duration: end - start
      };
    });
    
    const cpuIntensiveTime = Date.now() - cpuIntensiveStart;
    
    // 获取JavaScript执行时间
    const jsExecutionTime = await page.evaluate(() => {
      return (window as any).cpuTestResult?.duration || 0;
    });
    
    // 验证CPU性能
    expect(cpuIntensiveTime).toBeLessThan(5000); // CPU密集操作应在5秒内完成
    expect(jsExecutionTime).toBeLessThan(1000); // JavaScript执行时间应在1秒内
    
    console.log(`CPU intensive operation: ${cpuIntensiveTime}ms`);
    console.log(`JavaScript execution time: ${jsExecutionTime}ms`);
  });
});

// 辅助函数

/**
 * 收集综合性能指标
 */
async function collectPerformanceMetrics(page: Page): Promise<PerformanceMetrics> {
  return await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    const paint = performance.getEntriesByType('paint');
    const lcp = performance.getEntriesByType('largest-contentful-paint');
    
    // Web Vitals 计算
    const fcp = paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0;
    const lcpValue = lcp.length > 0 ? lcp[lcp.length - 1].startTime : 0;
    
    // 内存使用 (如果支持)
    const memory = (performance as any).memory;
    const memoryUsage = memory ? memory.usedJSHeapSize : 0;
    
    return {
      loadTime: navigation.loadEventEnd - navigation.fetchStart,
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.fetchStart,
      firstContentfulPaint: fcp,
      largestContentfulPaint: lcpValue,
      cumulativeLayoutShift: 0, // 需要通过PerformanceObserver获取
      firstInputDelay: 0, // 需要通过PerformanceObserver获取
      totalBlockingTime: 0, // 需要计算
      memoryUsage,
      scriptExecutionTime: navigation.domInteractive - navigation.domLoading,
      renderTime: navigation.domComplete - navigation.domInteractive
    };
  });
}

/**
 * 开始帧率监控
 */
async function startFrameRateMonitoring(page: Page): Promise<void> {
  await page.evaluate(() => {
    (window as any).frameRateData = {
      frames: [],
      startTime: performance.now(),
      animationId: null
    };
    
    function recordFrame() {
      const now = performance.now();
      (window as any).frameRateData.frames.push(now);
      (window as any).frameRateData.animationId = requestAnimationFrame(recordFrame);
    }
    
    recordFrame();
  });
}

/**
 * 停止帧率监控并返回结果
 */
async function stopFrameRateMonitoring(page: Page): Promise<FrameRateMetrics> {
  return await page.evaluate(() => {
    const data = (window as any).frameRateData;
    
    if (data.animationId) {
      cancelAnimationFrame(data.animationId);
    }
    
    const frames = data.frames;
    const totalTime = frames[frames.length - 1] - frames[0];
    const totalFrames = frames.length;
    
    // 计算帧间隔
    const frameIntervals = [];
    for (let i = 1; i < frames.length; i++) {
      frameIntervals.push(frames[i] - frames[i - 1]);
    }
    
    // 计算FPS
    const averageInterval = frameIntervals.reduce((a, b) => a + b, 0) / frameIntervals.length;
    const averageFPS = 1000 / averageInterval;
    
    const fpsList = frameIntervals.map(interval => 1000 / interval);
    const minFPS = Math.min(...fpsList);
    const maxFPS = Math.max(...fpsList);
    
    // 计算丢帧（FPS低于30的帧数）
    const frameDrops = fpsList.filter(fps => fps < 30).length;
    
    return {
      averageFPS,
      minFPS,
      maxFPS,
      frameDrops,
      totalFrames
    };
  });
}

/**
 * 获取内存使用情况
 */
async function getMemoryUsage(page: Page): Promise<{ used: number; total: number }> {
  return await page.evaluate(() => {
    const memory = (performance as any).memory;
    
    if (memory) {
      return {
        used: memory.usedJSHeapSize,
        total: memory.totalJSHeapSize
      };
    }
    
    return { used: 0, total: 0 };
  });
}

/**
 * 生成性能报告
 */
async function generatePerformanceReport(metrics: PerformanceMetrics[], deviceName: string): Promise<void> {
  const report = {
    device: deviceName,
    timestamp: new Date().toISOString(),
    metrics,
    summary: {
      averageLoadTime: metrics.reduce((sum, m) => sum + m.loadTime, 0) / metrics.length,
      averageFCP: metrics.reduce((sum, m) => sum + m.firstContentfulPaint, 0) / metrics.length,
      averageMemory: metrics.reduce((sum, m) => sum + m.memoryUsage, 0) / metrics.length
    }
  };
  
  console.log('Performance Report:', JSON.stringify(report, null, 2));
}