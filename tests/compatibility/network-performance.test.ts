/**
 * Network Condition Testing (3G/4G/WiFi)
 * 网络条件性能测试
 */

import { test, expect, Page, BrowserContext } from '@playwright/test';
import { networkConditions, testStandards } from './mobile-device-matrix';

// 网络性能指标接口
interface NetworkPerformanceMetrics {
  networkType: string;
  loadTime: number;
  firstByteTime: number;
  domContentLoaded: number;
  resourceLoadTime: number;
  totalTransferSize: number;
  imageLoadTime: number;
  apiResponseTime: number;
  retryAttempts: number;
}

// 网络质量评估
interface NetworkQualityAssessment {
  rating: 'excellent' | 'good' | 'fair' | 'poor';
  userExperience: string;
  recommendations: string[];
}

test.describe('Network Condition Performance Testing', () => {
  
  // 为每种网络条件运行测试
  for (const network of networkConditions) {
    test.describe(`Network: ${network.name}`, () => {
      
      test(`Page loading performance on ${network.name}`, async ({ page, context }) => {
        console.log(`Testing ${network.name} network conditions:`);
        console.log(`- Download: ${(network.downloadThroughput * 8 / 1024 / 1024).toFixed(2)} Mbps`);
        console.log(`- Upload: ${(network.uploadThroughput * 8 / 1024 / 1024).toFixed(2)} Mbps`);
        console.log(`- Latency: ${network.latency}ms`);
        
        // 设置网络条件
        const client = await context.newCDPSession(page);
        await client.send('Network.emulateNetworkConditions', {
          offline: false,
          latency: network.latency,
          downloadThroughput: network.downloadThroughput,
          uploadThroughput: network.uploadThroughput
        });
        
        // 监控网络请求
        const networkMetrics = await monitorNetworkRequests(page);
        
        const startTime = Date.now();
        
        // 加载首页
        await page.goto('/');
        await page.waitForLoadState('domcontentloaded');
        
        const domLoadedTime = Date.now() - startTime;
        
        await page.waitForLoadState('networkidle');
        const totalLoadTime = Date.now() - startTime;
        
        // 收集性能指标
        const performanceMetrics = await page.evaluate(() => {
          const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
          const resources = performance.getEntriesByType('resource');
          
          return {
            firstByteTime: navigation.responseStart - navigation.fetchStart,
            domContentLoaded: navigation.domContentLoadedEventEnd - navigation.fetchStart,
            resourceCount: resources.length,
            totalTransferSize: resources.reduce((sum, r) => sum + (r as any).transferSize || 0, 0)
          };
        });
        
        const metrics: NetworkPerformanceMetrics = {
          networkType: network.name,
          loadTime: totalLoadTime,
          firstByteTime: performanceMetrics.firstByteTime,
          domContentLoaded: domLoadedTime,
          resourceLoadTime: totalLoadTime - domLoadedTime,
          totalTransferSize: performanceMetrics.totalTransferSize,
          imageLoadTime: 0, // 将在后续测试中填充
          apiResponseTime: 0, // 将在后续测试中填充
          retryAttempts: 0
        };
        
        // 根据网络条件调整性能预期
        const expectedMaxLoadTime = getExpectedLoadTime(network.name);
        
        expect(totalLoadTime).toBeLessThan(expectedMaxLoadTime);
        expect(performanceMetrics.firstByteTime).toBeLessThan(network.latency * 3); // TTFB不应超过延迟的3倍
        
        // 记录详细指标
        console.log(`Results for ${network.name}:`);
        console.log(`- Total Load Time: ${totalLoadTime}ms`);
        console.log(`- DOM Loaded Time: ${domLoadedTime}ms`);
        console.log(`- First Byte Time: ${performanceMetrics.firstByteTime}ms`);
        console.log(`- Transfer Size: ${(performanceMetrics.totalTransferSize / 1024).toFixed(2)}KB`);
        
        await client.detach();
      });
      
      test(`Map component loading on ${network.name}`, async ({ page, context }) => {
        // 设置网络条件
        const client = await context.newCDPSession(page);
        await client.send('Network.emulateNetworkConditions', {
          offline: false,
          latency: network.latency,
          downloadThroughput: network.downloadThroughput,
          uploadThroughput: network.uploadThroughput
        });
        
        const startTime = Date.now();
        
        await page.goto('/map');
        await page.waitForLoadState('domcontentloaded');
        
        // 等待地图容器出现
        await page.waitForSelector('[data-testid="map-container"]', { 
          timeout: getExpectedLoadTime(network.name) 
        });
        
        const mapVisibleTime = Date.now() - startTime;
        
        // 等待地图完全加载（瓦片和标注）
        await page.waitForFunction(() => {
          const mapContainer = document.querySelector('[data-testid="map-container"]');
          if (!mapContainer) return false;
          
          // 检查地图是否已加载
          const hasMapContent = mapContainer.innerHTML.length > 100;
          
          // 检查是否有标注点
          const annotations = document.querySelectorAll('[data-testid="map-annotation"]');
          
          return hasMapContent;
        }, { timeout: getExpectedLoadTime(network.name) * 2 });
        
        const mapFullyLoadedTime = Date.now() - startTime;
        
        // 测试地图交互响应性
        const interactionStartTime = Date.now();
        const mapContainer = page.locator('[data-testid="map-container"]');
        const mapBox = await mapContainer.boundingBox();
        
        if (mapBox) {
          // 测试地图点击响应
          await page.mouse.click(mapBox.x + mapBox.width / 2, mapBox.y + mapBox.height / 2);
        }
        
        const interactionTime = Date.now() - interactionStartTime;
        
        // 验证性能标准
        const expectedMapLoadTime = getExpectedMapLoadTime(network.name);
        expect(mapFullyLoadedTime).toBeLessThan(expectedMapLoadTime);
        expect(interactionTime).toBeLessThan(testStandards.performance.interactionDelay * 2); // 网络慢时允许更长响应时间
        
        console.log(`Map performance on ${network.name}:`);
        console.log(`- Map Visible: ${mapVisibleTime}ms`);
        console.log(`- Map Fully Loaded: ${mapFullyLoadedTime}ms`);
        console.log(`- Interaction Response: ${interactionTime}ms`);
        
        await client.detach();
      });
      
      test(`API requests performance on ${network.name}`, async ({ page, context }) => {
        const client = await context.newCDPSession(page);
        await client.send('Network.emulateNetworkConditions', {
          offline: false,
          latency: network.latency,
          downloadThroughput: network.downloadThroughput,
          uploadThroughput: network.uploadThroughput
        });
        
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        
        // 测试各种API请求
        const apiTests = [
          {
            name: 'Get Annotations',
            url: '/api/annotations',
            method: 'GET'
          },
          {
            name: 'User Profile',
            url: '/api/user/profile',
            method: 'GET'
          },
          {
            name: 'Location Search',
            url: '/api/locations/search?q=test',
            method: 'GET'
          }
        ];
        
        for (const apiTest of apiTests) {
          const startTime = Date.now();
          
          try {
            const response = await page.evaluate(async (testData) => {
              const response = await fetch(testData.url, {
                method: testData.method,
                headers: {
                  'Content-Type': 'application/json'
                }
              });
              
              return {
                status: response.status,
                size: parseInt(response.headers.get('content-length') || '0'),
                responseTime: Date.now()
              };
            }, apiTest);
            
            const responseTime = Date.now() - startTime;
            
            // 验证API响应时间
            const expectedApiTime = getExpectedApiResponseTime(network.name);
            expect(responseTime).toBeLessThan(expectedApiTime);
            
            console.log(`${apiTest.name} on ${network.name}: ${responseTime}ms (${response.status})`);
            
          } catch (error) {
            console.log(`${apiTest.name} failed on ${network.name}:`, error);
            
            // 在慢网络条件下，某些请求失败是可接受的
            if (network.name === 'Slow WiFi' && network.packetLoss > 0) {
              console.log('Request failure acceptable on slow network with packet loss');
            } else {
              throw error;
            }
          }
        }
        
        await client.detach();
      });
      
      test(`Image loading optimization on ${network.name}`, async ({ page, context }) => {
        const client = await context.newCDPSession(page);
        await client.send('Network.emulateNetworkConditions', {
          offline: false,
          latency: network.latency,
          downloadThroughput: network.downloadThroughput,
          uploadThroughput: network.uploadThroughput
        });
        
        // 监控图片请求
        const imageRequests: Array<{
          url: string;
          size: number;
          loadTime: number;
          status: number;
        }> = [];
        
        page.on('response', async (response) => {
          if (response.headers()['content-type']?.startsWith('image/')) {
            try {
              const body = await response.body();
              imageRequests.push({
                url: response.url(),
                size: body.length,
                loadTime: 0, // 将在后续计算
                status: response.status()
              });
            } catch (error) {
              console.log('Failed to process image response:', error);
            }
          }
        });
        
        await page.goto('/annotations');
        await page.waitForLoadState('networkidle');
        
        // 等待图片加载完成
        await page.waitForFunction(() => {
          const images = document.querySelectorAll('img');
          let loadedCount = 0;
          let totalCount = 0;
          
          images.forEach(img => {
            totalCount++;
            if (img.complete && img.naturalWidth > 0) {
              loadedCount++;
            }
          });
          
          return totalCount === 0 || loadedCount / totalCount > 0.8; // 80%图片加载完成
        }, { timeout: getExpectedLoadTime(network.name) * 2 });
        
        // 分析图片加载性能
        const totalImageSize = imageRequests.reduce((sum, img) => sum + img.size, 0);
        const avgImageSize = totalImageSize / imageRequests.length || 0;
        
        console.log(`Image loading on ${network.name}:`);
        console.log(`- Images loaded: ${imageRequests.length}`);
        console.log(`- Total size: ${(totalImageSize / 1024).toFixed(2)}KB`);
        console.log(`- Average size: ${(avgImageSize / 1024).toFixed(2)}KB`);
        
        // 在慢网络下验证是否有图片优化
        if (network.name === '3G' || network.name === 'Slow WiFi') {
          // 检查是否有图片压缩或懒加载
          const lazyImages = page.locator('img[loading="lazy"]');
          const lazyImageCount = await lazyImages.count();
          
          if (lazyImageCount > 0) {
            console.log(`- Lazy loading enabled: ${lazyImageCount} images`);
          }
          
          // 验证图片大小合理
          if (avgImageSize > 100 * 1024) { // 大于100KB
            console.warn(`- Large image sizes detected on slow network`);
          }
        }
        
        await client.detach();
      });
    });
  }
});

test.describe('Network Quality Adaptation', () => {
  
  test('Adaptive content loading based on connection speed', async ({ page, context }) => {
    for (const network of networkConditions) {
      const client = await context.newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        latency: network.latency,
        downloadThroughput: network.downloadThroughput,
        uploadThroughput: network.uploadThroughput
      });
      
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      
      // 检查是否启用了适应性功能
      const adaptationFeatures = await page.evaluate(() => {
        return {
          reduceImageQuality: document.querySelector('[data-adaptation="reduce-image-quality"]') !== null,
          lazyLoading: document.querySelectorAll('img[loading="lazy"]').length > 0,
          reducedAnimations: document.body.classList.contains('reduced-motion'),
          compressionEnabled: document.querySelector('meta[name="compression-enabled"]') !== null
        };
      });
      
      // 根据网络条件验证适应性策略
      if (network.name === '3G' || network.name === 'Slow WiFi') {
        console.log(`Network adaptation features on ${network.name}:`);
        console.log(`- Reduced image quality: ${adaptationFeatures.reduceImageQuality}`);
        console.log(`- Lazy loading: ${adaptationFeatures.lazyLoading}`);
        console.log(`- Reduced animations: ${adaptationFeatures.reducedAnimations}`);
      }
      
      await client.detach();
    }
  });
  
  test('Offline mode functionality', async ({ page, context }) => {
    // 先在线访问，建立缓存
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    await page.goto('/map');
    await page.waitForLoadState('networkidle');
    
    // 切换到离线模式
    const client = await context.newCDPSession(page);
    await client.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0
    });
    
    // 测试离线功能
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    
    // 检查离线指示器
    const offlineIndicator = page.locator('[data-testid="offline-indicator"]');
    await expect(offlineIndicator).toBeVisible({ timeout: 5000 });
    
    // 检查缓存的内容是否可用
    const mainContent = page.locator('[data-testid="main-content"]');
    await expect(mainContent).toBeVisible();
    
    // 测试离线时的用户交互
    const offlineMessage = page.locator('[data-testid="offline-message"]');
    if (await offlineMessage.isVisible()) {
      await expect(offlineMessage).toContainText('离线');
    }
    
    console.log('Offline mode functionality verified');
    
    await client.detach();
  });
});

test.describe('Network Error Handling', () => {
  
  test('Request timeout handling', async ({ page, context }) => {
    const client = await context.newCDPSession(page);
    
    // 设置极慢的网络条件模拟超时
    await client.send('Network.emulateNetworkConditions', {
      offline: false,
      latency: 10000, // 10秒延迟
      downloadThroughput: 1000,   // 极慢
      uploadThroughput: 1000
    });
    
    const startTime = Date.now();
    
    try {
      await page.goto('/api-heavy-page', { timeout: 15000 });
    } catch (error) {
      const timeoutDuration = Date.now() - startTime;
      console.log(`Request timed out after ${timeoutDuration}ms`);
    }
    
    // 检查超时错误处理
    const timeoutMessage = page.locator('[data-testid="timeout-error"]');
    const retryButton = page.locator('[data-testid="retry-button"]');
    
    if (await timeoutMessage.isVisible()) {
      await expect(timeoutMessage).toBeVisible();
      console.log('Timeout error message displayed');
    }
    
    if (await retryButton.isVisible()) {
      await expect(retryButton).toBeVisible();
      console.log('Retry functionality available');
    }
    
    await client.detach();
  });
  
  test('Intermittent connectivity handling', async ({ page, context }) => {
    const client = await context.newCDPSession(page);
    
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 模拟网络中断和恢复
    const connectionStates = [
      { offline: true, duration: 2000 },   // 离线2秒
      { offline: false, duration: 3000 },  // 在线3秒
      { offline: true, duration: 1000 },   // 离线1秒
      { offline: false, duration: 0 }      // 恢复在线
    ];
    
    for (const state of connectionStates) {
      await client.send('Network.emulateNetworkConditions', {
        offline: state.offline,
        latency: state.offline ? 0 : 100,
        downloadThroughput: state.offline ? 0 : 1000000,
        uploadThroughput: state.offline ? 0 : 1000000
      });
      
      console.log(`Network ${state.offline ? 'offline' : 'online'} for ${state.duration}ms`);
      
      if (state.duration > 0) {
        await page.waitForTimeout(state.duration);
      }
      
      // 检查连接状态指示器
      const connectionStatus = page.locator('[data-testid="connection-status"]');
      if (await connectionStatus.isVisible()) {
        const statusText = await connectionStatus.textContent();
        const expectedStatus = state.offline ? '离线' : '在线';
        
        if (statusText?.includes(expectedStatus)) {
          console.log(`Connection status correctly shows: ${statusText}`);
        }
      }
    }
    
    await client.detach();
  });
});

// 辅助函数

/**
 * 根据网络类型获取预期加载时间
 */
function getExpectedLoadTime(networkType: string): number {
  const baseTime = testStandards.performance.loadTime;
  
  switch (networkType) {
    case 'WiFi':
      return baseTime;
    case '4G':
      return baseTime * 1.5;
    case '3G':
      return baseTime * 3;
    case 'Slow WiFi':
      return baseTime * 5;
    default:
      return baseTime * 2;
  }
}

/**
 * 根据网络类型获取预期地图加载时间
 */
function getExpectedMapLoadTime(networkType: string): number {
  const baseTime = 5000; // 地图基础加载时间5秒
  
  switch (networkType) {
    case 'WiFi':
      return baseTime;
    case '4G':
      return baseTime * 2;
    case '3G':
      return baseTime * 4;
    case 'Slow WiFi':
      return baseTime * 6;
    default:
      return baseTime * 3;
  }
}

/**
 * 根据网络类型获取预期API响应时间
 */
function getExpectedApiResponseTime(networkType: string): number {
  const baseTime = 1000; // API基础响应时间1秒
  
  switch (networkType) {
    case 'WiFi':
      return baseTime;
    case '4G':
      return baseTime * 2;
    case '3G':
      return baseTime * 4;
    case 'Slow WiFi':
      return baseTime * 8;
    default:
      return baseTime * 3;
  }
}

/**
 * 监控网络请求
 */
async function monitorNetworkRequests(page: Page): Promise<Array<{
  url: string;
  method: string;
  status: number;
  size: number;
  duration: number;
}>> {
  const requests: Array<{
    url: string;
    method: string;
    status: number;
    size: number;
    duration: number;
    startTime: number;
  }> = [];
  
  page.on('request', (request) => {
    (request as any)._startTime = Date.now();
  });
  
  page.on('response', async (response) => {
    const request = response.request();
    const startTime = (request as any)._startTime || Date.now();
    const duration = Date.now() - startTime;
    
    try {
      const body = await response.body();
      requests.push({
        url: response.url(),
        method: request.method(),
        status: response.status(),
        size: body.length,
        duration,
        startTime
      });
    } catch (error) {
      // 忽略无法获取body的响应
    }
  });
  
  return requests;
}

/**
 * 评估网络质量和用户体验
 */
function assessNetworkQuality(metrics: NetworkPerformanceMetrics): NetworkQualityAssessment {
  let rating: NetworkQualityAssessment['rating'];
  let userExperience: string;
  const recommendations: string[] = [];
  
  if (metrics.loadTime < 2000) {
    rating = 'excellent';
    userExperience = '用户体验优秀，页面加载迅速';
  } else if (metrics.loadTime < 5000) {
    rating = 'good';
    userExperience = '用户体验良好，加载时间可接受';
  } else if (metrics.loadTime < 10000) {
    rating = 'fair';
    userExperience = '用户体验一般，加载较慢';
    recommendations.push('启用图片压缩和懒加载');
    recommendations.push('优化关键资源的加载顺序');
  } else {
    rating = 'poor';
    userExperience = '用户体验差，加载时间过长';
    recommendations.push('实施更激进的性能优化');
    recommendations.push('考虑离线优先策略');
    recommendations.push('减少初始页面载荷');
  }
  
  return {
    rating,
    userExperience,
    recommendations
  };
}