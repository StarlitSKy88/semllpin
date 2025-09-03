import { test, expect } from '@playwright/test';
import { AuthPage } from './page-objects/auth-page';
import { EnhancedMapPage } from './page-objects/enhanced-map-page';

/**
 * SmellPin性能和压力测试套件
 * 
 * 测试范围：
 * 1. 大量数据加载性能
 * 2. 并发用户操作压力测试
 * 3. 内存泄漏检测
 * 4. 网络请求优化验证
 * 5. 地图渲染性能测试
 * 
 * @author Performance Test Suite
 * @version 1.0.0
 */

test.describe('SmellPin性能和压力测试', () => {
  let authPage: AuthPage;
  let mapPage: EnhancedMapPage;

  test.beforeEach(async ({ page, context }) => {
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 });

    authPage = new AuthPage(page);
    mapPage = new EnhancedMapPage(page);
  });

  test.describe('页面加载性能测试', () => {
    test('首页加载性能基准', async ({ page }) => {
      const metrics: any = {};

      await test.step('冷启动加载测试', async () => {
        // 清除缓存模拟首次访问
        await page.context().clearCookies();
        await page.evaluate(() => {
          localStorage.clear();
          sessionStorage.clear();
        });

        const startTime = Date.now();
        await page.goto('/', { waitUntil: 'networkidle' });
        metrics.coldLoadTime = Date.now() - startTime;

        // 获取Web Vitals指标
        const webVitals = await page.evaluate(() => {
          return new Promise((resolve) => {
            const vitals: any = {};
            let metricsCollected = 0;
            const targetMetrics = 4;

            const collectMetric = (name: string, value: number) => {
              vitals[name] = value;
              metricsCollected++;
              if (metricsCollected >= targetMetrics) {
                resolve(vitals);
              }
            };

            // FCP - First Contentful Paint
            new PerformanceObserver((list) => {
              for (const entry of list.getEntries()) {
                if (entry.name === 'first-contentful-paint') {
                  collectMetric('fcp', entry.startTime);
                }
              }
            }).observe({ entryTypes: ['paint'] });

            // LCP - Largest Contentful Paint
            new PerformanceObserver((list) => {
              const entries = list.getEntries();
              const lastEntry = entries[entries.length - 1];
              collectMetric('lcp', lastEntry.startTime);
            }).observe({ entryTypes: ['largest-contentful-paint'] });

            // FID - First Input Delay (模拟)
            let fidMeasured = false;
            const measureFID = () => {
              if (!fidMeasured) {
                fidMeasured = true;
                collectMetric('fid', 0); // 在自动化测试中FID通常为0
              }
            };
            document.addEventListener('click', measureFID, { once: true });
            setTimeout(measureFID, 100);

            // CLS - Cumulative Layout Shift
            new PerformanceObserver((list) => {
              let clsValue = 0;
              for (const entry of list.getEntries()) {
                if ((entry as any).hadRecentInput) continue;
                clsValue += (entry as any).value;
              }
              collectMetric('cls', clsValue);
            }).observe({ entryTypes: ['layout-shift'] });

            // 超时保护
            setTimeout(() => resolve(vitals), 5000);
          });
        });

        metrics.webVitals = webVitals;
        
        // 性能基准验证
        expect(metrics.coldLoadTime).toBeLessThan(5000); // 5秒内
        expect(webVitals.fcp).toBeLessThan(2000);        // FCP < 2秒
        expect(webVitals.lcp).toBeLessThan(4000);        // LCP < 4秒
        expect(webVitals.cls).toBeLessThan(0.1);         // CLS < 0.1

        console.log('首页加载性能指标:', metrics);
      });

      await test.step('热启动加载测试', async () => {
        // 二次加载（有缓存）
        const startTime = Date.now();
        await page.reload({ waitUntil: 'networkidle' });
        metrics.hotLoadTime = Date.now() - startTime;

        // 缓存加载应该更快
        expect(metrics.hotLoadTime).toBeLessThan(metrics.coldLoadTime * 0.7);
        expect(metrics.hotLoadTime).toBeLessThan(2000); // 2秒内

        console.log('热启动加载时间:', metrics.hotLoadTime);
      });
    });

    test('地图页面加载性能测试', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      const metrics: any = {};

      await test.step('地图初始加载', async () => {
        const startTime = Date.now();
        await mapPage.navigateToMap();
        await mapPage.waitForMapFullyLoaded();
        metrics.mapLoadTime = Date.now() - startTime;

        // 地图加载应该在10秒内完成
        expect(metrics.mapLoadTime).toBeLessThan(10000);

        console.log('地图加载时间:', metrics.mapLoadTime);
      });

      await test.step('地图瓦片加载性能', async () => {
        const tileLoadMetrics = await page.evaluate(() => {
          return new Promise((resolve) => {
            const startTime = Date.now();
            let tilesLoaded = 0;
            const totalTiles = document.querySelectorAll('.leaflet-tile').length;

            if (totalTiles === 0) {
              resolve({ tilesLoaded: 0, averageLoadTime: 0 });
              return;
            }

            const checkTilesLoaded = () => {
              const loadedTiles = document.querySelectorAll('.leaflet-tile[src]').length;
              if (loadedTiles >= totalTiles || Date.now() - startTime > 10000) {
                resolve({
                  tilesLoaded: loadedTiles,
                  totalTiles: totalTiles,
                  averageLoadTime: (Date.now() - startTime) / Math.max(loadedTiles, 1)
                });
              } else {
                setTimeout(checkTilesLoaded, 100);
              }
            };

            checkTilesLoaded();
          });
        });

        metrics.tileLoadMetrics = tileLoadMetrics;
        console.log('瓦片加载指标:', tileLoadMetrics);
      });
    });
  });

  test.describe('大量数据处理性能测试', () => {
    test('大量标注加载性能', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      await test.step('创建大量测试数据', async () => {
        const annotationCount = 50;
        const createPromises = [];

        const startTime = Date.now();

        // 批量创建标注
        for (let i = 0; i < annotationCount; i++) {
          const annotation = {
            title: `批量测试标注 ${i + 1}`,
            description: `这是第${i + 1}个测试标注，用于性能测试`,
            category: ['food', 'chemical', 'nature', 'smoke'][i % 4],
            intensity: (i % 5) + 1,
            rewardAmount: Math.floor(Math.random() * 50) + 10,
            latitude: 39.9042 + (Math.random() - 0.5) * 0.01,
            longitude: 116.4074 + (Math.random() - 0.5) * 0.01
          };

          // 批量创建（不等待每个完成）
          createPromises.push(
            mapPage.createDetailedAnnotation(annotation).catch(err => {
              console.warn(`标注 ${i + 1} 创建失败:`, err.message);
            })
          );

          // 每10个标注暂停一下，避免请求过于密集
          if ((i + 1) % 10 === 0) {
            await Promise.allSettled(createPromises.slice(-10));
            await page.waitForTimeout(1000);
          }
        }

        // 等待所有创建完成
        await Promise.allSettled(createPromises);
        
        const totalTime = Date.now() - startTime;
        console.log(`创建${annotationCount}个标注耗时: ${totalTime}ms`);
        
        await mapPage.takeScreenshot('bulk-annotations-created');
      });

      await test.step('大量标注渲染性能', async () => {
        const renderStartTime = Date.now();
        
        // 刷新页面重新加载所有标注
        await page.reload();
        await mapPage.waitForMapFullyLoaded();
        
        const renderTime = Date.now() - renderStartTime;
        
        // 验证标注正确显示
        const markers = page.locator('.marker, .annotation-marker');
        const markerCount = await markers.count();
        
        console.log(`渲染${markerCount}个标注耗时: ${renderTime}ms`);
        expect(markerCount).toBeGreaterThan(0);
        expect(renderTime).toBeLessThan(15000); // 15秒内完成渲染
        
        await mapPage.takeScreenshot('bulk-annotations-rendered');
      });

      await test.step('标注聚类性能测试', async () => {
        // 缩小地图以触发聚类
        const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
        
        const clusterStartTime = Date.now();
        
        // 连续缩小地图
        for (let i = 0; i < 5; i++) {
          await mapContainer.hover();
          await page.mouse.wheel(0, 500); // 缩小
          await page.waitForTimeout(200);
        }
        
        const clusterTime = Date.now() - clusterStartTime;
        
        // 验证聚类功能
        const clusters = page.locator('.marker-cluster, .cluster');
        if (await clusters.count() > 0) {
          console.log(`标注聚类处理耗时: ${clusterTime}ms`);
          expect(clusterTime).toBeLessThan(3000); // 3秒内完成聚类
          await mapPage.takeScreenshot('annotation-clusters');
        }
      });
    });

    test('搜索和筛选性能测试', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      await test.step('文本搜索性能', async () => {
        const searchTerms = ['测试', '化学', '食物', 'test', 'smell'];
        
        for (const term of searchTerms) {
          const searchStartTime = Date.now();
          
          await mapPage.performAdvancedSearch({ keyword: term });
          
          const searchTime = Date.now() - searchStartTime;
          console.log(`搜索"${term}"耗时: ${searchTime}ms`);
          
          expect(searchTime).toBeLessThan(2000); // 2秒内完成搜索
          await page.waitForTimeout(500);
        }
        
        await mapPage.takeScreenshot('search-results');
      });

      await test.step('复合筛选性能', async () => {
        const filterStartTime = Date.now();
        
        await mapPage.performAdvancedSearch({
          category: 'chemical',
          minReward: 10,
          maxReward: 50,
          maxDistance: 1000
        });
        
        const filterTime = Date.now() - filterStartTime;
        console.log(`复合筛选耗时: ${filterTime}ms`);
        
        expect(filterTime).toBeLessThan(3000); // 3秒内完成筛选
        await mapPage.takeScreenshot('filtered-results');
      });
    });
  });

  test.describe('并发操作压力测试', () => {
    test('多用户同时创建标注', async ({ browser }) => {
      const concurrentUsers = 5;
      const contextsAndPages = [];

      try {
        // 创建多个用户会话
        for (let i = 0; i < concurrentUsers; i++) {
          const context = await browser.newContext({
            permissions: ['geolocation'],
            geolocation: { latitude: 39.9042, longitude: 116.4074 }
          });
          
          const page = await context.newPage();
          const authPage = new AuthPage(page);
          const mapPage = new EnhancedMapPage(page);
          
          await authPage.createAndLoginTestUser();
          await mapPage.navigateToMap();
          await mapPage.waitForMapFullyLoaded();
          
          contextsAndPages.push({ context, page, authPage, mapPage });
        }

        await test.step('并发创建标注', async () => {
          const concurrentPromises = contextsAndPages.map(async (userSession, index) => {
            const annotation = {
              title: `并发测试标注-用户${index + 1}`,
              description: `用户${index + 1}创建的并发测试标注`,
              category: 'test',
              intensity: 3,
              rewardAmount: 15,
              latitude: 39.9042 + index * 0.001,
              longitude: 116.4074 + index * 0.001
            };

            try {
              await userSession.mapPage.createDetailedAnnotation(annotation);
              return { success: true, user: index + 1 };
            } catch (error) {
              console.warn(`用户${index + 1}创建标注失败:`, error);
              return { success: false, user: index + 1, error: error.message };
            }
          });

          const startTime = Date.now();
          const results = await Promise.allSettled(concurrentPromises);
          const totalTime = Date.now() - startTime;

          const successCount = results.filter(r => r.status === 'fulfilled' && (r.value as any).success).length;
          
          console.log(`${concurrentUsers}个用户并发创建标注: ${successCount}个成功, 总耗时: ${totalTime}ms`);
          
          // 至少80%的并发操作应该成功
          expect(successCount / concurrentUsers).toBeGreaterThanOrEqual(0.8);
          expect(totalTime).toBeLessThan(30000); // 30秒内完成
        });

      } finally {
        // 清理资源
        for (const session of contextsAndPages) {
          await session.context.close();
        }
      }
    });

    test('高频交互操作测试', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      await test.step('快速连续点击测试', async () => {
        const clickCount = 20;
        const clickTimes: number[] = [];
        
        const mapModeButton = page.locator('button:has-text("标记模式"), [data-testid="markers-mode"]');
        
        for (let i = 0; i < clickCount; i++) {
          const startTime = Date.now();
          await mapModeButton.click();
          const clickTime = Date.now() - startTime;
          clickTimes.push(clickTime);
          
          await page.waitForTimeout(50); // 短暂间隔
        }
        
        const averageClickTime = clickTimes.reduce((a, b) => a + b, 0) / clickTimes.length;
        const maxClickTime = Math.max(...clickTimes);
        
        console.log(`快速点击性能: 平均${averageClickTime}ms, 最大${maxClickTime}ms`);
        
        expect(averageClickTime).toBeLessThan(100); // 平均响应时间100ms内
        expect(maxClickTime).toBeLessThan(500);     // 最大响应时间500ms内
      });

      await test.step('连续搜索操作测试', async () => {
        const searchInput = page.locator('input[type="search"], input[placeholder*="搜索"]');
        const searchTerms = ['a', 'ab', 'abc', 'abcd', 'abcde'];
        
        const searchTimes: number[] = [];
        
        for (const term of searchTerms) {
          const startTime = Date.now();
          
          await searchInput.fill(term);
          await page.waitForTimeout(100); // 模拟用户输入间隔
          
          const searchTime = Date.now() - startTime;
          searchTimes.push(searchTime);
        }
        
        const averageSearchTime = searchTimes.reduce((a, b) => a + b, 0) / searchTimes.length;
        
        console.log(`连续搜索性能: 平均${averageSearchTime}ms`);
        expect(averageSearchTime).toBeLessThan(200); // 200ms内响应
      });
    });
  });

  test.describe('内存和资源泄漏测试', () => {
    test('长时间运行内存泄漏检测', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      const memorySnapshots: any[] = [];

      await test.step('基线内存使用', async () => {
        const initialMemory = await page.evaluate(() => {
          if ((performance as any).memory) {
            return {
              usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
              totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
              jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
            };
          }
          return null;
        });
        
        if (initialMemory) {
          memorySnapshots.push({ stage: 'initial', ...initialMemory });
          console.log('初始内存使用:', initialMemory);
        }
      });

      await test.step('重复操作内存监控', async () => {
        const operations = [
          () => mapPage.clickMapLocationSmart(39.9042, 116.4074),
          () => page.click('button:has-text("标记模式")'),
          () => page.click('button:has-text("热力图")'),
          () => page.reload().then(() => mapPage.waitForMapFullyLoaded()),
        ];
        
        for (let cycle = 0; cycle < 5; cycle++) {
          for (const operation of operations) {
            await operation();
            await page.waitForTimeout(1000);
          }
          
          // 每个周期后检查内存
          const cycleMemory = await page.evaluate(() => {
            if ((performance as any).memory) {
              return {
                usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
                totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
                jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
              };
            }
            return null;
          });
          
          if (cycleMemory) {
            memorySnapshots.push({ stage: `cycle-${cycle + 1}`, ...cycleMemory });
            console.log(`第${cycle + 1}周期内存使用:`, cycleMemory);
          }
        }
      });

      await test.step('内存泄漏分析', async () => {
        if (memorySnapshots.length > 1) {
          const initial = memorySnapshots[0];
          const final = memorySnapshots[memorySnapshots.length - 1];
          
          const memoryGrowth = final.usedJSHeapSize - initial.usedJSHeapSize;
          const growthPercentage = (memoryGrowth / initial.usedJSHeapSize) * 100;
          
          console.log(`内存增长: ${memoryGrowth} bytes (${growthPercentage.toFixed(2)}%)`);
          
          // 内存增长不应超过初始使用量的50%
          expect(growthPercentage).toBeLessThan(50);
          
          // 不应该超过总内存限制的80%
          const memoryUsageRatio = final.usedJSHeapSize / final.jsHeapSizeLimit;
          expect(memoryUsageRatio).toBeLessThan(0.8);
        }
      });
    });

    test('DOM元素泄漏检测', async ({ page }) => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      const domSnapshots: any[] = [];

      await test.step('DOM元素计数监控', async () => {
        const getDOMCount = () => page.evaluate(() => ({
          total: document.getElementsByTagName('*').length,
          divs: document.getElementsByTagName('div').length,
          buttons: document.getElementsByTagName('button').length,
          images: document.getElementsByTagName('img').length,
          listeners: (window as any).__eventListenerCount__ || 0
        }));
        
        // 初始DOM状态
        domSnapshots.push({ stage: 'initial', ...(await getDOMCount()) });
        
        // 执行多次创建/销毁操作
        for (let i = 0; i < 10; i++) {
          // 创建标注表单
          await mapPage.clickMapLocationSmart(39.9042 + i * 0.0001, 116.4074);
          await page.waitForTimeout(500);
          
          // 取消创建
          const cancelButton = page.locator('button:has-text("取消"), [data-testid="cancel-button"]');
          if (await cancelButton.isVisible()) {
            await cancelButton.click();
          }
          
          await page.waitForTimeout(500);
          
          // 每3次操作检查一次DOM
          if ((i + 1) % 3 === 0) {
            domSnapshots.push({ stage: `operation-${i + 1}`, ...(await getDOMCount()) });
          }
        }
        
        console.log('DOM元素变化:', domSnapshots);
      });

      await test.step('DOM泄漏分析', async () => {
        if (domSnapshots.length > 1) {
          const initial = domSnapshots[0];
          const final = domSnapshots[domSnapshots.length - 1];
          
          const elementGrowth = final.total - initial.total;
          const growthPercentage = (elementGrowth / initial.total) * 100;
          
          console.log(`DOM元素增长: ${elementGrowth} 个 (${growthPercentage.toFixed(2)}%)`);
          
          // DOM元素增长不应超过初始数量的30%
          expect(growthPercentage).toBeLessThan(30);
        }
      });
    });
  });

  test.describe('网络请求优化测试', () => {
    test('API请求优化验证', async ({ page }) => {
      const apiRequests: any[] = [];
      
      // 监控所有API请求
      page.on('request', request => {
        if (request.url().includes('/api/')) {
          apiRequests.push({
            url: request.url(),
            method: request.method(),
            timestamp: Date.now()
          });
        }
      });

      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapFullyLoaded();

      await test.step('请求频率分析', async () => {
        console.log(`总API请求数: ${apiRequests.length}`);
        
        // 按URL分组统计
        const requestsByUrl = apiRequests.reduce((acc, req) => {
          const url = new URL(req.url).pathname;
          acc[url] = (acc[url] || 0) + 1;
          return acc;
        }, {});
        
        console.log('请求频率分布:', requestsByUrl);
        
        // 检查是否有异常高频的请求
        const maxRequestsPerEndpoint = Math.max(...Object.values(requestsByUrl) as number[]);
        expect(maxRequestsPerEndpoint).toBeLessThan(20); // 单个端点不应超过20次请求
      });

      await test.step('请求缓存效果验证', async () => {
        const initialRequestCount = apiRequests.length;
        
        // 刷新页面
        await page.reload();
        await mapPage.waitForMapFullyLoaded();
        
        const afterReloadRequestCount = apiRequests.length;
        const additionalRequests = afterReloadRequestCount - initialRequestCount;
        
        console.log(`页面刷新后新增请求: ${additionalRequests}个`);
        
        // 由于缓存，刷新后的请求数应该明显减少
        expect(additionalRequests).toBeLessThan(initialRequestCount * 0.8);
      });
    });

    test('资源加载优化测试', async ({ page }) => {
      const resourceMetrics: any = {};

      await test.step('资源加载时序分析', async () => {
        await page.goto('/');
        
        const performanceEntries = await page.evaluate(() => {
          const entries = performance.getEntriesByType('resource');
          return entries.map(entry => ({
            name: entry.name,
            startTime: entry.startTime,
            duration: entry.duration,
            transferSize: (entry as any).transferSize || 0,
            encodedBodySize: (entry as any).encodedBodySize || 0,
            decodedBodySize: (entry as any).decodedBodySize || 0
          }));
        });
        
        const cssFiles = performanceEntries.filter(e => e.name.includes('.css'));
        const jsFiles = performanceEntries.filter(e => e.name.includes('.js'));
        const imageFiles = performanceEntries.filter(e => /\.(png|jpg|jpeg|gif|svg)/.test(e.name));
        
        resourceMetrics.css = {
          count: cssFiles.length,
          totalSize: cssFiles.reduce((sum, f) => sum + f.transferSize, 0),
          totalDuration: cssFiles.reduce((sum, f) => sum + f.duration, 0)
        };
        
        resourceMetrics.js = {
          count: jsFiles.length,
          totalSize: jsFiles.reduce((sum, f) => sum + f.transferSize, 0),
          totalDuration: jsFiles.reduce((sum, f) => sum + f.duration, 0)
        };
        
        resourceMetrics.images = {
          count: imageFiles.length,
          totalSize: imageFiles.reduce((sum, f) => sum + f.transferSize, 0),
          totalDuration: imageFiles.reduce((sum, f) => sum + f.duration, 0)
        };
        
        console.log('资源加载指标:', resourceMetrics);
      });

      await test.step('资源压缩效果验证', async () => {
        // 验证主要资源是否被压缩
        const mainResources = await page.evaluate(() => {
          const entries = performance.getEntriesByType('resource');
          return entries
            .filter(entry => entry.name.includes('.js') || entry.name.includes('.css'))
            .map(entry => ({
              name: entry.name,
              transferSize: (entry as any).transferSize || 0,
              encodedBodySize: (entry as any).encodedBodySize || 0,
              decodedBodySize: (entry as any).decodedBodySize || 0
            }))
            .filter(r => r.decodedBodySize > 0);
        });
        
        for (const resource of mainResources) {
          const compressionRatio = resource.transferSize / resource.decodedBodySize;
          console.log(`${resource.name}: 压缩比 ${(compressionRatio * 100).toFixed(2)}%`);
          
          // 主要资源应该有合理的压缩比
          if (resource.decodedBodySize > 10000) { // 大于10KB的文件
            expect(compressionRatio).toBeLessThan(0.8); // 压缩率应该超过20%
          }
        }
      });
    });
  });

  test.afterEach(async ({ page }, testInfo) => {
    // 收集测试结束时的性能指标
    const finalMetrics = await page.evaluate(() => {
      const metrics: any = {};
      
      if ((performance as any).memory) {
        metrics.memory = {
          usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
          totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
          jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
        };
      }
      
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      if (navigation) {
        metrics.navigation = {
          domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
          loadComplete: navigation.loadEventEnd - navigation.loadEventStart,
        };
      }
      
      return metrics;
    });
    
    console.log(`测试 ${testInfo.title} 结束时性能指标:`, finalMetrics);
    
    // 如果测试失败，收集额外的性能数据
    if (testInfo.status !== testInfo.expectedStatus) {
      await page.screenshot({
        path: `test-results/performance-failure-${testInfo.title.replace(/\s+/g, '-')}-${Date.now()}.png`,
        fullPage: true
      });
    }
  });
});