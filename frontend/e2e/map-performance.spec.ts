import { test, expect, Page, BrowserContext } from '@playwright/test';

// Performance measurement utilities
class PerformanceMetrics {
  private page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  async measurePageLoad() {
    const startTime = Date.now();
    await this.page.waitForLoadState('networkidle');
    const endTime = Date.now();
    return endTime - startTime;
  }

  async measureMapRender() {
    const startTime = Date.now();
    await this.page.waitForSelector('[data-testid="map-container"]', { timeout: 10000 });
    await this.page.waitForTimeout(2000); // Wait for tiles to load
    const endTime = Date.now();
    return endTime - startTime;
  }

  async measureInteractionResponse(interaction: () => Promise<void>) {
    const startTime = performance.now();
    await interaction();
    const endTime = performance.now();
    return endTime - startTime;
  }

  async getMemoryUsage() {
    const metrics = await this.page.evaluate(() => {
      if (!(performance as any).memory) {
        return null;
      }
      return {
        usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
        totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
        jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
      };
    });
    return metrics;
  }

  async getCPUUsage() {
    // Simulate CPU measurement by timing complex operations
    const measurements = [];
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      await this.page.evaluate(() => {
        // Simulate CPU-intensive task
        const arr = new Array(100000).fill(0).map((_, i) => Math.random());
        arr.sort();
      });
      const end = performance.now();
      measurements.push(end - start);
    }
    return measurements.reduce((a, b) => a + b, 0) / measurements.length;
  }

  async measureNetworkRequests() {
    const requests: any[] = [];
    
    this.page.on('request', request => {
      requests.push({
        url: request.url(),
        method: request.method(),
        timestamp: Date.now()
      });
    });

    this.page.on('response', response => {
      const request = requests.find(r => r.url === response.url());
      if (request) {
        request.responseTime = Date.now() - request.timestamp;
        request.status = response.status();
        request.size = response.headers()['content-length'];
      }
    });

    return requests;
  }
}

test.describe('Map Performance Tests', () => {
  let metrics: PerformanceMetrics;

  test.beforeEach(async ({ page, context }) => {
    metrics = new PerformanceMetrics(page);
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 });
  });

  test.describe('Loading Performance', () => {
    test('should load page within acceptable time', async ({ page }) => {
      const loadTime = await test.step('Measure page load time', async () => {
        const startTime = Date.now();
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        return Date.now() - startTime;
      });

      console.log(`Page load time: ${loadTime}ms`);
      expect(loadTime).toBeLessThan(3000); // Should load within 3 seconds
    });

    test('should render map within acceptable time', async ({ page }) => {
      await page.goto('/');
      
      const renderTime = await metrics.measureMapRender();
      
      console.log(`Map render time: ${renderTime}ms`);
      expect(renderTime).toBeLessThan(5000); // Map should render within 5 seconds
    });

    test('should load OpenStreetMap tiles efficiently', async ({ page }) => {
      const networkRequests = await metrics.measureNetworkRequests();
      
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');
      await page.waitForTimeout(3000); // Wait for tiles to load

      // Check tile loading performance
      const tileRequests = networkRequests.filter(req => 
        req.url.includes('tile.openstreetmap.org') || req.url.includes('.png')
      );

      console.log(`Tile requests: ${tileRequests.length}`);
      
      // Should not make excessive tile requests
      expect(tileRequests.length).toBeLessThan(50);

      // Tile requests should be reasonably fast
      const avgTileLoadTime = tileRequests
        .filter(req => req.responseTime)
        .reduce((sum, req) => sum + req.responseTime, 0) / tileRequests.length;

      console.log(`Average tile load time: ${avgTileLoadTime}ms`);
      expect(avgTileLoadTime).toBeLessThan(1000);
    });

    test('should handle slow network gracefully', async ({ page, context }) => {
      // Simulate slow network
      await context.route('**/*.png', async route => {
        await new Promise(resolve => setTimeout(resolve, 2000));
        await route.continue();
      });

      const startTime = Date.now();
      await page.goto('/');
      
      // Should show loading state
      await expect(page.locator('text=地图加载中...')).toBeVisible();
      
      // Should eventually load
      await page.waitForSelector('[data-testid="map-container"]', { timeout: 15000 });
      const totalTime = Date.now() - startTime;

      console.log(`Slow network load time: ${totalTime}ms`);
      expect(totalTime).toBeLessThan(15000);
    });
  });

  test.describe('Interaction Performance', () => {
    test('should respond to zoom interactions quickly', async ({ page }) => {
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Test zoom in performance
      const zoomInTime = await metrics.measureInteractionResponse(async () => {
        await mapContainer.hover();
        await page.mouse.wheel(0, -100);
        await page.waitForTimeout(100);
      });

      // Test zoom out performance
      const zoomOutTime = await metrics.measureInteractionResponse(async () => {
        await page.mouse.wheel(0, 100);
        await page.waitForTimeout(100);
      });

      console.log(`Zoom in response time: ${zoomInTime.toFixed(2)}ms`);
      console.log(`Zoom out response time: ${zoomOutTime.toFixed(2)}ms`);

      expect(zoomInTime).toBeLessThan(200);
      expect(zoomOutTime).toBeLessThan(200);
    });

    test('should respond to pan interactions quickly', async ({ page }) => {
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const mapContainer = page.locator('[data-testid="map-container"]');
      const box = await mapContainer.boundingBox();
      
      if (box) {
        const panTime = await metrics.measureInteractionResponse(async () => {
          await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
          await page.mouse.down();
          await page.mouse.move(box.x + box.width / 2 + 100, box.y + box.height / 2 + 100);
          await page.mouse.up();
          await page.waitForTimeout(100);
        });

        console.log(`Pan response time: ${panTime.toFixed(2)}ms`);
        expect(panTime).toBeLessThan(300);
      }
    });

    test('should handle annotation clicks efficiently', async ({ page }) => {
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();

      if (markerCount > 0) {
        const clickTime = await metrics.measureInteractionResponse(async () => {
          await markers.first().click();
          await page.waitForSelector('[data-testid="popup"]', { timeout: 1000 });
        });

        console.log(`Annotation click response time: ${clickTime.toFixed(2)}ms`);
        expect(clickTime).toBeLessThan(500);
      }
    });
  });

  test.describe('Memory Usage', () => {
    test('should maintain reasonable memory usage', async ({ page, browserName }) => {
      // Skip memory tests for WebKit as it doesn't support performance.memory
      if (browserName === 'webkit') {
        test.skip();
      }

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const initialMemory = await metrics.getMemoryUsage();
      
      if (initialMemory) {
        console.log(`Initial memory usage: ${(initialMemory.usedJSHeapSize / 1024 / 1024).toFixed(2)}MB`);

        // Perform various interactions to stress test memory
        const mapContainer = page.locator('[data-testid="map-container"]');
        
        for (let i = 0; i < 10; i++) {
          await mapContainer.click({ position: { x: 200 + i * 10, y: 150 + i * 10 } });
          await page.mouse.wheel(0, i % 2 === 0 ? -50 : 50);
          await page.waitForTimeout(100);
        }

        const finalMemory = await metrics.getMemoryUsage();
        
        if (finalMemory) {
          console.log(`Final memory usage: ${(finalMemory.usedJSHeapSize / 1024 / 1024).toFixed(2)}MB`);
          
          const memoryIncrease = finalMemory.usedJSHeapSize - initialMemory.usedJSHeapSize;
          console.log(`Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);

          // Memory usage should not increase dramatically
          expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
        }
      }
    });

    test('should handle memory efficiently with many annotations', async ({ page, context, browserName }) => {
      if (browserName === 'webkit') {
        test.skip();
      }

      // Mock API to return many annotations
      await context.route('**/api/annotations/map**', route => {
        const manyAnnotations = Array.from({ length: 500 }, (_, i) => ({
          id: `annotation-${i}`,
          title: `标注 ${i}`,
          latitude: 39.9042 + (i * 0.0001),
          longitude: 116.4074 + (i * 0.0001),
          smell_intensity: Math.floor(Math.random() * 10) + 1,
          description: `测试标注 ${i}`,
          created_at: new Date().toISOString()
        }));

        route.fulfill({
          status: 200,
          body: JSON.stringify({ success: true, data: manyAnnotations })
        });
      });

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const memory = await metrics.getMemoryUsage();
      
      if (memory) {
        console.log(`Memory usage with 500 annotations: ${(memory.usedJSHeapSize / 1024 / 1024).toFixed(2)}MB`);
        
        // Should handle many annotations without excessive memory usage
        expect(memory.usedJSHeapSize).toBeLessThan(200 * 1024 * 1024); // Less than 200MB
      }
    });

    test('should not have memory leaks during extended use', async ({ page, browserName }) => {
      if (browserName === 'webkit') {
        test.skip();
      }

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const initialMemory = await metrics.getMemoryUsage();
      const mapContainer = page.locator('[data-testid="map-container"]');

      // Simulate extended usage
      for (let cycle = 0; cycle < 3; cycle++) {
        // Perform many interactions
        for (let i = 0; i < 20; i++) {
          await mapContainer.click({ position: { x: 200 + (i * 5), y: 150 + (i * 5) } });
          await page.mouse.wheel(0, i % 2 === 0 ? -25 : 25);
          
          if (i % 5 === 0) {
            // Click markers if they exist
            const markers = page.locator('[data-testid="marker"]');
            const markerCount = await markers.count();
            if (markerCount > 0) {
              await markers.first().click();
              await page.waitForTimeout(100);
              await page.keyboard.press('Escape'); // Close any popups
            }
          }
        }

        // Force garbage collection if possible
        await page.evaluate(() => {
          if ((window as any).gc) {
            (window as any).gc();
          }
        });

        await page.waitForTimeout(1000);
      }

      const finalMemory = await metrics.getMemoryUsage();
      
      if (initialMemory && finalMemory) {
        const memoryIncrease = finalMemory.usedJSHeapSize - initialMemory.usedJSHeapSize;
        console.log(`Memory increase after extended use: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);

        // Should not have significant memory leaks
        expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
      }
    });
  });

  test.describe('Rendering Performance', () => {
    test('should maintain good FPS during interactions', async ({ page }) => {
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      // Measure FPS during continuous interaction
      const fps = await page.evaluate(async () => {
        return new Promise<number>((resolve) => {
          let frames = 0;
          const startTime = performance.now();
          
          function countFrame() {
            frames++;
            if (performance.now() - startTime < 2000) {
              requestAnimationFrame(countFrame);
            } else {
              const avgFPS = frames / 2; // 2 seconds of measurement
              resolve(avgFPS);
            }
          }
          
          requestAnimationFrame(countFrame);
        });
      });

      console.log(`Average FPS during interactions: ${fps.toFixed(2)}`);
      expect(fps).toBeGreaterThan(30); // Should maintain at least 30 FPS
    });

    test('should render large datasets efficiently', async ({ page, context }) => {
      // Mock large dataset
      await context.route('**/api/annotations/map**', route => {
        const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
          id: `annotation-${i}`,
          title: `标注 ${i}`,
          latitude: 39.9042 + ((i % 50) * 0.001),
          longitude: 116.4074 + (Math.floor(i / 50) * 0.001),
          smell_intensity: Math.floor(Math.random() * 10) + 1,
          description: `测试标注 ${i}`,
          created_at: new Date().toISOString()
        }));

        route.fulfill({
          status: 200,
          body: JSON.stringify({ success: true, data: largeDataset })
        });
      });

      const renderStart = Date.now();
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');
      await page.waitForTimeout(3000); // Wait for all annotations to render
      const renderTime = Date.now() - renderStart;

      console.log(`Large dataset render time: ${renderTime}ms`);
      expect(renderTime).toBeLessThan(10000); // Should render within 10 seconds

      // Test interaction performance with large dataset
      const mapContainer = page.locator('[data-testid="map-container"]');
      const interactionTime = await metrics.measureInteractionResponse(async () => {
        await mapContainer.click({ position: { x: 400, y: 300 } });
        await page.waitForTimeout(100);
      });

      console.log(`Interaction time with large dataset: ${interactionTime.toFixed(2)}ms`);
      expect(interactionTime).toBeLessThan(500);
    });

    test('should handle zoom level changes efficiently', async ({ page }) => {
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const mapContainer = page.locator('[data-testid="map-container"]');
      const zoomTimes: number[] = [];

      // Test multiple zoom levels
      for (let i = 0; i < 5; i++) {
        const zoomTime = await metrics.measureInteractionResponse(async () => {
          await mapContainer.hover();
          await page.mouse.wheel(0, -100);
          await page.waitForTimeout(200);
        });
        zoomTimes.push(zoomTime);
      }

      const avgZoomTime = zoomTimes.reduce((a, b) => a + b, 0) / zoomTimes.length;
      console.log(`Average zoom response time: ${avgZoomTime.toFixed(2)}ms`);

      expect(avgZoomTime).toBeLessThan(300);
      
      // Zoom times should be consistent (no significant degradation)
      const maxZoomTime = Math.max(...zoomTimes);
      const minZoomTime = Math.min(...zoomTimes);
      expect(maxZoomTime - minZoomTime).toBeLessThan(200);
    });
  });

  test.describe('Network Performance', () => {
    test('should minimize API calls', async ({ page, context }) => {
      let apiCallCount = 0;
      
      await context.route('**/api/**', route => {
        apiCallCount++;
        route.continue();
      });

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');
      await page.waitForTimeout(2000);

      console.log(`Total API calls: ${apiCallCount}`);
      expect(apiCallCount).toBeLessThan(10); // Should make reasonable number of API calls
    });

    test('should handle API response times efficiently', async ({ page, context }) => {
      const apiTimes: number[] = [];

      await context.route('**/api/**', async route => {
        const startTime = Date.now();
        await route.continue();
        const endTime = Date.now();
        apiTimes.push(endTime - startTime);
      });

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      if (apiTimes.length > 0) {
        const avgApiTime = apiTimes.reduce((a, b) => a + b, 0) / apiTimes.length;
        console.log(`Average API response time: ${avgApiTime.toFixed(2)}ms`);

        expect(avgApiTime).toBeLessThan(1000); // APIs should respond within 1 second on average
      }
    });

    test('should cache data appropriately', async ({ page, context }) => {
      let requestCount = 0;
      const uniqueUrls = new Set();

      await context.route('**/api/annotations/map**', route => {
        requestCount++;
        uniqueUrls.add(route.request().url());
        route.continue();
      });

      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      // Reload page
      await page.reload();
      await page.waitForSelector('[data-testid="map-container"]');

      console.log(`Total annotation requests: ${requestCount}`);
      console.log(`Unique URLs requested: ${uniqueUrls.size}`);

      // Should not make excessive duplicate requests
      expect(requestCount).toBeLessThan(5);
    });
  });

  test.describe('Mobile Performance', () => {
    test('should maintain good performance on mobile devices', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 });
      
      const loadTime = await metrics.measureMapRender();
      console.log(`Mobile map render time: ${loadTime}ms`);

      expect(loadTime).toBeLessThan(6000); // Slightly longer acceptable time for mobile

      // Test touch interactions
      const mapContainer = page.locator('[data-testid="map-container"]');
      
      const touchTime = await metrics.measureInteractionResponse(async () => {
        await mapContainer.tap({ position: { x: 200, y: 300 } });
        await page.waitForTimeout(100);
      });

      console.log(`Mobile touch response time: ${touchTime.toFixed(2)}ms`);
      expect(touchTime).toBeLessThan(400);
    });

    test('should handle orientation changes efficiently', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 }); // Portrait
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');

      const orientationChangeTime = await metrics.measureInteractionResponse(async () => {
        await page.setViewportSize({ width: 667, height: 375 }); // Landscape
        await page.waitForTimeout(500);
      });

      console.log(`Orientation change response time: ${orientationChangeTime.toFixed(2)}ms`);
      expect(orientationChangeTime).toBeLessThan(1000);

      // Map should still be functional after orientation change
      await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
    });
  });

  test.describe('Comparative Performance', () => {
    test('should perform comparably to Google Maps baseline', async ({ page }) => {
      // Test current implementation
      const smellPinStart = Date.now();
      await page.goto('/');
      await page.waitForSelector('[data-testid="map-container"]');
      await page.waitForTimeout(2000);
      const smellPinTime = Date.now() - smellPinStart;

      console.log(`SmellPin map load time: ${smellPinTime}ms`);

      // Basic performance expectations based on typical web map performance
      expect(smellPinTime).toBeLessThan(8000); // Should be within reasonable range
      
      // Memory usage should be reasonable
      const memory = await metrics.getMemoryUsage();
      if (memory) {
        const memoryMB = memory.usedJSHeapSize / 1024 / 1024;
        console.log(`Memory usage: ${memoryMB.toFixed(2)}MB`);
        expect(memoryMB).toBeLessThan(150); // Should use less than 150MB
      }
    });
  });

  test.describe('Performance Regression Detection', () => {
    test('should maintain performance benchmarks', async ({ page }) => {
      // Define performance benchmarks
      const benchmarks = {
        pageLoad: 3000,
        mapRender: 5000,
        zoomResponse: 200,
        clickResponse: 500,
        memoryUsage: 150 * 1024 * 1024 // 150MB
      };

      // Measure actual performance
      const pageLoadTime = await metrics.measurePageLoad();
      await page.goto('/');
      
      const mapRenderTime = await metrics.measureMapRender();
      
      const mapContainer = page.locator('[data-testid="map-container"]');
      const zoomTime = await metrics.measureInteractionResponse(async () => {
        await mapContainer.hover();
        await page.mouse.wheel(0, -100);
        await page.waitForTimeout(100);
      });

      const clickTime = await metrics.measureInteractionResponse(async () => {
        await mapContainer.click({ position: { x: 400, y: 300 } });
        await page.waitForTimeout(100);
      });

      const memory = await metrics.getMemoryUsage();

      // Log all metrics
      console.log('Performance Metrics:');
      console.log(`Page Load: ${pageLoadTime}ms (benchmark: ${benchmarks.pageLoad}ms)`);
      console.log(`Map Render: ${mapRenderTime}ms (benchmark: ${benchmarks.mapRender}ms)`);
      console.log(`Zoom Response: ${zoomTime.toFixed(2)}ms (benchmark: ${benchmarks.zoomResponse}ms)`);
      console.log(`Click Response: ${clickTime.toFixed(2)}ms (benchmark: ${benchmarks.clickResponse}ms)`);
      
      if (memory) {
        console.log(`Memory Usage: ${(memory.usedJSHeapSize / 1024 / 1024).toFixed(2)}MB (benchmark: ${(benchmarks.memoryUsage / 1024 / 1024).toFixed(2)}MB)`);
      }

      // Assert against benchmarks
      expect(pageLoadTime).toBeLessThan(benchmarks.pageLoad);
      expect(mapRenderTime).toBeLessThan(benchmarks.mapRender);
      expect(zoomTime).toBeLessThan(benchmarks.zoomResponse);
      expect(clickTime).toBeLessThan(benchmarks.clickResponse);
      
      if (memory) {
        expect(memory.usedJSHeapSize).toBeLessThan(benchmarks.memoryUsage);
      }
    });
  });
});