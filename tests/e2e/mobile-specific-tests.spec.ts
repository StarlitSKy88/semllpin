import { test, expect, devices } from '@playwright/test';
import { AuthPage } from './page-objects/auth-page';
import { EnhancedMapPage } from './page-objects/enhanced-map-page';

/**
 * SmellPin移动端专属测试套件
 * 
 * 专注于：
 * 1. 触摸手势交互
 * 2. 移动设备特有功能
 * 3. 响应式设计验证
 * 4. 移动网络环境适应
 * 5. 设备传感器集成
 * 
 * @author Mobile E2E Test Suite
 * @version 1.0.0
 */

test.describe('SmellPin移动端专属测试', () => {
  // 移动设备配置
  const mobileDevices = [
    {
      name: 'iPhone 12',
      device: devices['iPhone 12'],
      userAgent: 'iOS'
    },
    {
      name: 'iPhone 13 Pro',
      device: devices['iPhone 13 Pro'],
      userAgent: 'iOS'
    },
    {
      name: 'Pixel 5',
      device: devices['Pixel 5'],
      userAgent: 'Android'
    },
    {
      name: 'Samsung Galaxy S21',
      device: devices['Galaxy S21'],
      userAgent: 'Android'
    }
  ];

  // 为每个移动设备运行测试
  for (const deviceConfig of mobileDevices) {
    test.describe(`${deviceConfig.name} 测试`, () => {
      test.use({ ...deviceConfig.device });

      let authPage: AuthPage;
      let mapPage: EnhancedMapPage;

      test.beforeEach(async ({ page, context }) => {
        // 授予必要权限
        await context.grantPermissions(['geolocation', 'camera', 'microphone']);
        await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 });

        authPage = new AuthPage(page);
        mapPage = new EnhancedMapPage(page);

        // 设置移动端特定的事件监听
        await page.addInitScript(() => {
          // 模拟设备方向变化事件
          (window as any).__orientationChange__ = (orientation: number) => {
            const event = new Event('orientationchange');
            (window as any).orientation = orientation;
            window.dispatchEvent(event);
          };

          // 模拟触摸事件
          (window as any).__simulateTouch__ = (type: string, x: number, y: number) => {
            const touch = new Touch({
              identifier: Date.now(),
              target: document.elementFromPoint(x, y) || document.body,
              clientX: x,
              clientY: y,
              radiusX: 2.5,
              radiusY: 2.5,
              rotationAngle: 0,
              force: 0.5,
            });

            const touchEvent = new TouchEvent(type, {
              cancelable: true,
              bubbles: true,
              touches: [touch],
              targetTouches: [touch],
              changedTouches: [touch],
            });

            document.elementFromPoint(x, y)?.dispatchEvent(touchEvent);
          };
        });
      });

      test('移动端基础交互测试', async ({ page }) => {
        await test.step('用户登录', async () => {
          await authPage.createAndLoginTestUser();
          await mapPage.navigateToMap();
          await mapPage.waitForMapFullyLoaded();
        });

        await test.step('触摸交互测试', async () => {
          // 1. 单击测试
          const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
          await mapContainer.tap();
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-tap-interaction`);

          // 2. 长按测试
          await mapContainer.tap({ timeout: 2000 });
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-long-press`);

          // 3. 双击测试
          await mapContainer.dblclick();
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-double-tap`);
        });

        await test.step('滑动手势测试', async () => {
          const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
          const bounds = await mapContainer.boundingBox();
          
          if (bounds) {
            // 水平滑动
            await page.touchscreen.tap(bounds.x + bounds.width * 0.2, bounds.y + bounds.height / 2);
            await page.mouse.move(bounds.x + bounds.width * 0.2, bounds.y + bounds.height / 2);
            await page.mouse.down();
            await page.mouse.move(bounds.x + bounds.width * 0.8, bounds.y + bounds.height / 2, { steps: 10 });
            await page.mouse.up();
            await page.waitForTimeout(1000);
            await mapPage.takeScreenshot(`${deviceConfig.name}-horizontal-swipe`);

            // 垂直滑动
            await page.touchscreen.tap(bounds.x + bounds.width / 2, bounds.y + bounds.height * 0.2);
            await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height * 0.2);
            await page.mouse.down();
            await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height * 0.8, { steps: 10 });
            await page.mouse.up();
            await page.waitForTimeout(1000);
            await mapPage.takeScreenshot(`${deviceConfig.name}-vertical-swipe`);
          }
        });

        await test.step('缩放手势测试', async () => {
          const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
          
          // 模拟双指缩放
          await page.evaluate(() => {
            const map = document.querySelector('[data-testid="map"], #map, .map-container');
            if (map) {
              // 模拟pinch事件
              const event = new Event('wheel', { bubbles: true });
              (event as any).deltaY = -100; // 放大
              map.dispatchEvent(event);
            }
          });
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-zoom-in`);

          await page.evaluate(() => {
            const map = document.querySelector('[data-testid="map"], #map, .map-container');
            if (map) {
              const event = new Event('wheel', { bubbles: true });
              (event as any).deltaY = 100; // 缩小
              map.dispatchEvent(event);
            }
          });
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-zoom-out`);
        });
      });

      test('设备方向变化测试', async ({ page }) => {
        await authPage.createAndLoginTestUser();
        await mapPage.navigateToMap();
        await mapPage.waitForMapFullyLoaded();

        await test.step('竖屏模式', async () => {
          // 设置竖屏
          await page.setViewportSize({ width: 375, height: 812 });
          await page.evaluate(() => (window as any).__orientationChange__(0));
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-portrait`);

          // 验证竖屏布局
          await mapPage.verifyResponsiveMapBehavior(375);
        });

        await test.step('横屏模式', async () => {
          // 设置横屏
          await page.setViewportSize({ width: 812, height: 375 });
          await page.evaluate(() => (window as any).__orientationChange__(90));
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-landscape`);

          // 验证横屏布局
          const mapContainer = page.locator('[data-testid="map"], #map, .map-container');
          await expect(mapContainer).toBeVisible();
          
          // 在横屏模式下地图应该占用更多空间
          const mapBounds = await mapContainer.boundingBox();
          expect(mapBounds?.width).toBeGreaterThan(700);
        });

        await test.step('方向变化动画', async () => {
          // 快速切换方向测试动画流畅性
          for (let i = 0; i < 3; i++) {
            await page.setViewportSize({ width: 375, height: 812 });
            await page.evaluate(() => (window as any).__orientationChange__(0));
            await page.waitForTimeout(500);
            
            await page.setViewportSize({ width: 812, height: 375 });
            await page.evaluate(() => (window as any).__orientationChange__(90));
            await page.waitForTimeout(500);
          }
          
          await mapPage.takeScreenshot(`${deviceConfig.name}-orientation-final`);
        });
      });

      test('移动端表单交互测试', async ({ page }) => {
        await authPage.createAndLoginTestUser();
        await mapPage.navigateToMap();
        await mapPage.waitForMapFullyLoaded();

        await test.step('创建标注表单', async () => {
          // 打开创建标注表单
          await mapPage.clickMapLocationSmart(39.9042, 116.4074);
          await page.waitForTimeout(2000);

          // 验证移动端表单布局
          const modal = page.locator('[data-testid="create-annotation-modal"], .create-modal');
          await expect(modal).toBeVisible();
          await mapPage.takeScreenshot(`${deviceConfig.name}-form-opened`);

          // 测试虚拟键盘交互
          const titleInput = page.locator('input[name="title"], input[placeholder*="标题"]');
          await titleInput.tap();
          await titleInput.fill('移动端测试标注');
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-keyboard-title`);

          const descriptionInput = page.locator('textarea[name="description"]');
          await descriptionInput.tap();
          await descriptionInput.fill('这是在移动设备上创建的测试标注，用于验证移动端表单交互功能。包含emoji测试：🏭🌸🚗');
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-keyboard-description`);

          // 测试下拉选择
          const categorySelect = page.locator('select[name="category"], [data-testid="category-select"]');
          if (await categorySelect.isVisible()) {
            await categorySelect.tap();
            await page.waitForTimeout(500);
            await mapPage.takeScreenshot(`${deviceConfig.name}-select-dropdown`);
            await categorySelect.selectOption('chemical');
          }

          // 测试滑块控件
          const intensitySlider = page.locator('[data-testid="intensity-slider"], .intensity-slider');
          if (await intensitySlider.isVisible()) {
            const sliderBounds = await intensitySlider.boundingBox();
            if (sliderBounds) {
              await page.touchscreen.tap(sliderBounds.x + sliderBounds.width * 0.6, sliderBounds.y + sliderBounds.height / 2);
              await page.waitForTimeout(500);
              await mapPage.takeScreenshot(`${deviceConfig.name}-slider-interaction`);
            }
          }
        });

        await test.step('文件上传测试', async ({ browserName }) => {
          // 跳过 webkit 的文件上传测试（Safari 限制）
          if (browserName === 'webkit' && deviceConfig.userAgent === 'iOS') {
            test.skip('Safari iOS 文件上传限制');
          }

          const fileInput = page.locator('input[type="file"]');
          if (await fileInput.isVisible()) {
            // 创建测试图片文件
            const testImagePath = './test-data/test-image.jpg';
            await fileInput.setInputFiles([{
              name: 'test-image.jpg',
              mimeType: 'image/jpeg',
              buffer: Buffer.from('fake-image-data')
            }]);
            await page.waitForTimeout(1000);
            await mapPage.takeScreenshot(`${deviceConfig.name}-file-upload`);
          }
        });

        await test.step('表单提交', async () => {
          const submitButton = page.locator('button[type="submit"], button:has-text("创建")');
          await submitButton.tap();
          await page.waitForTimeout(3000);
          
          // 验证成功或错误消息
          const hasSuccess = await page.locator('.success, [data-testid="success"]').isVisible();
          const hasError = await page.locator('.error, [data-testid="error"]').isVisible();
          
          expect(hasSuccess || hasError).toBeTruthy();
          await mapPage.takeScreenshot(`${deviceConfig.name}-form-result`);
        });
      });

      test('移动端网络状态测试', async ({ page }) => {
        await authPage.createAndLoginTestUser();

        await test.step('良好网络条件', async () => {
          await mapPage.navigateToMap();
          await mapPage.waitForMapFullyLoaded();
          await mapPage.takeScreenshot(`${deviceConfig.name}-good-network`);
        });

        await test.step('慢网络模拟', async () => {
          // 模拟3G网络
          await page.route('**/*', async route => {
            await new Promise(resolve => setTimeout(resolve, 2000)); // 2秒延迟
            await route.continue();
          });

          await page.reload();
          await page.waitForTimeout(5000);
          await mapPage.takeScreenshot(`${deviceConfig.name}-slow-network`);

          // 验证加载指示器
          const loadingIndicator = page.locator('.loading, .spinner, [data-testid="loading"]');
          if (await loadingIndicator.isVisible()) {
            await mapPage.takeScreenshot(`${deviceConfig.name}-loading-indicator`);
          }
        });

        await test.step('网络中断恢复', async () => {
          // 恢复正常网络
          await page.unroute('**/*');
          await page.reload();
          await mapPage.waitForMapFullyLoaded();
          await mapPage.takeScreenshot(`${deviceConfig.name}-network-recovered`);
        });
      });

      test('移动端性能测试', async ({ page }) => {
        const performanceMetrics: any = {};

        await test.step('页面加载性能', async () => {
          const startTime = Date.now();
          await authPage.createAndLoginTestUser();
          await mapPage.navigateToMap();
          await mapPage.waitForMapFullyLoaded();
          performanceMetrics.totalLoadTime = Date.now() - startTime;

          // 获取移动端特定的性能指标
          const mobileMetrics = await mapPage.getMapPerformanceMetrics();
          performanceMetrics.mobile = mobileMetrics;

          console.log(`${deviceConfig.name} 性能指标:`, performanceMetrics);
        });

        await test.step('交互响应性能', async () => {
          const interactionTimes: number[] = [];
          
          // 测试10次点击响应时间
          for (let i = 0; i < 10; i++) {
            const startTime = Date.now();
            await page.tap('button:has-text("标记模式"), [data-testid="markers-mode"]');
            await page.waitForTimeout(100);
            interactionTimes.push(Date.now() - startTime);
          }
          
          const avgResponseTime = interactionTimes.reduce((a, b) => a + b, 0) / interactionTimes.length;
          performanceMetrics.averageInteractionTime = avgResponseTime;
          
          // 移动端交互应该在300ms内响应
          expect(avgResponseTime).toBeLessThan(300);
        });

        await test.step('滚动性能测试', async () => {
          const startTime = Date.now();
          
          // 执行连续滚动
          for (let i = 0; i < 5; i++) {
            await page.evaluate(() => {
              window.scrollBy(0, 100);
            });
            await page.waitForTimeout(100);
            await page.evaluate(() => {
              window.scrollBy(0, -100);
            });
            await page.waitForTimeout(100);
          }
          
          performanceMetrics.scrollPerformance = Date.now() - startTime;
          
          // 滚动性能应该流畅
          expect(performanceMetrics.scrollPerformance).toBeLessThan(2000);
        });

        await test.step('内存使用监控', async () => {
          // 获取内存使用情况
          const memoryInfo = await page.evaluate(() => {
            return (performance as any).memory ? {
              usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
              totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
              jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
            } : null;
          });
          
          if (memoryInfo) {
            performanceMetrics.memory = memoryInfo;
            console.log(`${deviceConfig.name} 内存使用:`, memoryInfo);
            
            // 验证内存使用不超过限制的80%
            const memoryUsageRatio = memoryInfo.usedJSHeapSize / memoryInfo.jsHeapSizeLimit;
            expect(memoryUsageRatio).toBeLessThan(0.8);
          }
        });
      });

      test('移动端可访问性测试', async ({ page }) => {
        await authPage.createAndLoginTestUser();
        await mapPage.navigateToMap();
        await mapPage.waitForMapFullyLoaded();

        await test.step('触摸目标大小', async () => {
          // 检查所有可点击元素的大小
          const clickableElements = page.locator('button, a, input, [role="button"]');
          const count = await clickableElements.count();
          
          for (let i = 0; i < Math.min(count, 20); i++) { // 测试前20个元素
            const element = clickableElements.nth(i);
            const bounds = await element.boundingBox();
            
            if (bounds) {
              // 移动端触摸目标应至少44x44px
              expect(bounds.width).toBeGreaterThanOrEqual(40);
              expect(bounds.height).toBeGreaterThanOrEqual(40);
            }
          }
        });

        await test.step('对比度和可读性', async () => {
          // 检查文本对比度
          const textElements = page.locator('p, span, div[class*="text"], h1, h2, h3, h4, h5, h6');
          const sampleSize = Math.min(10, await textElements.count());
          
          for (let i = 0; i < sampleSize; i++) {
            const element = textElements.nth(i);
            const isVisible = await element.isVisible();
            
            if (isVisible) {
              const styles = await element.evaluate(el => {
                const computed = getComputedStyle(el);
                return {
                  color: computed.color,
                  backgroundColor: computed.backgroundColor,
                  fontSize: computed.fontSize
                };
              });
              
              // 确保字体大小在移动端足够大
              const fontSize = parseInt(styles.fontSize);
              expect(fontSize).toBeGreaterThanOrEqual(14); // 最小14px
            }
          }
        });

        await test.step('键盘导航', async () => {
          // 测试Tab键导航
          await page.keyboard.press('Tab');
          await page.waitForTimeout(500);
          
          const focusedElement = await page.locator(':focus');
          await expect(focusedElement).toBeVisible();
          await mapPage.takeScreenshot(`${deviceConfig.name}-keyboard-focus`);
        });
      });

      test('设备特定功能测试', async ({ page }) => {
        await authPage.createAndLoginTestUser();
        await mapPage.navigateToMap();
        await mapPage.waitForMapFullyLoaded();

        if (deviceConfig.userAgent === 'iOS') {
          await test.step('iOS特定功能', async () => {
            // 测试iOS Safari特有的行为
            await page.evaluate(() => {
              // 模拟iOS的bounce scrolling
              document.body.style.webkitOverflowScrolling = 'touch';
            });

            // 测试viewport meta标签效果
            const viewport = await page.evaluate(() => {
              const meta = document.querySelector('meta[name="viewport"]');
              return meta ? meta.getAttribute('content') : null;
            });
            
            expect(viewport).toContain('width=device-width');
            expect(viewport).toContain('initial-scale=1');
          });
        }

        if (deviceConfig.userAgent === 'Android') {
          await test.step('Android特定功能', async () => {
            // 测试Android Chrome特有的行为
            await page.evaluate(() => {
              // 模拟Android的下拉刷新
              if ('ontouchstart' in window) {
                const event = new TouchEvent('touchstart', { bubbles: true });
                document.body.dispatchEvent(event);
              }
            });

            // 测试Android返回按钮行为
            await page.goBack();
            await page.waitForTimeout(1000);
            await page.goForward();
            await mapPage.waitForMapFullyLoaded();
          });
        }
      });
    });
  }

  // 跨设备兼容性测试
  test.describe('跨设备兼容性测试', () => {
    test('数据同步测试', async ({ browser }) => {
      const devices = [
        { name: 'iPhone', config: devices['iPhone 12'] },
        { name: 'Android', config: devices['Pixel 5'] }
      ];

      const contexts = [];
      const pages = [];
      const authPages = [];

      try {
        // 创建多个设备上下文
        for (const device of devices) {
          const context = await browser.newContext({
            ...device.config,
            permissions: ['geolocation'],
            geolocation: { latitude: 39.9042, longitude: 116.4074 }
          });
          
          const page = await context.newPage();
          const authPage = new AuthPage(page);
          
          contexts.push(context);
          pages.push(page);
          authPages.push(authPage);
        }

        // 在第一个设备上创建用户并标注
        const testUser = await authPages[0].createAndLoginTestUser();
        const mapPage1 = new EnhancedMapPage(pages[0]);
        
        await mapPage1.navigateToMap();
        await mapPage1.waitForMapFullyLoaded();
        
        const annotation = {
          title: '跨设备同步测试',
          description: '此标注应在不同设备间同步',
          category: 'test',
          intensity: 3,
          rewardAmount: 15,
          latitude: 39.9042,
          longitude: 116.4074
        };
        
        await mapPage1.createDetailedAnnotation(annotation);
        await pages[0].waitForTimeout(3000);

        // 在第二个设备上登录相同用户
        await authPages[1].login(testUser.email, testUser.password);
        const mapPage2 = new EnhancedMapPage(pages[1]);
        
        await mapPage2.navigateToMap();
        await mapPage2.waitForMapFullyLoaded();

        // 验证数据同步
        const markers = pages[1].locator('.marker, .annotation-marker');
        await expect(markers).toHaveCount(1, { timeout: 10000 });
        
        await mapPage1.takeScreenshot('device1-annotation-created');
        await mapPage2.takeScreenshot('device2-annotation-synced');

      } finally {
        // 清理资源
        for (const context of contexts) {
          await context.close();
        }
      }
    });

    test('响应式断点测试', async ({ page }) => {
      const breakpoints = [
        { width: 320, height: 568, name: 'small-mobile' },
        { width: 375, height: 667, name: 'large-mobile' },
        { width: 768, height: 1024, name: 'tablet' },
        { width: 1024, height: 1366, name: 'desktop' }
      ];

      await authPage.createAndLoginTestUser();
      const mapPage = new EnhancedMapPage(page);

      for (const breakpoint of breakpoints) {
        await test.step(`${breakpoint.name} 断点测试`, async () => {
          await page.setViewportSize({ width: breakpoint.width, height: breakpoint.height });
          await mapPage.navigateToMap();
          await mapPage.waitForMapFullyLoaded();
          
          await mapPage.verifyResponsiveMapBehavior(breakpoint.width);
          await mapPage.takeScreenshot(`responsive-${breakpoint.name}`);
          
          // 验证关键元素在当前断点下可见
          const mapContainer = page.locator('[data-testid="map"], #map, .map-container');
          await expect(mapContainer).toBeVisible();
          
          const bounds = await mapContainer.boundingBox();
          expect(bounds?.width).toBeGreaterThan(breakpoint.width * 0.7); // 地图应占用至少70%宽度
        });
      }
    });
  });
});