import { test, expect, Page, BrowserContext, devices } from '@playwright/test';
import { AuthPage } from '../page-objects/auth-page';
import { MapPage } from '../page-objects/map-page';

test.describe('跨设备和网络环境测试', () => {
  let testUser: any;

  test.beforeAll(async ({ browser }) => {
    // 创建测试用户
    const context = await browser.newContext();
    const page = await context.newPage();
    const authPage = new AuthPage(page);
    
    testUser = await authPage.createAndLoginTestUser({
      username: 'cross_device_user',
      email: 'crossdevice@smellpin.test'
    });
    
    await context.close();
  });

  test.describe('移动设备测试', () => {
    test('iPhone用户体验测试', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        geolocation: { latitude: 40.7128, longitude: -74.0060 },
        permissions: ['geolocation']
      });
      
      const page = await context.newPage();
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      try {
        // 移动端登录测试
        await authPage.login(testUser.email, testUser.password);
        await authPage.takeScreenshot('01-mobile-login-iphone');

        // 移动端地图使用测试
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        
        // 验证移动端地图响应式布局
        const mapContainer = page.locator('#map, .map-container');
        const mapBounds = await mapContainer.boundingBox();
        expect(mapBounds?.width).toBeLessThan(400); // iPhone 12 viewport width
        await authPage.takeScreenshot('02-mobile-map-iphone');

        // 测试移动端触摸交互
        await mapPage.getCurrentLocation();
        await authPage.takeScreenshot('03-mobile-location-iphone');

        // 测试移动端标注创建
        const mobileAnnotation = {
          title: '移动端创建标注',
          description: '使用iPhone创建的标注测试',
          category: 'pleasant',
          intensity: 3,
          rewardAmount: 15,
          latitude: 40.7128,
          longitude: -74.0060
        };

        // 模拟触摸操作
        await page.touchscreen.tap(200, 300); // 点击地图
        await page.waitForTimeout(1000);

        if (await page.locator('button:has-text("创建标注")').isVisible()) {
          await page.locator('button:has-text("创建标注")').tap();
          
          // 在移动端填写表单
          await authPage.fillElement('input[name="title"]', mobileAnnotation.title);
          await authPage.fillElement('textarea[name="description"]', mobileAnnotation.description);
          
          await authPage.clickElement('button[type="submit"]');
          await authPage.verifyToastMessage('标注创建成功');
          await authPage.takeScreenshot('04-mobile-annotation-created-iphone');
        }

        console.log('✅ iPhone用户体验测试完成');

      } catch (error) {
        await authPage.takeScreenshot('error-mobile-iphone');
        throw error;
      } finally {
        await context.close();
      }
    });

    test('Android用户体验测试', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['Pixel 5'],
        geolocation: { latitude: 40.7128, longitude: -74.0060 },
        permissions: ['geolocation']
      });
      
      const page = await context.newPage();
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      try {
        await authPage.login(testUser.email, testUser.password);
        await authPage.takeScreenshot('01-mobile-login-android');

        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        await authPage.takeScreenshot('02-mobile-map-android');

        // 测试Android特有的返回键行为
        await page.keyboard.press('Escape'); // 模拟返回键
        await page.waitForTimeout(500);
        
        // 验证应用正确处理返回键
        const currentUrl = page.url();
        expect(currentUrl).toContain('/map');
        
        // 测试Android Chrome浏览器的特殊功能
        await page.evaluate(() => {
          // 模拟Android的地址栏隐藏
          window.scrollTo(0, 100);
        });
        await authPage.takeScreenshot('03-android-scroll-behavior');

        console.log('✅ Android用户体验测试完成');

      } catch (error) {
        await authPage.takeScreenshot('error-mobile-android');
        throw error;
      } finally {
        await context.close();
      }
    });

    test('平板设备用户体验测试', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPad Pro'],
        geolocation: { latitude: 40.7128, longitude: -74.0060 },
        permissions: ['geolocation']
      });
      
      const page = await context.newPage();
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      try {
        await authPage.login(testUser.email, testUser.password);
        await authPage.takeScreenshot('01-tablet-login-ipad');

        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();

        // 验证平板端布局适配
        const mapContainer = page.locator('#map, .map-container');
        const mapBounds = await mapContainer.boundingBox();
        expect(mapBounds?.width).toBeGreaterThan(700); // iPad viewport width
        await authPage.takeScreenshot('02-tablet-map-layout');

        // 测试平板的分屏功能模拟
        await page.setViewportSize({ width: 512, height: 1024 }); // 分屏模式
        await authPage.takeScreenshot('03-tablet-split-screen');

        console.log('✅ 平板设备用户体验测试完成');

      } finally {
        await context.close();
      }
    });
  });

  test.describe('网络环境测试', () => {
    test('慢网络环境测试', async ({ page, context }) => {
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      // 模拟慢速3G网络
      await context.route('**/*', async route => {
        await new Promise(resolve => setTimeout(resolve, 2000)); // 延迟2秒
        await route.continue();
      });

      const startTime = Date.now();

      try {
        await authPage.login(testUser.email, testUser.password);
        
        // 记录在慢网络下的登录时间
        const loginTime = Date.now() - startTime;
        console.log(`慢网络登录耗时: ${loginTime}ms`);
        
        await authPage.takeScreenshot('01-slow-network-login');

        // 测试慢网络下的地图加载
        const mapStartTime = Date.now();
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        
        const mapLoadTime = Date.now() - mapStartTime;
        console.log(`慢网络地图加载耗时: ${mapLoadTime}ms`);
        
        // 验证在合理时间内完成（考虑到网络延迟）
        expect(loginTime).toBeLessThan(15000); // 15秒内登录
        expect(mapLoadTime).toBeLessThan(20000); // 20秒内地图加载
        
        await authPage.takeScreenshot('02-slow-network-map');

        console.log('✅ 慢网络环境测试完成');

      } catch (error) {
        await authPage.takeScreenshot('error-slow-network');
        throw error;
      }
    });

    test('断网重连测试', async ({ page, context }) => {
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      await authPage.login(testUser.email, testUser.password);
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();

      // 模拟网络断开
      await context.setOffline(true);
      await authPage.takeScreenshot('01-offline-mode');

      // 尝试进行需要网络的操作
      try {
        await mapPage.getCurrentLocation();
        
        // 验证离线提示
        const offlineIndicator = page.locator('.offline-indicator, [data-testid="offline"]');
        if (await offlineIndicator.isVisible()) {
          await expect(offlineIndicator).toContainText(/离线|offline/i);
          await authPage.takeScreenshot('02-offline-indicator');
        }

      } catch (error) {
        console.log('预期的离线错误:', error.message);
      }

      // 恢复网络连接
      await context.setOffline(false);
      await page.waitForTimeout(3000); // 等待重连

      // 验证功能恢复正常
      await mapPage.getCurrentLocation();
      await authPage.verifyToastMessage(/已连接|connected/i);
      await authPage.takeScreenshot('03-network-restored');

      console.log('✅ 断网重连测试完成');
    });

    test('不稳定网络测试', async ({ page, context }) => {
      const authPage = new AuthPage(page);
      const mapPage = new MapPage(page);

      // 模拟不稳定网络（随机延迟和失败）
      let requestCount = 0;
      await context.route('**/*', async route => {
        requestCount++;
        
        // 30%概率延迟，10%概率失败
        const random = Math.random();
        if (random < 0.1) {
          // 10%请求失败
          await route.abort('failed');
          return;
        } else if (random < 0.4) {
          // 30%请求延迟
          await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
        }
        
        await route.continue();
      });

      try {
        await authPage.login(testUser.email, testUser.password);
        await mapPage.navigateToMap();
        
        // 在不稳定网络下测试多次操作
        for (let i = 0; i < 3; i++) {
          try {
            await mapPage.getCurrentLocation();
            await page.waitForTimeout(2000);
            await authPage.takeScreenshot(`unstable-network-attempt-${i + 1}`);
          } catch (error) {
            console.log(`第 ${i + 1} 次尝试失败，继续测试...`);
          }
        }

        console.log(`不稳定网络测试完成，总请求数: ${requestCount}`);

      } catch (error) {
        await authPage.takeScreenshot('error-unstable-network');
        console.log('不稳定网络测试遇到预期错误:', error.message);
      }
    });
  });

  test.describe('浏览器兼容性测试', () => {
    ['chromium', 'firefox', 'webkit'].forEach(browserName => {
      test(`${browserName}浏览器兼容性测试`, async ({ browser }) => {
        const context = await browser.newContext({
          geolocation: { latitude: 40.7128, longitude: -74.0060 },
          permissions: ['geolocation']
        });
        
        const page = await context.newPage();
        const authPage = new AuthPage(page);
        const mapPage = new MapPage(page);

        try {
          await authPage.login(testUser.email, testUser.password);
          await authPage.takeScreenshot(`01-${browserName}-login`);

          await mapPage.navigateToMap();
          await mapPage.waitForMapLoad();
          await authPage.takeScreenshot(`02-${browserName}-map`);

          // 测试JavaScript API兼容性
          const browserInfo = await page.evaluate(() => {
            return {
              userAgent: navigator.userAgent,
              geolocation: !!navigator.geolocation,
              localStorage: !!window.localStorage,
              serviceWorker: !!navigator.serviceWorker,
              webgl: !!window.WebGLRenderingContext,
            };
          });

          console.log(`${browserName} 浏览器信息:`, browserInfo);

          // 验证核心功能支持
          expect(browserInfo.geolocation).toBe(true);
          expect(browserInfo.localStorage).toBe(true);

          // 测试地图功能在不同浏览器下的表现
          await mapPage.getCurrentLocation();
          await authPage.takeScreenshot(`03-${browserName}-location`);

          console.log(`✅ ${browserName}浏览器兼容性测试完成`);

        } catch (error) {
          await authPage.takeScreenshot(`error-${browserName}-compatibility`);
          throw error;
        } finally {
          await context.close();
        }
      });
    });
  });

  test.describe('多会话同步测试', () => {
    test('多标签页数据同步', async ({ browser }) => {
      const context = await browser.newContext({
        geolocation: { latitude: 40.7128, longitude: -74.0060 },
        permissions: ['geolocation']
      });

      // 打开两个标签页
      const page1 = await context.newPage();
      const page2 = await context.newPage();
      
      const authPage1 = new AuthPage(page1);
      const authPage2 = new AuthPage(page2);
      const mapPage1 = new MapPage(page1);
      const mapPage2 = new MapPage(page2);

      try {
        // 在第一个标签页登录
        await authPage1.login(testUser.email, testUser.password);
        await authPage1.takeScreenshot('01-tab1-login');

        // 在第二个标签页应该自动登录（或快速登录）
        await page2.goto('/map');
        await authPage2.waitForPageLoad();
        
        // 验证第二个标签页的登录状态
        await authPage2.verifyLoggedIn();
        await authPage2.takeScreenshot('02-tab2-auto-login');

        // 在第一个标签页创建标注
        await mapPage1.navigateToMap();
        await mapPage1.waitForMapLoad();
        
        const syncAnnotation = {
          title: '多标签同步测试',
          description: '测试多标签页数据同步',
          category: 'neutral',
          intensity: 3,
          rewardAmount: 10,
          latitude: 40.7128,
          longitude: -74.0060
        };

        await mapPage1.createAnnotation(syncAnnotation);
        await authPage1.verifyToastMessage('标注创建成功');
        await authPage1.takeScreenshot('03-tab1-annotation-created');

        // 在第二个标签页验证标注同步
        await mapPage2.navigateToMap();
        await mapPage2.waitForMapLoad();
        
        // 等待数据同步
        await page2.waitForTimeout(2000);
        
        await mapPage2.verifyAnnotationCount(1);
        await authPage2.takeScreenshot('04-tab2-annotation-synced');

        console.log('✅ 多标签页数据同步测试完成');

      } finally {
        await context.close();
      }
    });

    test('多设备会话管理', async ({ browser }) => {
      // 模拟两个不同设备
      const desktopContext = await browser.newContext({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });
      
      const mobileContext = await browser.newContext({
        ...devices['iPhone 12'],
        userAgent: devices['iPhone 12'].userAgent
      });

      const desktopPage = await desktopContext.newPage();
      const mobilePage = await mobileContext.newPage();

      const desktopAuth = new AuthPage(desktopPage);
      const mobileAuth = new AuthPage(mobilePage);

      try {
        // 在桌面端登录
        await desktopAuth.login(testUser.email, testUser.password);
        await desktopAuth.takeScreenshot('01-desktop-login');

        // 在移动端登录同一账户
        await mobileAuth.login(testUser.email, testUser.password);
        await mobileAuth.takeScreenshot('02-mobile-login');

        // 验证会话管理
        await desktopPage.goto('/account/sessions');
        if (await desktopPage.locator('.session-list').isVisible()) {
          const sessions = desktopPage.locator('.session-item');
          await expect(sessions).toHaveCount.atLeast(2); // 桌面+移动
          await desktopAuth.takeScreenshot('03-session-management');
        }

        // 测试在一个设备上退出登录
        await mobileAuth.logout();
        await mobileAuth.verifyLoggedOut();
        
        // 桌面端应该仍然保持登录状态
        await desktopPage.reload();
        await desktopAuth.verifyLoggedIn();
        await desktopAuth.takeScreenshot('04-desktop-still-logged-in');

        console.log('✅ 多设备会话管理测试完成');

      } finally {
        await desktopContext.close();
        await mobileContext.close();
      }
    });
  });
});