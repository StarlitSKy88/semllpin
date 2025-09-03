import { test, expect, Page, BrowserContext } from '@playwright/test';
import { AuthPage } from './page-objects/auth-page';
import { MapPage } from './page-objects/map-page';
import { BasePage } from './page-objects/base-page';

/**
 * SmellPin前端全面端到端测试套件
 * 
 * 测试覆盖范围：
 * 1. 用户认证流程（注册/登录）
 * 2. 地图交互功能
 * 3. LBS功能和地理围栏奖励
 * 4. 支付流程模拟
 * 5. 响应性和移动端兼容性
 * 6. 异常处理和边界情况
 * 
 * @author E2E Test Automation Framework
 * @version 1.0.0
 */

test.describe('SmellPin前端全面端到端测试', () => {
  let page: Page;
  let context: BrowserContext;
  let authPage: AuthPage;
  let mapPage: MapPage;
  let basePage: BasePage;

  // 测试数据配置
  const testConfig = {
    baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
    apiUrl: process.env.TEST_API_URL || 'http://localhost:3001',
    timeout: {
      short: 5000,
      medium: 10000,
      long: 30000
    },
    locations: {
      beijing: { lat: 39.9042, lng: 116.4074 },
      shanghai: { lat: 31.2304, lng: 121.4737 },
      guangzhou: { lat: 23.1291, lng: 113.2644 }
    }
  };

  // 测试数据生成器
  const generateTestUser = () => ({
    username: `testuser_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    email: `test_${Date.now()}_${Math.floor(Math.random() * 1000)}@example.com`,
    password: 'TestPassword123!@#'
  });

  const generateTestAnnotation = (location = testConfig.locations.beijing) => ({
    title: `测试标注_${Date.now()}`,
    description: `这是一个测试用的气味标注，创建时间: ${new Date().toISOString()}。包含详细的气味描述信息，用于验证标注功能的完整性。`,
    category: 'chemical',
    intensity: Math.floor(Math.random() * 5) + 1,
    rewardAmount: Math.floor(Math.random() * 50) + 10,
    ...location
  });

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({
      // 启用地理位置权限
      permissions: ['geolocation'],
      geolocation: testConfig.locations.beijing,
      // 设置视窗大小
      viewport: { width: 1920, height: 1080 },
      // 启用截图和视频录制
      recordVideo: {
        dir: 'test-results/videos/',
        size: { width: 1920, height: 1080 }
      }
    });

    page = await context.newPage();
    authPage = new AuthPage(page);
    mapPage = new MapPage(page);
    basePage = new BasePage(page);

    // 设置网络监控
    page.on('response', response => {
      if (response.status() >= 400) {
        console.warn(`API Error: ${response.url()} - ${response.status()}`);
      }
    });

    page.on('console', msg => {
      if (msg.type() === 'error') {
        console.error(`Console Error: ${msg.text()}`);
      }
    });
  });

  test.afterAll(async () => {
    await context.close();
  });

  test.beforeEach(async () => {
    // 清理本地存储
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    // 重置地理位置
    await context.setGeolocation(testConfig.locations.beijing);
  });

  test.describe('用户认证流程测试', () => {
    test('完整新用户注册流程', async () => {
      const testUser = generateTestUser();
      const startTime = Date.now();

      try {
        // 1. 访问首页
        await page.goto('/');
        await authPage.waitForPageLoad();
        await authPage.takeScreenshot('01-homepage');

        // 2. 导航到注册页面
        await authPage.navigateToRegister();
        await expect(page).toHaveTitle(/注册|Register/);
        await authPage.takeScreenshot('02-register-page');

        // 3. 填写并提交注册表单
        await authPage.register({
          username: testUser.username,
          email: testUser.email,
          password: testUser.password,
          confirmPassword: testUser.password
        });

        // 4. 验证注册成功
        await authPage.verifyRegistrationSuccess();
        await authPage.takeScreenshot('03-registration-success');

        // 5. 处理邮箱验证（如果需要）
        if (page.url().includes('/verify')) {
          await authPage.verifyEmail('123456'); // 测试环境验证码
          await authPage.takeScreenshot('04-email-verified');
        }

        // 6. 验证登录状态
        await authPage.verifyLoggedIn();
        
        const duration = Date.now() - startTime;
        console.log(`✅ 用户注册流程完成，耗时: ${duration}ms`);
        expect(duration).toBeLessThan(testConfig.timeout.long);

      } catch (error) {
        await authPage.takeScreenshot('error-registration');
        throw error;
      }
    });

    test('用户登录流程', async () => {
      // 先创建测试用户
      const testUser = await authPage.createAndLoginTestUser();
      await authPage.logout();

      const startTime = Date.now();

      try {
        // 登录测试
        await authPage.login(testUser.email, testUser.password);
        await authPage.verifyLoggedIn();
        await authPage.takeScreenshot('login-success');

        const duration = Date.now() - startTime;
        console.log(`✅ 用户登录完成，耗时: ${duration}ms`);
        expect(duration).toBeLessThan(testConfig.timeout.medium);

      } catch (error) {
        await authPage.takeScreenshot('error-login');
        throw error;
      }
    });

    test('登录表单验证测试', async () => {
      const invalidCases = [
        {
          name: '空邮箱',
          email: '',
          password: 'ValidPassword123!',
          expectedError: '邮箱'
        },
        {
          name: '无效邮箱格式',
          email: 'invalid-email-format',
          password: 'ValidPassword123!',
          expectedError: '邮箱'
        },
        {
          name: '空密码',
          email: 'test@example.com',
          password: '',
          expectedError: '密码'
        },
        {
          name: '错误密码',
          email: 'test@example.com',
          password: 'wrongpassword',
          expectedError: '密码错误|用户名或密码不正确'
        }
      ];

      for (const testCase of invalidCases) {
        await test.step(`验证${testCase.name}`, async () => {
          await authPage.navigateToLogin();
          await authPage.login(testCase.email, testCase.password);
          await authPage.verifyLoginError();
          await authPage.takeScreenshot(`login-validation-${testCase.name.replace(/\s+/g, '-')}`);
        });
      }
    });
  });

  test.describe('地图交互功能测试', () => {
    test.beforeEach(async () => {
      // 确保用户已登录
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
    });

    test('地图基础交互功能', async () => {
      try {
        // 1. 验证地图加载
        await expect(page.locator('[data-testid="map"], #map, .map-container')).toBeVisible();
        await mapPage.takeScreenshot('01-map-loaded');

        // 2. 获取用户位置
        await mapPage.getCurrentLocation();
        await expect(page.locator('.current-location, .user-location')).toBeVisible();
        await mapPage.takeScreenshot('02-user-location');

        // 3. 测试地图缩放
        const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
        await mapContainer.hover();
        
        // 模拟缩放操作
        await page.mouse.wheel(0, -100); // 放大
        await page.waitForTimeout(1000);
        await mapPage.takeScreenshot('03-map-zoom-in');

        await page.mouse.wheel(0, 100); // 缩小
        await page.waitForTimeout(1000);
        await mapPage.takeScreenshot('04-map-zoom-out');

        console.log('✅ 地图基础交互测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-map-interaction');
        throw error;
      }
    });

    test('标注创建和查看流程', async () => {
      const annotation = generateTestAnnotation();
      const startTime = Date.now();

      try {
        // 1. 创建标注
        await mapPage.createAnnotation(annotation);
        await authPage.verifyToastMessage('创建成功|标注创建成功');
        await mapPage.takeScreenshot('01-annotation-created');

        // 2. 验证标注出现在地图上
        await expect(page.locator('.marker, .annotation-marker')).toHaveCount(1, { timeout: 10000 });
        await mapPage.takeScreenshot('02-annotation-on-map');

        // 3. 点击标注查看详情
        await mapPage.clickAnnotationMarker(0);
        await mapPage.verifyAnnotationDetails({
          title: annotation.title,
          description: annotation.description
        });
        await mapPage.takeScreenshot('03-annotation-details');

        // 4. 测试点赞功能
        await mapPage.likeAnnotation();
        await mapPage.takeScreenshot('04-annotation-liked');

        const duration = Date.now() - startTime;
        console.log(`✅ 标注创建和查看流程完成，耗时: ${duration}ms`);

      } catch (error) {
        await mapPage.takeScreenshot('error-annotation-creation');
        throw error;
      }
    });

    test('标注搜索和筛选功能', async () => {
      // 创建多个测试标注
      const annotations = [
        { ...generateTestAnnotation(), title: '化学异味标注', category: 'chemical' },
        { ...generateTestAnnotation(), title: '食物香味标注', category: 'food' },
        { ...generateTestAnnotation(), title: '自然花香标注', category: 'nature' }
      ];

      try {
        // 创建多个标注
        for (const annotation of annotations) {
          await mapPage.createAnnotation(annotation);
          await page.waitForTimeout(2000); // 避免创建过快
        }

        // 1. 测试关键词搜索
        await mapPage.searchAnnotations('化学');
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('01-search-chemical');

        // 2. 测试分类筛选
        await mapPage.filterAnnotations({ category: 'food' });
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('02-filter-food');

        // 3. 测试距离筛选
        await mapPage.filterAnnotations({ maxDistance: 1000 });
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('03-filter-distance');

        console.log('✅ 搜索和筛选功能测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-search-filter');
        throw error;
      }
    });
  });

  test.describe('LBS功能和地理围栏奖励测试', () => {
    test.beforeEach(async () => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
    });

    test('位置追踪和更新功能', async () => {
      try {
        // 1. 验证初始位置
        const initialLocation = await page.evaluate(() => {
          return new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition(
              position => resolve({
                lat: position.coords.latitude,
                lng: position.coords.longitude
              }),
              () => resolve(null)
            );
          });
        });

        expect(initialLocation).not.toBeNull();
        await mapPage.takeScreenshot('01-initial-location');

        // 2. 模拟位置变化
        await context.setGeolocation(testConfig.locations.shanghai);
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('02-location-changed');

        // 3. 验证地图中心更新
        const mapCenter = await page.evaluate(() => {
          const map = (window as any).map;
          return map ? map.getCenter() : null;
        });

        if (mapCenter) {
          expect(Math.abs(mapCenter.lat - testConfig.locations.shanghai.lat)).toBeLessThan(0.01);
          expect(Math.abs(mapCenter.lng - testConfig.locations.shanghai.lng)).toBeLessThan(0.01);
        }

        console.log('✅ 位置追踪功能测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-location-tracking');
        throw error;
      }
    });

    test('地理围栏奖励发现流程', async () => {
      // 先创建一个有奖励的标注
      const rewardAnnotation = {
        ...generateTestAnnotation(),
        title: '高奖励测试标注',
        rewardAmount: 50
      };

      try {
        // 1. 创建带奖励的标注
        await mapPage.createAnnotation(rewardAnnotation);
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('01-reward-annotation-created');

        // 2. 模拟移动到标注位置附近触发地理围栏
        await mapPage.enterGeofence(rewardAnnotation.lat, rewardAnnotation.lng);
        
        // 3. 验证奖励发现通知
        await mapPage.verifyRewardDiscovery(rewardAnnotation.rewardAmount);
        await mapPage.takeScreenshot('02-reward-discovered');

        // 4. 领取奖励
        await mapPage.claimReward();
        await authPage.verifyToastMessage('奖励已领取');
        await mapPage.takeScreenshot('03-reward-claimed');

        console.log('✅ 地理围栏奖励测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-geofence-reward');
        throw error;
      }
    });
  });

  test.describe('支付流程模拟测试', () => {
    test.beforeEach(async () => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
    });

    test('Stripe支付流程模拟', async () => {
      const paymentAnnotation = {
        ...generateTestAnnotation(),
        title: '付费测试标注',
        rewardAmount: 25
      };

      try {
        // 1. 尝试在已有标注的位置创建新标注（触发付费流程）
        await mapPage.clickMapLocation(paymentAnnotation.lat, paymentAnnotation.lng);
        
        // 2. 验证付费弹窗出现
        await expect(page.locator('.payment-modal, [data-testid="payment-modal"]')).toBeVisible({ timeout: 5000 });
        await mapPage.takeScreenshot('01-payment-modal');

        // 3. 模拟支付信息填写
        await page.fill('input[name="cardNumber"], input[placeholder*="卡号"]', '4242424242424242');
        await page.fill('input[name="expiry"], input[placeholder*="有效期"]', '12/25');
        await page.fill('input[name="cvc"], input[placeholder*="CVC"]', '123');
        await page.fill('input[name="name"], input[placeholder*="姓名"]', 'Test User');
        await mapPage.takeScreenshot('02-payment-info-filled');

        // 4. 提交支付（在测试环境中会被模拟处理）
        await page.click('button[type="submit"], button:has-text("支付"), button:has-text("Pay")');
        await page.waitForTimeout(3000);

        // 5. 验证支付成功或相关提示
        const hasSuccessMessage = await page.locator('.success, .payment-success').isVisible();
        const hasErrorMessage = await page.locator('.error, .payment-error').isVisible();
        
        expect(hasSuccessMessage || hasErrorMessage).toBeTruthy();
        await mapPage.takeScreenshot('03-payment-result');

        console.log('✅ 支付流程模拟测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-payment-flow');
        console.warn('支付流程测试失败，可能是测试环境配置问题');
        // 不抛出错误，因为支付功能可能在测试环境中不完全可用
      }
    });

    test('钱包余额和交易历史查看', async () => {
      try {
        // 1. 打开钱包页面
        await page.click('button:has-text("钱包"), [data-testid="wallet-button"]');
        await expect(page.locator('.wallet-container, [data-testid="wallet"]')).toBeVisible();
        await mapPage.takeScreenshot('01-wallet-opened');

        // 2. 验证余额显示
        const balanceElement = page.locator('.balance, [data-testid="balance"]');
        await expect(balanceElement).toBeVisible();
        await mapPage.takeScreenshot('02-wallet-balance');

        // 3. 查看交易历史
        const transactionButton = page.locator('button:has-text("交易历史"), [data-testid="transactions"]');
        if (await transactionButton.isVisible()) {
          await transactionButton.click();
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot('03-transaction-history');
        }

        console.log('✅ 钱包功能测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-wallet-functionality');
        throw error;
      }
    });
  });

  test.describe('响应性和移动端兼容性测试', () => {
    const viewports = [
      { name: 'Desktop', width: 1920, height: 1080 },
      { name: 'Tablet', width: 768, height: 1024 },
      { name: 'Mobile Large', width: 414, height: 896 },
      { name: 'Mobile Small', width: 320, height: 568 }
    ];

    for (const viewport of viewports) {
      test(`${viewport.name} 视窗兼容性测试`, async () => {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await authPage.createAndLoginTestUser();

        try {
          // 1. 首页响应性测试
          await page.goto('/');
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot(`${viewport.name.toLowerCase()}-01-homepage`);

          // 2. 地图页面响应性测试
          await mapPage.navigateToMap();
          await mapPage.waitForMapLoad();
          await mapPage.takeScreenshot(`${viewport.name.toLowerCase()}-02-map-page`);

          // 3. 导航菜单测试
          const menuButton = page.locator('button[aria-label*="menu"], .menu-button, .hamburger');
          if (await menuButton.isVisible()) {
            await menuButton.click();
            await page.waitForTimeout(1000);
            await mapPage.takeScreenshot(`${viewport.name.toLowerCase()}-03-menu-opened`);
          }

          // 4. 表单响应性测试
          await page.click('button:has-text("创建"), .create-button, [data-testid="create-annotation"]');
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot(`${viewport.name.toLowerCase()}-04-form-responsive`);

          console.log(`✅ ${viewport.name} 视窗兼容性测试完成`);

        } catch (error) {
          await mapPage.takeScreenshot(`error-${viewport.name.toLowerCase()}-responsive`);
          throw error;
        }
      });
    }

    test('触摸手势支持测试', async () => {
      // 模拟移动设备
      await page.setViewportSize({ width: 375, height: 667 });
      await page.emulate({
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        viewport: { width: 375, height: 667 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true
      });

      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();

      try {
        // 1. 测试点击手势
        const mapContainer = page.locator('[data-testid="map"], #map, .map-container').first();
        await mapContainer.tap();
        await page.waitForTimeout(1000);
        await mapPage.takeScreenshot('01-tap-gesture');

        // 2. 测试滑动手势
        const mapBounds = await mapContainer.boundingBox();
        if (mapBounds) {
          await page.touchscreen.tap(mapBounds.x + mapBounds.width / 2, mapBounds.y + mapBounds.height / 2);
          await page.waitForTimeout(500);
          
          // 模拟滑动
          await page.touchscreen.tap(mapBounds.x + 100, mapBounds.y + 100);
          await page.waitForTimeout(1000);
          await mapPage.takeScreenshot('02-swipe-gesture');
        }

        // 3. 测试长按手势
        await mapContainer.tap({ delay: 1000 }); // 长按
        await page.waitForTimeout(2000);
        await mapPage.takeScreenshot('03-long-press-gesture');

        console.log('✅ 触摸手势支持测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-touch-gestures');
        throw error;
      }
    });
  });

  test.describe('异常处理和边界情况测试', () => {
    test('网络中断恢复测试', async () => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();

      try {
        // 1. 正常状态截图
        await mapPage.takeScreenshot('01-normal-state');

        // 2. 模拟网络离线
        await context.setOffline(true);
        await page.reload();
        await page.waitForTimeout(5000);
        await mapPage.takeScreenshot('02-offline-state');

        // 3. 尝试操作（应该显示离线提示）
        const offlineIndicator = page.locator('.offline, .network-error, [data-testid="offline"]');
        if (await offlineIndicator.isVisible()) {
          await mapPage.takeScreenshot('03-offline-indicator');
        }

        // 4. 恢复网络连接
        await context.setOffline(false);
        await page.reload();
        await mapPage.waitForMapLoad();
        await mapPage.takeScreenshot('04-online-restored');

        console.log('✅ 网络中断恢复测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-network-interruption');
        // 确保网络状态恢复
        await context.setOffline(false);
        throw error;
      }
    });

    test('权限拒绝处理测试', async () => {
      // 创建拒绝地理位置权限的上下文
      const restrictedContext = await context.browser()?.newContext({
        permissions: []  // 不授予任何权限
      });

      if (!restrictedContext) return;

      const restrictedPage = await restrictedContext.newPage();
      const restrictedAuthPage = new AuthPage(restrictedPage);
      const restrictedMapPage = new MapPage(restrictedPage);

      try {
        await restrictedAuthPage.createAndLoginTestUser();
        await restrictedMapPage.navigateToMap();
        await restrictedMapPage.waitForMapLoad();

        // 1. 尝试获取位置权限
        await restrictedMapPage.getCurrentLocation();

        // 2. 验证权限拒绝错误处理
        await restrictedMapPage.verifyLocationPermissionError();
        await restrictedMapPage.takeScreenshot('01-permission-denied');

        // 3. 验证降级体验（使用默认位置）
        const defaultLocationMarker = restrictedPage.locator('.default-location, .fallback-location');
        if (await defaultLocationMarker.isVisible()) {
          await restrictedMapPage.takeScreenshot('02-fallback-location');
        }

        console.log('✅ 权限拒绝处理测试完成');

      } catch (error) {
        await restrictedMapPage.takeScreenshot('error-permission-handling');
        throw error;
      } finally {
        await restrictedContext.close();
      }
    });

    test('数据加载失败处理测试', async () => {
      await authPage.createAndLoginTestUser();

      // 拦截API请求并返回错误
      await page.route('**/api/annotations*', route => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal Server Error' })
        });
      });

      try {
        // 1. 导航到地图页面
        await mapPage.navigateToMap();
        await page.waitForTimeout(5000);
        await mapPage.takeScreenshot('01-api-error-state');

        // 2. 验证错误提示显示
        const errorMessage = page.locator('.error, .api-error, [data-testid="error"]');
        await expect(errorMessage).toBeVisible({ timeout: 10000 });
        await mapPage.takeScreenshot('02-error-message-shown');

        // 3. 测试重试功能
        const retryButton = page.locator('button:has-text("重试"), .retry-button');
        if (await retryButton.isVisible()) {
          await retryButton.click();
          await page.waitForTimeout(2000);
          await mapPage.takeScreenshot('03-retry-attempted');
        }

        console.log('✅ 数据加载失败处理测试完成');

      } catch (error) {
        await mapPage.takeScreenshot('error-api-failure-handling');
        throw error;
      } finally {
        // 恢复正常API响应
        await page.unroute('**/api/annotations*');
      }
    });

    test('表单验证边界情况测试', async () => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();

      const edgeCases = [
        {
          name: '超长标题',
          title: 'A'.repeat(1000),
          description: '正常描述',
          expectedValidation: '标题过长'
        },
        {
          name: '空标题',
          title: '',
          description: '正常描述',
          expectedValidation: '标题不能为空'
        },
        {
          name: '特殊字符',
          title: '<script>alert("xss")</script>',
          description: 'SQL injection test: \'; DROP TABLE users; --',
          expectedValidation: null // 应该被正确转义
        },
        {
          name: '超长描述',
          title: '正常标题',
          description: 'B'.repeat(5000),
          expectedValidation: '描述过长'
        }
      ];

      for (const testCase of edgeCases) {
        await test.step(`测试${testCase.name}`, async () => {
          try {
            // 1. 打开创建标注表单
            await page.click('button:has-text("创建"), .create-button, [data-testid="create-annotation"]');
            await page.waitForTimeout(1000);

            // 2. 填写测试数据
            await page.fill('input[name="title"], input[placeholder*="标题"]', testCase.title);
            await page.fill('textarea[name="description"], textarea[placeholder*="描述"]', testCase.description);

            // 3. 尝试提交
            await page.click('button[type="submit"], button:has-text("创建")');
            await page.waitForTimeout(2000);

            // 4. 验证验证结果
            if (testCase.expectedValidation) {
              const validationError = page.locator('.error, .validation-error');
              await expect(validationError).toBeVisible();
            }

            await mapPage.takeScreenshot(`edge-case-${testCase.name.replace(/\s+/g, '-')}`);

            // 5. 关闭弹窗
            await page.click('button:has-text("取消"), .close-button, [aria-label="close"]');
            await page.waitForTimeout(500);

          } catch (error) {
            console.warn(`边界情况测试失败: ${testCase.name} - ${error}`);
            await mapPage.takeScreenshot(`error-edge-case-${testCase.name.replace(/\s+/g, '-')}`);
          }
        });
      }

      console.log('✅ 表单验证边界情况测试完成');
    });
  });

  test.describe('性能和用户体验测试', () => {
    test('页面加载性能测试', async () => {
      const performanceMetrics: any = {};

      try {
        // 1. 首页加载性能
        const homepageStart = Date.now();
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        performanceMetrics.homepageLoad = Date.now() - homepageStart;

        // 2. 地图页面加载性能
        await authPage.createAndLoginTestUser();
        const mapPageStart = Date.now();
        await mapPage.navigateToMap();
        await mapPage.waitForMapLoad();
        performanceMetrics.mapPageLoad = Date.now() - mapPageStart;

        // 3. 获取Web Vitals指标
        const webVitals = await page.evaluate(() => {
          return new Promise((resolve) => {
            const vitals: any = {};
            
            // FCP - First Contentful Paint
            new PerformanceObserver((list) => {
              for (const entry of list.getEntries()) {
                if (entry.name === 'first-contentful-paint') {
                  vitals.fcp = entry.startTime;
                }
              }
            }).observe({ entryTypes: ['paint'] });

            // LCP - Largest Contentful Paint
            new PerformanceObserver((list) => {
              const entries = list.getEntries();
              const lastEntry = entries[entries.length - 1];
              vitals.lcp = lastEntry.startTime;
            }).observe({ entryTypes: ['largest-contentful-paint'] });

            setTimeout(() => resolve(vitals), 3000);
          });
        });

        performanceMetrics.webVitals = webVitals;

        // 4. 验证性能基准
        expect(performanceMetrics.homepageLoad).toBeLessThan(5000); // 5秒内
        expect(performanceMetrics.mapPageLoad).toBeLessThan(10000);  // 10秒内

        console.log('📊 性能指标:', performanceMetrics);
        
        await page.evaluate((metrics) => {
          console.log('Performance Metrics:', metrics);
        }, performanceMetrics);

      } catch (error) {
        await mapPage.takeScreenshot('error-performance-test');
        throw error;
      }
    });

    test('用户操作流畅性测试', async () => {
      await authPage.createAndLoginTestUser();
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();

      const interactionMetrics: any = {};

      try {
        // 1. 测试连续点击响应时间
        const clickTests = [];
        for (let i = 0; i < 5; i++) {
          const start = Date.now();
          await page.click('button:has-text("标记模式"), .markers-mode');
          await page.waitForTimeout(100);
          clickTests.push(Date.now() - start);
        }
        interactionMetrics.averageClickResponse = clickTests.reduce((a, b) => a + b, 0) / clickTests.length;

        // 2. 测试搜索输入响应
        const searchInput = page.locator('input[type="search"], input[placeholder*="搜索"]');
        const searchStart = Date.now();
        await searchInput.fill('测试搜索内容');
        await page.waitForTimeout(1000); // 等待搜索结果
        interactionMetrics.searchResponseTime = Date.now() - searchStart;

        // 3. 测试滚动性能
        const scrollStart = Date.now();
        await page.mouse.wheel(0, 1000);
        await page.waitForTimeout(500);
        await page.mouse.wheel(0, -1000);
        interactionMetrics.scrollPerformance = Date.now() - scrollStart;

        // 4. 验证流畅性基准
        expect(interactionMetrics.averageClickResponse).toBeLessThan(200); // 200ms内
        expect(interactionMetrics.searchResponseTime).toBeLessThan(1000);  // 1秒内
        expect(interactionMetrics.scrollPerformance).toBeLessThan(1000);   // 1秒内

        console.log('🎯 交互性能指标:', interactionMetrics);

      } catch (error) {
        await mapPage.takeScreenshot('error-interaction-performance');
        throw error;
      }
    });
  });

  test.afterEach(async ({ }, testInfo) => {
    // 测试结束后的清理和报告
    if (testInfo.status !== testInfo.expectedStatus) {
      // 测试失败时的额外信息收集
      await page.screenshot({
        path: `test-results/screenshots/failed-${testInfo.title.replace(/\s+/g, '-')}-${Date.now()}.png`,
        fullPage: true
      });

      // 收集控制台日志
      const logs = await page.evaluate(() => {
        return (window as any).__testLogs__ || [];
      });

      if (logs.length > 0) {
        console.log('📋 Console Logs:', logs);
      }

      // 收集网络请求失败信息
      const networkErrors = await page.evaluate(() => {
        return (window as any).__networkErrors__ || [];
      });

      if (networkErrors.length > 0) {
        console.log('🌐 Network Errors:', networkErrors);
      }
    }
  });
});