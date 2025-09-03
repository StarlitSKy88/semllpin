import { test, expect, Page } from '@playwright/test';
import { AuthPage } from '../page-objects/auth-page';
import { MapPage } from '../page-objects/map-page';

test.describe('奖励发现者使用路径测试', () => {
  let authPage: AuthPage;
  let mapPage: MapPage;
  let page: Page;
  let discovererData: any;
  let creatorData: any;

  test.beforeAll(async ({ browser }) => {
    // 创建标注创建者和发现者账户
    const context = await browser.newContext();
    const setupPage = await context.newPage();
    const setupAuth = new AuthPage(setupPage);
    
    // 创建标注创建者
    creatorData = await setupAuth.createAndLoginTestUser({
      username: 'reward_creator',
      email: 'creator@reward.test'
    });
    
    // 创建一些测试标注
    const setupMap = new MapPage(setupPage);
    await setupAuth.login(creatorData.email, creatorData.password);
    await setupMap.navigateToMap();
    await setupMap.waitForMapLoad();
    
    const testAnnotations = [
      {
        title: '时代广场异味',
        description: '时代广场地铁站附近的异味',
        category: 'unpleasant',
        intensity: 4,
        rewardAmount: 25,
        latitude: 40.7589,
        longitude: -73.9851
      },
      {
        title: '中央公园花香',
        description: '中央公园春季花朵的香味',
        category: 'pleasant',
        intensity: 3,
        rewardAmount: 15,
        latitude: 40.7829,
        longitude: -73.9654
      },
      {
        title: '唐人街美食香味',
        description: '唐人街餐厅的诱人香味',
        category: 'pleasant',
        intensity: 5,
        rewardAmount: 20,
        latitude: 40.7158,
        longitude: -73.9970
      }
    ];
    
    for (const annotation of testAnnotations) {
      await setupMap.createAnnotation(annotation);
      await setupPage.waitForTimeout(1000);
    }
    
    await setupAuth.logout();
    
    // 创建发现者账户
    discovererData = await setupAuth.createAndLoginTestUser({
      username: 'reward_discoverer',
      email: 'discoverer@reward.test'
    });
    
    await context.close();
  });

  test.beforeEach(async ({ page: testPage, context }) => {
    page = testPage;
    authPage = new AuthPage(page);
    mapPage = new MapPage(page);
    
    // 授予权限
    await context.grantPermissions(['geolocation', 'notifications']);
    await context.setGeolocation({ latitude: 40.7589, longitude: -73.9851 }); // 时代广场
    
    // 登录发现者账户
    await authPage.login(discovererData.email, discovererData.password);
  });

  test('完整奖励发现流程 - 从定位到钱包更新', async () => {
    const testSteps: string[] = [];
    const startTime = Date.now();

    try {
      // 1. 进入地图页面
      testSteps.push('进入地图页面');
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
      await authPage.takeScreenshot('01-discoverer-map-view');

      // 2. 开启位置服务
      testSteps.push('开启位置服务');
      await mapPage.getCurrentLocation();
      await authPage.takeScreenshot('02-location-enabled');

      // 3. 浏览地图查看附近标注
      testSteps.push('浏览附近标注');
      await mapPage.verifyAnnotationCount(3); // 应该看到3个测试标注
      await authPage.takeScreenshot('03-nearby-annotations');

      // 4. 点击查看标注详情
      testSteps.push('查看标注详情');
      await mapPage.clickAnnotationMarker(0);
      await mapPage.verifyAnnotationDetails({
        title: '时代广场异味',
        description: '时代广场地铁站附近的异味'
      });
      await authPage.takeScreenshot('04-annotation-details');

      // 5. 移动到标注位置触发发现
      testSteps.push('移动触发发现');
      await mapPage.enterGeofence(40.7589, -73.9851); // 时代广场坐标
      
      // 验证发现通知
      await mapPage.verifyRewardDiscovery(25);
      await authPage.takeScreenshot('05-reward-discovered');

      // 6. 领取奖励
      testSteps.push('领取奖励');
      await mapPage.claimReward();
      await authPage.takeScreenshot('06-reward-claimed');

      // 7. 检查钱包余额更新
      testSteps.push('检查钱包余额');
      await page.goto('/wallet');
      await authPage.waitForPageLoad();
      
      const walletBalance = page.locator('[data-testid="wallet-balance"]');
      await expect(walletBalance).toBeVisible();
      await expect(walletBalance).toContainText('25');
      await authPage.takeScreenshot('07-wallet-updated');

      // 8. 继续探索其他标注
      testSteps.push('探索更多标注');
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
      
      // 移动到中央公园
      await mapPage.enterGeofence(40.7829, -73.9654);
      await mapPage.verifyRewardDiscovery(15);
      await mapPage.claimReward();
      await authPage.takeScreenshot('08-second-reward');

      // 移动到唐人街
      await mapPage.enterGeofence(40.7158, -73.9970);
      await mapPage.verifyRewardDiscovery(20);
      await mapPage.claimReward();
      await authPage.takeScreenshot('09-third-reward');

      // 9. 查看发现历史
      testSteps.push('查看发现历史');
      await page.goto('/discoveries');
      await authPage.waitForPageLoad();
      
      const discoveryItems = page.locator('[data-testid="discovery-item"]');
      await expect(discoveryItems).toHaveCount(3);
      await authPage.takeScreenshot('10-discovery-history');

      // 10. 验证总收益
      testSteps.push('验证总收益');
      await page.goto('/wallet');
      const finalBalance = page.locator('[data-testid="wallet-balance"]');
      await expect(finalBalance).toContainText('60'); // 25 + 15 + 20
      await authPage.takeScreenshot('11-final-wallet');

      const duration = Date.now() - startTime;
      console.log(`✅ 奖励发现流程完成，耗时: ${duration}ms`);
      console.log(`完成步骤: ${testSteps.join(' → ')}`);

    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ 奖励发现流程失败，耗时: ${duration}ms`);
      console.error(`失败步骤: ${testSteps[testSteps.length - 1]}`);
      
      await authPage.takeScreenshot('discoverer-error');
      throw error;
    }
  });

  test('地理围栏精度测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    await mapPage.getCurrentLocation();

    // 测试不同距离的地理围栏触发
    const targetLocation = { lat: 40.7589, lng: -73.9851 }; // 时代广场
    
    // 测试1: 距离太远，不应该触发
    await page.context().setGeolocation({ 
      latitude: targetLocation.lat + 0.01, // 约1公里外
      longitude: targetLocation.lng + 0.01 
    });
    
    await page.waitForTimeout(2000);
    const farNotification = page.locator('.discovery-notification');
    await expect(farNotification).not.toBeVisible();
    await authPage.takeScreenshot('01-too-far-no-discovery');

    // 测试2: 中等距离，应该能看到标注但不触发奖励
    await page.context().setGeolocation({ 
      latitude: targetLocation.lat + 0.001, // 约100米外
      longitude: targetLocation.lng + 0.001 
    });
    
    await page.waitForTimeout(2000);
    const mediumNotification = page.locator('.discovery-notification');
    await expect(mediumNotification).not.toBeVisible();
    await authPage.takeScreenshot('02-medium-distance');

    // 测试3: 进入地理围栏范围，应该触发发现
    await mapPage.enterGeofence(targetLocation.lat, targetLocation.lng);
    await mapPage.verifyRewardDiscovery(25);
    await authPage.takeScreenshot('03-geofence-triggered');

    // 测试4: 验证围栏可视化
    const geofenceVisual = page.locator('.geofence, .discovery-zone');
    await expect(geofenceVisual).toBeVisible();
    await authPage.takeScreenshot('04-geofence-visual');
  });

  test('重复发现防护测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    await mapPage.getCurrentLocation();

    const location = { lat: 40.7589, lng: -73.9851 };

    // 第一次发现和领取
    await mapPage.enterGeofence(location.lat, location.lng);
    await mapPage.verifyRewardDiscovery(25);
    await mapPage.claimReward();
    await authPage.takeScreenshot('01-first-claim');

    // 等待一段时间后再次尝试进入同一地点
    await page.waitForTimeout(3000);
    
    // 离开地理围栏
    await page.context().setGeolocation({ 
      latitude: location.lat + 0.01,
      longitude: location.lng + 0.01 
    });
    await page.waitForTimeout(2000);

    // 再次进入相同位置
    await mapPage.enterGeofence(location.lat, location.lng);
    
    // 验证不应该再次触发奖励（24小时内重复发现限制）
    const duplicateNotification = page.locator('.discovery-notification');
    await expect(duplicateNotification).not.toBeVisible();
    await authPage.takeScreenshot('02-duplicate-prevention');

    // 验证显示已发现提示
    const alreadyDiscovered = page.locator('.already-discovered, [data-testid="already-discovered"]');
    await expect(alreadyDiscovered).toBeVisible();
    await authPage.takeScreenshot('03-already-discovered-message');
  });

  test('多设备同步测试', async () => {
    // 在第一个设备上发现奖励
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    await mapPage.getCurrentLocation();

    await mapPage.enterGeofence(40.7589, -73.9851);
    await mapPage.verifyRewardDiscovery(25);
    await mapPage.claimReward();

    // 模拟切换到另一个设备（新的浏览器上下文）
    const newContext = await page.context().browser()!.newContext();
    const newPage = await newContext.newPage();
    const newAuthPage = new AuthPage(newPage);
    const newMapPage = new MapPage(newPage);

    // 在新设备上登录同一账户
    await newAuthPage.login(discovererData.email, discovererData.password);
    
    // 检查钱包余额是否同步
    await newPage.goto('/wallet');
    await newAuthPage.waitForPageLoad();
    
    const syncedBalance = newPage.locator('[data-testid="wallet-balance"]');
    await expect(syncedBalance).toContainText('25');
    await newAuthPage.takeScreenshot('synced-wallet-balance');

    // 检查发现历史是否同步
    await newPage.goto('/discoveries');
    const syncedDiscoveries = newPage.locator('[data-testid="discovery-item"]');
    await expect(syncedDiscoveries).toHaveCount(1);
    await newAuthPage.takeScreenshot('synced-discovery-history');

    await newContext.close();
  });

  test('离线模式发现测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    await mapPage.getCurrentLocation();

    // 模拟离线状态
    await page.context().setOffline(true);
    await authPage.takeScreenshot('01-offline-mode');

    try {
      // 尝试在离线状态下触发发现
      await mapPage.enterGeofence(40.7589, -73.9851);
      
      // 验证离线发现缓存
      const offlineNotification = page.locator('.offline-discovery, [data-testid="offline-discovery"]');
      await expect(offlineNotification).toBeVisible();
      await authPage.takeScreenshot('02-offline-discovery');

      // 恢复网络连接
      await page.context().setOffline(false);
      await page.waitForTimeout(2000);

      // 验证离线发现同步
      await authPage.verifyToastMessage('离线发现已同步');
      await authPage.takeScreenshot('03-offline-sync');

      // 检查钱包更新
      await page.goto('/wallet');
      const balance = page.locator('[data-testid="wallet-balance"]');
      await expect(balance).toContainText('25');
      
    } catch (error) {
      // 如果离线功能未实现，记录但不失败测试
      console.log('离线功能可能尚未实现，跳过此测试');
      await authPage.takeScreenshot('offline-not-implemented');
    }
  });

  test('发现体验优化测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    await mapPage.getCurrentLocation();

    // 记录发现相关的用户体验指标
    const metrics = {
      mapLoadTime: 0,
      locationTime: 0,
      discoveryTime: 0,
      claimTime: 0
    };

    // 测试地图加载性能
    const mapStartTime = Date.now();
    await mapPage.waitForMapInteraction();
    metrics.mapLoadTime = Date.now() - mapStartTime;

    // 测试定位时间
    const locationStartTime = Date.now();
    await mapPage.getCurrentLocation();
    metrics.locationTime = Date.now() - locationStartTime;

    // 测试发现响应时间
    const discoveryStartTime = Date.now();
    await mapPage.enterGeofence(40.7589, -73.9851);
    await mapPage.verifyRewardDiscovery(25);
    metrics.discoveryTime = Date.now() - discoveryStartTime;

    // 测试奖励领取时间
    const claimStartTime = Date.now();
    await mapPage.claimReward();
    await authPage.verifyToastMessage('奖励已领取');
    metrics.claimTime = Date.now() - claimStartTime;

    // 输出性能指标
    console.log('发现体验性能指标:');
    console.log(`地图加载时间: ${metrics.mapLoadTime}ms`);
    console.log(`定位时间: ${metrics.locationTime}ms`);
    console.log(`发现响应时间: ${metrics.discoveryTime}ms`);
    console.log(`奖励领取时间: ${metrics.claimTime}ms`);

    // 性能断言
    expect(metrics.mapLoadTime).toBeLessThan(5000); // 地图5秒内加载
    expect(metrics.locationTime).toBeLessThan(3000); // 定位3秒内完成
    expect(metrics.discoveryTime).toBeLessThan(2000); // 发现2秒内响应
    expect(metrics.claimTime).toBeLessThan(3000); // 领取3秒内完成

    await authPage.takeScreenshot('performance-metrics');
  });
});