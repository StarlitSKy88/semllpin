import { test, expect, Page } from '@playwright/test';
import { AuthPage } from '../page-objects/auth-page';
import { MapPage } from '../page-objects/map-page';

test.describe('新用户注册流程测试', () => {
  let authPage: AuthPage;
  let mapPage: MapPage;
  let page: Page;

  test.beforeEach(async ({ page: testPage, context }) => {
    page = testPage;
    authPage = new AuthPage(page);
    mapPage = new MapPage(page);
    
    // 授予地理位置权限
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 }); // 北京
  });

  test('完整新用户注册流程 - 从首页到首次标注创建', async () => {
    const testData = {
      username: `newuser_${Date.now()}`,
      email: `newuser_${Date.now()}@example.com`,
      password: 'NewUser123!',
    };

    // 测试步骤记录
    const testSteps: string[] = [];
    const startTime = Date.now();

    try {
      // 1. 访问首页
      testSteps.push('访问首页');
      await page.goto('/');
      await authPage.waitForPageLoad();
      await authPage.takeScreenshot('01-homepage');

      // 2. 点击注册链接
      testSteps.push('导航到注册页面');
      await authPage.navigateToRegister();
      await authPage.verifyPageTitle(/注册|Register/);
      await authPage.takeScreenshot('02-register-page');

      // 3. 填写注册信息
      testSteps.push('填写注册表单');
      await authPage.register({
        username: testData.username,
        email: testData.email,
        password: testData.password,
        confirmPassword: testData.password
      });

      // 4. 验证注册成功
      testSteps.push('验证注册成功');
      await authPage.verifyRegistrationSuccess();
      await authPage.takeScreenshot('03-registration-success');

      // 5. 处理邮箱验证（如果需要）
      if (page.url().includes('/verify')) {
        testSteps.push('邮箱验证');
        await authPage.verifyEmail('123456'); // 测试环境验证码
        await authPage.takeScreenshot('04-email-verified');
      }

      // 6. 验证自动登录状态
      testSteps.push('验证登录状态');
      await authPage.verifyLoggedIn();

      // 7. 进入地图页面（新手引导）
      testSteps.push('进入地图页面');
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
      await authPage.takeScreenshot('05-map-page');

      // 8. 获取当前位置
      testSteps.push('获取用户位置');
      await mapPage.getCurrentLocation();
      await authPage.takeScreenshot('06-user-location');

      // 9. 创建首次标注（新手引导）
      testSteps.push('创建首次标注');
      const firstAnnotation = {
        title: '我的第一个标注',
        description: '这是我在SmellPin上创建的第一个气味标注',
        category: 'pleasant',
        intensity: 3,
        rewardAmount: 10,
        latitude: 39.9042,
        longitude: 116.4074
      };

      await mapPage.createAnnotation(firstAnnotation);
      await authPage.takeScreenshot('07-first-annotation-created');

      // 10. 验证标注创建成功
      testSteps.push('验证标注创建成功');
      await authPage.verifyToastMessage('标注创建成功');
      await mapPage.verifyAnnotationCount(1);

      // 11. 点击查看自己的标注
      testSteps.push('查看标注详情');
      await mapPage.clickAnnotationMarker(0);
      await mapPage.verifyAnnotationDetails({
        title: firstAnnotation.title,
        description: firstAnnotation.description
      });
      await authPage.takeScreenshot('08-annotation-details');

      // 记录成功完成的步骤
      const duration = Date.now() - startTime;
      console.log(`✅ 新用户注册流程完成，耗时: ${duration}ms`);
      console.log(`完成步骤: ${testSteps.join(' → ')}`);

    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ 新用户注册流程失败，耗时: ${duration}ms`);
      console.error(`失败步骤: ${testSteps[testSteps.length - 1]}`);
      console.error(`完成步骤: ${testSteps.slice(0, -1).join(' → ')}`);
      
      await authPage.takeScreenshot('error-screenshot');
      throw error;
    }
  });

  test('新用户注册 - 输入验证测试', async () => {
    // 测试各种无效输入
    const invalidCases = [
      {
        name: '空用户名',
        data: { username: '', email: 'test@example.com', password: 'Test123!' },
        expectedError: '用户名'
      },
      {
        name: '无效邮箱',
        data: { username: 'testuser', email: 'invalid-email', password: 'Test123!' },
        expectedError: '邮箱'
      },
      {
        name: '弱密码',
        data: { username: 'testuser', email: 'test@example.com', password: '123' },
        expectedError: '密码'
      },
      {
        name: '密码不匹配',
        data: { 
          username: 'testuser', 
          email: 'test@example.com', 
          password: 'Test123!',
          confirmPassword: 'Different123!'
        },
        expectedError: '密码不一致'
      }
    ];

    for (const testCase of invalidCases) {
      await authPage.navigateToRegister();
      
      await authPage.register({
        username: testCase.data.username,
        email: testCase.data.email,
        password: testCase.data.password,
        confirmPassword: testCase.data.confirmPassword || testCase.data.password
      });

      // 验证错误消息
      await authPage.verifyLoginError();
      await authPage.takeScreenshot(`validation-error-${testCase.name.replace(/\s+/g, '-')}`);
    }
  });

  test('新用户注册 - 重复邮箱测试', async () => {
    const existingEmail = 'existing@example.com';
    
    // 第一次注册
    await authPage.navigateToRegister();
    await authPage.register({
      username: 'firstuser',
      email: existingEmail,
      password: 'Test123!'
    });

    // 处理验证（如果需要）
    if (page.url().includes('/verify')) {
      await authPage.verifyEmail('123456');
    }

    // 退出登录
    if (await page.locator('[data-testid="user-menu"]').isVisible()) {
      await authPage.logout();
    }

    // 尝试用相同邮箱再次注册
    await authPage.navigateToRegister();
    await authPage.register({
      username: 'seconduser',
      email: existingEmail, // 重复邮箱
      password: 'Test123!'
    });

    // 验证重复邮箱错误
    await authPage.verifyLoginError('邮箱已存在');
    await authPage.takeScreenshot('duplicate-email-error');
  });

  test('新用户注册流程 - 网络异常情况', async () => {
    const testData = {
      username: `slowuser_${Date.now()}`,
      email: `slowuser_${Date.now()}@example.com`,
      password: 'SlowUser123!',
    };

    // 模拟慢网络
    await authPage.simulateSlowNetwork();

    await authPage.navigateToRegister();
    
    // 开始注册
    const startTime = Date.now();
    await authPage.register({
      username: testData.username,
      email: testData.email,
      password: testData.password,
      confirmPassword: testData.password
    });

    // 验证在慢网络下仍能成功注册
    await authPage.verifyRegistrationSuccess();
    
    const duration = Date.now() - startTime;
    console.log(`慢网络注册耗时: ${duration}ms`);
    
    // 验证注册时间在合理范围内（考虑到网络延迟）
    expect(duration).toBeLessThan(30000); // 30秒内完成
    
    await authPage.takeScreenshot('slow-network-registration');
  });

  test('新用户首次奖励发现体验', async () => {
    // 先创建一个测试用户和标注
    const userData = await authPage.createAndLoginTestUser();
    
    // 进入地图
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 创建一个标注
    const annotation = {
      title: '测试奖励标注',
      description: '用于测试首次奖励发现的标注',
      category: 'unpleasant',
      intensity: 4,
      rewardAmount: 20,
      latitude: 39.9042,
      longitude: 116.4074
    };

    await mapPage.createAnnotation(annotation);
    await authPage.logout();

    // 注册新用户
    const newUser = await authPage.createAndLoginTestUser();
    
    // 进入地图
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 获取位置权限
    await mapPage.getCurrentLocation();

    // 模拟移动到标注位置触发发现
    await mapPage.enterGeofence(39.9042, 116.4074);

    // 验证奖励发现
    await mapPage.verifyRewardDiscovery(20);
    await authPage.takeScreenshot('first-reward-discovery');

    // 领取奖励
    await mapPage.claimReward();
    await authPage.takeScreenshot('reward-claimed');
  });
});