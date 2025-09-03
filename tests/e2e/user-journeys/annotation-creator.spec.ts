import { test, expect, Page } from '@playwright/test';
import { AuthPage } from '../page-objects/auth-page';
import { MapPage } from '../page-objects/map-page';

test.describe('标注创建者使用路径测试', () => {
  let authPage: AuthPage;
  let mapPage: MapPage;
  let page: Page;
  let creatorData: any;

  test.beforeAll(async ({ browser }) => {
    // 创建标注创建者用户
    const context = await browser.newContext();
    const setupPage = await context.newPage();
    const setupAuth = new AuthPage(setupPage);
    
    creatorData = await setupAuth.createAndLoginTestUser({
      username: 'annotation_creator',
      email: 'creator@smellpin.test'
    });

    await context.close();
  });

  test.beforeEach(async ({ page: testPage, context }) => {
    page = testPage;
    authPage = new AuthPage(page);
    mapPage = new MapPage(page);
    
    // 授予权限
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({ latitude: 40.7128, longitude: -74.0060 }); // 纽约
    
    // 登录创建者账户
    await authPage.login(creatorData.email, creatorData.password);
  });

  test('完整标注创建流程 - 从登录到收益查看', async () => {
    const testSteps: string[] = [];
    const startTime = Date.now();

    try {
      // 1. 进入地图页面
      testSteps.push('进入地图页面');
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
      await authPage.takeScreenshot('01-creator-map-view');

      // 2. 获取当前位置
      testSteps.push('获取当前位置');
      await mapPage.getCurrentLocation();
      await authPage.takeScreenshot('02-creator-location');

      // 3. 创建高质量标注（高奖励）
      testSteps.push('创建高质量标注');
      const premiumAnnotation = {
        title: '中央公园异味区域',
        description: '在中央公园东侧发现强烈的工业异味，疑似来自附近的建筑工地。建议相关部门调查处理。',
        category: 'unpleasant',
        intensity: 5,
        rewardAmount: 50,
        latitude: 40.7829,
        longitude: -73.9654,
        mediaFile: './tests/e2e/fixtures/sample-image.jpg'
      };

      await mapPage.createAnnotation(premiumAnnotation);
      await authPage.verifyToastMessage('标注创建成功');
      await authPage.takeScreenshot('03-premium-annotation-created');

      // 4. 创建多个不同类型的标注
      testSteps.push('创建多种类型标注');
      const annotations = [
        {
          title: '咖啡店香味',
          description: '路过的咖啡店传出浓郁的咖啡香味',
          category: 'pleasant',
          intensity: 3,
          rewardAmount: 15,
          latitude: 40.7580,
          longitude: -73.9855
        },
        {
          title: '垃圾处理站异味',
          description: '垃圾处理站周围有刺鼻气味',
          category: 'unpleasant',
          intensity: 4,
          rewardAmount: 25,
          latitude: 40.7305,
          longitude: -73.9950
        },
        {
          title: '花园芳香',
          description: '春季花园里花朵的淡雅香味',
          category: 'pleasant',
          intensity: 2,
          rewardAmount: 10,
          latitude: 40.7614,
          longitude: -73.9776
        }
      ];

      for (let i = 0; i < annotations.length; i++) {
        await mapPage.createAnnotation(annotations[i]);
        await authPage.verifyToastMessage('标注创建成功');
        await authPage.takeScreenshot(`04-annotation-${i + 1}-created`);
        
        // 短暂等待避免创建过快
        await page.waitForTimeout(1000);
      }

      // 5. 验证所有标注都显示在地图上
      testSteps.push('验证标注显示');
      await mapPage.verifyAnnotationCount(4); // 1个高质量 + 3个常规
      await authPage.takeScreenshot('05-all-annotations-visible');

      // 6. 查看标注详情和状态
      testSteps.push('查看标注状态');
      await mapPage.clickAnnotationMarker(0);
      await mapPage.verifyAnnotationDetails({
        title: premiumAnnotation.title,
        description: premiumAnnotation.description
      });
      await authPage.takeScreenshot('06-annotation-details');

      // 7. 模拟其他用户发现奖励
      testSteps.push('模拟奖励被发现');
      // 这里应该有API调用来模拟其他用户发现奖励
      
      // 8. 查看收益统计
      testSteps.push('查看收益统计');
      await page.goto('/dashboard');
      await authPage.waitForPageLoad();
      await authPage.takeScreenshot('07-creator-dashboard');

      // 验证创建的标注统计
      const statsSection = page.locator('[data-testid="creator-stats"], .creator-stats');
      await expect(statsSection).toBeVisible();
      
      // 验证标注数量
      const annotationCount = page.locator('[data-testid="annotation-count"]');
      await expect(annotationCount).toContainText('4');

      const duration = Date.now() - startTime;
      console.log(`✅ 标注创建者流程完成，耗时: ${duration}ms`);
      console.log(`完成步骤: ${testSteps.join(' → ')}`);

    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ 标注创建者流程失败，耗时: ${duration}ms`);
      console.error(`失败步骤: ${testSteps[testSteps.length - 1]}`);
      
      await authPage.takeScreenshot('creator-error');
      throw error;
    }
  });

  test('标注创建 - 支付流程测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 创建需要付费的标注
    const paidAnnotation = {
      title: '高奖励测试标注',
      description: '用于测试支付流程的高奖励标注',
      category: 'unpleasant',
      intensity: 5,
      rewardAmount: 100, // 高奖励需要付费
      latitude: 40.7128,
      longitude: -74.0060
    };

    // 开始创建标注
    await mapPage.clickMapLocation(paidAnnotation.latitude, paidAnnotation.longitude);
    await mapPage.clickElement('button:has-text("创建标注")');
    
    // 填写表单
    await authPage.fillElement('input[name="title"]', paidAnnotation.title);
    await authPage.fillElement('textarea[name="description"]', paidAnnotation.description);
    await authPage.selectOption('select[name="category"]', paidAnnotation.category);
    await authPage.fillElement('input[name="reward"]', paidAnnotation.rewardAmount.toString());

    // 提交后应该跳转到支付页面
    await authPage.clickElement('button[type="submit"]');
    
    // 验证跳转到支付页面
    await expect(page).toHaveURL(/\/payment|\/checkout/);
    await authPage.takeScreenshot('payment-page');

    // 验证支付信息显示
    const paymentAmount = page.locator('[data-testid="payment-amount"]');
    await expect(paymentAmount).toBeVisible();
    
    // 模拟支付成功（测试环境）
    const mockPayButton = page.locator('button:has-text("模拟支付成功")');
    if (await mockPayButton.isVisible()) {
      await mockPayButton.click();
    }

    // 验证支付成功并创建标注
    await authPage.waitForPageLoad();
    await authPage.verifyToastMessage('支付成功');
    await authPage.takeScreenshot('payment-success');
  });

  test('标注管理 - 编辑和删除', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 创建测试标注
    const testAnnotation = {
      title: '待编辑标注',
      description: '这个标注将被编辑',
      category: 'neutral',
      intensity: 3,
      rewardAmount: 20,
      latitude: 40.7128,
      longitude: -74.0060
    };

    await mapPage.createAnnotation(testAnnotation);
    await authPage.verifyToastMessage('标注创建成功');

    // 点击标注打开详情
    await mapPage.clickAnnotationMarker(0);
    
    // 点击编辑按钮（作为创建者应该能看到）
    const editButton = page.locator('button:has-text("编辑"), [data-testid="edit-annotation"]');
    await expect(editButton).toBeVisible();
    await editButton.click();

    // 编辑标注信息
    const updatedTitle = '已编辑的标注标题';
    await authPage.fillElement('input[name="title"]', updatedTitle);
    
    // 保存更改
    await authPage.clickElement('button:has-text("保存")');
    await authPage.waitForAPI('/api/annotations/update');
    
    // 验证编辑成功
    await authPage.verifyToastMessage('标注更新成功');
    await mapPage.verifyAnnotationDetails({
      title: updatedTitle,
      description: testAnnotation.description
    });
    
    await authPage.takeScreenshot('annotation-edited');

    // 测试删除标注
    await authPage.clickElement('button:has-text("删除"), [data-testid="delete-annotation"]');
    
    // 确认删除
    const confirmDialog = page.locator('[role="dialog"], .confirm-dialog');
    await expect(confirmDialog).toBeVisible();
    await authPage.clickElement('button:has-text("确认删除")');
    
    // 验证删除成功
    await authPage.verifyToastMessage('标注已删除');
    await mapPage.verifyAnnotationCount(0);
    
    await authPage.takeScreenshot('annotation-deleted');
  });

  test('批量标注创建效率测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    const batchSize = 5;
    const startTime = Date.now();
    const locations = [
      { lat: 40.7589, lng: -73.9851 }, // 时代广场
      { lat: 40.7505, lng: -73.9934 }, // 帝国大厦
      { lat: 40.7614, lng: -73.9776 }, // 中央公园南
      { lat: 40.7829, lng: -73.9654 }, // 中央公园北
      { lat: 40.7282, lng: -73.7949 }  // 法拉盛
    ];

    // 批量创建标注
    for (let i = 0; i < batchSize; i++) {
      const annotation = {
        title: `批量测试标注 ${i + 1}`,
        description: `第 ${i + 1} 个批量创建的测试标注`,
        category: i % 2 === 0 ? 'pleasant' : 'unpleasant',
        intensity: Math.floor(Math.random() * 5) + 1,
        rewardAmount: (i + 1) * 10,
        latitude: locations[i].lat,
        longitude: locations[i].lng
      };

      await mapPage.createAnnotation(annotation);
      await authPage.verifyToastMessage('标注创建成功');
      
      // 记录每次创建的时间
      const currentTime = Date.now();
      console.log(`标注 ${i + 1} 创建完成，耗时: ${currentTime - startTime}ms`);
    }

    const totalDuration = Date.now() - startTime;
    const avgDuration = totalDuration / batchSize;

    console.log(`批量创建 ${batchSize} 个标注完成`);
    console.log(`总耗时: ${totalDuration}ms`);
    console.log(`平均每个标注: ${avgDuration}ms`);

    // 验证所有标注都创建成功
    await mapPage.verifyAnnotationCount(batchSize);
    
    // 性能断言
    expect(avgDuration).toBeLessThan(15000); // 每个标注平均创建时间不超过15秒
    expect(totalDuration).toBeLessThan(60000); // 总时间不超过1分钟
    
    await authPage.takeScreenshot('batch-annotations-created');
  });

  test('标注创建 - 媒体上传测试', async () => {
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 创建带媒体文件的标注
    const mediaAnnotation = {
      title: '带图片的标注',
      description: '这个标注包含了现场拍摄的图片',
      category: 'unpleasant',
      intensity: 4,
      rewardAmount: 30,
      latitude: 40.7128,
      longitude: -74.0060,
      mediaFile: './tests/e2e/fixtures/sample-image.jpg'
    };

    await mapPage.createAnnotation(mediaAnnotation);
    await authPage.verifyToastMessage('标注创建成功');

    // 验证图片上传成功
    await mapPage.clickAnnotationMarker(0);
    const mediaElement = page.locator('img, video, [data-testid="annotation-media"]');
    await expect(mediaElement).toBeVisible();
    
    await authPage.takeScreenshot('annotation-with-media');

    // 测试多媒体文件上传
    const videoAnnotation = {
      title: '带视频的标注',
      description: '这个标注包含了现场录制的视频',
      category: 'pleasant',
      intensity: 3,
      rewardAmount: 40,
      latitude: 40.7589,
      longitude: -73.9851,
      mediaFile: './tests/e2e/fixtures/sample-video.mp4'
    };

    await mapPage.createAnnotation(videoAnnotation);
    await authPage.verifyToastMessage('标注创建成功');
    
    await authPage.takeScreenshot('annotation-with-video');
  });
});