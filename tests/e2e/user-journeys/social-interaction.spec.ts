import { test, expect, Page } from '@playwright/test';
import { AuthPage } from '../page-objects/auth-page';
import { MapPage } from '../page-objects/map-page';

test.describe('社交互动使用路径测试', () => {
  let authPage: AuthPage;
  let mapPage: MapPage;
  let page: Page;
  let socialUser1: any;
  let socialUser2: any;
  let socialUser3: any;

  test.beforeAll(async ({ browser }) => {
    // 创建多个社交互动测试用户
    const context = await browser.newContext();
    const setupPage = await context.newPage();
    const setupAuth = new AuthPage(setupPage);
    const setupMap = new MapPage(setupPage);
    
    // 创建用户1（内容创建者）
    socialUser1 = await setupAuth.createAndLoginTestUser({
      username: 'social_creator',
      email: 'creator@social.test'
    });
    
    // 用户1创建一些标注
    await setupAuth.login(socialUser1.email, socialUser1.password);
    await setupMap.navigateToMap();
    await setupMap.waitForMapLoad();
    
    const socialAnnotations = [
      {
        title: '布鲁克林大桥美景',
        description: '从布鲁克林大桥看到的绝美日落景色，空气中弥漫着海风的咸味',
        category: 'pleasant',
        intensity: 4,
        rewardAmount: 30,
        latitude: 40.7061,
        longitude: -73.9969
      },
      {
        title: '华尔街咖啡香味',
        description: '华尔街附近咖啡店的浓郁咖啡香，是上班族最爱的味道',
        category: 'pleasant',
        intensity: 3,
        rewardAmount: 20,
        latitude: 40.7074,
        longitude: -74.0113
      }
    ];
    
    for (const annotation of socialAnnotations) {
      await setupMap.createAnnotation(annotation);
      await setupPage.waitForTimeout(1000);
    }
    
    await setupAuth.logout();
    
    // 创建用户2（活跃互动者）
    socialUser2 = await setupAuth.createAndLoginTestUser({
      username: 'social_user2',
      email: 'user2@social.test'
    });
    
    // 创建用户3（普通用户）
    socialUser3 = await setupAuth.createAndLoginTestUser({
      username: 'social_user3',
      email: 'user3@social.test'
    });
    
    await context.close();
  });

  test.beforeEach(async ({ page: testPage, context }) => {
    page = testPage;
    authPage = new AuthPage(page);
    mapPage = new MapPage(page);
    
    // 授予权限
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({ latitude: 40.7061, longitude: -73.9969 }); // 布鲁克林大桥
  });

  test('完整社交互动流程 - 浏览、点赞、评论、分享', async () => {
    const testSteps: string[] = [];
    const startTime = Date.now();

    try {
      // 用户2登录开始社交互动
      testSteps.push('用户2登录');
      await authPage.login(socialUser2.email, socialUser2.password);
      await authPage.takeScreenshot('01-user2-login');

      // 1. 浏览地图上的标注
      testSteps.push('浏览地图标注');
      await mapPage.navigateToMap();
      await mapPage.waitForMapLoad();
      await mapPage.verifyAnnotationCount(2); // 应该看到用户1创建的2个标注
      await authPage.takeScreenshot('02-map-with-annotations');

      // 2. 点击查看标注详情
      testSteps.push('查看标注详情');
      await mapPage.clickAnnotationMarker(0);
      await mapPage.verifyAnnotationDetails({
        title: '布鲁克林大桥美景',
        description: '从布鲁克林大桥看到的绝美日落景色，空气中弥漫着海风的咸味'
      });
      await authPage.takeScreenshot('03-annotation-details');

      // 3. 点赞标注
      testSteps.push('点赞标注');
      await mapPage.likeAnnotation();
      
      // 验证点赞状态
      const likeButton = page.locator('.like-button, button[aria-label*="like"]');
      await expect(likeButton).toHaveClass(/liked|active/);
      
      // 验证点赞数量增加
      const likeCount = page.locator('.like-count, [data-testid="like-count"]');
      await expect(likeCount).toContainText('1');
      await authPage.takeScreenshot('04-annotation-liked');

      // 4. 添加评论
      testSteps.push('添加评论');
      const commentText = '真的很美！我也在这里感受到了海风的味道，谢谢分享！';
      
      await authPage.clickElement('.comment-button, button[aria-label*="comment"]');
      
      // 等待评论表单出现
      const commentForm = page.locator('.comment-form, [data-testid="comment-form"]');
      await expect(commentForm).toBeVisible();
      
      await authPage.fillElement('textarea[name="comment"], .comment-input', commentText);
      await authPage.clickElement('button:has-text("发布"), button:has-text("Post")');
      
      // 等待评论发布成功
      await authPage.waitForAPI('/api/comments');
      await authPage.verifyToastMessage('评论发布成功');
      
      // 验证评论显示
      const commentItem = page.locator('.comment-item, [data-testid="comment"]').first();
      await expect(commentItem).toContainText(commentText);
      await expect(commentItem).toContainText(socialUser2.username);
      await authPage.takeScreenshot('05-comment-added');

      // 5. 分享标注
      testSteps.push('分享标注');
      await authPage.clickElement('.share-button, button[aria-label*="share"]');
      
      const shareModal = page.locator('.share-modal, [data-testid="share-modal"]');
      await expect(shareModal).toBeVisible();
      
      // 测试复制链接功能
      const copyLinkButton = page.locator('button:has-text("复制链接"), [data-testid="copy-link"]');
      await copyLinkButton.click();
      await authPage.verifyToastMessage('链接已复制');
      await authPage.takeScreenshot('06-share-modal');

      // 6. 关注标注创建者
      testSteps.push('关注用户');
      const creatorProfile = page.locator('.creator-profile, [data-testid="creator-info"]');
      await expect(creatorProfile).toBeVisible();
      
      const followButton = creatorProfile.locator('button:has-text("关注"), button:has-text("Follow")');
      await followButton.click();
      
      await authPage.waitForAPI('/api/users/follow');
      await authPage.verifyToastMessage('已关注');
      
      // 验证关注状态
      await expect(followButton).toHaveText(/已关注|Following/);
      await authPage.takeScreenshot('07-user-followed');

      // 7. 查看第二个标注并互动
      testSteps.push('查看其他标注');
      await page.locator('.modal-close, [aria-label="Close"]').click(); // 关闭当前弹窗
      await mapPage.clickAnnotationMarker(1);
      
      await mapPage.verifyAnnotationDetails({
        title: '华尔街咖啡香味',
        description: '华尔街附近咖啡店的浓郁咖啡香，是上班族最爱的味道'
      });
      
      // 也点赞这个标注
      await mapPage.likeAnnotation();
      await authPage.takeScreenshot('08-second-annotation-liked');

      // 8. 查看动态流
      testSteps.push('查看动态流');
      await page.goto('/feed');
      await authPage.waitForPageLoad();
      
      // 验证动态流显示关注用户的活动
      const feedItems = page.locator('.feed-item, [data-testid="feed-item"]');
      await expect(feedItems).toHaveCount.atLeast(1);
      
      // 验证能看到用户1的标注活动
      const userActivity = feedItems.first();
      await expect(userActivity).toContainText(socialUser1.username);
      await authPage.takeScreenshot('09-activity-feed');

      // 9. 查看个人资料页面
      testSteps.push('查看个人资料');
      await page.goto(`/profile/${socialUser1.username}`);
      await authPage.waitForPageLoad();
      
      // 验证用户资料信息
      const profileInfo = page.locator('.profile-info, [data-testid="profile-info"]');
      await expect(profileInfo).toBeVisible();
      
      const userAnnotations = page.locator('.user-annotations, [data-testid="user-annotations"]');
      await expect(userAnnotations).toBeVisible();
      
      // 验证显示用户的标注列表
      const annotationList = page.locator('.annotation-item, [data-testid="annotation-item"]');
      await expect(annotationList).toHaveCount(2);
      await authPage.takeScreenshot('10-user-profile');

      const duration = Date.now() - startTime;
      console.log(`✅ 社交互动流程完成，耗时: ${duration}ms`);
      console.log(`完成步骤: ${testSteps.join(' → ')}`);

    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ 社交互动流程失败，耗时: ${duration}ms`);
      console.error(`失败步骤: ${testSteps[testSteps.length - 1]}`);
      
      await authPage.takeScreenshot('social-interaction-error');
      throw error;
    }
  });

  test('评论系统深度测试', async () => {
    await authPage.login(socialUser2.email, socialUser2.password);
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();

    // 点击查看标注
    await mapPage.clickAnnotationMarker(0);
    
    // 添加主评论
    await authPage.clickElement('.comment-button');
    const mainComment = '这个地方我也去过，确实风景很棒！';
    await authPage.fillElement('.comment-input', mainComment);
    await authPage.clickElement('button:has-text("发布")');
    await authPage.verifyToastMessage('评论发布成功');

    // 用用户3登录来回复评论
    await authPage.logout();
    await authPage.login(socialUser3.email, socialUser3.password);
    
    await mapPage.navigateToMap();
    await mapPage.clickAnnotationMarker(0);
    
    // 回复评论
    const replyButton = page.locator('.reply-button, button:has-text("回复")').first();
    await replyButton.click();
    
    const replyText = '同意！我下次也要去看看';
    await authPage.fillElement('.reply-input', replyText);
    await authPage.clickElement('button:has-text("回复")');
    
    // 验证回复显示
    const replyItem = page.locator('.reply-item, [data-testid="reply"]').first();
    await expect(replyItem).toContainText(replyText);
    await expect(replyItem).toContainText(socialUser3.username);
    await authPage.takeScreenshot('comment-with-reply');

    // 测试评论点赞
    const commentLike = page.locator('.comment-like, .comment .like-button').first();
    await commentLike.click();
    
    const commentLikeCount = page.locator('.comment-like-count').first();
    await expect(commentLikeCount).toContainText('1');
    await authPage.takeScreenshot('comment-liked');
  });

  test('用户关注系统测试', async () => {
    await authPage.login(socialUser2.email, socialUser2.password);
    
    // 查看用户1的个人资料
    await page.goto(`/profile/${socialUser1.username}`);
    await authPage.waitForPageLoad();
    
    // 关注用户1
    const followButton = page.locator('button:has-text("关注")');
    await followButton.click();
    await authPage.verifyToastMessage('已关注');
    
    // 验证关注状态改变
    await expect(followButton).toHaveText(/已关注|Following/);
    
    // 查看关注列表
    await page.goto('/following');
    const followingList = page.locator('.following-item, [data-testid="following-item"]');
    await expect(followingList).toHaveCount(1);
    await expect(followingList.first()).toContainText(socialUser1.username);
    await authPage.takeScreenshot('following-list');

    // 用用户1登录查看粉丝列表
    await authPage.logout();
    await authPage.login(socialUser1.email, socialUser1.password);
    
    await page.goto('/followers');
    const followersList = page.locator('.follower-item, [data-testid="follower-item"]');
    await expect(followersList).toHaveCount(1);
    await expect(followersList.first()).toContainText(socialUser2.username);
    await authPage.takeScreenshot('followers-list');

    // 测试取消关注
    await authPage.login(socialUser2.email, socialUser2.password);
    await page.goto(`/profile/${socialUser1.username}`);
    
    const unfollowButton = page.locator('button:has-text("已关注")');
    await unfollowButton.click();
    await authPage.verifyToastMessage('已取消关注');
    
    // 验证状态恢复
    await expect(page.locator('button:has-text("关注")')).toBeVisible();
    await authPage.takeScreenshot('unfollowed');
  });

  test('社区讨论参与测试', async () => {
    await authPage.login(socialUser2.email, socialUser2.password);
    
    // 进入社区讨论页面
    await page.goto('/community');
    await authPage.waitForPageLoad();
    
    // 创建新话题
    const createTopicButton = page.locator('button:has-text("发起讨论"), [data-testid="create-topic"]');
    if (await createTopicButton.isVisible()) {
      await createTopicButton.click();
      
      const topicTitle = '纽约最佳气味打卡地推荐';
      const topicContent = '大家有什么推荐的纽约气味打卡地点吗？我想收集一些独特的嗅觉体验地点。';
      
      await authPage.fillElement('input[name="title"]', topicTitle);
      await authPage.fillElement('textarea[name="content"]', topicContent);
      await authPage.clickElement('button:has-text("发布话题")');
      
      await authPage.verifyToastMessage('话题发布成功');
      await authPage.takeScreenshot('topic-created');
      
      // 验证话题显示在列表中
      const topicItem = page.locator('.topic-item, [data-testid="topic-item"]').first();
      await expect(topicItem).toContainText(topicTitle);
      await expect(topicItem).toContainText(socialUser2.username);
    }

    // 参与现有讨论
    const existingTopic = page.locator('.topic-item').first();
    await existingTopic.click();
    
    // 添加讨论回复
    const discussionReply = '我推荐中央公园的花园区域，春天的时候花香很浓郁！';
    await authPage.fillElement('.discussion-input, textarea[name="reply"]', discussionReply);
    await authPage.clickElement('button:has-text("回复")');
    
    // 验证回复显示
    const replyItem = page.locator('.discussion-reply').last();
    await expect(replyItem).toContainText(discussionReply);
    await authPage.takeScreenshot('discussion-reply');
  });

  test('成就系统互动测试', async () => {
    await authPage.login(socialUser2.email, socialUser2.password);
    
    // 查看成就页面
    await page.goto('/achievements');
    await authPage.waitForPageLoad();
    
    // 验证成就系统显示
    const achievementGrid = page.locator('.achievement-grid, [data-testid="achievements"]');
    await expect(achievementGrid).toBeVisible();
    
    // 检查社交相关成就
    const socialAchievements = [
      '首次点赞', '评论达人', '社交新星', '热心用户'
    ];
    
    for (const achievement of socialAchievements) {
      const achievementItem = page.locator(`[data-testid="achievement-${achievement}"], .achievement:has-text("${achievement}")`);
      // 成就项目应该存在（无论是否已解锁）
      await expect(achievementItem).toBeVisible();
    }
    await authPage.takeScreenshot('achievements-page');

    // 触发新成就（通过完成特定动作）
    await mapPage.navigateToMap();
    await mapPage.waitForMapLoad();
    
    // 连续点赞多个标注来触发"点赞达人"成就
    for (let i = 0; i < 2; i++) {
      await mapPage.clickAnnotationMarker(i);
      await mapPage.likeAnnotation();
      await page.locator('.modal-close, [aria-label="Close"]').click().catch(() => {});
      await page.waitForTimeout(1000);
    }
    
    // 检查是否有成就解锁通知
    const achievementNotification = page.locator('.achievement-notification, [data-testid="achievement-unlocked"]');
    if (await achievementNotification.isVisible()) {
      await expect(achievementNotification).toContainText('成就解锁');
      await authPage.takeScreenshot('achievement-unlocked');
    }
  });

  test('内容分享和传播测试', async () => {
    await authPage.login(socialUser1.email, socialUser1.password);
    
    // 进入个人创作页面
    await page.goto('/dashboard');
    await authPage.waitForPageLoad();
    
    // 查看标注的分享统计
    const annotationStats = page.locator('.annotation-stats, [data-testid="annotation-stats"]');
    await expect(annotationStats).toBeVisible();
    
    // 验证显示点赞数、评论数、分享数
    const statsItems = page.locator('.stat-item');
    await expect(statsItems).toHaveCount.atLeast(3);
    await authPage.takeScreenshot('content-stats');
    
    // 查看详细的互动数据
    await authPage.clickElement('button:has-text("详细数据"), [data-testid="view-details"]');
    
    const detailsModal = page.locator('.stats-modal, [data-testid="stats-details"]');
    if (await detailsModal.isVisible()) {
      // 验证显示用户互动明细
      const interactionList = page.locator('.interaction-item');
      await expect(interactionList).toHaveCount.atLeast(1);
      await authPage.takeScreenshot('interaction-details');
    }

    // 测试内容推广功能
    await page.goto('/promote');
    if (await page.locator('.promote-content').isVisible()) {
      // 选择要推广的标注
      const promoteButton = page.locator('button:has-text("推广此标注")').first();
      await promoteButton.click();
      
      // 设置推广参数
      await authPage.selectOption('[name="duration"]', '7'); // 推广7天
      await authPage.fillElement('[name="budget"]', '50'); // 预算50元
      
      await authPage.clickElement('button:has-text("开始推广")');
      await authPage.verifyToastMessage('推广设置成功');
      await authPage.takeScreenshot('content-promotion');
    }
  });
});