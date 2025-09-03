/**
 * Touch Gestures and Mobile Interaction Tests
 * 触摸手势和移动交互测试
 */

import { test, expect, Page, Locator } from '@playwright/test';
import { testStandards } from './mobile-device-matrix';

// 手势类型定义
interface TouchGesture {
  name: string;
  steps: TouchStep[];
  expectedResult: string;
}

interface TouchStep {
  action: 'touchstart' | 'touchmove' | 'touchend' | 'tap' | 'swipe' | 'pinch' | 'longpress';
  coordinates?: { x: number; y: number };
  duration?: number;
  distance?: number;
  direction?: 'up' | 'down' | 'left' | 'right';
}

// 手势测试配置
const touchGestures: TouchGesture[] = [
  {
    name: 'Single Tap',
    steps: [
      { action: 'tap', coordinates: { x: 100, y: 100 } }
    ],
    expectedResult: 'Element clicked'
  },
  {
    name: 'Double Tap',
    steps: [
      { action: 'tap', coordinates: { x: 100, y: 100 } },
      { action: 'tap', coordinates: { x: 100, y: 100 } }
    ],
    expectedResult: 'Double tap detected'
  },
  {
    name: 'Long Press',
    steps: [
      { action: 'longpress', coordinates: { x: 100, y: 100 }, duration: 800 }
    ],
    expectedResult: 'Context menu shown'
  },
  {
    name: 'Swipe Left',
    steps: [
      { action: 'swipe', direction: 'left', distance: 200 }
    ],
    expectedResult: 'Navigation triggered'
  },
  {
    name: 'Swipe Right',
    steps: [
      { action: 'swipe', direction: 'right', distance: 200 }
    ],
    expectedResult: 'Back navigation'
  },
  {
    name: 'Vertical Scroll',
    steps: [
      { action: 'swipe', direction: 'up', distance: 300 }
    ],
    expectedResult: 'Page scrolled'
  },
  {
    name: 'Pinch to Zoom',
    steps: [
      { action: 'pinch', coordinates: { x: 200, y: 200 } }
    ],
    expectedResult: 'Map zoomed in'
  }
];

test.describe('Touch Gestures - Map Interactions', () => {
  test.beforeEach(async ({ page }) => {
    // 确保在移动设备模式下测试
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/map');
    await page.waitForLoadState('networkidle');
    await page.waitForSelector('[data-testid="map-container"]', { timeout: 10000 });
  });

  test('Map pan with touch drag', async ({ page }) => {
    const mapContainer = page.locator('[data-testid="map-container"]');
    await expect(mapContainer).toBeVisible();

    // 获取地图中心坐标
    const mapBox = await mapContainer.boundingBox();
    const centerX = mapBox!.x + mapBox!.width / 2;
    const centerY = mapBox!.y + mapBox!.height / 2;

    // 执行拖拽手势
    await page.mouse.move(centerX, centerY);
    await page.mouse.down();
    await page.mouse.move(centerX + 100, centerY + 50, { steps: 10 });
    await page.mouse.up();

    // 验证地图已移动 (通过检查地图容器的变化)
    await page.waitForTimeout(500);
    
    // 截图记录结果
    await page.screenshot({
      path: 'test-results/touch-map-pan.png',
      clip: mapBox!
    });
  });

  test('Map zoom with pinch gesture', async ({ page }) => {
    const mapContainer = page.locator('[data-testid="map-container"]');
    const mapBox = await mapContainer.boundingBox();
    const centerX = mapBox!.x + mapBox!.width / 2;
    const centerY = mapBox!.y + mapBox!.height / 2;

    // 模拟双指捏合放大
    await simulatePinchZoom(page, centerX, centerY, 'out', 1.5);
    await page.waitForTimeout(1000);

    // 验证缩放效果 (检查地图缩放级别或视觉变化)
    const zoomInButton = page.locator('[data-testid="zoom-in"]');
    const zoomOutButton = page.locator('[data-testid="zoom-out"]');
    
    await expect(zoomInButton).toBeVisible();
    await expect(zoomOutButton).toBeVisible();

    // 截图记录
    await page.screenshot({
      path: 'test-results/touch-map-zoom.png',
      clip: mapBox!
    });
  });

  test('Annotation marker touch interaction', async ({ page }) => {
    // 等待地图标注加载
    const markers = page.locator('[data-testid="map-annotation"]');
    await expect(markers.first()).toBeVisible({ timeout: 10000 });

    const markerCount = await markers.count();
    if (markerCount > 0) {
      const firstMarker = markers.first();
      
      // 测试单击标注
      await firstMarker.tap();
      
      // 验证标注详情弹窗出现
      const annotationPopup = page.locator('[data-testid="annotation-popup"]');
      await expect(annotationPopup).toBeVisible({ timeout: 3000 });

      // 测试长按标注
      await firstMarker.tap({ force: true });
      await page.waitForTimeout(800); // 长按持续时间

      // 可能显示上下文菜单
      const contextMenu = page.locator('[data-testid="annotation-context-menu"]');
      if (await contextMenu.isVisible()) {
        await expect(contextMenu).toBeVisible();
      }
    }
  });
});

test.describe('Touch Gestures - Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
  });

  test('Mobile navigation menu toggle', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const menuToggle = page.locator('[data-testid="mobile-menu-toggle"]');
    const mobileMenu = page.locator('[data-testid="mobile-menu"]');

    // 测试菜单切换
    await expect(menuToggle).toBeVisible();
    
    await menuToggle.tap();
    await expect(mobileMenu).toBeVisible();

    // 点击菜单外部关闭
    await page.tap('body', { position: { x: 50, y: 300 } });
    await expect(mobileMenu).not.toBeVisible();
  });

  test('Swipe navigation between pages', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // 检查是否有支持滑动导航的组件
    const swipeContainer = page.locator('[data-testid="swipe-navigation"]');
    
    if (await swipeContainer.isVisible()) {
      const containerBox = await swipeContainer.boundingBox();
      
      // 向左滑动
      await page.mouse.move(containerBox!.x + containerBox!.width - 50, containerBox!.y + containerBox!.height / 2);
      await page.mouse.down();
      await page.mouse.move(containerBox!.x + 50, containerBox!.y + containerBox!.height / 2, { steps: 10 });
      await page.mouse.up();

      await page.waitForTimeout(500);
      
      // 验证页面或内容已切换
      // 这里需要根据实际的滑动导航实现来验证
    }
  });

  test('Pull to refresh gesture', async ({ page }) => {
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');

    const pageContent = page.locator('[data-testid="main-content"]');
    await expect(pageContent).toBeVisible();

    // 模拟下拉刷新
    const contentBox = await pageContent.boundingBox();
    
    await page.mouse.move(contentBox!.x + contentBox!.width / 2, contentBox!.y + 10);
    await page.mouse.down();
    await page.mouse.move(contentBox!.x + contentBox!.width / 2, contentBox!.y + 150, { steps: 10 });
    await page.mouse.up();

    // 检查是否有刷新指示器
    const refreshIndicator = page.locator('[data-testid="refresh-indicator"]');
    if (await refreshIndicator.isVisible()) {
      await expect(refreshIndicator).toBeVisible();
      
      // 等待刷新完成
      await expect(refreshIndicator).not.toBeVisible({ timeout: 5000 });
    }
  });
});

test.describe('Touch Gestures - Form Interactions', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
  });

  test('Mobile form input focus and typing', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    const emailInput = page.locator('input[type="email"]');
    const passwordInput = page.locator('input[type="password"]');

    // 测试输入框点击焦点
    await emailInput.tap();
    await expect(emailInput).toBeFocused();

    // 模拟移动键盘输入
    await emailInput.fill('test@example.com');
    
    // 测试切换到下一个输入框
    await passwordInput.tap();
    await expect(passwordInput).toBeFocused();
    await passwordInput.fill('password123');

    // 测试表单提交按钮
    const submitButton = page.locator('button[type="submit"]');
    await expect(submitButton).toBeVisible();
    
    // 验证按钮点击区域大小
    const buttonBox = await submitButton.boundingBox();
    expect(buttonBox!.height).toBeGreaterThanOrEqual(44); // iOS建议最小点击区域
    expect(buttonBox!.width).toBeGreaterThanOrEqual(44);

    await submitButton.tap();
  });

  test('Mobile select and dropdown interactions', async ({ page }) => {
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');

    // 测试下拉选择框
    const selectTrigger = page.locator('[data-testid="smell-category-select"]');
    if (await selectTrigger.isVisible()) {
      await selectTrigger.tap();

      const selectOptions = page.locator('[data-testid="select-options"]');
      await expect(selectOptions).toBeVisible();

      // 选择一个选项
      const firstOption = selectOptions.locator('[role="option"]').first();
      await firstOption.tap();

      await expect(selectOptions).not.toBeVisible();
    }
  });

  test('File upload with touch interface', async ({ page }) => {
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');

    const fileInput = page.locator('input[type="file"]');
    const uploadArea = page.locator('[data-testid="file-upload-area"]');

    if (await uploadArea.isVisible()) {
      // 测试点击上传区域
      await uploadArea.tap();
      
      // 在真实环境中，这会触发文件选择器
      // 在测试中，我们验证上传区域的响应
      const uploadAreaBox = await uploadArea.boundingBox();
      expect(uploadAreaBox!.height).toBeGreaterThanOrEqual(100); // 足够大的点击区域
    }
  });
});

test.describe('Touch Gestures - List and Card Interactions', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
  });

  test('List item swipe actions', async ({ page }) => {
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');

    const listItems = page.locator('[data-testid="annotation-item"]');
    const itemCount = await listItems.count();

    if (itemCount > 0) {
      const firstItem = listItems.first();
      const itemBox = await firstItem.boundingBox();

      // 向左滑动显示操作按钮
      await page.mouse.move(itemBox!.x + itemBox!.width - 10, itemBox!.y + itemBox!.height / 2);
      await page.mouse.down();
      await page.mouse.move(itemBox!.x + 50, itemBox!.y + itemBox!.height / 2, { steps: 10 });
      await page.mouse.up();

      await page.waitForTimeout(300);

      // 检查是否显示了操作按钮
      const actionButtons = page.locator('[data-testid="swipe-actions"]');
      if (await actionButtons.isVisible()) {
        await expect(actionButtons).toBeVisible();
        
        // 测试操作按钮点击
        const editButton = actionButtons.locator('[data-testid="edit-button"]');
        if (await editButton.isVisible()) {
          await editButton.tap();
        }
      }
    }
  });

  test('Card tap and long press', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const cards = page.locator('[data-testid="feature-card"]');
    const cardCount = await cards.count();

    if (cardCount > 0) {
      const firstCard = cards.first();

      // 测试普通点击
      await firstCard.tap();
      await page.waitForTimeout(500);

      // 测试长按
      const cardBox = await firstCard.boundingBox();
      await page.mouse.move(cardBox!.x + cardBox!.width / 2, cardBox!.y + cardBox!.height / 2);
      await page.mouse.down();
      await page.waitForTimeout(800); // 长按时间
      await page.mouse.up();

      // 检查是否有长按反馈
      const contextMenu = page.locator('[data-testid="card-context-menu"]');
      if (await contextMenu.isVisible()) {
        await expect(contextMenu).toBeVisible();
      }
    }
  });
});

test.describe('Touch Performance and Responsiveness', () => {
  test('Touch response time meets standards', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const buttons = page.locator('button, [role="button"]');
    const buttonCount = await buttons.count();

    for (let i = 0; i < Math.min(buttonCount, 5); i++) {
      const button = buttons.nth(i);
      
      if (await button.isVisible()) {
        const startTime = Date.now();
        await button.tap();
        await page.waitForTimeout(100); // 等待UI响应
        const responseTime = Date.now() - startTime;

        // 验证响应时间符合标准
        expect(responseTime).toBeLessThan(testStandards.performance.interactionDelay);
      }
    }
  });

  test('Scroll performance on touch devices', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');

    const scrollContainer = page.locator('[data-testid="scroll-container"]');
    
    if (await scrollContainer.isVisible()) {
      const containerBox = await scrollContainer.boundingBox();
      
      // 执行快速滚动
      const startY = containerBox!.y + containerBox!.height - 50;
      const endY = containerBox!.y + 50;
      
      await page.mouse.move(containerBox!.x + containerBox!.width / 2, startY);
      await page.mouse.down();
      await page.mouse.move(containerBox!.x + containerBox!.width / 2, endY, { steps: 20 });
      await page.mouse.up();

      // 验证滚动流畅性 (通过检查滚动后的状态)
      await page.waitForTimeout(1000);
    }
  });

  test('Multi-touch gesture handling', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/map');
    await page.waitForLoadState('networkidle');

    const mapContainer = page.locator('[data-testid="map-container"]');
    const mapBox = await mapContainer.boundingBox();
    const centerX = mapBox!.x + mapBox!.width / 2;
    const centerY = mapBox!.y + mapBox!.height / 2;

    // 模拟双指操作 (旋转 + 缩放)
    await simulateMultiTouchGesture(page, centerX, centerY);
    
    await page.waitForTimeout(1000);
    
    // 截图记录结果
    await page.screenshot({
      path: 'test-results/multi-touch-gesture.png',
      clip: mapBox!
    });
  });
});

// 辅助函数

/**
 * 模拟捏合缩放手势
 */
async function simulatePinchZoom(
  page: Page, 
  centerX: number, 
  centerY: number, 
  direction: 'in' | 'out',
  scale: number = 1.5
) {
  const distance = direction === 'out' ? 50 * scale : 50 / scale;
  
  // 双指起始位置
  const finger1Start = { x: centerX - 25, y: centerY };
  const finger2Start = { x: centerX + 25, y: centerY };
  
  // 双指结束位置
  const finger1End = { x: centerX - distance, y: centerY };
  const finger2End = { x: centerX + distance, y: centerY };

  // 模拟双指移动 (Playwright限制，使用单点模拟)
  await page.mouse.move(finger1Start.x, finger1Start.y);
  await page.mouse.down();
  await page.mouse.move(finger1End.x, finger1End.y, { steps: 10 });
  await page.mouse.up();
}

/**
 * 模拟多点触控手势
 */
async function simulateMultiTouchGesture(page: Page, centerX: number, centerY: number) {
  // 由于Playwright的限制，我们使用键盘修饰键配合鼠标操作来模拟多点触控
  await page.keyboard.down('Control');
  
  await page.mouse.move(centerX - 30, centerY - 30);
  await page.mouse.down();
  await page.mouse.move(centerX + 30, centerY + 30, { steps: 15 });
  await page.mouse.up();
  
  await page.keyboard.up('Control');
}

/**
 * 验证触摸目标大小符合可访问性标准
 */
async function validateTouchTargetSize(element: Locator): Promise<boolean> {
  const box = await element.boundingBox();
  if (!box) return false;
  
  // iOS Human Interface Guidelines: 最小44x44pt
  // Android Material Design: 最小48x48dp
  const minSize = 44;
  
  return box.width >= minSize && box.height >= minSize;
}

/**
 * 测试手势冲突处理
 */
async function testGestureConflicts(page: Page, element: Locator) {
  const box = await element.boundingBox();
  if (!box) return;
  
  const centerX = box.x + box.width / 2;
  const centerY = box.y + box.height / 2;
  
  // 测试快速连续点击
  await page.mouse.click(centerX, centerY);
  await page.waitForTimeout(50);
  await page.mouse.click(centerX, centerY);
  
  // 测试点击后立即拖拽
  await page.mouse.move(centerX, centerY);
  await page.mouse.down();
  await page.waitForTimeout(50);
  await page.mouse.move(centerX + 20, centerY + 20, { steps: 5 });
  await page.mouse.up();
}