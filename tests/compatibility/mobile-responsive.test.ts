/**
 * Mobile Responsive Design Tests
 * 移动端响应式设计测试
 */

import { test, expect, Page } from '@playwright/test';
import { testStandards } from './mobile-device-matrix';

interface ResponsiveBreakpoint {
  name: string;
  width: number;
  height: number;
  expectations: {
    navigationCollapsed: boolean;
    gridColumns: number;
    sidebarHidden: boolean;
    fontSizeAdjusted: boolean;
  };
}

const responsiveBreakpoints: ResponsiveBreakpoint[] = [
  {
    name: 'Mobile Portrait',
    width: 375,
    height: 667,
    expectations: {
      navigationCollapsed: true,
      gridColumns: 1,
      sidebarHidden: true,
      fontSizeAdjusted: true,
    },
  },
  {
    name: 'Mobile Landscape',
    width: 667,
    height: 375,
    expectations: {
      navigationCollapsed: true,
      gridColumns: 2,
      sidebarHidden: true,
      fontSizeAdjusted: true,
    },
  },
  {
    name: 'Tablet Portrait',
    width: 768,
    height: 1024,
    expectations: {
      navigationCollapsed: false,
      gridColumns: 2,
      sidebarHidden: false,
      fontSizeAdjusted: false,
    },
  },
  {
    name: 'Tablet Landscape',
    width: 1024,
    height: 768,
    expectations: {
      navigationCollapsed: false,
      gridColumns: 3,
      sidebarHidden: false,
      fontSizeAdjusted: false,
    },
  },
  {
    name: 'Desktop',
    width: 1920,
    height: 1080,
    expectations: {
      navigationCollapsed: false,
      gridColumns: 4,
      sidebarHidden: false,
      fontSizeAdjusted: false,
    },
  },
];

// 测试首页响应式布局
test.describe('Homepage Responsive Layout', () => {
  responsiveBreakpoints.forEach((breakpoint) => {
    test(`${breakpoint.name} (${breakpoint.width}x${breakpoint.height})`, async ({ page }) => {
      // 设置视口大小
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      // 导航到首页
      await page.goto('/');
      await page.waitForLoadState('networkidle');

      // 截图用于视觉对比
      await page.screenshot({
        path: `test-results/responsive-homepage-${breakpoint.name.toLowerCase().replace(' ', '-')}.png`,
        fullPage: true,
      });

      // 测试导航栏适配
      const navigation = page.locator('[data-testid="main-navigation"]');
      if (breakpoint.expectations.navigationCollapsed) {
        await expect(navigation.locator('[data-testid="mobile-menu-toggle"]')).toBeVisible();
        await expect(navigation.locator('[data-testid="desktop-menu"]')).not.toBeVisible();
      } else {
        await expect(navigation.locator('[data-testid="desktop-menu"]')).toBeVisible();
        await expect(navigation.locator('[data-testid="mobile-menu-toggle"]')).not.toBeVisible();
      }

      // 测试主要内容区域
      const mainContent = page.locator('[data-testid="main-content"]');
      await expect(mainContent).toBeVisible();

      // 验证字体大小调整
      if (breakpoint.expectations.fontSizeAdjusted) {
        const heading = page.locator('h1').first();
        const fontSize = await heading.evaluate(el => 
          window.getComputedStyle(el).fontSize
        );
        const fontSizeNum = parseFloat(fontSize);
        expect(fontSizeNum).toBeLessThanOrEqual(32); // 移动端标题字体不超过32px
      }

      // 测试按钮点击区域大小
      const buttons = page.locator('button, [role="button"]');
      const buttonCount = await buttons.count();
      
      for (let i = 0; i < Math.min(buttonCount, 5); i++) {
        const button = buttons.nth(i);
        if (await button.isVisible()) {
          const box = await button.boundingBox();
          if (box && breakpoint.width <= 768) {
            // 移动端按钮最小点击区域44x44px
            expect(box.height).toBeGreaterThanOrEqual(44);
            expect(box.width).toBeGreaterThanOrEqual(44);
          }
        }
      }
    });
  });
});

// 测试地图组件响应式
test.describe('Map Component Responsive', () => {
  responsiveBreakpoints.forEach((breakpoint) => {
    test(`Map adapts to ${breakpoint.name}`, async ({ page }) => {
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      await page.goto('/map');
      await page.waitForLoadState('networkidle');

      // 等待地图加载
      await page.waitForSelector('[data-testid="map-container"]', { timeout: 10000 });
      
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();

      // 验证地图容器尺寸
      const mapBox = await mapContainer.boundingBox();
      expect(mapBox).not.toBeNull();
      expect(mapBox!.width).toBeGreaterThan(0);
      expect(mapBox!.height).toBeGreaterThan(0);

      // 测试地图控件位置
      if (breakpoint.width <= 768) {
        // 移动端控件应该在底部
        const controls = page.locator('[data-testid="map-controls"]');
        await expect(controls).toBeVisible();
        const controlsBox = await controls.boundingBox();
        expect(controlsBox!.y).toBeGreaterThan(mapBox!.height * 0.7);
      } else {
        // 桌面端控件在右上角
        const controls = page.locator('[data-testid="map-controls"]');
        await expect(controls).toBeVisible();
      }

      // 测试地图标注点击区域
      const annotations = page.locator('[data-testid="map-annotation"]');
      const annotationCount = await annotations.count();
      
      if (annotationCount > 0) {
        const firstAnnotation = annotations.first();
        const annotationBox = await firstAnnotation.boundingBox();
        if (breakpoint.width <= 768) {
          // 移动端标注点击区域更大
          expect(annotationBox!.width).toBeGreaterThanOrEqual(32);
          expect(annotationBox!.height).toBeGreaterThanOrEqual(32);
        }
      }

      // 截图
      await page.screenshot({
        path: `test-results/responsive-map-${breakpoint.name.toLowerCase().replace(' ', '-')}.png`,
        fullPage: true,
      });
    });
  });
});

// 测试表单响应式
test.describe('Forms Responsive Design', () => {
  const formPages = [
    { path: '/login', name: 'Login' },
    { path: '/register', name: 'Register' },
    { path: '/annotation/create', name: 'Create Annotation' },
  ];

  formPages.forEach((formPage) => {
    responsiveBreakpoints.forEach((breakpoint) => {
      test(`${formPage.name} form on ${breakpoint.name}`, async ({ page }) => {
        await page.setViewportSize({
          width: breakpoint.width,
          height: breakpoint.height,
        });

        await page.goto(formPage.path);
        await page.waitForLoadState('networkidle');

        // 查找表单
        const form = page.locator('form').first();
        await expect(form).toBeVisible();

        // 测试输入框响应式
        const inputs = form.locator('input[type="text"], input[type="email"], input[type="password"], textarea');
        const inputCount = await inputs.count();

        for (let i = 0; i < inputCount; i++) {
          const input = inputs.nth(i);
          const inputBox = await input.boundingBox();
          
          if (inputBox) {
            if (breakpoint.width <= 768) {
              // 移动端输入框应该占满宽度
              const formBox = await form.boundingBox();
              const widthRatio = inputBox.width / (formBox!.width * 0.9); // 考虑padding
              expect(widthRatio).toBeGreaterThan(0.8);
              
              // 移动端输入框高度适配
              expect(inputBox.height).toBeGreaterThanOrEqual(48);
            }
          }
        }

        // 测试按钮响应式
        const submitButton = form.locator('button[type="submit"]');
        if (await submitButton.isVisible()) {
          const buttonBox = await submitButton.boundingBox();
          if (buttonBox && breakpoint.width <= 768) {
            // 移动端提交按钮应该足够大
            expect(buttonBox.height).toBeGreaterThanOrEqual(48);
            expect(buttonBox.width).toBeGreaterThanOrEqual(120);
          }
        }

        // 截图
        await page.screenshot({
          path: `test-results/responsive-form-${formPage.name.toLowerCase()}-${breakpoint.name.toLowerCase().replace(' ', '-')}.png`,
          fullPage: true,
        });
      });
    });
  });
});

// 测试内容网格响应式
test.describe('Content Grid Responsive', () => {
  test('Annotation grid adapts to screen size', async ({ page }) => {
    for (const breakpoint of responsiveBreakpoints) {
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      await page.goto('/annotations');
      await page.waitForLoadState('networkidle');

      // 等待注释网格加载
      const grid = page.locator('[data-testid="annotation-grid"]');
      await expect(grid).toBeVisible();

      // 计算网格列数
      const gridItems = grid.locator('[data-testid="annotation-item"]');
      const itemCount = await gridItems.count();

      if (itemCount > 0) {
        // 获取前几个项目的位置来计算列数
        const positions: number[] = [];
        const maxItems = Math.min(itemCount, 6);
        
        for (let i = 0; i < maxItems; i++) {
          const item = gridItems.nth(i);
          const box = await item.boundingBox();
          if (box) {
            positions.push(box.x);
          }
        }

        // 计算唯一的x坐标数量(即列数)
        const uniqueXPositions = [...new Set(positions.map(x => Math.round(x / 10) * 10))];
        const actualColumns = uniqueXPositions.length;

        // 验证列数符合预期
        const expectedColumns = breakpoint.expectations.gridColumns;
        expect(actualColumns).toBeGreaterThanOrEqual(Math.min(expectedColumns, itemCount));
        expect(actualColumns).toBeLessThanOrEqual(expectedColumns);
      }

      // 截图
      await page.screenshot({
        path: `test-results/responsive-grid-${breakpoint.name.toLowerCase().replace(' ', '-')}.png`,
        fullPage: true,
      });
    }
  });
});

// 测试侧边栏响应式
test.describe('Sidebar Responsive Behavior', () => {
  test('Sidebar shows/hides based on screen size', async ({ page }) => {
    // 访问有侧边栏的页面
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    for (const breakpoint of responsiveBreakpoints) {
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      // 等待布局调整
      await page.waitForTimeout(500);

      const sidebar = page.locator('[data-testid="sidebar"]');
      const sidebarToggle = page.locator('[data-testid="sidebar-toggle"]');

      if (breakpoint.expectations.sidebarHidden) {
        // 移动端: 侧边栏默认隐藏，显示切换按钮
        await expect(sidebarToggle).toBeVisible();
        
        // 测试切换功能
        await sidebarToggle.click();
        await expect(sidebar).toBeVisible();
        
        // 再次点击隐藏
        await sidebarToggle.click();
        await expect(sidebar).not.toBeVisible();
      } else {
        // 桌面端: 侧边栏直接显示
        await expect(sidebar).toBeVisible();
        
        // 桌面端可能没有切换按钮，或者切换按钮不可见
        if (await sidebarToggle.isVisible()) {
          await expect(sidebarToggle).not.toBeVisible();
        }
      }
    }
  });
});

// 测试文本和间距响应式
test.describe('Typography and Spacing Responsive', () => {
  test('Text scales appropriately across devices', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    for (const breakpoint of responsiveBreakpoints) {
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      await page.waitForTimeout(500);

      // 测试标题字体大小
      const h1 = page.locator('h1').first();
      if (await h1.isVisible()) {
        const fontSize = await h1.evaluate(el => 
          parseInt(window.getComputedStyle(el).fontSize)
        );

        if (breakpoint.width <= 768) {
          // 移动端字体应该更小
          expect(fontSize).toBeLessThanOrEqual(32);
          expect(fontSize).toBeGreaterThanOrEqual(24);
        } else {
          // 桌面端字体可以更大
          expect(fontSize).toBeGreaterThanOrEqual(28);
        }
      }

      // 测试段落间距
      const paragraphs = page.locator('p');
      if (await paragraphs.count() > 1) {
        const firstP = paragraphs.nth(0);
        const marginBottom = await firstP.evaluate(el => 
          parseInt(window.getComputedStyle(el).marginBottom)
        );

        if (breakpoint.width <= 768) {
          // 移动端间距更紧凑
          expect(marginBottom).toBeLessThanOrEqual(16);
        } else {
          // 桌面端间距更宽松
          expect(marginBottom).toBeGreaterThanOrEqual(16);
        }
      }
    }
  });
});

// 性能测试
test.describe('Responsive Performance', () => {
  test('Page loads quickly on different screen sizes', async ({ page }) => {
    for (const breakpoint of responsiveBreakpoints) {
      await page.setViewportSize({
        width: breakpoint.width,
        height: breakpoint.height,
      });

      const startTime = Date.now();
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      const loadTime = Date.now() - startTime;

      // 验证加载时间符合标准
      expect(loadTime).toBeLessThan(testStandards.performance.loadTime);

      // 测试交互响应时间
      const button = page.locator('button').first();
      if (await button.isVisible()) {
        const interactionStart = Date.now();
        await button.click();
        await page.waitForLoadState('networkidle');
        const interactionTime = Date.now() - interactionStart;

        expect(interactionTime).toBeLessThan(testStandards.performance.interactionDelay);
      }
    }
  });
});

// 辅助函数
async function measureElementSpacing(page: Page, selector: string): Promise<{
  marginTop: number;
  marginBottom: number;
  paddingTop: number;
  paddingBottom: number;
}> {
  const element = page.locator(selector).first();
  
  return await element.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return {
      marginTop: parseInt(styles.marginTop),
      marginBottom: parseInt(styles.marginBottom),
      paddingTop: parseInt(styles.paddingTop),
      paddingBottom: parseInt(styles.paddingBottom),
    };
  });
}

async function getGridColumnCount(page: Page, gridSelector: string): Promise<number> {
  const grid = page.locator(gridSelector);
  
  return await grid.evaluate(el => {
    const styles = window.getComputedStyle(el);
    const gridTemplate = styles.gridTemplateColumns;
    
    if (gridTemplate && gridTemplate !== 'none') {
      return gridTemplate.split(' ').length;
    }
    
    // 如果没有CSS Grid，计算flex布局的列数
    const children = Array.from(el.children) as HTMLElement[];
    if (children.length === 0) return 0;
    
    const firstChildY = children[0].offsetTop;
    let columnCount = 0;
    
    for (const child of children) {
      if (child.offsetTop === firstChildY) {
        columnCount++;
      } else {
        break;
      }
    }
    
    return columnCount;
  });
}