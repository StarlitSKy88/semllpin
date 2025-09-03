/**
 * Cross-Browser Compatibility Tests
 * 跨浏览器兼容性测试
 */

import { test, expect, Page, Browser } from '@playwright/test';
import { desktopBrowsers, testStandards } from './mobile-device-matrix';

// 浏览器特定功能测试
interface BrowserFeatureTest {
  name: string;
  feature: string;
  testFunction: (page: Page) => Promise<boolean>;
  fallbackRequired: boolean;
}

const browserFeatureTests: BrowserFeatureTest[] = [
  {
    name: 'WebGL Support',
    feature: 'WebGL',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        return !!gl;
      });
    },
    fallbackRequired: true
  },
  {
    name: 'Service Worker Support',
    feature: 'ServiceWorker',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        return 'serviceWorker' in navigator;
      });
    },
    fallbackRequired: true
  },
  {
    name: 'WebRTC Support',
    feature: 'WebRTC',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        return !!(window as any).RTCPeerConnection || !!(window as any).webkitRTCPeerConnection || !!(window as any).mozRTCPeerConnection;
      });
    },
    fallbackRequired: true
  },
  {
    name: 'Geolocation Support',
    feature: 'Geolocation',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        return 'geolocation' in navigator;
      });
    },
    fallbackRequired: false
  },
  {
    name: 'Local Storage Support',
    feature: 'LocalStorage',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        try {
          const test = 'test';
          localStorage.setItem(test, test);
          localStorage.removeItem(test);
          return true;
        } catch (e) {
          return false;
        }
      });
    },
    fallbackRequired: true
  },
  {
    name: 'Push Notifications Support',
    feature: 'PushNotifications',
    testFunction: async (page) => {
      return await page.evaluate(() => {
        return 'Notification' in window && 'serviceWorker' in navigator && 'PushManager' in window;
      });
    },
    fallbackRequired: true
  }
];

test.describe('Cross-Browser Feature Support', () => {
  
  // 为每个浏览器测试功能支持
  for (const browser of desktopBrowsers) {
    test.describe(`${browser.name} Feature Tests`, () => {
      
      test('Core web features availability', async ({ page }) => {
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        
        const featureResults: { [key: string]: boolean } = {};
        
        for (const featureTest of browserFeatureTests) {
          const isSupported = await featureTest.testFunction(page);
          featureResults[featureTest.feature] = isSupported;
          
          // 记录结果
          console.log(`${browser.name} - ${featureTest.name}: ${isSupported ? '✓' : '✗'}`);
          
          // 如果功能不支持但是必需的，检查是否有降级方案
          if (!isSupported && featureTest.fallbackRequired) {
            const fallbackElement = page.locator(`[data-testid="fallback-${featureTest.feature.toLowerCase()}"]`);
            const hasFallback = await fallbackElement.isVisible();
            
            if (hasFallback) {
              console.log(`  → Fallback available for ${featureTest.feature}`);
            } else {
              console.warn(`  ⚠ No fallback found for ${featureTest.feature}`);
            }
          }
        }
        
        // 验证核心功能支持率
        const supportedFeatures = Object.values(featureResults).filter(supported => supported).length;
        const supportRate = (supportedFeatures / browserFeatureTests.length) * 100;
        
        expect(supportRate).toBeGreaterThan(testStandards.compatibility.coverageThreshold);
      });
      
      test('CSS Grid and Flexbox support', async ({ page }) => {
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        
        const cssSupport = await page.evaluate(() => {
          const testEl = document.createElement('div');
          testEl.style.display = 'grid';
          const supportsGrid = testEl.style.display === 'grid';
          
          testEl.style.display = 'flex';
          const supportsFlex = testEl.style.display === 'flex';
          
          return {
            grid: supportsGrid,
            flexbox: supportsFlex
          };
        });
        
        expect(cssSupport.flexbox).toBe(true); // Flexbox should be supported everywhere
        
        if (!cssSupport.grid) {
          // 检查Grid降级方案
          const gridFallback = page.locator('[data-testid="grid-fallback"]');
          if (await gridFallback.isVisible()) {
            console.log(`${browser.name}: CSS Grid fallback detected`);
          }
        }
        
        console.log(`${browser.name} CSS Support - Grid: ${cssSupport.grid}, Flexbox: ${cssSupport.flexbox}`);
      });
      
      test('JavaScript ES6+ features support', async ({ page }) => {
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        
        const jsFeatures = await page.evaluate(() => {
          const features: { [key: string]: boolean } = {};
          
          // Arrow functions
          try {
            eval('(() => {})');
            features.arrowFunctions = true;
          } catch (e) {
            features.arrowFunctions = false;
          }
          
          // Async/await
          try {
            eval('(async () => {})');
            features.asyncAwait = true;
          } catch (e) {
            features.asyncAwait = false;
          }
          
          // Classes
          try {
            eval('class Test {}');
            features.classes = true;
          } catch (e) {
            features.classes = false;
          }
          
          // Template literals
          try {
            eval('`template`');
            features.templateLiterals = true;
          } catch (e) {
            features.templateLiterals = false;
          }
          
          // Destructuring
          try {
            eval('const [a] = [1]');
            features.destructuring = true;
          } catch (e) {
            features.destructuring = false;
          }
          
          // Modules
          features.modules = 'import' in document.createElement('script');
          
          return features;
        });
        
        // 记录支持情况
        for (const [feature, supported] of Object.entries(jsFeatures)) {
          console.log(`${browser.name} - ${feature}: ${supported ? '✓' : '✗'}`);
        }
        
        // 验证核心ES6功能支持
        expect(jsFeatures.arrowFunctions).toBe(true);
        expect(jsFeatures.classes).toBe(true);
      });
    });
  }
});

test.describe('Cross-Browser Visual Consistency', () => {
  
  test('Layout rendering consistency', async ({ page }) => {
    const testPages = ['/', '/map', '/annotations', '/login'];
    
    for (const pagePath of testPages) {
      await page.goto(pagePath);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000); // 等待动画完成
      
      // 截图用于视觉对比
      const browserName = page.context().browser()?.browserType().name() || 'unknown';
      await page.screenshot({
        path: `test-results/cross-browser-${browserName}-${pagePath.replace('/', 'home')}.png`,
        fullPage: true
      });
      
      // 验证关键元素是否存在
      const keyElements = [
        '[data-testid="main-navigation"]',
        '[data-testid="main-content"]',
        '[data-testid="footer"]'
      ];
      
      for (const selector of keyElements) {
        const element = page.locator(selector);
        if (await element.count() > 0) {
          await expect(element.first()).toBeVisible();
        }
      }
    }
  });
  
  test('Font rendering and typography', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 测试字体加载和渲染
    const fontMetrics = await page.evaluate(() => {
      const testTexts = document.querySelectorAll('h1, h2, h3, p');
      const metrics: Array<{
        element: string;
        fontSize: string;
        fontFamily: string;
        lineHeight: string;
      }> = [];
      
      testTexts.forEach((el, index) => {
        if (index < 10) { // 限制测试数量
          const styles = window.getComputedStyle(el);
          metrics.push({
            element: el.tagName.toLowerCase(),
            fontSize: styles.fontSize,
            fontFamily: styles.fontFamily,
            lineHeight: styles.lineHeight
          });
        }
      });
      
      return metrics;
    });
    
    // 验证字体指标一致性
    for (const metric of fontMetrics) {
      expect(metric.fontSize).toMatch(/^\d+(\.\d+)?px$/); // 应该有有效的像素值
      expect(metric.fontFamily).toBeTruthy(); // 应该有字体族
      
      console.log(`${metric.element}: ${metric.fontSize}, ${metric.fontFamily}`);
    }
  });
  
  test('Color and theme consistency', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 测试主题颜色
    const colorScheme = await page.evaluate(() => {
      const root = document.documentElement;
      const styles = window.getComputedStyle(root);
      
      // 获取CSS变量定义的颜色
      const colors = {
        primary: styles.getPropertyValue('--color-primary').trim(),
        secondary: styles.getPropertyValue('--color-secondary').trim(),
        background: styles.getPropertyValue('--color-background').trim(),
        text: styles.getPropertyValue('--color-text').trim()
      };
      
      return colors;
    });
    
    // 验证主题颜色存在
    for (const [colorName, colorValue] of Object.entries(colorScheme)) {
      if (colorValue) {
        expect(colorValue).toMatch(/^(#[0-9a-f]{3,6}|rgb\(|hsl\()/i);
        console.log(`${colorName}: ${colorValue}`);
      }
    }
    
    // 测试暗色主题切换（如果存在）
    const themeToggle = page.locator('[data-testid="theme-toggle"]');
    if (await themeToggle.isVisible()) {
      await themeToggle.click();
      await page.waitForTimeout(500);
      
      const darkModeActive = await page.evaluate(() => {
        return document.documentElement.classList.contains('dark') ||
               document.body.classList.contains('dark-mode');
      });
      
      if (darkModeActive) {
        console.log('Dark mode activated successfully');
      }
    }
  });
});

test.describe('Cross-Browser Performance', () => {
  
  test('JavaScript execution performance', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 测试JavaScript性能
    const jsPerformance = await page.evaluate(() => {
      const start = performance.now();
      
      // 执行一些计算密集任务
      let result = 0;
      for (let i = 0; i < 100000; i++) {
        result += Math.sin(i) * Math.cos(i);
      }
      
      const executionTime = performance.now() - start;
      
      return {
        executionTime,
        result: result.toFixed(2)
      };
    });
    
    const browserName = page.context().browser()?.browserType().name() || 'unknown';
    console.log(`${browserName} JS execution time: ${jsPerformance.executionTime.toFixed(2)}ms`);
    
    // 验证性能在合理范围内
    expect(jsPerformance.executionTime).toBeLessThan(1000); // 应该在1秒内完成
  });
  
  test('DOM manipulation performance', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    const domPerformance = await page.evaluate(() => {
      const start = performance.now();
      
      // 创建和操作DOM元素
      const container = document.createElement('div');
      document.body.appendChild(container);
      
      for (let i = 0; i < 1000; i++) {
        const element = document.createElement('div');
        element.textContent = `Element ${i}`;
        element.className = 'test-element';
        container.appendChild(element);
      }
      
      // 查询和修改元素
      const elements = container.querySelectorAll('.test-element');
      elements.forEach((el, index) => {
        if (index % 2 === 0) {
          el.classList.add('even');
        }
      });
      
      // 清理
      document.body.removeChild(container);
      
      const domTime = performance.now() - start;
      
      return {
        domTime,
        elementsCreated: 1000
      };
    });
    
    const browserName = page.context().browser()?.browserType().name() || 'unknown';
    console.log(`${browserName} DOM manipulation time: ${domPerformance.domTime.toFixed(2)}ms`);
    
    // 验证DOM操作性能
    expect(domPerformance.domTime).toBeLessThan(2000); // 应该在2秒内完成
  });
});

test.describe('Cross-Browser Error Handling', () => {
  
  test('JavaScript error handling consistency', async ({ page }) => {
    const jsErrors: string[] = [];
    const consoleErrors: string[] = [];
    
    // 监听JavaScript错误
    page.on('pageerror', (error) => {
      jsErrors.push(error.message);
    });
    
    // 监听控制台错误
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // 导航到不同页面检查错误
    const testPages = ['/map', '/annotations', '/login'];
    
    for (const pagePath of testPages) {
      await page.goto(pagePath);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
    }
    
    // 记录错误情况
    const browserName = page.context().browser()?.browserType().name() || 'unknown';
    console.log(`${browserName} - JavaScript errors: ${jsErrors.length}`);
    console.log(`${browserName} - Console errors: ${consoleErrors.length}`);
    
    if (jsErrors.length > 0) {
      console.log('JavaScript Errors:', jsErrors);
    }
    
    if (consoleErrors.length > 0) {
      console.log('Console Errors:', consoleErrors);
    }
    
    // 验证错误数量在可接受范围内
    expect(jsErrors.length).toBeLessThan(5); // 允许少量非关键错误
    expect(consoleErrors.length).toBeLessThan(10); // 允许一些警告级别的控制台输出
  });
  
  test('Network error handling', async ({ page }) => {
    // 测试网络请求错误处理
    await page.route('**/api/annotations', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal Server Error' })
      });
    });
    
    await page.goto('/annotations');
    await page.waitForLoadState('networkidle');
    
    // 检查错误处理UI
    const errorMessage = page.locator('[data-testid="error-message"]');
    const retryButton = page.locator('[data-testid="retry-button"]');
    
    // 应该显示友好的错误信息
    const hasErrorUI = await errorMessage.isVisible() || await retryButton.isVisible();
    expect(hasErrorUI).toBe(true);
    
    console.log('Network error handling UI present');
  });
});

// 辅助函数

/**
 * 比较不同浏览器的截图差异
 */
async function compareScreenshots(page1Path: string, page2Path: string): Promise<number> {
  // 这里可以集成图像对比工具如 pixelmatch
  // 返回差异百分比
  return 0; // 占位符
}

/**
 * 检测浏览器用户代理
 */
async function detectBrowserUserAgent(page: Page): Promise<string> {
  return await page.evaluate(() => navigator.userAgent);
}

/**
 * 测试浏览器特定的API兼容性
 */
async function testBrowserSpecificAPIs(page: Page): Promise<{ [key: string]: boolean }> {
  return await page.evaluate(() => {
    const apis: { [key: string]: boolean } = {};
    
    // 测试各种Web API
    apis.fetch = 'fetch' in window;
    apis.promise = 'Promise' in window;
    apis.intersectionObserver = 'IntersectionObserver' in window;
    apis.mutationObserver = 'MutationObserver' in window;
    apis.webWorker = 'Worker' in window;
    apis.webSocket = 'WebSocket' in window;
    apis.indexedDB = 'indexedDB' in window;
    apis.canvas = 'HTMLCanvasElement' in window;
    apis.webAudio = 'AudioContext' in window || 'webkitAudioContext' in window;
    apis.fileReader = 'FileReader' in window;
    apis.formData = 'FormData' in window;
    apis.history = 'history' in window && 'pushState' in history;
    
    return apis;
  });
}

/**
 * 验证CSS属性支持
 */
async function testCSSPropertySupport(page: Page, property: string, value: string): Promise<boolean> {
  return await page.evaluate(({ prop, val }) => {
    const testEl = document.createElement('div');
    testEl.style.setProperty(prop, val);
    return testEl.style.getPropertyValue(prop) === val;
  }, { prop: property, val: value });
}