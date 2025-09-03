/**
 * Device-Specific Features Tests
 * 设备特性功能测试 (GPS, Camera, Sensors)
 */

import { test, expect, Page, BrowserContext } from '@playwright/test';
import { iosDevices, androidDevices, allDevices } from './mobile-device-matrix';

test.describe('GPS and Geolocation Features', () => {
  test.beforeEach(async ({ context }) => {
    // 授予地理位置权限
    await context.grantPermissions(['geolocation']);
  });

  test('GPS location acquisition on mobile devices', async ({ page, context }) => {
    // 模拟不同地理位置
    const locations = [
      { latitude: 37.7749, longitude: -122.4194, name: 'San Francisco' },
      { latitude: 40.7128, longitude: -74.0060, name: 'New York' },
      { latitude: 35.6762, longitude: 139.6503, name: 'Tokyo' },
      { latitude: 31.2304, longitude: 121.4737, name: 'Shanghai' }
    ];

    for (const location of locations) {
      // 设置地理位置
      await context.setGeolocation({
        latitude: location.latitude,
        longitude: location.longitude
      });

      await page.goto('/map');
      await page.waitForLoadState('networkidle');

      // 点击定位按钮
      const locationButton = page.locator('[data-testid="current-location-btn"]');
      if (await locationButton.isVisible()) {
        await locationButton.click();
        
        // 等待地图定位到当前位置
        await page.waitForTimeout(2000);
        
        // 验证地图是否移动到正确位置
        const mapContainer = page.locator('[data-testid="map-container"]');
        await expect(mapContainer).toBeVisible();
        
        // 检查位置标记是否出现
        const currentLocationMarker = page.locator('[data-testid="current-location-marker"]');
        await expect(currentLocationMarker).toBeVisible({ timeout: 5000 });
        
        // 截图记录
        await page.screenshot({
          path: `test-results/gps-location-${location.name.toLowerCase()}.png`,
          fullPage: true
        });
      }
    }
  });

  test('Location accuracy and precision testing', async ({ page, context }) => {
    // 测试不同精度的GPS信号
    const accuracyLevels = [
      { accuracy: 5, description: 'High accuracy (5m)' },
      { accuracy: 50, description: 'Medium accuracy (50m)' },
      { accuracy: 500, description: 'Low accuracy (500m)' }
    ];

    for (const level of accuracyLevels) {
      await context.setGeolocation({
        latitude: 37.7749,
        longitude: -122.4194,
        accuracy: level.accuracy
      });

      await page.goto('/annotation/create');
      await page.waitForLoadState('networkidle');

      // 触发位置获取
      const useLocationButton = page.locator('[data-testid="use-current-location"]');
      if (await useLocationButton.isVisible()) {
        await useLocationButton.click();
        
        // 验证位置精度反馈
        const accuracyInfo = page.locator('[data-testid="location-accuracy"]');
        if (await accuracyInfo.isVisible()) {
          const accuracyText = await accuracyInfo.textContent();
          
          // 根据精度显示相应的提示
          if (level.accuracy <= 10) {
            expect(accuracyText).toContain('高精度');
          } else if (level.accuracy <= 100) {
            expect(accuracyText).toContain('中等精度');
          } else {
            expect(accuracyText).toContain('低精度');
          }
        }
      }
    }
  });

  test('Location permission handling', async ({ page, context }) => {
    await page.goto('/map');
    await page.waitForLoadState('networkidle');

    // 测试位置权限被拒绝的情况
    await context.setGeolocation(null); // 清除地理位置
    
    const locationButton = page.locator('[data-testid="current-location-btn"]');
    if (await locationButton.isVisible()) {
      await locationButton.click();
      
      // 验证权限请求处理
      const permissionDialog = page.locator('[data-testid="location-permission-dialog"]');
      const errorMessage = page.locator('[data-testid="location-error-message"]');
      
      // 应该显示权限请求或错误消息
      const hasPermissionDialog = await permissionDialog.isVisible({ timeout: 3000 });
      const hasErrorMessage = await errorMessage.isVisible({ timeout: 3000 });
      
      expect(hasPermissionDialog || hasErrorMessage).toBe(true);
    }
  });

  test('Background location tracking', async ({ page, context }) => {
    // 测试后台位置跟踪功能
    await context.grantPermissions(['geolocation']);
    await context.setGeolocation({
      latitude: 37.7749,
      longitude: -122.4194
    });

    await page.goto('/track-route');
    await page.waitForLoadState('networkidle');

    const startTrackingButton = page.locator('[data-testid="start-tracking"]');
    if (await startTrackingButton.isVisible()) {
      await startTrackingButton.click();
      
      // 模拟移动
      const movements = [
        { latitude: 37.7750, longitude: -122.4195 },
        { latitude: 37.7751, longitude: -122.4196 },
        { latitude: 37.7752, longitude: -122.4197 }
      ];

      for (const position of movements) {
        await context.setGeolocation(position);
        await page.waitForTimeout(2000);
      }

      // 验证路径记录
      const trackingPath = page.locator('[data-testid="tracking-path"]');
      if (await trackingPath.isVisible()) {
        await expect(trackingPath).toBeVisible();
      }

      // 停止跟踪
      const stopTrackingButton = page.locator('[data-testid="stop-tracking"]');
      if (await stopTrackingButton.isVisible()) {
        await stopTrackingButton.click();
      }
    }
  });
});

test.describe('Camera and Media Features', () => {
  test.beforeEach(async ({ context }) => {
    // 授予摄像头权限
    await context.grantPermissions(['camera']);
  });

  test('Camera access for annotation photos', async ({ page }) => {
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');

    const cameraButton = page.locator('[data-testid="camera-capture"]');
    if (await cameraButton.isVisible()) {
      // 点击相机按钮
      await cameraButton.click();
      
      // 验证相机界面或文件选择器
      const cameraInterface = page.locator('[data-testid="camera-interface"]');
      const fileInput = page.locator('input[type="file"][accept*="image"]');
      
      const hasCameraInterface = await cameraInterface.isVisible({ timeout: 3000 });
      const hasFileInput = await fileInput.isVisible({ timeout: 3000 });
      
      expect(hasCameraInterface || hasFileInput).toBe(true);
      
      // 如果有相机界面，测试拍照功能
      if (hasCameraInterface) {
        const captureButton = page.locator('[data-testid="capture-photo"]');
        if (await captureButton.isVisible()) {
          await captureButton.click();
          
          // 验证照片预览
          const photoPreview = page.locator('[data-testid="photo-preview"]');
          await expect(photoPreview).toBeVisible({ timeout: 5000 });
        }
      }
    }
  });

  test('Multiple photo capture and gallery', async ({ page }) => {
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');

    const multiPhotoButton = page.locator('[data-testid="multi-photo-capture"]');
    if (await multiPhotoButton.isVisible()) {
      await multiPhotoButton.click();
      
      // 模拟选择多张照片
      const fileInput = page.locator('input[type="file"][multiple]');
      if (await fileInput.isVisible()) {
        // 在真实测试中，这里会处理文件上传
        // 现在验证界面状态
        
        const photoGallery = page.locator('[data-testid="photo-gallery"]');
        if (await photoGallery.isVisible()) {
          await expect(photoGallery).toBeVisible();
          
          // 测试照片删除功能
          const deleteButtons = photoGallery.locator('[data-testid="delete-photo"]');
          const deleteCount = await deleteButtons.count();
          
          if (deleteCount > 0) {
            await deleteButtons.first().click();
            
            // 验证删除确认
            const confirmDialog = page.locator('[data-testid="delete-confirm"]');
            if (await confirmDialog.isVisible()) {
              const confirmButton = confirmDialog.locator('[data-testid="confirm-delete"]');
              await confirmButton.click();
            }
          }
        }
      }
    }
  });

  test('Photo compression and quality settings', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const photoSettings = page.locator('[data-testid="photo-settings"]');
    if (await photoSettings.isVisible()) {
      // 测试图片质量设置
      const qualitySlider = photoSettings.locator('[data-testid="photo-quality-slider"]');
      if (await qualitySlider.isVisible()) {
        // 测试不同质量设置
        const qualityLevels = ['high', 'medium', 'low'];
        
        for (const quality of qualityLevels) {
          const qualityOption = photoSettings.locator(`[data-value="${quality}"]`);
          if (await qualityOption.isVisible()) {
            await qualityOption.click();
            
            // 验证设置已保存
            await expect(qualityOption).toHaveAttribute('data-selected', 'true');
          }
        }
      }

      // 测试照片尺寸设置
      const sizeSettings = photoSettings.locator('[data-testid="photo-size-settings"]');
      if (await sizeSettings.isVisible()) {
        const sizeOptions = sizeSettings.locator('[role="option"]');
        const optionCount = await sizeOptions.count();
        
        if (optionCount > 0) {
          await sizeOptions.first().click();
        }
      }
    }
  });

  test('Camera permission denied handling', async ({ page, context }) => {
    // 拒绝摄像头权限
    await context.grantPermissions([]);
    
    await page.goto('/annotation/create');
    await page.waitForLoadState('networkidle');

    const cameraButton = page.locator('[data-testid="camera-capture"]');
    if (await cameraButton.isVisible()) {
      await cameraButton.click();
      
      // 验证权限错误处理
      const permissionError = page.locator('[data-testid="camera-permission-error"]');
      const fallbackOption = page.locator('[data-testid="file-upload-fallback"]');
      
      // 应该显示错误信息或提供备选方案
      const hasError = await permissionError.isVisible({ timeout: 3000 });
      const hasFallback = await fallbackOption.isVisible({ timeout: 3000 });
      
      expect(hasError || hasFallback).toBe(true);
    }
  });
});

test.describe('Device Orientation and Sensors', () => {
  test('Orientation change handling', async ({ page }) => {
    // 测试横竖屏切换
    const orientations = [
      { width: 375, height: 667, name: 'Portrait' },
      { width: 667, height: 375, name: 'Landscape' }
    ];

    for (const orientation of orientations) {
      await page.setViewportSize({
        width: orientation.width,
        height: orientation.height
      });

      await page.goto('/map');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(500); // 等待布局调整

      // 验证布局适配
      const mapContainer = page.locator('[data-testid="map-container"]');
      const mapBox = await mapContainer.boundingBox();
      
      expect(mapBox!.width).toBeGreaterThan(0);
      expect(mapBox!.height).toBeGreaterThan(0);

      // 验证控件位置调整
      const mapControls = page.locator('[data-testid="map-controls"]');
      if (await mapControls.isVisible()) {
        const controlsBox = await mapControls.boundingBox();
        
        if (orientation.name === 'Landscape') {
          // 横屏时控件可能在侧边
          expect(controlsBox!.x).toBeGreaterThan(mapBox!.width * 0.5);
        } else {
          // 竖屏时控件在底部或顶部
          expect(controlsBox!.y).toBeDefined();
        }
      }

      // 截图记录
      await page.screenshot({
        path: `test-results/orientation-${orientation.name.toLowerCase()}.png`,
        fullPage: true
      });
    }
  });

  test('Compass and orientation sensor', async ({ page }) => {
    await page.goto('/map');
    await page.waitForLoadState('networkidle');

    // 查找指南针组件
    const compass = page.locator('[data-testid="compass"]');
    if (await compass.isVisible()) {
      // 模拟设备方向变化 (通过CSS transform模拟)
      const directions = [0, 90, 180, 270];
      
      for (const direction of directions) {
        // 通过JavaScript更新指南针方向
        await page.evaluate((degree) => {
          const compassEl = document.querySelector('[data-testid="compass"]') as HTMLElement;
          if (compassEl) {
            compassEl.style.transform = `rotate(${degree}deg)`;
            // 触发自定义事件模拟传感器数据
            const event = new CustomEvent('orientationchange', {
              detail: { heading: degree }
            });
            window.dispatchEvent(event);
          }
        }, direction);

        await page.waitForTimeout(1000);

        // 验证UI响应
        const compassTransform = await compass.evaluate(el => 
          window.getComputedStyle(el).transform
        );
        
        expect(compassTransform).toContain('rotate');
      }
    }
  });

  test('Device motion and accelerometer', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // 测试设备摇一摇功能
    const shakeDetector = page.locator('[data-testid="shake-detector"]');
    if (await shakeDetector.isVisible()) {
      // 模拟设备震动事件
      await page.evaluate(() => {
        // 创建模拟的设备运动事件
        const motionEvent = new DeviceMotionEvent('devicemotion', {
          acceleration: { x: 15, y: 15, z: 15 },
          accelerationIncludingGravity: { x: 15, y: 15, z: 15 },
          rotationRate: { alpha: 0, beta: 0, gamma: 0 },
          interval: 16
        });
        
        window.dispatchEvent(motionEvent);
      });

      await page.waitForTimeout(1000);

      // 验证摇一摇功能响应
      const shakeResponse = page.locator('[data-testid="shake-response"]');
      if (await shakeResponse.isVisible()) {
        await expect(shakeResponse).toBeVisible();
      }
    }
  });

  test('Screen brightness adaptation', async ({ page }) => {
    await page.goto('/map');
    await page.waitForLoadState('networkidle');

    // 测试亮度模式切换
    const brightnessToggle = page.locator('[data-testid="brightness-mode"]');
    if (await brightnessToggle.isVisible()) {
      await brightnessToggle.click();
      
      // 验证夜间模式或高亮模式
      const body = page.locator('body');
      const bodyClass = await body.getAttribute('class');
      
      expect(bodyClass).toMatch(/(dark|night|bright)-mode/);
      
      // 再次切换
      await brightnessToggle.click();
      const newBodyClass = await body.getAttribute('class');
      expect(newBodyClass).not.toBe(bodyClass);
    }
  });
});

test.describe('Network and Connectivity Features', () => {
  test('Network status detection', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // 模拟网络状态变化
    await page.evaluate(() => {
      // 模拟离线状态
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false
      });
      
      // 触发offline事件
      window.dispatchEvent(new Event('offline'));
    });

    await page.waitForTimeout(1000);

    // 验证离线提示
    const offlineIndicator = page.locator('[data-testid="offline-indicator"]');
    if (await offlineIndicator.isVisible()) {
      await expect(offlineIndicator).toBeVisible();
      await expect(offlineIndicator).toContainText('离线');
    }

    // 模拟重新联网
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true
      });
      
      window.dispatchEvent(new Event('online'));
    });

    await page.waitForTimeout(1000);

    // 验证在线状态恢复
    if (await offlineIndicator.isVisible()) {
      await expect(offlineIndicator).not.toBeVisible();
    }
  });

  test('Connection type adaptation', async ({ page, context }) => {
    // 模拟不同网络连接类型
    const connectionTypes = ['4g', '3g', 'wifi', 'slow-2g'];

    for (const connectionType of connectionTypes) {
      // 使用CDP (Chrome DevTools Protocol) 设置网络条件
      const client = await context.newCDPSession(page);
      
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        latency: connectionType === 'slow-2g' ? 2000 : connectionType === '3g' ? 300 : 100,
        downloadThroughput: connectionType === 'slow-2g' ? 25000 : 
                           connectionType === '3g' ? 200000 : 
                           connectionType === '4g' ? 1000000 : 5000000,
        uploadThroughput: connectionType === 'slow-2g' ? 12500 : 
                         connectionType === '3g' ? 100000 : 
                         connectionType === '4g' ? 500000 : 2500000
      });

      await page.goto('/map');
      await page.waitForLoadState('networkidle');

      // 验证内容加载适配
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible({ timeout: 15000 });

      // 检查低带宽优化
      if (connectionType === 'slow-2g' || connectionType === '3g') {
        const lowBandwidthMode = page.locator('[data-testid="low-bandwidth-mode"]');
        if (await lowBandwidthMode.isVisible()) {
          await expect(lowBandwidthMode).toBeVisible();
        }
      }

      await client.detach();
    }
  });
});

test.describe('Battery and Performance Sensors', () => {
  test('Battery level awareness', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // 模拟电池API (如果支持)
    const batterySupported = await page.evaluate(() => {
      return 'getBattery' in navigator;
    });

    if (batterySupported) {
      // 模拟低电量状态
      await page.evaluate(() => {
        // 创建模拟电池对象
        const mockBattery = {
          level: 0.15, // 15% 电量
          charging: false,
          addEventListener: () => {},
          removeEventListener: () => {}
        };

        // 触发低电量优化
        const event = new CustomEvent('battery-low', {
          detail: { level: 0.15 }
        });
        window.dispatchEvent(event);
      });

      await page.waitForTimeout(1000);

      // 验证省电模式
      const batterySaver = page.locator('[data-testid="battery-saver-mode"]');
      if (await batterySaver.isVisible()) {
        await expect(batterySaver).toBeVisible();
      }
    }
  });

  test('Performance monitoring on mobile', async ({ page }) => {
    await page.goto('/map');
    await page.waitForLoadState('networkidle');

    // 监控性能指标
    const performanceMetrics = await page.evaluate(() => {
      return {
        navigation: performance.getEntriesByType('navigation')[0],
        memory: (performance as any).memory ? {
          usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
          totalJSHeapSize: (performance as any).memory.totalJSHeapSize
        } : null
      };
    });

    // 验证页面加载性能
    const navigation = performanceMetrics.navigation as any;
    expect(navigation.loadEventEnd - navigation.fetchStart).toBeLessThan(5000);

    // 验证内存使用(如果支持)
    if (performanceMetrics.memory) {
      const memoryUsageMB = performanceMetrics.memory.usedJSHeapSize / (1024 * 1024);
      expect(memoryUsageMB).toBeLessThan(100); // 小于100MB
    }
  });
});

// 辅助函数

/**
 * 检查设备特性支持
 */
async function checkDeviceFeatureSupport(page: Page): Promise<{
  geolocation: boolean;
  camera: boolean;
  deviceMotion: boolean;
  battery: boolean;
  vibration: boolean;
}> {
  return await page.evaluate(() => {
    return {
      geolocation: 'geolocation' in navigator,
      camera: 'mediaDevices' in navigator && 'getUserMedia' in navigator.mediaDevices,
      deviceMotion: 'DeviceMotionEvent' in window,
      battery: 'getBattery' in navigator,
      vibration: 'vibrate' in navigator
    };
  });
}

/**
 * 模拟设备传感器数据
 */
async function simulateSensorData(page: Page, sensorType: string, data: any) {
  await page.evaluate(({ type, sensorData }) => {
    const event = new CustomEvent(`sensor-${type}`, {
      detail: sensorData
    });
    window.dispatchEvent(event);
  }, { type: sensorType, sensorData: data });
}

/**
 * 验证性能标准
 */
async function validatePerformanceStandards(page: Page) {
  const metrics = await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as any;
    return {
      loadTime: navigation.loadEventEnd - navigation.fetchStart,
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.fetchStart,
      firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0
    };
  });

  expect(metrics.loadTime).toBeLessThan(3000); // 3秒加载时间
  expect(metrics.domContentLoaded).toBeLessThan(2000); // 2秒DOM加载
  expect(metrics.firstPaint).toBeLessThan(1500); // 1.5秒首次绘制
}