/**
 * Playwright Configuration for Mobile Compatibility Testing
 * 移动端兼容性测试的Playwright配置
 */

import { defineConfig, devices } from '@playwright/test';
import { 
  iosDevices, 
  androidDevices, 
  desktopBrowsers, 
  networkConditions,
  testStandards 
} from './mobile-device-matrix';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000';
const frontendURL = process.env.FRONTEND_URL || 'http://localhost:3001';

export default defineConfig({
  testDir: './compatibility',
  
  // 全局配置
  timeout: 60000, // 60秒超时
  expect: {
    timeout: 10000, // 断言超时10秒
  },
  
  // 并发配置
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 4 : 2,
  
  // 报告配置
  reporter: [
    ['html', { outputFolder: 'compatibility-report' }],
    ['json', { outputFile: 'compatibility-results.json' }],
    ['junit', { outputFile: 'compatibility-results.xml' }],
    ['list'],
  ],
  
  // 全局设置
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    
    // 启用所有必要的权限
    permissions: ['geolocation', 'camera', 'microphone', 'notifications'],
    
    // 性能监控
    actionTimeout: testStandards.performance.interactionDelay,
  },
  
  projects: [
    // ==== iOS设备测试 ====
    ...iosDevices.map((device) => ({
      name: `iOS-${device.name}`,
      use: {
        ...devices['iPhone 12 Pro'], // 使用Playwright预设作为基础
        viewport: device.viewport,
        userAgent: device.userAgent,
        deviceScaleFactor: device.viewport.deviceScaleFactor,
        isMobile: device.viewport.isMobile,
        hasTouch: device.viewport.hasTouch,
        
        // iOS特定设置
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 }, // San Francisco
        },
      },
      testMatch: [
        '**/mobile-responsive.test.ts',
        '**/touch-gestures.test.ts',
        '**/ios-specific.test.ts',
        '**/device-features.test.ts',
        '**/performance-mobile.test.ts',
      ],
    })),
    
    // ==== Android设备测试 ====
    ...androidDevices.map((device) => ({
      name: `Android-${device.name}`,
      use: {
        ...devices['Pixel 5'], // 使用Playwright预设作为基础
        viewport: device.viewport,
        userAgent: device.userAgent,
        deviceScaleFactor: device.viewport.deviceScaleFactor,
        isMobile: device.viewport.isMobile,
        hasTouch: device.viewport.hasTouch,
        
        // Android特定设置
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/mobile-responsive.test.ts',
        '**/touch-gestures.test.ts',
        '**/android-specific.test.ts',
        '**/device-features.test.ts',
        '**/performance-mobile.test.ts',
      ],
    })),
    
    // ==== 桌面浏览器测试 ====
    {
      name: 'Desktop-Chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/desktop-responsive.test.ts',
        '**/cross-browser.test.ts',
        '**/performance-desktop.test.ts',
      ],
    },
    
    {
      name: 'Desktop-Firefox',
      use: {
        ...devices['Desktop Firefox'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/desktop-responsive.test.ts',
        '**/cross-browser.test.ts',
        '**/firefox-specific.test.ts',
      ],
    },
    
    {
      name: 'Desktop-Safari',
      use: {
        ...devices['Desktop Safari'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/desktop-responsive.test.ts',
        '**/cross-browser.test.ts',
        '**/safari-specific.test.ts',
      ],
    },
    
    {
      name: 'Desktop-Edge',
      use: {
        ...devices['Microsoft Edge'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/desktop-responsive.test.ts',
        '**/cross-browser.test.ts',
      ],
    },
    
    // ==== 平板设备测试 ====
    {
      name: 'Tablet-iPad',
      use: {
        ...devices['iPad Pro'],
        contextOptions: {
          geolocation: { latitude: 37.7749, longitude: -122.4194 },
        },
      },
      testMatch: [
        '**/tablet-responsive.test.ts',
        '**/touch-gestures.test.ts',
        '**/orientation.test.ts',
      ],
    },
    
    // ==== 网络条件测试 ====
    ...networkConditions.map((network) => ({
      name: `Network-${network.name}`,
      use: {
        ...devices['Desktop Chrome'],
        contextOptions: {
          // 网络节流设置
          offline: false,
          downloadThroughput: network.downloadThroughput,
          uploadThroughput: network.uploadThroughput,
          latency: network.latency,
        },
      },
      testMatch: [
        '**/network-performance.test.ts',
        '**/offline-mode.test.ts',
      ],
    })),
  ],
  
  // Web服务器配置
  webServer: [
    {
      command: 'npm run dev',
      port: 3000,
      reuseExistingServer: !process.env.CI,
      env: {
        NODE_ENV: 'test',
      },
    },
    {
      command: 'cd frontend && npm run dev',
      port: 3001,
      reuseExistingServer: !process.env.CI,
      env: {
        NODE_ENV: 'test',
        NEXT_PUBLIC_API_URL: baseURL,
      },
    },
  ],
});

// 导出辅助函数
export function createNetworkCondition(networkName: string) {
  const network = networkConditions.find(n => n.name === networkName);
  if (!network) {
    throw new Error(`Network condition "${networkName}" not found`);
  }
  
  return {
    offline: false,
    downloadThroughput: network.downloadThroughput,
    uploadThroughput: network.uploadThroughput,
    latency: network.latency,
  };
}

export function createDeviceViewport(deviceName: string) {
  const allDeviceConfigs = [...iosDevices, ...androidDevices];
  const device = allDeviceConfigs.find(d => d.name === deviceName);
  if (!device) {
    throw new Error(`Device "${deviceName}" not found`);
  }
  
  return device.viewport;
}