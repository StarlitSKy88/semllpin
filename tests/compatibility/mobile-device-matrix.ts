/**
 * SmellPin Mobile Device Compatibility Test Matrix
 * 移动设备兼容性测试矩阵配置
 */

export interface DeviceConfig {
  name: string;
  userAgent: string;
  viewport: {
    width: number;
    height: number;
    deviceScaleFactor: number;
    isMobile: boolean;
    hasTouch: boolean;
  };
  capabilities: {
    gps: boolean;
    camera: boolean;
    orientation: boolean;
    networkInfo: boolean;
  };
}

export interface BrowserConfig {
  name: string;
  browserType: 'chromium' | 'firefox' | 'webkit';
  version: string;
  features: {
    webGL: boolean;
    serviceWorker: boolean;
    webRTC: boolean;
    geolocation: boolean;
    pushNotifications: boolean;
  };
}

// iOS设备配置
export const iosDevices: DeviceConfig[] = [
  {
    name: 'iPhone 14 Pro',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    viewport: {
      width: 393,
      height: 852,
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: true,
    },
  },
  {
    name: 'iPhone 12',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
    viewport: {
      width: 390,
      height: 844,
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: true,
    },
  },
  {
    name: 'iPad Pro 12.9',
    userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    viewport: {
      width: 1024,
      height: 1366,
      deviceScaleFactor: 2,
      isMobile: false,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: true,
    },
  },
];

// Android设备配置
export const androidDevices: DeviceConfig[] = [
  {
    name: 'Samsung Galaxy S23',
    userAgent: 'Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    viewport: {
      width: 360,
      height: 780,
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: true,
    },
  },
  {
    name: 'Google Pixel 7',
    userAgent: 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    viewport: {
      width: 412,
      height: 915,
      deviceScaleFactor: 2.625,
      isMobile: true,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: true,
    },
  },
  {
    name: 'Huawei P40',
    userAgent: 'Mozilla/5.0 (Linux; Android 10; ELS-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    viewport: {
      width: 360,
      height: 760,
      deviceScaleFactor: 2.5,
      isMobile: true,
      hasTouch: true,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: true,
      networkInfo: false, // 华为服务限制
    },
  },
];

// 桌面浏览器配置
export const desktopBrowsers: BrowserConfig[] = [
  {
    name: 'Chrome 119+',
    browserType: 'chromium',
    version: '119.0.0.0',
    features: {
      webGL: true,
      serviceWorker: true,
      webRTC: true,
      geolocation: true,
      pushNotifications: true,
    },
  },
  {
    name: 'Firefox 119+',
    browserType: 'firefox',
    version: '119.0.0',
    features: {
      webGL: true,
      serviceWorker: true,
      webRTC: true,
      geolocation: true,
      pushNotifications: true,
    },
  },
  {
    name: 'Safari 17+',
    browserType: 'webkit',
    version: '17.0.0',
    features: {
      webGL: true,
      serviceWorker: true,
      webRTC: true,
      geolocation: true,
      pushNotifications: false, // Safari推送限制
    },
  },
  {
    name: 'Edge 119+',
    browserType: 'chromium',
    version: '119.0.0.0',
    features: {
      webGL: true,
      serviceWorker: true,
      webRTC: true,
      geolocation: true,
      pushNotifications: true,
    },
  },
];

// 网络连接配置
export interface NetworkConfig {
  name: string;
  downloadThroughput: number; // bytes/s
  uploadThroughput: number;   // bytes/s
  latency: number;           // ms
  packetLoss: number;        // percentage
}

export const networkConditions: NetworkConfig[] = [
  {
    name: '3G',
    downloadThroughput: 1.6 * 1024 * 1024 / 8, // 1.6Mbps
    uploadThroughput: 750 * 1024 / 8,           // 750Kbps
    latency: 300,
    packetLoss: 0,
  },
  {
    name: '4G',
    downloadThroughput: 9 * 1024 * 1024 / 8,   // 9Mbps
    uploadThroughput: 3 * 1024 * 1024 / 8,     // 3Mbps
    latency: 100,
    packetLoss: 0,
  },
  {
    name: 'WiFi',
    downloadThroughput: 30 * 1024 * 1024 / 8,  // 30Mbps
    uploadThroughput: 15 * 1024 * 1024 / 8,    // 15Mbps
    latency: 20,
    packetLoss: 0,
  },
  {
    name: 'Slow WiFi',
    downloadThroughput: 2 * 1024 * 1024 / 8,   // 2Mbps
    uploadThroughput: 1 * 1024 * 1024 / 8,     // 1Mbps
    latency: 500,
    packetLoss: 2,
  },
];

// 测试标准配置
export interface TestStandards {
  performance: {
    loadTime: number;      // 页面加载时间 (ms)
    interactionDelay: number; // 交互响应时间 (ms)
    scrollFPS: number;     // 滚动帧率
    memoryUsage: number;   // 内存使用限制 (MB)
  };
  compatibility: {
    coverageThreshold: number; // 兼容性覆盖率阈值
    criticalFeatures: string[]; // 关键功能列表
    fallbackRequired: string[]; // 需要降级处理的功能
  };
}

export const testStandards: TestStandards = {
  performance: {
    loadTime: 3000,        // < 3秒加载时间
    interactionDelay: 200, // < 200ms交互响应
    scrollFPS: 50,         // > 50 FPS滚动
    memoryUsage: 100,      // < 100MB内存使用
  },
  compatibility: {
    coverageThreshold: 95,  // 95%兼容性覆盖
    criticalFeatures: [
      'map-rendering',
      'gps-location',
      'touch-gestures',
      'file-upload',
      'payment-flow',
    ],
    fallbackRequired: [
      'camera-access',
      'push-notifications',
      'offline-mode',
    ],
  },
};

// 组合所有设备配置
export const allDevices = [...iosDevices, ...androidDevices];

// 导出测试配置生成器
export function generateTestMatrix() {
  const testMatrix: Array<{
    device: DeviceConfig;
    browser: BrowserConfig;
    network: NetworkConfig;
  }> = [];

  // 移动设备测试组合
  allDevices.forEach((device) => {
    const mobileBrowser = device.name.includes('iPhone') || device.name.includes('iPad') 
      ? desktopBrowsers.find(b => b.name.includes('Safari'))!
      : desktopBrowsers.find(b => b.name.includes('Chrome'))!;
    
    networkConditions.forEach((network) => {
      testMatrix.push({
        device,
        browser: mobileBrowser,
        network,
      });
    });
  });

  // 桌面浏览器测试组合 (使用标准桌面分辨率)
  const desktopDevice: DeviceConfig = {
    name: 'Desktop',
    userAgent: '',
    viewport: {
      width: 1920,
      height: 1080,
      deviceScaleFactor: 1,
      isMobile: false,
      hasTouch: false,
    },
    capabilities: {
      gps: true,
      camera: true,
      orientation: false,
      networkInfo: true,
    },
  };

  desktopBrowsers.forEach((browser) => {
    networkConditions.forEach((network) => {
      testMatrix.push({
        device: desktopDevice,
        browser,
        network,
      });
    });
  });

  return testMatrix;
}