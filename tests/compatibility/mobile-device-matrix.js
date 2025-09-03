"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.allDevices = exports.testStandards = exports.networkConditions = exports.desktopBrowsers = exports.androidDevices = exports.iosDevices = void 0;
exports.generateTestMatrix = generateTestMatrix;
exports.iosDevices = [
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
exports.androidDevices = [
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
            networkInfo: false,
        },
    },
];
exports.desktopBrowsers = [
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
            pushNotifications: false,
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
exports.networkConditions = [
    {
        name: '3G',
        downloadThroughput: 1.6 * 1024 * 1024 / 8,
        uploadThroughput: 750 * 1024 / 8,
        latency: 300,
        packetLoss: 0,
    },
    {
        name: '4G',
        downloadThroughput: 9 * 1024 * 1024 / 8,
        uploadThroughput: 3 * 1024 * 1024 / 8,
        latency: 100,
        packetLoss: 0,
    },
    {
        name: 'WiFi',
        downloadThroughput: 30 * 1024 * 1024 / 8,
        uploadThroughput: 15 * 1024 * 1024 / 8,
        latency: 20,
        packetLoss: 0,
    },
    {
        name: 'Slow WiFi',
        downloadThroughput: 2 * 1024 * 1024 / 8,
        uploadThroughput: 1 * 1024 * 1024 / 8,
        latency: 500,
        packetLoss: 2,
    },
];
exports.testStandards = {
    performance: {
        loadTime: 3000,
        interactionDelay: 200,
        scrollFPS: 50,
        memoryUsage: 100,
    },
    compatibility: {
        coverageThreshold: 95,
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
exports.allDevices = [...exports.iosDevices, ...exports.androidDevices];
function generateTestMatrix() {
    const testMatrix = [];
    exports.allDevices.forEach((device) => {
        const mobileBrowser = device.name.includes('iPhone') || device.name.includes('iPad')
            ? exports.desktopBrowsers.find(b => b.name.includes('Safari'))
            : exports.desktopBrowsers.find(b => b.name.includes('Chrome'));
        exports.networkConditions.forEach((network) => {
            testMatrix.push({
                device,
                browser: mobileBrowser,
                network,
            });
        });
    });
    const desktopDevice = {
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
    exports.desktopBrowsers.forEach((browser) => {
        exports.networkConditions.forEach((network) => {
            testMatrix.push({
                device: desktopDevice,
                browser,
                network,
            });
        });
    });
    return testMatrix;
}
//# sourceMappingURL=mobile-device-matrix.js.map