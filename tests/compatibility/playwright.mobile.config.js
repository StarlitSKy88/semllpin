"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createNetworkCondition = createNetworkCondition;
exports.createDeviceViewport = createDeviceViewport;
const test_1 = require("@playwright/test");
const mobile_device_matrix_1 = require("./mobile-device-matrix");
const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000';
const frontendURL = process.env.FRONTEND_URL || 'http://localhost:3001';
exports.default = (0, test_1.defineConfig)({
    testDir: './compatibility',
    timeout: 60000,
    expect: {
        timeout: 10000,
    },
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 1,
    workers: process.env.CI ? 4 : 2,
    reporter: [
        ['html', { outputFolder: 'compatibility-report' }],
        ['json', { outputFile: 'compatibility-results.json' }],
        ['junit', { outputFile: 'compatibility-results.xml' }],
        ['list'],
    ],
    use: {
        baseURL,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        permissions: ['geolocation', 'camera', 'microphone', 'notifications'],
        actionTimeout: mobile_device_matrix_1.testStandards.performance.interactionDelay,
    },
    projects: [
        ...mobile_device_matrix_1.iosDevices.map((device) => ({
            name: `iOS-${device.name}`,
            use: {
                ...test_1.devices['iPhone 12 Pro'],
                viewport: device.viewport,
                userAgent: device.userAgent,
                deviceScaleFactor: device.viewport.deviceScaleFactor,
                isMobile: device.viewport.isMobile,
                hasTouch: device.viewport.hasTouch,
                contextOptions: {
                    geolocation: { latitude: 37.7749, longitude: -122.4194 },
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
        ...mobile_device_matrix_1.androidDevices.map((device) => ({
            name: `Android-${device.name}`,
            use: {
                ...test_1.devices['Pixel 5'],
                viewport: device.viewport,
                userAgent: device.userAgent,
                deviceScaleFactor: device.viewport.deviceScaleFactor,
                isMobile: device.viewport.isMobile,
                hasTouch: device.viewport.hasTouch,
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
        {
            name: 'Desktop-Chrome',
            use: {
                ...test_1.devices['Desktop Chrome'],
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
                ...test_1.devices['Desktop Firefox'],
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
                ...test_1.devices['Desktop Safari'],
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
                ...test_1.devices['Microsoft Edge'],
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
        {
            name: 'Tablet-iPad',
            use: {
                ...test_1.devices['iPad Pro'],
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
        ...mobile_device_matrix_1.networkConditions.map((network) => ({
            name: `Network-${network.name}`,
            use: {
                ...test_1.devices['Desktop Chrome'],
                contextOptions: {
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
function createNetworkCondition(networkName) {
    const network = mobile_device_matrix_1.networkConditions.find(n => n.name === networkName);
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
function createDeviceViewport(deviceName) {
    const allDeviceConfigs = [...mobile_device_matrix_1.iosDevices, ...mobile_device_matrix_1.androidDevices];
    const device = allDeviceConfigs.find(d => d.name === deviceName);
    if (!device) {
        throw new Error(`Device "${deviceName}" not found`);
    }
    return device.viewport;
}
//# sourceMappingURL=playwright.mobile.config.js.map