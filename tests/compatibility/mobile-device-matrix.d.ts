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
export declare const iosDevices: DeviceConfig[];
export declare const androidDevices: DeviceConfig[];
export declare const desktopBrowsers: BrowserConfig[];
export interface NetworkConfig {
    name: string;
    downloadThroughput: number;
    uploadThroughput: number;
    latency: number;
    packetLoss: number;
}
export declare const networkConditions: NetworkConfig[];
export interface TestStandards {
    performance: {
        loadTime: number;
        interactionDelay: number;
        scrollFPS: number;
        memoryUsage: number;
    };
    compatibility: {
        coverageThreshold: number;
        criticalFeatures: string[];
        fallbackRequired: string[];
    };
}
export declare const testStandards: TestStandards;
export declare const allDevices: DeviceConfig[];
export declare function generateTestMatrix(): {
    device: DeviceConfig;
    browser: BrowserConfig;
    network: NetworkConfig;
}[];
//# sourceMappingURL=mobile-device-matrix.d.ts.map