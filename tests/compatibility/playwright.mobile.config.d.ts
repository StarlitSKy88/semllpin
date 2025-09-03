declare const _default: import("@playwright/test").PlaywrightTestConfig<{}, {}>;
export default _default;
export declare function createNetworkCondition(networkName: string): {
    offline: boolean;
    downloadThroughput: number;
    uploadThroughput: number;
    latency: number;
};
export declare function createDeviceViewport(deviceName: string): {
    width: number;
    height: number;
    deviceScaleFactor: number;
    isMobile: boolean;
    hasTouch: boolean;
};
//# sourceMappingURL=playwright.mobile.config.d.ts.map