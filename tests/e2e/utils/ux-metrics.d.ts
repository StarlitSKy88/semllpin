import { Page } from '@playwright/test';
export interface UXMetrics {
    pageLoadTime: number;
    timeToInteractive: number;
    firstContentfulPaint: number;
    largestContentfulPaint: number;
    cumulativeLayoutShift: number;
    clickResponseTime: number[];
    formFillTime: number;
    navigationTime: number;
    taskCompletionTime: number;
    errorRate: number;
    conversionFunnelMetrics: Record<string, number>;
    deviceInfo: DeviceInfo;
    networkConditions: NetworkConditions;
    perceivedPerformance: number;
    taskSuccess: boolean;
    userFrustrationEvents: string[];
}
export interface DeviceInfo {
    userAgent: string;
    viewport: {
        width: number;
        height: number;
    };
    devicePixelRatio: number;
    isMobile: boolean;
    isTablet: boolean;
    browserName: string;
}
export interface NetworkConditions {
    effectiveType: string;
    downlink: number;
    rtt: number;
    saveData: boolean;
}
export declare class UXMetricsCollector {
    private page;
    private metrics;
    private startTimes;
    private interactionTimes;
    private errorEvents;
    constructor(page: Page);
    private setupMetricsCollection;
    startTask(taskName: string): void;
    endTask(taskName: string): number;
    collectWebVitals(): Promise<void>;
    collectInteractionMetrics(): Promise<void>;
    collectDeviceInfo(): Promise<void>;
    collectNetworkConditions(): Promise<void>;
    measurePageLoadTime(): Promise<number>;
    measureTimeToInteractive(): Promise<number>;
    evaluateUserSatisfaction(): number;
    createConversionFunnel(steps: string[]): Record<string, number>;
    generateUXReport(): Promise<UXMetrics>;
    exportMetrics(filename: string): Promise<void>;
    private getBrowserName;
    checkPerformanceBudget(budget: Partial<UXMetrics>): {
        passed: boolean;
        violations: string[];
    };
}
//# sourceMappingURL=ux-metrics.d.ts.map