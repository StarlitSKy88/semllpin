import { Page } from '@playwright/test';
import { BasePage } from './base-page';
export declare class EnhancedMapPage extends BasePage {
    private readonly selectors;
    constructor(page: Page);
    waitForMapFullyLoaded(): Promise<void>;
    clickMapLocationSmart(lat: number, lng: number): Promise<void>;
    createDetailedAnnotation(annotationData: {
        title: string;
        description: string;
        category: string;
        intensity: number;
        rewardAmount: number;
        latitude: number;
        longitude: number;
        images?: string[];
    }): Promise<void>;
    performAdvancedSearch(searchCriteria: {
        keyword?: string;
        category?: string;
        minReward?: number;
        maxReward?: number;
        maxDistance?: number;
        dateFrom?: string;
        dateTo?: string;
    }): Promise<void>;
    simulateGeofenceEntry(lat: number, lng: number, radius?: number): Promise<void>;
    verifyAndClaimReward(expectedAmount: number): Promise<void>;
    simulatePaymentFlow(paymentData: {
        cardNumber: string;
        expiry: string;
        cvc: string;
        name: string;
        amount: number;
    }): Promise<void>;
    verifyMarkerClustering(expectedClusterCount: number): Promise<void>;
    testMapPanAndZoom(): Promise<void>;
    verifyResponsiveMapBehavior(viewportWidth: number): Promise<void>;
    getMapPerformanceMetrics(): Promise<any>;
    simulateNetworkChange(condition: 'online' | 'offline' | 'slow'): Promise<void>;
    verifyErrorRecovery(): Promise<void>;
}
//# sourceMappingURL=enhanced-map-page.d.ts.map