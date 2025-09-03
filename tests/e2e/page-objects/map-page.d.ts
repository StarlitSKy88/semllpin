import { Page } from '@playwright/test';
import { BasePage } from './base-page';
export declare class MapPage extends BasePage {
    private readonly selectors;
    constructor(page: Page);
    navigateToMap(): Promise<void>;
    waitForMapLoad(): Promise<void>;
    createAnnotation(annotationData: {
        title: string;
        description: string;
        category: string;
        intensity: number;
        rewardAmount: number;
        latitude: number;
        longitude: number;
        mediaFile?: string;
    }): Promise<void>;
    clickMapLocation(latitude: number, longitude: number): Promise<void>;
    searchAnnotations(query: string): Promise<void>;
    filterAnnotations(filters: {
        category?: string;
        maxDistance?: number;
    }): Promise<void>;
    clickAnnotationMarker(index?: number): Promise<void>;
    verifyAnnotationDetails(expectedData: {
        title: string;
        description: string;
    }): Promise<void>;
    likeAnnotation(): Promise<void>;
    getCurrentLocation(): Promise<void>;
    enterGeofence(latitude: number, longitude: number): Promise<void>;
    verifyRewardDiscovery(expectedAmount: number): Promise<void>;
    claimReward(): Promise<void>;
    verifyAnnotationCount(expectedCount: number): Promise<void>;
    verifyLocationPermissionError(): Promise<void>;
    waitForMapInteraction(): Promise<void>;
}
//# sourceMappingURL=map-page.d.ts.map