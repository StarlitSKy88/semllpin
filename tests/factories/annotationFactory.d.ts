import { TestDataFactory } from './index';
export interface TestAnnotationData {
    id?: string;
    userId: string;
    title: string;
    description?: string;
    smellType: string;
    intensity: number;
    latitude: number;
    longitude: number;
    locationName?: string;
    address?: string;
    status?: 'draft' | 'published' | 'approved' | 'rejected' | 'flagged';
    visibility?: 'public' | 'private' | 'friends_only';
    tags?: string[];
    mediaFiles?: string[];
    likeCount?: number;
    commentCount?: number;
    shareCount?: number;
    createdAt?: Date;
    updatedAt?: Date;
    publishedAt?: Date;
    moderatedAt?: Date;
    moderatorId?: string;
    moderationNote?: string;
    reportCount?: number;
    featured?: boolean;
    verified?: boolean;
    language?: string;
    deviceInfo?: any;
    weatherCondition?: string;
    temperature?: number;
    humidity?: number;
    windSpeed?: number;
    airQualityIndex?: number;
}
declare class AnnotationFactoryClass implements TestDataFactory<TestAnnotationData> {
    private counter;
    private smellTypes;
    private beijingLocations;
    create(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    private getRandomWeather;
    createMultiple(count: number, overrides?: Partial<TestAnnotationData>): TestAnnotationData[];
    build(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    buildList(count: number, overrides?: Partial<TestAnnotationData>): TestAnnotationData[];
    createDraftAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    createApprovedAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    createRejectedAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    createFlaggedAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    createHighIntensityAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
    createClusteredAnnotations(centerLat: number, centerLng: number, count: number, radius?: number): TestAnnotationData[];
    reset(): void;
}
export declare const AnnotationFactory: AnnotationFactoryClass;
export declare function createTestAnnotation(overrides?: Partial<TestAnnotationData>): TestAnnotationData;
export declare function createMultipleTestAnnotations(count: number, overrides?: Partial<TestAnnotationData>): TestAnnotationData[];
export declare function persistTestAnnotation(annotationData: TestAnnotationData, db?: any): Promise<any>;
export {};
//# sourceMappingURL=annotationFactory.d.ts.map