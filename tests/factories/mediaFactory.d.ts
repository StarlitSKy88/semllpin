import { TestDataFactory } from './index';
export interface TestMediaData {
    id?: string;
    userId: string;
    annotationId?: string;
    filename: string;
    originalName: string;
    mimetype: string;
    size: number;
    path: string;
    url?: string;
    thumbnailUrl?: string;
    width?: number;
    height?: number;
    duration?: number;
    fileHash?: string;
    uploadStatus?: 'uploading' | 'completed' | 'failed';
    metadata?: any;
    createdAt?: Date;
    updatedAt?: Date;
    deletedAt?: Date;
}
declare class MediaFactoryClass implements TestDataFactory<TestMediaData> {
    private counter;
    create(overrides?: Partial<TestMediaData>): TestMediaData;
    createMultiple(count: number, overrides?: Partial<TestMediaData>): TestMediaData[];
    build(overrides?: Partial<TestMediaData>): TestMediaData;
    buildList(count: number, overrides?: Partial<TestMediaData>): TestMediaData[];
    createImageMedia(overrides?: Partial<TestMediaData>): TestMediaData;
    createVideoMedia(overrides?: Partial<TestMediaData>): TestMediaData;
    createAudioMedia(overrides?: Partial<TestMediaData>): TestMediaData;
    reset(): void;
}
export declare const MediaFactory: MediaFactoryClass;
export declare function createTestMedia(overrides?: Partial<TestMediaData>): TestMediaData;
export {};
//# sourceMappingURL=mediaFactory.d.ts.map