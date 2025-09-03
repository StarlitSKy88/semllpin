export { UserFactory, createTestUser, createMultipleTestUsers } from './userFactory';
export { AnnotationFactory, createTestAnnotation, createMultipleTestAnnotations } from './annotationFactory';
export { MediaFactory, createTestMedia } from './mediaFactory';
export { LocationFactory, createTestLocation } from './locationFactory';
export { PaymentFactory, createTestPayment } from './paymentFactory';
export interface TestDataFactory<T> {
    create(overrides?: Partial<T>): T;
    createMultiple(count: number, overrides?: Partial<T>): T[];
    build(overrides?: Partial<T>): T;
    buildList(count: number, overrides?: Partial<T>): T[];
}
export interface FactoryConfig {
    seed?: number;
    locale?: string;
    timezone?: string;
}
export declare function configureFactories(config: Partial<FactoryConfig>): void;
export declare function getFactoryConfig(): FactoryConfig;
export declare function resetFactories(): void;
export declare function cleanupTestData(): Promise<void>;
//# sourceMappingURL=index.d.ts.map