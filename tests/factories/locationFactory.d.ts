import { TestDataFactory } from './index';
export interface TestLocationData {
    id?: string;
    name: string;
    latitude: number;
    longitude: number;
    address?: string;
    city?: string;
    province?: string;
    country?: string;
    postalCode?: string;
    placeId?: string;
    types?: string[];
    vicinity?: string;
    formattedAddress?: string;
}
declare class LocationFactoryClass implements TestDataFactory<TestLocationData> {
    private counter;
    private chineseCities;
    create(overrides?: Partial<TestLocationData>): TestLocationData;
    createMultiple(count: number, overrides?: Partial<TestLocationData>): TestLocationData[];
    build(overrides?: Partial<TestLocationData>): TestLocationData;
    buildList(count: number, overrides?: Partial<TestLocationData>): TestLocationData[];
    reset(): void;
}
export declare const LocationFactory: LocationFactoryClass;
export declare function createTestLocation(overrides?: Partial<TestLocationData>): TestLocationData;
export {};
//# sourceMappingURL=locationFactory.d.ts.map