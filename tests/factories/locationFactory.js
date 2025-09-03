"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocationFactory = void 0;
exports.createTestLocation = createTestLocation;
class LocationFactoryClass {
    constructor() {
        this.counter = 0;
        this.chineseCities = [
            { name: '北京', lat: 39.9042, lng: 116.4074, province: '北京市' },
            { name: '上海', lat: 31.2304, lng: 121.4737, province: '上海市' },
            { name: '广州', lat: 23.1291, lng: 113.2644, province: '广东省' },
            { name: '深圳', lat: 22.5431, lng: 114.0579, province: '广东省' },
            { name: '杭州', lat: 30.2741, lng: 120.1551, province: '浙江省' },
            { name: '成都', lat: 30.5728, lng: 104.0668, province: '四川省' },
            { name: '西安', lat: 34.3416, lng: 108.9398, province: '陕西省' },
            { name: '南京', lat: 32.0603, lng: 118.7969, province: '江苏省' },
        ];
    }
    create(overrides = {}) {
        this.counter++;
        const city = this.chineseCities[this.counter % this.chineseCities.length];
        const baseLocation = {
            id: overrides.id || `test-location-${this.counter}`,
            name: overrides.name || `${city.name}测试地点${this.counter}`,
            latitude: overrides.latitude ?? city.lat + (Math.random() - 0.5) * 0.1,
            longitude: overrides.longitude ?? city.lng + (Math.random() - 0.5) * 0.1,
            address: overrides.address || `测试街道${this.counter}号`,
            city: overrides.city || city.name,
            province: overrides.province || city.province,
            country: overrides.country || '中国',
            postalCode: overrides.postalCode || `${100000 + this.counter}`,
            placeId: overrides.placeId || `test_place_${this.counter}`,
            types: overrides.types || ['establishment', 'point_of_interest'],
            vicinity: overrides.vicinity || `${city.name}市中心`,
            formattedAddress: overrides.formattedAddress || `中国${city.province}${city.name}测试街道${this.counter}号`,
        };
        return { ...baseLocation, ...overrides };
    }
    createMultiple(count, overrides = {}) {
        return Array.from({ length: count }, () => this.create(overrides));
    }
    build(overrides = {}) {
        const tempCounter = this.counter;
        const location = this.create(overrides);
        this.counter = tempCounter;
        return location;
    }
    buildList(count, overrides = {}) {
        return Array.from({ length: count }, () => this.build(overrides));
    }
    reset() {
        this.counter = 0;
    }
}
exports.LocationFactory = new LocationFactoryClass();
function createTestLocation(overrides = {}) {
    return exports.LocationFactory.create(overrides);
}
//# sourceMappingURL=locationFactory.js.map