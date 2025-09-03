"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.USER_PATTERNS = exports.SMELL_CATEGORIES = exports.BEIJING_HOTSPOTS = exports.DataGenerator = exports.GeoFactory = exports.PaymentFactory = exports.AnnotationFactory = exports.UserFactory = void 0;
exports.resetSeed = resetSeed;
const faker_1 = require("@faker-js/faker");
const jest_setup_1 = require("../setup/jest-setup");
faker_1.faker.seed(42);
const BEIJING_HOTSPOTS = [
    { name: '三里屯', lat: 39.9369, lng: 116.4462, category: 'commercial' },
    { name: '中关村', lat: 39.9788, lng: 116.3014, category: 'tech' },
    { name: '国贸CBD', lat: 39.9090, lng: 116.4587, category: 'business' },
    { name: '故宫', lat: 39.9163, lng: 116.3972, category: 'tourist' },
    { name: '天坛', lat: 39.8812, lng: 116.4068, category: 'tourist' },
    { name: '亦庄', lat: 39.7987, lng: 116.5267, category: 'industrial' },
    { name: '望京', lat: 39.9963, lng: 116.4723, category: 'residential' },
    { name: '西单', lat: 39.9069, lng: 116.3760, category: 'commercial' }
];
exports.BEIJING_HOTSPOTS = BEIJING_HOTSPOTS;
const SMELL_CATEGORIES = {
    industrial: {
        types: ['chemical', 'paint', 'plastic', 'metal', 'rubber'],
        intensities: [6, 7, 8, 9, 10],
        descriptions: ['刺鼻的化学气味', '浓烈的油漆味', '塑料燃烧味', '金属加工异味']
    },
    sewage: {
        types: ['sewer', 'waste', 'drainage'],
        intensities: [4, 5, 6, 7, 8],
        descriptions: ['下水道臭味', '污水处理异味', '排水管道气味']
    },
    garbage: {
        types: ['rotting', 'organic', 'compost'],
        intensities: [3, 4, 5, 6, 7],
        descriptions: ['腐烂垃圾味', '有机物发酵味', '堆肥发酵气味']
    },
    food: {
        types: ['cooking', 'frying', 'fermentation'],
        intensities: [2, 3, 4, 5],
        descriptions: ['油烟味', '煎炸食物气味', '发酵食品味']
    }
};
exports.SMELL_CATEGORIES = SMELL_CATEGORIES;
const USER_PATTERNS = {
    NewUser: {
        sessionDuration: { min: 5, max: 15 },
        actionsPerSession: { min: 3, max: 8 },
        errorProbability: 0.15,
        helpSeekingProbability: 0.3
    },
    ActiveUser: {
        sessionDuration: { min: 10, max: 30 },
        actionsPerSession: { min: 8, max: 20 },
        errorProbability: 0.05,
        helpSeekingProbability: 0.1
    },
    PowerUser: {
        sessionDuration: { min: 20, max: 60 },
        actionsPerSession: { min: 15, max: 40 },
        errorProbability: 0.02,
        helpSeekingProbability: 0.05
    },
    MobileUser: {
        sessionDuration: { min: 3, max: 12 },
        actionsPerSession: { min: 2, max: 10 },
        errorProbability: 0.08,
        locationChangeProbability: 0.7
    },
    StressUser: {
        sessionDuration: { min: 1, max: 3 },
        actionsPerSession: { min: 10, max: 100 },
        errorProbability: 0.3,
        maliciousProbability: 0.1
    }
};
exports.USER_PATTERNS = USER_PATTERNS;
class UserFactory {
    static create(overrides = {}) {
        const baseUser = {
            id: faker_1.faker.string.uuid(),
            username: faker_1.faker.internet.userName(),
            email: faker_1.faker.internet.email(),
            password: faker_1.faker.internet.password({ length: 12 }),
            nickname: faker_1.faker.person.fullName(),
            avatar: faker_1.faker.image.avatar(),
            phoneNumber: faker_1.faker.phone.number('13#########'),
            location: jest_setup_1.testUtils.generateBeijingCoordinate(),
            isVerified: faker_1.faker.datatype.boolean({ probability: 0.7 }),
            level: faker_1.faker.helpers.arrayElement([1, 2, 3, 4, 5]),
            points: faker_1.faker.number.int({ min: 0, max: 10000 }),
            joinedAt: faker_1.faker.date.past({ years: 2 }),
            lastActiveAt: faker_1.faker.date.recent({ days: 7 }),
            preferences: {
                notifications: faker_1.faker.datatype.boolean({ probability: 0.8 }),
                privacyLevel: faker_1.faker.helpers.arrayElement(['public', 'friends', 'private']),
                language: faker_1.faker.helpers.arrayElement(['zh-CN', 'en-US'])
            },
            stats: {
                annotationsCreated: faker_1.faker.number.int({ min: 0, max: 100 }),
                likesReceived: faker_1.faker.number.int({ min: 0, max: 500 }),
                commentsReceived: faker_1.faker.number.int({ min: 0, max: 200 })
            }
        };
        return { ...baseUser, ...overrides };
    }
    static createBatch(count, overrides = {}) {
        return Array.from({ length: count }, () => this.create(overrides));
    }
    static createByType(userType, overrides = {}) {
        const pattern = USER_PATTERNS[userType];
        const typeSpecificData = {
            userType,
            sessionPattern: pattern,
            level: userType === 'NewUser' ? 1 :
                userType === 'PowerUser' ? faker_1.faker.number.int({ min: 4, max: 5 }) :
                    faker_1.faker.number.int({ min: 2, max: 4 }),
            isVerified: userType === 'StressUser' ? false : faker_1.faker.datatype.boolean({ probability: 0.8 })
        };
        return this.create({ ...typeSpecificData, ...overrides });
    }
}
exports.UserFactory = UserFactory;
class AnnotationFactory {
    static create(overrides = {}) {
        const hotspot = faker_1.faker.helpers.arrayElement(BEIJING_HOTSPOTS);
        const category = faker_1.faker.helpers.arrayElement(Object.keys(SMELL_CATEGORIES));
        const smellData = SMELL_CATEGORIES[category];
        const location = {
            lat: hotspot.lat + faker_1.faker.number.float({ min: -0.005, max: 0.005 }),
            lng: hotspot.lng + faker_1.faker.number.float({ min: -0.005, max: 0.005 })
        };
        const baseAnnotation = {
            id: faker_1.faker.string.uuid(),
            title: faker_1.faker.lorem.sentence({ min: 3, max: 8 }),
            description: faker_1.faker.helpers.arrayElement(smellData.descriptions) + '。' + faker_1.faker.lorem.sentences(2),
            location,
            category,
            smellType: faker_1.faker.helpers.arrayElement(smellData.types),
            intensity: faker_1.faker.helpers.arrayElement(smellData.intensities),
            tags: faker_1.faker.helpers.arrayElements(['异味', '污染', '环境', '举报', '监测', hotspot.name], { min: 2, max: 4 }),
            userId: faker_1.faker.string.uuid(),
            media: faker_1.faker.datatype.boolean({ probability: 0.6 }) ? [
                {
                    id: faker_1.faker.string.uuid(),
                    type: 'image',
                    url: faker_1.faker.image.url({ width: 800, height: 600 }),
                    thumbnailUrl: faker_1.faker.image.url({ width: 200, height: 150 })
                }
            ] : [],
            status: faker_1.faker.helpers.arrayElement(['active', 'verified', 'flagged', 'resolved']),
            visibility: faker_1.faker.helpers.arrayElement(['public', 'friends', 'private']),
            likesCount: faker_1.faker.number.int({ min: 0, max: 100 }),
            commentsCount: faker_1.faker.number.int({ min: 0, max: 50 }),
            reportsCount: faker_1.faker.number.int({ min: 0, max: 5 }),
            createdAt: faker_1.faker.date.recent({ days: 30 }),
            updatedAt: faker_1.faker.date.recent({ days: 7 }),
            expiresAt: faker_1.faker.date.future({ years: 1 }),
            geohash: generateGeoHash(location.lat, location.lng),
            nearbyHotspot: hotspot.name,
            distanceFromCenter: calculateDistanceFromCenter(location)
        };
        return { ...baseAnnotation, ...overrides };
    }
    static createBatch(count, overrides = {}) {
        return Array.from({ length: count }, () => this.create(overrides));
    }
    static createForHotspot(hotspotName, count = 1) {
        const hotspot = BEIJING_HOTSPOTS.find(h => h.name === hotspotName);
        if (!hotspot)
            throw new Error(`Unknown hotspot: ${hotspotName}`);
        return this.createBatch(count, {
            location: {
                lat: hotspot.lat + faker_1.faker.number.float({ min: -0.002, max: 0.002 }),
                lng: hotspot.lng + faker_1.faker.number.float({ min: -0.002, max: 0.002 })
            },
            nearbyHotspot: hotspot.name
        });
    }
}
exports.AnnotationFactory = AnnotationFactory;
class PaymentFactory {
    static create(overrides = {}) {
        const paymentMethods = ['alipay', 'wechat', 'stripe', 'paypal'];
        const currencies = ['CNY', 'USD'];
        const statuses = ['pending', 'processing', 'completed', 'failed', 'refunded'];
        const basePayment = {
            id: faker_1.faker.string.uuid(),
            userId: faker_1.faker.string.uuid(),
            annotationId: faker_1.faker.string.uuid(),
            amount: faker_1.faker.number.int({ min: 100, max: 5000 }),
            currency: faker_1.faker.helpers.arrayElement(currencies),
            method: faker_1.faker.helpers.arrayElement(paymentMethods),
            status: faker_1.faker.helpers.arrayElement(statuses),
            transactionId: faker_1.faker.string.alphanumeric(20),
            platformTransactionId: `${faker_1.faker.helpers.arrayElement(['pi_', 'ch_', 'tr_'])}${faker_1.faker.string.alphanumeric(24)}`,
            description: '标注费用支付',
            metadata: {
                annotationType: faker_1.faker.helpers.arrayElement(['basic', 'premium', 'emergency']),
                userLevel: faker_1.faker.number.int({ min: 1, max: 5 }),
                discount: faker_1.faker.datatype.boolean({ probability: 0.2 }) ? faker_1.faker.number.float({ min: 0.1, max: 0.3 }) : 0
            },
            createdAt: faker_1.faker.date.recent({ days: 30 }),
            updatedAt: faker_1.faker.date.recent({ days: 1 }),
            completedAt: faker_1.faker.date.recent({ days: 1 })
        };
        return { ...basePayment, ...overrides };
    }
    static createBatch(count, overrides = {}) {
        return Array.from({ length: count }, () => this.create(overrides));
    }
}
exports.PaymentFactory = PaymentFactory;
class GeoFactory {
    static createGeofence(center, radius = 1000) {
        const fenceCenter = center || jest_setup_1.testUtils.generateBeijingCoordinate();
        return {
            id: faker_1.faker.string.uuid(),
            name: faker_1.faker.location.city() + '围栏区域',
            center: fenceCenter,
            radius,
            type: faker_1.faker.helpers.arrayElement(['circle', 'polygon']),
            isActive: faker_1.faker.datatype.boolean({ probability: 0.8 }),
            createdAt: faker_1.faker.date.recent({ days: 30 })
        };
    }
    static createTrajectory(startPoint, pointsCount = 10) {
        const start = startPoint || jest_setup_1.testUtils.generateBeijingCoordinate();
        const points = [start];
        for (let i = 1; i < pointsCount; i++) {
            const lastPoint = points[i - 1];
            const nextPoint = {
                lat: lastPoint.lat + faker_1.faker.number.float({ min: -0.002, max: 0.002 }),
                lng: lastPoint.lng + faker_1.faker.number.float({ min: -0.002, max: 0.002 }),
                timestamp: new Date(Date.now() + i * 60000),
                speed: faker_1.faker.number.float({ min: 1, max: 15 }),
                accuracy: faker_1.faker.number.int({ min: 5, max: 20 })
            };
            points.push(nextPoint);
        }
        return {
            id: faker_1.faker.string.uuid(),
            userId: faker_1.faker.string.uuid(),
            points,
            totalDistance: calculateTrajectoryDistance(points),
            duration: pointsCount * 60,
            createdAt: faker_1.faker.date.recent({ days: 1 })
        };
    }
    static createSpatialQuery() {
        const queryTypes = ['nearest', 'within', 'intersects', 'contains'];
        const center = jest_setup_1.testUtils.generateBeijingCoordinate();
        return {
            type: faker_1.faker.helpers.arrayElement(queryTypes),
            center,
            radius: faker_1.faker.number.int({ min: 500, max: 5000 }),
            bbox: {
                north: center.lat + 0.01,
                south: center.lat - 0.01,
                east: center.lng + 0.01,
                west: center.lng - 0.01
            },
            expectedResultCount: faker_1.faker.number.int({ min: 0, max: 50 })
        };
    }
}
exports.GeoFactory = GeoFactory;
function generateGeoHash(lat, lng) {
    return faker_1.faker.string.alphanumeric(12);
}
function calculateDistanceFromCenter(location) {
    const CENTER = { lat: 39.9042, lng: 116.4074 };
    return calculateDistance(location, CENTER);
}
function calculateDistance(p1, p2) {
    const R = 6371000;
    const φ1 = (p1.lat * Math.PI) / 180;
    const φ2 = (p2.lat * Math.PI) / 180;
    const Δφ = ((p2.lat - p1.lat) * Math.PI) / 180;
    const Δλ = ((p2.lng - p1.lng) * Math.PI) / 180;
    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}
function calculateTrajectoryDistance(points) {
    let totalDistance = 0;
    for (let i = 1; i < points.length; i++) {
        totalDistance += calculateDistance(points[i - 1], points[i]);
    }
    return totalDistance;
}
class DataGenerator {
    static async seedTestDatabase() {
        console.log('🌱 开始生成测试数据...');
        const users = UserFactory.createBatch(100);
        const annotations = AnnotationFactory.createBatch(500);
        const payments = PaymentFactory.createBatch(200);
        console.log(`✅ 生成完成: ${users.length} 用户, ${annotations.length} 标注, ${payments.length} 支付记录`);
        return { users, annotations, payments };
    }
    static createRealisticScenario() {
        const scenario = {
            name: '工业园区污染事件',
            location: BEIJING_HOTSPOTS.find(h => h.category === 'industrial'),
            users: [
                UserFactory.createByType('NewUser'),
                ...UserFactory.createBatch(3, { userType: 'ActiveUser' }),
                UserFactory.createByType('PowerUser')
            ],
            annotations: [],
            timespan: {
                start: faker_1.faker.date.recent({ days: 7 }),
                end: faker_1.faker.date.recent({ days: 1 })
            }
        };
        scenario.annotations = AnnotationFactory.createForHotspot(scenario.location.name, 10)
            .map(annotation => ({
            ...annotation,
            category: 'industrial',
            intensity: faker_1.faker.number.int({ min: 6, max: 10 }),
            createdAt: faker_1.faker.date.between({
                from: scenario.timespan.start,
                to: scenario.timespan.end
            })
        }));
        return scenario;
    }
}
exports.DataGenerator = DataGenerator;
function resetSeed(seed = 42) {
    faker_1.faker.seed(seed);
    console.log(`🎲 重置随机种子为: ${seed}`);
}
//# sourceMappingURL=enhanced-factories.js.map