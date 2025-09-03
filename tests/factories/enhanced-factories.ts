/**
 * SmellPin 测试数据工厂 - Phase 2
 * 可重复随机种子 + 生产级数据生成
 * 支持地理热区数据 + 业务真实场景
 */
import { faker } from '@faker-js/faker';
import { testUtils } from '../setup/jest-setup';

// 设置可重复的随机种子
faker.seed(42);

// 真实的北京地理热区数据
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

// 气味类型真实数据
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

// 用户行为模式数据
const USER_PATTERNS = {
  NewUser: {
    sessionDuration: { min: 5, max: 15 }, // 分钟
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

/**
 * 用户数据工厂
 */
export class UserFactory {
  static create(overrides: Partial<any> = {}) {
    const baseUser = {
      id: faker.string.uuid(),
      username: faker.internet.userName(),
      email: faker.internet.email(),
      password: faker.internet.password({ length: 12 }),
      nickname: faker.person.fullName(),
      avatar: faker.image.avatar(),
      phoneNumber: faker.phone.number({ style: 'national' }),
      location: testUtils.generateBeijingCoordinate(),
      isVerified: faker.datatype.boolean({ probability: 0.7 }),
      level: faker.helpers.arrayElement([1, 2, 3, 4, 5]),
      points: faker.number.int({ min: 0, max: 10000 }),
      joinedAt: faker.date.past({ years: 2 }),
      lastActiveAt: faker.date.recent({ days: 7 }),
      preferences: {
        notifications: faker.datatype.boolean({ probability: 0.8 }),
        privacyLevel: faker.helpers.arrayElement(['public', 'friends', 'private']),
        language: faker.helpers.arrayElement(['zh-CN', 'en-US'])
      },
      stats: {
        annotationsCreated: faker.number.int({ min: 0, max: 100 }),
        likesReceived: faker.number.int({ min: 0, max: 500 }),
        commentsReceived: faker.number.int({ min: 0, max: 200 })
      }
    };

    return { ...baseUser, ...overrides };
  }

  static createBatch(count: number, overrides: Partial<any> = {}) {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  static createByType(userType: keyof typeof USER_PATTERNS, overrides: Partial<any> = {}) {
    const pattern = USER_PATTERNS[userType];
    const typeSpecificData = {
      userType,
      sessionPattern: pattern,
      // 根据用户类型调整属性
      level: userType === 'NewUser' ? 1 : 
             userType === 'PowerUser' ? faker.number.int({ min: 4, max: 5 }) : 
             faker.number.int({ min: 2, max: 4 }),
      isVerified: userType === 'StressUser' ? false : faker.datatype.boolean({ probability: 0.8 })
    };

    return this.create({ ...typeSpecificData, ...overrides });
  }
}

/**
 * 标注数据工厂
 */
export class AnnotationFactory {
  static create(overrides: Partial<any> = {}) {
    // 随机选择一个热区
    const hotspot = faker.helpers.arrayElement(BEIJING_HOTSPOTS);
    const category = faker.helpers.arrayElement(Object.keys(SMELL_CATEGORIES));
    const smellData = SMELL_CATEGORIES[category as keyof typeof SMELL_CATEGORIES];
    
    // 在热区附近生成位置（500米范围内）
    const location = {
      lat: hotspot.lat + faker.number.float({ min: -0.005, max: 0.005 }),
      lng: hotspot.lng + faker.number.float({ min: -0.005, max: 0.005 })
    };

    const baseAnnotation = {
      id: faker.string.uuid(),
      title: faker.lorem.sentence({ min: 3, max: 8 }),
      description: faker.helpers.arrayElement(smellData.descriptions) + '。' + faker.lorem.sentences(2),
      location,
      category,
      smellType: faker.helpers.arrayElement(smellData.types),
      intensity: faker.helpers.arrayElement(smellData.intensities),
      tags: faker.helpers.arrayElements(
        ['异味', '污染', '环境', '举报', '监测', hotspot.name],
        { min: 2, max: 4 }
      ),
      userId: faker.string.uuid(),
      media: faker.datatype.boolean({ probability: 0.6 }) ? [
        {
          id: faker.string.uuid(),
          type: 'image',
          url: faker.image.url({ width: 800, height: 600 }),
          thumbnailUrl: faker.image.url({ width: 200, height: 150 })
        }
      ] : [],
      status: faker.helpers.arrayElement(['active', 'verified', 'flagged', 'resolved']),
      visibility: faker.helpers.arrayElement(['public', 'friends', 'private']),
      likesCount: faker.number.int({ min: 0, max: 100 }),
      commentsCount: faker.number.int({ min: 0, max: 50 }),
      reportsCount: faker.number.int({ min: 0, max: 5 }),
      createdAt: faker.date.recent({ days: 30 }),
      updatedAt: faker.date.recent({ days: 7 }),
      expiresAt: faker.date.future({ years: 1 }),
      // PostGIS 相关字段
      geohash: generateGeoHash(location.lat, location.lng),
      nearbyHotspot: hotspot.name,
      distanceFromCenter: calculateDistanceFromCenter(location)
    };

    return { ...baseAnnotation, ...overrides };
  }

  static createBatch(count: number, overrides: Partial<any> = {}) {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  static createForHotspot(hotspotName: string, count: number = 1) {
    const hotspot = BEIJING_HOTSPOTS.find(h => h.name === hotspotName);
    if (!hotspot) throw new Error(`Unknown hotspot: ${hotspotName}`);

    return this.createBatch(count, {
      location: {
        lat: hotspot.lat + faker.number.float({ min: -0.002, max: 0.002 }),
        lng: hotspot.lng + faker.number.float({ min: -0.002, max: 0.002 })
      },
      nearbyHotspot: hotspot.name
    });
  }
}

/**
 * 支付数据工厂
 */
export class PaymentFactory {
  static create(overrides: Partial<any> = {}) {
    const paymentMethods = ['alipay', 'wechat', 'stripe', 'paypal'];
    const currencies = ['CNY', 'USD'];
    const statuses = ['pending', 'processing', 'completed', 'failed', 'refunded'];

    const basePayment = {
      id: faker.string.uuid(),
      userId: faker.string.uuid(),
      annotationId: faker.string.uuid(),
      amount: faker.number.int({ min: 100, max: 5000 }), // 分为单位
      currency: faker.helpers.arrayElement(currencies),
      method: faker.helpers.arrayElement(paymentMethods),
      status: faker.helpers.arrayElement(statuses),
      transactionId: faker.string.alphanumeric(20),
      platformTransactionId: `${faker.helpers.arrayElement(['pi_', 'ch_', 'tr_'])}${faker.string.alphanumeric(24)}`,
      description: '标注费用支付',
      metadata: {
        annotationType: faker.helpers.arrayElement(['basic', 'premium', 'emergency']),
        userLevel: faker.number.int({ min: 1, max: 5 }),
        discount: faker.datatype.boolean({ probability: 0.2 }) ? faker.number.float({ min: 0.1, max: 0.3 }) : 0
      },
      createdAt: faker.date.recent({ days: 30 }),
      updatedAt: faker.date.recent({ days: 1 }),
      completedAt: faker.date.recent({ days: 1 })
    };

    return { ...basePayment, ...overrides };
  }

  static createBatch(count: number, overrides: Partial<any> = {}) {
    return Array.from({ length: count }, () => this.create(overrides));
  }
}

/**
 * 地理测试数据工厂
 */
export class GeoFactory {
  // 创建地理围栏测试数据
  static createGeofence(center?: { lat: number; lng: number }, radius: number = 1000) {
    const fenceCenter = center || testUtils.generateBeijingCoordinate();
    
    return {
      id: faker.string.uuid(),
      name: faker.location.city() + '围栏区域',
      center: fenceCenter,
      radius,
      type: faker.helpers.arrayElement(['circle', 'polygon']),
      isActive: faker.datatype.boolean({ probability: 0.8 }),
      createdAt: faker.date.recent({ days: 30 })
    };
  }

  // 创建路径轨迹数据
  static createTrajectory(startPoint?: { lat: number; lng: number }, pointsCount: number = 10) {
    const start = startPoint || testUtils.generateBeijingCoordinate();
    const points = [start];

    for (let i = 1; i < pointsCount; i++) {
      const lastPoint = points[i - 1];
      // 每次移动 50-200 米
      const nextPoint = {
        lat: lastPoint.lat + faker.number.float({ min: -0.002, max: 0.002 }),
        lng: lastPoint.lng + faker.number.float({ min: -0.002, max: 0.002 }),
        timestamp: new Date(Date.now() + i * 60000), // 每分钟一个点
        speed: faker.number.float({ min: 1, max: 15 }), // km/h
        accuracy: faker.number.int({ min: 5, max: 20 }) // 米
      };
      points.push(nextPoint);
    }

    return {
      id: faker.string.uuid(),
      userId: faker.string.uuid(),
      points,
      totalDistance: calculateTrajectoryDistance(points),
      duration: pointsCount * 60, // 秒
      createdAt: faker.date.recent({ days: 1 })
    };
  }

  // 创建 PostGIS 查询测试数据
  static createSpatialQuery() {
    const queryTypes = ['nearest', 'within', 'intersects', 'contains'];
    const center = testUtils.generateBeijingCoordinate();
    
    return {
      type: faker.helpers.arrayElement(queryTypes),
      center,
      radius: faker.number.int({ min: 500, max: 5000 }),
      bbox: {
        north: center.lat + 0.01,
        south: center.lat - 0.01,
        east: center.lng + 0.01,
        west: center.lng - 0.01
      },
      expectedResultCount: faker.number.int({ min: 0, max: 50 })
    };
  }
}

// 辅助函数
function generateGeoHash(lat: number, lng: number): string {
  // 简化的 geohash 生成（实际应使用专业库）
  return faker.string.alphanumeric(12);
}

function calculateDistanceFromCenter(location: { lat: number; lng: number }): number {
  // 以天安门为中心点
  const CENTER = { lat: 39.9042, lng: 116.4074 };
  return calculateDistance(location, CENTER);
}

function calculateDistance(p1: { lat: number; lng: number }, p2: { lat: number; lng: number }): number {
  const R = 6371000; // 地球半径（米）
  const φ1 = (p1.lat * Math.PI) / 180;
  const φ2 = (p2.lat * Math.PI) / 180;
  const Δφ = ((p2.lat - p1.lat) * Math.PI) / 180;
  const Δλ = ((p2.lng - p1.lng) * Math.PI) / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

function calculateTrajectoryDistance(points: any[]): number {
  let totalDistance = 0;
  for (let i = 1; i < points.length; i++) {
    totalDistance += calculateDistance(points[i - 1], points[i]);
  }
  return totalDistance;
}

// 批量数据生成器
export class DataGenerator {
  static async seedTestDatabase() {
    console.log('🌱 开始生成测试数据...');
    
    const users = UserFactory.createBatch(100);
    const annotations = AnnotationFactory.createBatch(500);
    const payments = PaymentFactory.createBatch(200);
    
    // 这里应该插入到数据库中
    // 具体实现根据你的数据库层而定
    
    console.log(`✅ 生成完成: ${users.length} 用户, ${annotations.length} 标注, ${payments.length} 支付记录`);
    
    return { users, annotations, payments };
  }

  static createRealisticScenario() {
    // 创建一个真实的业务场景
    const scenario = {
      name: '工业园区污染事件',
      location: BEIJING_HOTSPOTS.find(h => h.category === 'industrial')!,
      users: [
        UserFactory.createByType('NewUser'),
        ...UserFactory.createBatch(3, { userType: 'ActiveUser' }),
        UserFactory.createByType('PowerUser')
      ],
      annotations: [],
      timespan: {
        start: faker.date.recent({ days: 7 }),
        end: faker.date.recent({ days: 1 })
      }
    };

    // 在该位置附近创建多个相关标注
    scenario.annotations = AnnotationFactory.createForHotspot(scenario.location.name, 10)
      .map(annotation => ({
        ...annotation,
        category: 'industrial',
        intensity: faker.number.int({ min: 6, max: 10 }),
        createdAt: faker.date.between({ 
          from: scenario.timespan.start, 
          to: scenario.timespan.end 
        })
      }));

    return scenario;
  }
}

// 重置随机种子的工具函数
export function resetSeed(seed: number = 42) {
  faker.seed(seed);
  console.log(`🎲 重置随机种子为: ${seed}`);
}

// 导出热区数据供测试使用
export { BEIJING_HOTSPOTS, SMELL_CATEGORIES, USER_PATTERNS };