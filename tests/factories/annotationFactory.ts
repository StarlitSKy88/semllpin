// 标注测试数据工厂
import { TestDataFactory, getFactoryConfig } from './index';

// 测试标注数据接口
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

class AnnotationFactoryClass implements TestDataFactory<TestAnnotationData> {
  private counter = 0;
  
  // 预定义的气味类型
  private smellTypes = [
    '食物香味', '垃圾异味', '化学品味', '花香', '汽油味', 
    '香水味', '烟味', '油漆味', '海腥味', '土腥味'
  ];
  
  // 预定义的北京地区坐标
  private beijingLocations = [
    { lat: 39.9042, lng: 116.4074, name: '天安门广场' },
    { lat: 39.9163, lng: 116.3972, name: '故宫博物院' }, 
    { lat: 39.8847, lng: 116.3975, name: '天坛公园' },
    { lat: 40.0098, lng: 116.3349, name: '颐和园' },
    { lat: 39.9390, lng: 116.1173, name: '香山公园' },
    { lat: 39.9280, lng: 116.3830, name: '北海公园' },
    { lat: 39.8754, lng: 116.4348, name: '北京南站' },
    { lat: 40.0658, lng: 116.4103, name: '鸟巢体育场' },
  ];
  
  create(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    const config = getFactoryConfig();
    this.counter++;
    
    const location = this.beijingLocations[this.counter % this.beijingLocations.length];
    const smellType = this.smellTypes[this.counter % this.smellTypes.length];
    
    const baseAnnotation: TestAnnotationData = {
      id: overrides.id || `test-annotation-${this.counter}`,
      userId: overrides.userId || `test-user-${this.counter}`,
      title: overrides.title || `测试标注${this.counter}: ${smellType}`,
      description: overrides.description || `这是一个关于${smellType}的测试标注，位于${location.name}附近。`,
      smellType: overrides.smellType || smellType,
      intensity: overrides.intensity ?? Math.floor(Math.random() * 5) + 1, // 1-5
      latitude: overrides.latitude ?? location.lat + (Math.random() - 0.5) * 0.01,
      longitude: overrides.longitude ?? location.lng + (Math.random() - 0.5) * 0.01,
      locationName: overrides.locationName || location.name,
      address: overrides.address || `北京市朝阳区测试街道${this.counter}号`,
      status: overrides.status || 'published',
      visibility: overrides.visibility || 'public',
      tags: overrides.tags || [`测试${this.counter}`, smellType, '自动化测试'],
      mediaFiles: overrides.mediaFiles || [],
      likeCount: overrides.likeCount ?? Math.floor(Math.random() * 100),
      commentCount: overrides.commentCount ?? Math.floor(Math.random() * 20),
      shareCount: overrides.shareCount ?? Math.floor(Math.random() * 10),
      createdAt: overrides.createdAt || new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
      updatedAt: overrides.updatedAt || new Date(),
      publishedAt: overrides.publishedAt || new Date(Date.now() - Math.random() * 6 * 24 * 60 * 60 * 1000),
      moderatedAt: overrides.moderatedAt || null,
      moderatorId: overrides.moderatorId || null,
      moderationNote: overrides.moderationNote || null,
      reportCount: overrides.reportCount ?? 0,
      featured: overrides.featured ?? false,
      verified: overrides.verified ?? Math.random() < 0.3, // 30%概率验证
      language: overrides.language || config.locale || 'zh-CN',
      deviceInfo: overrides.deviceInfo || {
        platform: 'web',
        browser: 'Chrome',
        version: '91.0',
        userAgent: 'test-user-agent'
      },
      weatherCondition: overrides.weatherCondition || this.getRandomWeather(),
      temperature: overrides.temperature ?? Math.floor(Math.random() * 40) - 10, // -10到30度
      humidity: overrides.humidity ?? Math.floor(Math.random() * 100),
      windSpeed: overrides.windSpeed ?? Math.floor(Math.random() * 20),
      airQualityIndex: overrides.airQualityIndex ?? Math.floor(Math.random() * 300),
    };
    
    return { ...baseAnnotation, ...overrides };
  }
  
  private getRandomWeather(): string {
    const conditions = ['晴', '多云', '阴', '小雨', '中雨', '大雨', '雪', '雾', '霾'];
    return conditions[Math.floor(Math.random() * conditions.length)];
  }
  
  createMultiple(count: number, overrides: Partial<TestAnnotationData> = {}): TestAnnotationData[] {
    return Array.from({ length: count }, (_, index) => {
      const location = this.beijingLocations[index % this.beijingLocations.length];
      return this.create({
        ...overrides,
        title: overrides.title || `测试标注${this.counter + index + 1}`,
        latitude: location.lat + (Math.random() - 0.5) * 0.01,
        longitude: location.lng + (Math.random() - 0.5) * 0.01,
        locationName: location.name,
      });
    });
  }
  
  build(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    const tempCounter = this.counter;
    const annotation = this.create(overrides);
    this.counter = tempCounter;
    return annotation;
  }
  
  buildList(count: number, overrides: Partial<TestAnnotationData> = {}): TestAnnotationData[] {
    return Array.from({ length: count }, () => this.build(overrides));
  }
  
  // 特殊标注类型创建方法
  createDraftAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    return this.create({
      status: 'draft',
      publishedAt: null,
      visibility: 'private',
      likeCount: 0,
      commentCount: 0,
      shareCount: 0,
      ...overrides,
    });
  }
  
  createApprovedAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    return this.create({
      status: 'approved',
      verified: true,
      featured: Math.random() < 0.5,
      moderatedAt: new Date(),
      moderatorId: 'test-moderator-1',
      moderationNote: '内容审核通过',
      ...overrides,
    });
  }
  
  createRejectedAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    return this.create({
      status: 'rejected',
      visibility: 'private',
      moderatedAt: new Date(),
      moderatorId: 'test-moderator-1',
      moderationNote: '内容不符合社区准则',
      ...overrides,
    });
  }
  
  createFlaggedAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    return this.create({
      status: 'flagged',
      reportCount: Math.floor(Math.random() * 10) + 1,
      moderationNote: '用户举报待审核',
      ...overrides,
    });
  }
  
  createHighIntensityAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
    return this.create({
      intensity: 5,
      smellType: '化学品味',
      title: `高强度气味警报${this.counter}`,
      description: '检测到高强度异常气味，请注意安全',
      featured: true,
      verified: true,
      ...overrides,
    });
  }
  
  createClusteredAnnotations(
    centerLat: number, 
    centerLng: number, 
    count: number, 
    radius: number = 0.005
  ): TestAnnotationData[] {
    return Array.from({ length: count }, () => {
      const angle = Math.random() * 2 * Math.PI;
      const distance = Math.random() * radius;
      const lat = centerLat + distance * Math.cos(angle);
      const lng = centerLng + distance * Math.sin(angle);
      
      return this.create({
        latitude: lat,
        longitude: lng,
        locationName: '聚集区域',
      });
    });
  }
  
  // 重置计数器
  reset(): void {
    this.counter = 0;
  }
}

export const AnnotationFactory = new AnnotationFactoryClass();

// 便捷函数
export function createTestAnnotation(overrides: Partial<TestAnnotationData> = {}): TestAnnotationData {
  return AnnotationFactory.create(overrides);
}

export function createMultipleTestAnnotations(
  count: number, 
  overrides: Partial<TestAnnotationData> = {}
): TestAnnotationData[] {
  return AnnotationFactory.createMultiple(count, overrides);
}

// 数据库持久化辅助函数
export async function persistTestAnnotation(
  annotationData: TestAnnotationData, 
  db?: any
): Promise<any> {
  if (!db) {
    throw new Error('Database connection required for persistence');
  }
  
  try {
    const [annotation] = await db('annotations')
      .insert({
        user_id: annotationData.userId,
        title: annotationData.title,
        description: annotationData.description,
        smell_type: annotationData.smellType,
        intensity: annotationData.intensity,
        latitude: annotationData.latitude,
        longitude: annotationData.longitude,
        location_name: annotationData.locationName,
        address: annotationData.address,
        status: annotationData.status,
        visibility: annotationData.visibility,
        tags: JSON.stringify(annotationData.tags),
        media_files: JSON.stringify(annotationData.mediaFiles),
        like_count: annotationData.likeCount,
        comment_count: annotationData.commentCount,
        share_count: annotationData.shareCount,
        created_at: annotationData.createdAt,
        updated_at: annotationData.updatedAt,
        published_at: annotationData.publishedAt,
        moderated_at: annotationData.moderatedAt,
        moderator_id: annotationData.moderatorId,
        moderation_note: annotationData.moderationNote,
        report_count: annotationData.reportCount,
        featured: annotationData.featured,
        verified: annotationData.verified,
        language: annotationData.language,
        device_info: JSON.stringify(annotationData.deviceInfo),
        weather_condition: annotationData.weatherCondition,
        temperature: annotationData.temperature,
        humidity: annotationData.humidity,
        wind_speed: annotationData.windSpeed,
        air_quality_index: annotationData.airQualityIndex,
      })
      .returning('*');
    
    return annotation;
  } catch (error) {
    console.error('Failed to persist test annotation:', error);
    throw error;
  }
}