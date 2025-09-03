// 媒体文件测试数据工厂
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

class MediaFactoryClass implements TestDataFactory<TestMediaData> {
  private counter = 0;
  
  create(overrides: Partial<TestMediaData> = {}): TestMediaData {
    this.counter++;
    
    const isImage = !overrides.mimetype || overrides.mimetype.startsWith('image/');
    const isVideo = overrides.mimetype && overrides.mimetype.startsWith('video/');
    
    const baseMedia: TestMediaData = {
      id: overrides.id || `test-media-${this.counter}`,
      userId: overrides.userId || `test-user-${this.counter}`,
      annotationId: overrides.annotationId || `test-annotation-${this.counter}`,
      filename: overrides.filename || `test-image-${this.counter}.jpg`,
      originalName: overrides.originalName || `测试图片${this.counter}.jpg`,
      mimetype: overrides.mimetype || 'image/jpeg',
      size: overrides.size ?? Math.floor(Math.random() * 5000000) + 100000, // 100KB-5MB
      path: overrides.path || `/uploads/test/test-image-${this.counter}.jpg`,
      url: overrides.url || `https://test.smellpin.com/uploads/test-image-${this.counter}.jpg`,
      thumbnailUrl: overrides.thumbnailUrl || (isImage ? `https://test.smellpin.com/uploads/thumb/test-image-${this.counter}_thumb.jpg` : undefined),
      width: overrides.width ?? (isImage ? Math.floor(Math.random() * 2000) + 800 : undefined),
      height: overrides.height ?? (isImage ? Math.floor(Math.random() * 2000) + 600 : undefined),
      duration: overrides.duration ?? (isVideo ? Math.floor(Math.random() * 300) + 10 : undefined),
      fileHash: overrides.fileHash || `test_hash_${this.counter}_${Math.random().toString(36).substr(2, 9)}`,
      uploadStatus: overrides.uploadStatus || 'completed',
      metadata: overrides.metadata || {
        device: 'test-device',
        location: { lat: 39.9042, lng: 116.4074 },
        timestamp: new Date().toISOString(),
      },
      createdAt: overrides.createdAt || new Date(),
      updatedAt: overrides.updatedAt || new Date(),
      deletedAt: overrides.deletedAt || null,
    };
    
    return { ...baseMedia, ...overrides };
  }
  
  createMultiple(count: number, overrides: Partial<TestMediaData> = {}): TestMediaData[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }
  
  build(overrides: Partial<TestMediaData> = {}): TestMediaData {
    const tempCounter = this.counter;
    const media = this.create(overrides);
    this.counter = tempCounter;
    return media;
  }
  
  buildList(count: number, overrides: Partial<TestMediaData> = {}): TestMediaData[] {
    return Array.from({ length: count }, () => this.build(overrides));
  }
  
  createImageMedia(overrides: Partial<TestMediaData> = {}): TestMediaData {
    return this.create({
      mimetype: 'image/jpeg',
      filename: `test-image-${this.counter}.jpg`,
      originalName: `测试图片${this.counter}.jpg`,
      width: 1920,
      height: 1080,
      ...overrides,
    });
  }
  
  createVideoMedia(overrides: Partial<TestMediaData> = {}): TestMediaData {
    return this.create({
      mimetype: 'video/mp4',
      filename: `test-video-${this.counter}.mp4`,
      originalName: `测试视频${this.counter}.mp4`,
      duration: 30,
      width: 1920,
      height: 1080,
      ...overrides,
    });
  }
  
  createAudioMedia(overrides: Partial<TestMediaData> = {}): TestMediaData {
    return this.create({
      mimetype: 'audio/mp3',
      filename: `test-audio-${this.counter}.mp3`,
      originalName: `测试音频${this.counter}.mp3`,
      duration: 60,
      width: undefined,
      height: undefined,
      thumbnailUrl: undefined,
      ...overrides,
    });
  }
  
  reset(): void {
    this.counter = 0;
  }
}

export const MediaFactory = new MediaFactoryClass();

export function createTestMedia(overrides: Partial<TestMediaData> = {}): TestMediaData {
  return MediaFactory.create(overrides);
}