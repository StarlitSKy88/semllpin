// 测试数据工厂 - SmellPin自动化测试方案2.0
export { UserFactory, createTestUser, createMultipleTestUsers } from './userFactory';
export { AnnotationFactory, createTestAnnotation, createMultipleTestAnnotations } from './annotationFactory';
export { MediaFactory, createTestMedia } from './mediaFactory';
export { LocationFactory, createTestLocation } from './locationFactory';
export { PaymentFactory, createTestPayment } from './paymentFactory';

// 通用工厂接口
export interface TestDataFactory<T> {
  create(overrides?: Partial<T>): T;
  createMultiple(count: number, overrides?: Partial<T>): T[];
  build(overrides?: Partial<T>): T;
  buildList(count: number, overrides?: Partial<T>): T[];
}

// 测试数据生成器配置
export interface FactoryConfig {
  seed?: number;
  locale?: string;
  timezone?: string;
}

// 全局工厂配置
const defaultConfig: FactoryConfig = {
  seed: 12345,
  locale: 'zh-CN',
  timezone: 'Asia/Shanghai',
};

let factoryConfig = { ...defaultConfig };

export function configureFactories(config: Partial<FactoryConfig>): void {
  factoryConfig = { ...factoryConfig, ...config };
}

export function getFactoryConfig(): FactoryConfig {
  return factoryConfig;
}

// 重置所有工厂数据
export function resetFactories(): void {
  factoryConfig = { ...defaultConfig };
}

// 数据清理工具
export async function cleanupTestData(): Promise<void> {
  // 这个函数会被各个工厂模块使用来清理测试数据
  console.log('🧹 Cleaning up test data...');
}