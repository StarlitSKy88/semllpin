// 用户测试数据工厂
import { TestDataFactory, getFactoryConfig } from './index';
import { User } from '../../src/models/User';
import bcrypt from 'bcrypt';

// 测试用户数据接口
export interface TestUserData {
  id?: string;
  username: string;
  email: string;
  password?: string;
  hashedPassword?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  status?: 'active' | 'inactive' | 'banned';
  emailVerified?: boolean;
  phoneNumber?: string;
  dateOfBirth?: Date;
  gender?: string;
  bio?: string;
  location?: string;
  preferredLanguage?: string;
  timezone?: string;
  createdAt?: Date;
  updatedAt?: Date;
  lastLoginAt?: Date;
  loginCount?: number;
  twoFactorEnabled?: boolean;
}

class UserFactoryClass implements TestDataFactory<TestUserData> {
  private counter = 0;
  
  create(overrides: Partial<TestUserData> = {}): TestUserData {
    const config = getFactoryConfig();
    this.counter++;
    
    const baseUser: TestUserData = {
      id: overrides.id || `test-user-${this.counter}`,
      username: overrides.username || `testuser${this.counter}`,
      email: overrides.email || `test${this.counter}@smellpin.test`,
      password: overrides.password || 'TestPassword123!',
      hashedPassword: overrides.hashedPassword || bcrypt.hashSync('TestPassword123!', 10),
      firstName: overrides.firstName || `测试用户${this.counter}`,
      lastName: overrides.lastName || '姓氏',
      avatar: overrides.avatar || null,
      status: overrides.status || 'active',
      emailVerified: overrides.emailVerified ?? true,
      phoneNumber: overrides.phoneNumber || `1380000${String(this.counter).padStart(4, '0')}`,
      dateOfBirth: overrides.dateOfBirth || new Date('1990-01-01'),
      gender: overrides.gender || 'other',
      bio: overrides.bio || `这是测试用户${this.counter}的个人简介`,
      location: overrides.location || '北京市',
      preferredLanguage: overrides.preferredLanguage || 'zh-CN',
      timezone: overrides.timezone || config.timezone || 'Asia/Shanghai',
      createdAt: overrides.createdAt || new Date(),
      updatedAt: overrides.updatedAt || new Date(),
      lastLoginAt: overrides.lastLoginAt || new Date(),
      loginCount: overrides.loginCount || 1,
      twoFactorEnabled: overrides.twoFactorEnabled || false,
    };
    
    return { ...baseUser, ...overrides };
  }
  
  createMultiple(count: number, overrides: Partial<TestUserData> = {}): TestUserData[] {
    return Array.from({ length: count }, (_, index) => {
      return this.create({
        ...overrides,
        username: overrides.username || `testuser${this.counter + index + 1}`,
        email: overrides.email || `test${this.counter + index + 1}@smellpin.test`,
      });
    });
  }
  
  build(overrides: Partial<TestUserData> = {}): TestUserData {
    // build方法不递增计数器，用于构建但不持久化的数据
    const tempCounter = this.counter;
    const user = this.create(overrides);
    this.counter = tempCounter;
    return user;
  }
  
  buildList(count: number, overrides: Partial<TestUserData> = {}): TestUserData[] {
    return Array.from({ length: count }, () => this.build(overrides));
  }
  
  // 特殊用户类型创建方法
  createAdmin(overrides: Partial<TestUserData> = {}): TestUserData {
    return this.create({
      username: `admin${this.counter}`,
      email: `admin${this.counter}@smellpin.test`,
      firstName: '管理员',
      bio: '系统管理员账户',
      ...overrides,
    });
  }
  
  createPremiumUser(overrides: Partial<TestUserData> = {}): TestUserData {
    return this.create({
      username: `premium${this.counter}`,
      email: `premium${this.counter}@smellpin.test`,
      firstName: '高级用户',
      bio: '付费高级用户账户',
      ...overrides,
    });
  }
  
  createInactiveUser(overrides: Partial<TestUserData> = {}): TestUserData {
    return this.create({
      status: 'inactive',
      emailVerified: false,
      lastLoginAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30天前
      ...overrides,
    });
  }
  
  createBannedUser(overrides: Partial<TestUserData> = {}): TestUserData {
    return this.create({
      status: 'banned',
      bio: '因违规操作被封禁的用户',
      ...overrides,
    });
  }
  
  // 重置计数器
  reset(): void {
    this.counter = 0;
  }
}

export const UserFactory = new UserFactoryClass();

// 便捷函数
export async function createTestUser(overrides: Partial<TestUserData> = {}): Promise<TestUserData> {
  return UserFactory.create(overrides);
}

export async function createMultipleTestUsers(
  count: number, 
  overrides: Partial<TestUserData> = {}
): Promise<TestUserData[]> {
  return UserFactory.createMultiple(count, overrides);
}

// 数据库持久化辅助函数（需要数据库连接）
export async function persistTestUser(
  userData: TestUserData, 
  db?: any
): Promise<any> {
  if (!db) {
    throw new Error('Database connection required for persistence');
  }
  
  try {
    const [user] = await db('users')
      .insert({
        username: userData.username,
        email: userData.email,
        password_hash: userData.hashedPassword,
        first_name: userData.firstName,
        last_name: userData.lastName,
        avatar: userData.avatar,
        status: userData.status,
        email_verified: userData.emailVerified,
        phone_number: userData.phoneNumber,
        date_of_birth: userData.dateOfBirth,
        gender: userData.gender,
        bio: userData.bio,
        location: userData.location,
        preferred_language: userData.preferredLanguage,
        timezone: userData.timezone,
        created_at: userData.createdAt,
        updated_at: userData.updatedAt,
        last_login_at: userData.lastLoginAt,
        login_count: userData.loginCount,
        two_factor_enabled: userData.twoFactorEnabled,
      })
      .returning('*');
    
    return user;
  } catch (error) {
    console.error('Failed to persist test user:', error);
    throw error;
  }
}

// 批量持久化
export async function persistMultipleTestUsers(
  usersData: TestUserData[], 
  db?: any
): Promise<any[]> {
  if (!db) {
    throw new Error('Database connection required for persistence');
  }
  
  const users = [];
  for (const userData of usersData) {
    const user = await persistTestUser(userData, db);
    users.push(user);
  }
  
  return users;
}