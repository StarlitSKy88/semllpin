"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserFactory = void 0;
exports.createTestUser = createTestUser;
exports.createMultipleTestUsers = createMultipleTestUsers;
exports.persistTestUser = persistTestUser;
exports.persistMultipleTestUsers = persistMultipleTestUsers;
const index_1 = require("./index");
const bcrypt_1 = __importDefault(require("bcrypt"));
class UserFactoryClass {
    constructor() {
        this.counter = 0;
    }
    create(overrides = {}) {
        const config = (0, index_1.getFactoryConfig)();
        this.counter++;
        const baseUser = {
            id: overrides.id || `test-user-${this.counter}`,
            username: overrides.username || `testuser${this.counter}`,
            email: overrides.email || `test${this.counter}@smellpin.test`,
            password: overrides.password || 'TestPassword123!',
            hashedPassword: overrides.hashedPassword || bcrypt_1.default.hashSync('TestPassword123!', 10),
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
    createMultiple(count, overrides = {}) {
        return Array.from({ length: count }, (_, index) => {
            return this.create({
                ...overrides,
                username: overrides.username || `testuser${this.counter + index + 1}`,
                email: overrides.email || `test${this.counter + index + 1}@smellpin.test`,
            });
        });
    }
    build(overrides = {}) {
        const tempCounter = this.counter;
        const user = this.create(overrides);
        this.counter = tempCounter;
        return user;
    }
    buildList(count, overrides = {}) {
        return Array.from({ length: count }, () => this.build(overrides));
    }
    createAdmin(overrides = {}) {
        return this.create({
            username: `admin${this.counter}`,
            email: `admin${this.counter}@smellpin.test`,
            firstName: '管理员',
            bio: '系统管理员账户',
            ...overrides,
        });
    }
    createPremiumUser(overrides = {}) {
        return this.create({
            username: `premium${this.counter}`,
            email: `premium${this.counter}@smellpin.test`,
            firstName: '高级用户',
            bio: '付费高级用户账户',
            ...overrides,
        });
    }
    createInactiveUser(overrides = {}) {
        return this.create({
            status: 'inactive',
            emailVerified: false,
            lastLoginAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            ...overrides,
        });
    }
    createBannedUser(overrides = {}) {
        return this.create({
            status: 'banned',
            bio: '因违规操作被封禁的用户',
            ...overrides,
        });
    }
    reset() {
        this.counter = 0;
    }
}
exports.UserFactory = new UserFactoryClass();
async function createTestUser(overrides = {}) {
    return exports.UserFactory.create(overrides);
}
async function createMultipleTestUsers(count, overrides = {}) {
    return exports.UserFactory.createMultiple(count, overrides);
}
async function persistTestUser(userData, db) {
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
    }
    catch (error) {
        console.error('Failed to persist test user:', error);
        throw error;
    }
}
async function persistMultipleTestUsers(usersData, db) {
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
//# sourceMappingURL=userFactory.js.map