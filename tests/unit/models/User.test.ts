// 用户模型单元测试 - SmellPin自动化测试方案2.0
import { User } from '../../../src/models/User';
import { UserFactory, createTestUser } from '../../factories/userFactory';
import { getTestDb, setupTestDatabase, cleanupTestDatabase, teardownTestDatabase } from '../../setup/databaseSetup';
import bcrypt from 'bcrypt';

describe('User Model', () => {
  let db: any;

  beforeAll(async () => {
    await setupTestDatabase();
    db = getTestDb();
  });

  afterEach(async () => {
    await cleanupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('User Creation', () => {
    it('should create a new user with valid data', async () => {
      const userData = UserFactory.create({
        username: 'testuser1',
        email: 'test1@smellpin.test',
        password: 'TestPassword123!',
      });

      const user = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
        firstName: userData.firstName,
        lastName: userData.lastName,
      });

      expect(user).toBeDefined();
      expect(user.id).toBeDefined();
      expect(user.username).toBe(userData.username);
      expect(user.email).toBe(userData.email);
      expect(user.status).toBe('active');
      expect(user.emailVerified).toBe(false); // 新用户默认未验证
    });

    it('should hash password during user creation', async () => {
      const userData = UserFactory.create({
        password: 'PlainTextPassword123!',
      });

      const user = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      });

      // 密码应该被hash
      expect(user.passwordHash).toBeDefined();
      expect(user.passwordHash).not.toBe(userData.password);
      expect(user.passwordHash).toMatch(/^\$2[ayb]\$\d{2}\$/);

      // 验证密码hash
      const isValid = await bcrypt.compare(userData.password!, user.passwordHash!);
      expect(isValid).toBe(true);
    });

    it('should reject user creation with invalid email', async () => {
      const userData = UserFactory.create({
        email: 'invalid-email',
      });

      await expect(User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      })).rejects.toThrow();
    });

    it('should reject user creation with duplicate username', async () => {
      const userData1 = UserFactory.create({
        username: 'duplicateuser',
      });

      const userData2 = UserFactory.create({
        username: 'duplicateuser', // 相同用户名
        email: 'different@smellpin.test',
      });

      // 创建第一个用户成功
      await User.create({
        username: userData1.username,
        email: userData1.email,
        password: userData1.password!,
      });

      // 创建第二个相同用户名的用户应该失败
      await expect(User.create({
        username: userData2.username,
        email: userData2.email,
        password: userData2.password!,
      })).rejects.toThrow();
    });

    it('should reject user creation with duplicate email', async () => {
      const userData1 = UserFactory.create({
        email: 'duplicate@smellpin.test',
      });

      const userData2 = UserFactory.create({
        username: 'differentuser',
        email: 'duplicate@smellpin.test', // 相同邮箱
      });

      // 创建第一个用户成功
      await User.create({
        username: userData1.username,
        email: userData1.email,
        password: userData1.password!,
      });

      // 创建第二个相同邮箱的用户应该失败
      await expect(User.create({
        username: userData2.username,
        email: userData2.email,
        password: userData2.password!,
      })).rejects.toThrow();
    });
  });

  describe('User Authentication', () => {
    let testUser: any;

    beforeEach(async () => {
      const userData = UserFactory.create({
        username: 'authtest',
        email: 'authtest@smellpin.test',
        password: 'AuthPassword123!',
      });

      testUser = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      });
    });

    it('should authenticate user with correct credentials', async () => {
      const authenticatedUser = await User.authenticate('authtest@smellpin.test', 'AuthPassword123!');
      
      expect(authenticatedUser).toBeDefined();
      expect(authenticatedUser!.id).toBe(testUser.id);
      expect(authenticatedUser!.email).toBe(testUser.email);
    });

    it('should fail authentication with incorrect password', async () => {
      const authenticatedUser = await User.authenticate('authtest@smellpin.test', 'WrongPassword123!');
      expect(authenticatedUser).toBeNull();
    });

    it('should fail authentication with non-existent email', async () => {
      const authenticatedUser = await User.authenticate('nonexistent@smellpin.test', 'AnyPassword123!');
      expect(authenticatedUser).toBeNull();
    });

    it('should fail authentication with inactive user', async () => {
      // 将用户状态设置为inactive
      await User.update(testUser.id, { status: 'inactive' });

      const authenticatedUser = await User.authenticate('authtest@smellpin.test', 'AuthPassword123!');
      expect(authenticatedUser).toBeNull();
    });
  });

  describe('User Profile Management', () => {
    let testUser: any;

    beforeEach(async () => {
      const userData = UserFactory.create({
        username: 'profiletest',
        email: 'profiletest@smellpin.test',
      });

      testUser = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      });
    });

    it('should update user profile successfully', async () => {
      const updateData = {
        firstName: '更新后的名字',
        lastName: '更新后的姓氏',
        bio: '更新后的个人简介',
        location: '北京市朝阳区',
      };

      const updatedUser = await User.update(testUser.id, updateData);

      expect(updatedUser.firstName).toBe(updateData.firstName);
      expect(updatedUser.lastName).toBe(updateData.lastName);
      expect(updatedUser.bio).toBe(updateData.bio);
      expect(updatedUser.location).toBe(updateData.location);
      expect(updatedUser.updatedAt).toBeInstanceOf(Date);
    });

    it('should update password correctly', async () => {
      const newPassword = 'NewPassword123!';
      const updatedUser = await User.updatePassword(testUser.id, newPassword);

      expect(updatedUser.passwordHash).toBeDefined();
      expect(updatedUser.passwordHash).not.toBe(testUser.passwordHash);

      // 验证新密码
      const isValid = await bcrypt.compare(newPassword, updatedUser.passwordHash!);
      expect(isValid).toBe(true);
    });

    it('should verify email successfully', async () => {
      expect(testUser.emailVerified).toBe(false);

      const verifiedUser = await User.verifyEmail(testUser.id);

      expect(verifiedUser.emailVerified).toBe(true);
      expect(verifiedUser.updatedAt).toBeInstanceOf(Date);
    });
  });

  describe('User Statistics', () => {
    let testUser: any;

    beforeEach(async () => {
      const userData = UserFactory.create({
        username: 'statstest',
        email: 'statstest@smellpin.test',
      });

      testUser = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      });
    });

    it('should get user statistics', async () => {
      const stats = await User.getStats(testUser.id);

      expect(stats).toBeDefined();
      expect(stats.user).toBeDefined();
      expect(stats.user.id).toBe(testUser.id);
      expect(stats.counts).toBeDefined();
      expect(stats.counts.annotations).toBe(0); // 新用户没有标注
      expect(stats.counts.likes).toBe(0);
      expect(stats.counts.comments).toBe(0);
      expect(stats.counts.followers).toBe(0);
      expect(stats.counts.following).toBe(0);
    });
  });

  describe('User Search and Retrieval', () => {
    beforeEach(async () => {
      // 创建多个测试用户
      const users = UserFactory.createMultiple(5, {});
      
      for (let i = 0; i < users.length; i++) {
        await User.create({
          username: users[i].username,
          email: users[i].email,
          password: users[i].password!,
          firstName: users[i].firstName,
          status: i % 2 === 0 ? 'active' : 'inactive', // 交替设置状态
        });
      }
    });

    it('should find user by ID', async () => {
      const users = await User.findAll();
      expect(users.length).toBeGreaterThan(0);

      const userId = users[0].id;
      const foundUser = await User.findById(userId);

      expect(foundUser).toBeDefined();
      expect(foundUser!.id).toBe(userId);
    });

    it('should find user by email', async () => {
      const users = await User.findAll();
      expect(users.length).toBeGreaterThan(0);

      const userEmail = users[0].email;
      const foundUser = await User.findByEmail(userEmail);

      expect(foundUser).toBeDefined();
      expect(foundUser!.email).toBe(userEmail);
    });

    it('should find user by username', async () => {
      const users = await User.findAll();
      expect(users.length).toBeGreaterThan(0);

      const username = users[0].username;
      const foundUser = await User.findByUsername(username);

      expect(foundUser).toBeDefined();
      expect(foundUser!.username).toBe(username);
    });

    it('should find all active users', async () => {
      const activeUsers = await User.findActive();
      
      expect(Array.isArray(activeUsers)).toBe(true);
      activeUsers.forEach(user => {
        expect(user.status).toBe('active');
      });
    });

    it('should paginate user results', async () => {
      const page1 = await User.findAll({ page: 1, limit: 2 });
      const page2 = await User.findAll({ page: 2, limit: 2 });

      expect(Array.isArray(page1)).toBe(true);
      expect(Array.isArray(page2)).toBe(true);
      expect(page1.length).toBeLessThanOrEqual(2);
      expect(page2.length).toBeLessThanOrEqual(2);
      
      if (page1.length > 0 && page2.length > 0) {
        expect(page1[0].id).not.toBe(page2[0].id);
      }
    });
  });

  describe('User Deletion', () => {
    let testUser: any;

    beforeEach(async () => {
      const userData = UserFactory.create({
        username: 'deletetest',
        email: 'deletetest@smellpin.test',
      });

      testUser = await User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      });
    });

    it('should soft delete user', async () => {
      const deletedUser = await User.delete(testUser.id);

      expect(deletedUser.deletedAt).toBeInstanceOf(Date);
      expect(deletedUser.status).toBe('inactive');

      // 用户应该仍然存在但被标记为删除
      const foundUser = await User.findById(testUser.id, { includeDeleted: true });
      expect(foundUser).toBeDefined();
      expect(foundUser!.deletedAt).toBeInstanceOf(Date);
    });

    it('should not find soft deleted user in normal queries', async () => {
      await User.delete(testUser.id);

      const foundUser = await User.findById(testUser.id);
      expect(foundUser).toBeNull();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty search queries gracefully', async () => {
      const users = await User.search('');
      expect(Array.isArray(users)).toBe(true);
    });

    it('should handle invalid user ID gracefully', async () => {
      const user = await User.findById('invalid-id');
      expect(user).toBeNull();
    });

    it('should handle non-existent user updates gracefully', async () => {
      await expect(User.update('non-existent-id', { firstName: 'test' }))
        .rejects.toThrow();
    });

    it('should validate email format', async () => {
      const userData = UserFactory.create({
        email: 'invalid.email.format',
      });

      await expect(User.create({
        username: userData.username,
        email: userData.email,
        password: userData.password!,
      })).rejects.toThrow();
    });

    it('should enforce username length constraints', async () => {
      const shortUsername = UserFactory.create({
        username: 'ab', // 太短
      });

      await expect(User.create({
        username: shortUsername.username,
        email: shortUsername.email,
        password: shortUsername.password!,
      })).rejects.toThrow();

      const longUsername = UserFactory.create({
        username: 'a'.repeat(51), // 太长
      });

      await expect(User.create({
        username: longUsername.username,
        email: longUsername.email,
        password: longUsername.password!,
      })).rejects.toThrow();
    });

    it('should enforce password strength requirements', async () => {
      const weakPassword = UserFactory.create({
        password: '123', // 太弱
      });

      await expect(User.create({
        username: weakPassword.username,
        email: weakPassword.email,
        password: weakPassword.password!,
      })).rejects.toThrow();
    });
  });
});