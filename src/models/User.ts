import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface User {
  id: string;
  email: string;
  username: string;
  password_hash: string;
  display_name?: string;
  bio?: string;
  avatar_url?: string;
  university?: string;
  graduation_year?: number;
  role: 'user' | 'moderator' | 'admin';
  status: 'active' | 'suspended' | 'deleted';
  email_verified: boolean;
  email_verification_token?: string;
  password_reset_token?: string;
  password_reset_expires?: Date;
  last_login_at?: Date;
  created_at: Date;
  updated_at: Date;
}

export interface CreateUserData {
  email: string;
  username: string;
  password: string;
  display_name?: string;
  university?: string;
  graduation_year?: number;
  role?: 'user' | 'moderator' | 'admin';
}

export interface UpdateUserData {
  display_name?: string;
  bio?: string;
  avatar_url?: string;
  status?: 'active' | 'suspended' | 'deleted';
  role?: 'user' | 'moderator' | 'admin';
  email_verified?: boolean;
  last_login_at?: Date;
}

export interface UserStats {
  total_annotations: number;
  total_comments: number;
  total_payments: number;
  reputation_score: number;
  // 社交统计
  followers_count: number;
  following_count: number;
  likes_received: number;
  likes_given: number;
  favorites_count: number;
  shares_count: number;
  // 活跃度统计
  activity_score: number;
  weekly_posts: number;
  monthly_posts: number;
}

const TABLE_NAME = 'users';

export class UserModel {
  // Create a new user
  static async create(userData: CreateUserData): Promise<User> {
    try {
      const saltRounds = 12;
      const password_hash = await bcrypt.hash(userData.password, saltRounds);

      const [user] = await db(TABLE_NAME)
        .insert({
          id: uuidv4(),
          email: userData.email.toLowerCase(),
          username: userData.username,
          password_hash,
          display_name: userData.display_name || userData.username,
          role: userData.role || 'user',
          status: 'active',
          email_verified: false,
        })
        .returning('*');

      logger.info('用户创建成功', { userId: user.id, email: user.email });
      return user;
    } catch (error) {
      logger.error('用户创建失败', error);
      throw error;
    }
  }

  // Find user by ID
  static async findById(id: string): Promise<User | null> {
    try {
      const user = await db(TABLE_NAME)
        .where({ id, status: 'active' })
        .first();

      return user || null;
    } catch (error) {
      logger.error('查找用户失败', { userId: id, error });
      throw error;
    }
  }

  // Find user by email
  static async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await db(TABLE_NAME)
        .where({ email: email.toLowerCase() })
        .first();

      return user || null;
    } catch (error) {
      logger.error('通过邮箱查找用户失败', { email, error });
      throw error;
    }
  }

  // Find user by username
  static async findByUsername(username: string): Promise<User | null> {
    try {
      const user = await db(TABLE_NAME)
        .where({ username })
        .first();

      return user || null;
    } catch (error) {
      logger.error('通过用户名查找用户失败', { username, error });
      throw error;
    }
  }

  // Update user
  static async update(id: string, updateData: UpdateUserData): Promise<User | null> {
    try {
      const [user] = await db(TABLE_NAME)
        .where({ id })
        .update({
          ...updateData,
          updated_at: new Date(),
        })
        .returning('*');

      if (user) {
        logger.info('用户更新成功', { userId: id });
      }

      return user || null;
    } catch (error) {
      logger.error('用户更新失败', { userId: id, error });
      throw error;
    }
  }

  // Verify password
  static async verifyPassword(user: User, password: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, user.password_hash);
    } catch (error) {
      logger.error('密码验证失败', { userId: user.id, error });
      return false;
    }
  }

  // Update password
  static async updatePassword(id: string, newPassword: string): Promise<boolean> {
    try {
      const saltRounds = 12;
      const password_hash = await bcrypt.hash(newPassword, saltRounds);

      const result = await db(TABLE_NAME)
        .where({ id })
        .update({
          password_hash,
          password_reset_token: null,
          password_reset_expires: null,
          updated_at: new Date(),
        });

      if (result > 0) {
        logger.info('密码更新成功', { userId: id });
        return true;
      }

      return false;
    } catch (error) {
      logger.error('密码更新失败', { userId: id, error });
      throw error;
    }
  }

  // Set password reset token
  static async setPasswordResetToken(
    email: string,
    token: string,
    expiresAt: Date,
  ): Promise<boolean> {
    try {
      const result = await db(TABLE_NAME)
        .where({ email: email.toLowerCase() })
        .update({
          password_reset_token: token,
          password_reset_expires: expiresAt,
          updated_at: new Date(),
        });

      return result > 0;
    } catch (error) {
      logger.error('设置密码重置令牌失败', { email, error });
      throw error;
    }
  }

  // Find user by password reset token
  static async findByPasswordResetToken(token: string): Promise<User | null> {
    try {
      const user = await db(TABLE_NAME)
        .where({ password_reset_token: token })
        .where('password_reset_expires', '>', new Date())
        .first();

      return user || null;
    } catch (error) {
      logger.error('通过密码重置令牌查找用户失败', { error });
      throw error;
    }
  }

  // Set email verification token
  static async setEmailVerificationToken(id: string, token: string): Promise<boolean> {
    try {
      const result = await db(TABLE_NAME)
        .where({ id })
        .update({
          email_verification_token: token,
          updated_at: new Date(),
        });

      return result > 0;
    } catch (error) {
      logger.error('设置邮箱验证令牌失败', { userId: id, error });
      throw error;
    }
  }

  // Verify email
  static async verifyEmail(token: string): Promise<User | null> {
    try {
      const [user] = await db(TABLE_NAME)
        .where({ email_verification_token: token })
        .update({
          email_verified: true,
          email_verification_token: null,
          updated_at: new Date(),
        })
        .returning('*');

      if (user) {
        logger.info('邮箱验证成功', { userId: user.id });
      }

      return user || null;
    } catch (error) {
      logger.error('邮箱验证失败', { error });
      throw error;
    }
  }

  // Update last login
  static async updateLastLogin(id: string): Promise<void> {
    try {
      await db(TABLE_NAME)
        .where({ id })
        .update({
          last_login_at: new Date(),
          updated_at: new Date(),
        });
    } catch (error) {
      logger.error('更新最后登录时间失败', { userId: id, error });
      // Don't throw error for this non-critical operation
    }
  }

  // Get user statistics
  static async getStats(id: string): Promise<UserStats> {
    try {
      // First check if user exists
      const user = await db(TABLE_NAME).where({ id }).first();
      if (!user) {
        throw new Error('用户不存在');
      }

      // 获取基本统计数据
      const [basicStats] = await Promise.all([
        this.getBasicStats(id),
        this.getSocialStats(id),
        this.getActivityStats(id)
      ]);
      
      const [_, socialStats, activityStats] = await Promise.all([
        Promise.resolve(),
        this.getSocialStats(id),
        this.getActivityStats(id)
      ]);

      return {
        ...basicStats,
        ...socialStats,
        ...activityStats
      };
    } catch (error) {
      logger.error('获取用户统计失败', { userId: id, error });
      throw error;
    }
  }

  // 获取基本统计
  private static async getBasicStats(id: string) {
    try {
      // 检查表是否存在，如果不存在就返回默认值
      const tables = ['annotations', 'comments', 'payments'];
      const existingTables = [];
      
      for (const table of tables) {
        try {
          await db.raw(`SELECT 1 FROM ${table} LIMIT 1`);
          existingTables.push(table);
        } catch (error) {
          logger.warn(`表 ${table} 不存在，将跳过相关统计`);
        }
      }
      
      // 如果没有任何表存在，返回默认统计
      if (existingTables.length === 0) {
        return {
          total_annotations: 0,
          total_comments: 0,
          total_payments: 0,
          reputation_score: 0,
        };
      }
      
      // 构建动态查询
      let annotationsJoin = 'LEFT JOIN (SELECT NULL as user_id, 0 as total_annotations WHERE FALSE) a ON FALSE';
      let commentsJoin = 'LEFT JOIN (SELECT NULL as user_id, 0 as total_comments WHERE FALSE) c ON FALSE';
      let paymentsJoin = 'LEFT JOIN (SELECT NULL as user_id, 0 as total_payments WHERE FALSE) p ON FALSE';
      
      if (existingTables.includes('annotations')) {
        annotationsJoin = `LEFT JOIN (
          SELECT user_id, COUNT(*) as total_annotations
          FROM annotations 
          WHERE status = 'approved'
          GROUP BY user_id
        ) a ON u.id = a.user_id`;
      }
      
      if (existingTables.includes('comments')) {
        commentsJoin = `LEFT JOIN (
          SELECT user_id, COUNT(*) as total_comments
          FROM comments 
          WHERE status = 'active'
          GROUP BY user_id
        ) c ON u.id = c.user_id`;
      }
      
      if (existingTables.includes('payments')) {
        paymentsJoin = `LEFT JOIN (
          SELECT user_id, COUNT(*) as total_payments
          FROM payments 
          WHERE status = 'completed'
          GROUP BY user_id
        ) p ON u.id = p.user_id`;
      }
      
      const result = await db.raw(`
        SELECT 
          COALESCE(a.total_annotations, 0) as total_annotations,
          COALESCE(c.total_comments, 0) as total_comments,
          COALESCE(p.total_payments, 0) as total_payments,
          COALESCE(a.total_annotations * 10 + c.total_comments * 2, 0) as reputation_score
        FROM users u
        ${annotationsJoin}
        ${commentsJoin}
        ${paymentsJoin}
        WHERE u.id = ?
      `, [id]);

      const stats = result[0];
      return {
        total_annotations: parseInt(stats?.total_annotations) || 0,
        total_comments: parseInt(stats?.total_comments) || 0,
        total_payments: parseInt(stats?.total_payments) || 0,
        reputation_score: parseInt(stats?.reputation_score) || 0,
      };
    } catch (error) {
      logger.error('获取基本统计失败，返回默认值', { userId: id, error });
      return {
        total_annotations: 0,
        total_comments: 0,
        total_payments: 0,
        reputation_score: 0,
      };
    }
  }

  // 获取社交统计
  private static async getSocialStats(id: string) {
    try {
      const stats = {
        followers_count: 0,
        following_count: 0,
        likes_received: 0,
        likes_given: 0,
        favorites_count: 0,
        shares_count: 0
      };
      
      // 检查并获取关注者数量
      try {
        const followersResult = await db('user_follows')
          .where('following_id', id)
          .count('* as count');
        stats.followers_count = parseInt(followersResult[0]?.['count'] as string) || 0;

        // 关注数量
        const followingResult = await db('user_follows')
          .where('follower_id', id)
          .count('* as count');
        stats.following_count = parseInt(followingResult[0]?.['count'] as string) || 0;
      } catch (error) {
        logger.warn('user_follows表不存在，跳过关注统计');
      }

      // 检查并获取点赞统计
      try {
        // 给出的点赞数
        const likesGivenResult = await db('annotation_likes')
          .where('user_id', id)
          .count('* as count');
        stats.likes_given = parseInt(likesGivenResult[0]?.['count'] as string) || 0;
        
        // 收到的点赞数(需要joins annotations表)
        try {
          const likesReceivedResult = await db('annotation_likes')
            .join('annotations', 'annotation_likes.annotation_id', 'annotations.id')
            .where('annotations.user_id', id)
            .count('* as count');
          stats.likes_received = parseInt(likesReceivedResult[0]?.['count'] as string) || 0;
        } catch (error) {
          logger.warn('annotations表不存在，跳过收到的点赞统计');
        }
      } catch (error) {
        logger.warn('annotation_likes表不存在，跳过点赞统计');
      }

      // 检查并获取收藏数量
      try {
        const favoritesResult = await db('user_favorites')
          .where('user_id', id)
          .count('* as count');
        stats.favorites_count = parseInt(favoritesResult[0]?.['count'] as string) || 0;
      } catch (error) {
        logger.warn('user_favorites表不存在，跳过收藏统计');
      }

      // 检查并获取分享数量
      try {
        const sharesResult = await db('share_records')
          .where('user_id', id)
          .count('* as count');
        stats.shares_count = parseInt(sharesResult[0]?.['count'] as string) || 0;
      } catch (error) {
        logger.warn('share_records表不存在，跳过分享统计');
      }

      return stats;
    } catch (error) {
      logger.error('获取社交统计失败', { userId: id, error });
      return {
        followers_count: 0,
        following_count: 0,
        likes_received: 0,
        likes_given: 0,
        favorites_count: 0,
        shares_count: 0
      };
    }
  }

  // 获取活跃度统计
  private static async getActivityStats(id: string) {
    try {
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      
      let weekly_posts = 0;
      let monthly_posts = 0;

      // 检查annotations表是否存在
      try {
        // 本周发布数
        const weeklyResult = await db('annotations')
          .where('user_id', id)
          .where('created_at', '>=', weekAgo)
          .count('* as count');
        weekly_posts = parseInt(weeklyResult[0]?.['count'] as string) || 0;

        // 本月发布数
        const monthlyResult = await db('annotations')
          .where('user_id', id)
          .where('created_at', '>=', monthAgo)
          .count('* as count');
        monthly_posts = parseInt(monthlyResult[0]?.['count'] as string) || 0;
      } catch (error) {
        logger.warn('annotations表不存在，跳过活跃度统计');
      }

      // 活跃度分数计算
      const activity_score = weekly_posts * 10 + monthly_posts * 3;

      return {
        activity_score,
        weekly_posts,
        monthly_posts
      };
    } catch (error) {
      logger.error('获取活跃度统计失败', { userId: id, error });
      return {
        activity_score: 0,
        weekly_posts: 0,
        monthly_posts: 0
      };
    }
  }

  // Get users list (admin)
  static async getList(options: {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    search?: string;
    role?: string;
    status?: string;
  } = {}): Promise<{ users: User[]; total: number }> {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'created_at',
        sortOrder = 'desc',
        search,
        role,
        status,
      } = options;

      let query = db(TABLE_NAME).select('*');

      // Apply filters
      if (search) {
        query = query.where(function () {
          this.where('email', 'ilike', `%${search}%`)
            .orWhere('username', 'ilike', `%${search}%`)
            .orWhere('display_name', 'ilike', `%${search}%`);
        });
      }

      if (role) {
        query = query.where('role', role);
      }

      if (status) {
        query = query.where('status', status);
      }

      // Get total count
      const countResult = await query.clone().count('* as count');
      const total = parseInt((countResult[0] as any).count as string, 10);

      // Apply pagination and sorting
      const users = await query
        .orderBy(sortBy, sortOrder)
        .limit(limit)
        .offset((page - 1) * limit);

      return { users, total };
    } catch (error) {
      logger.error('获取用户列表失败', error);
      throw error;
    }
  }

  // Delete user (soft delete)
  static async delete(id: string): Promise<boolean> {
    try {
      const result = await db(TABLE_NAME)
        .where({ id })
        .update({
          status: 'deleted',
          updated_at: new Date(),
        });

      if (result > 0) {
        logger.info('用户删除成功', { userId: id });
        return true;
      }

      return false;
    } catch (error) {
      logger.error('用户删除失败', { userId: id, error });
      throw error;
    }
  }

  // Check if email exists
  static async emailExists(email: string, excludeId?: string): Promise<boolean> {
    try {
      let query = db(TABLE_NAME)
        .where({ email: email.toLowerCase() })
        .whereNot({ status: 'deleted' });

      if (excludeId) {
        query = query.whereNot({ id: excludeId });
      }

      const user = await query.first();
      return !!user;
    } catch (error) {
      logger.error('检查邮箱是否存在失败', { email, error });
      throw error;
    }
  }

  // Check if username exists
  static async usernameExists(username: string, excludeId?: string): Promise<boolean> {
    try {
      let query = db(TABLE_NAME)
        .where({ username })
        .whereNot({ status: 'deleted' });

      if (excludeId) {
        query = query.whereNot({ id: excludeId });
      }

      const user = await query.first();
      return !!user;
    } catch (error) {
      logger.error('检查用户名是否存在失败', { username, error });
      throw error;
    }
  }
}

export default UserModel;
