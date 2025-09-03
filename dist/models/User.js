"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserModel = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const uuid_1 = require("uuid");
const database_1 = require("@/config/database");
const logger_1 = require("@/utils/logger");
const TABLE_NAME = 'users';
class UserModel {
    static async create(userData) {
        try {
            const saltRounds = 12;
            const password_hash = await bcrypt_1.default.hash(userData.password, saltRounds);
            const [user] = await (0, database_1.db)(TABLE_NAME)
                .insert({
                id: (0, uuid_1.v4)(),
                email: userData.email.toLowerCase(),
                username: userData.username,
                password_hash,
                display_name: userData.display_name || userData.username,
                role: userData.role || 'user',
                status: 'active',
                email_verified: false,
            })
                .returning('*');
            logger_1.logger.info('用户创建成功', { userId: user.id, email: user.email });
            return user;
        }
        catch (error) {
            logger_1.logger.error('用户创建失败', error);
            throw error;
        }
    }
    static async findById(id) {
        try {
            const user = await (0, database_1.db)(TABLE_NAME)
                .where({ id, status: 'active' })
                .first();
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('查找用户失败', { userId: id, error });
            throw error;
        }
    }
    static async findByEmail(email) {
        try {
            const user = await (0, database_1.db)(TABLE_NAME)
                .where({ email: email.toLowerCase() })
                .first();
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('通过邮箱查找用户失败', { email, error });
            throw error;
        }
    }
    static async findByUsername(username) {
        try {
            const user = await (0, database_1.db)(TABLE_NAME)
                .where({ username })
                .first();
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('通过用户名查找用户失败', { username, error });
            throw error;
        }
    }
    static async update(id, updateData) {
        try {
            const [user] = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                ...updateData,
                updated_at: new Date(),
            })
                .returning('*');
            if (user) {
                logger_1.logger.info('用户更新成功', { userId: id });
            }
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('用户更新失败', { userId: id, error });
            throw error;
        }
    }
    static async verifyPassword(user, password) {
        try {
            return await bcrypt_1.default.compare(password, user.password_hash);
        }
        catch (error) {
            logger_1.logger.error('密码验证失败', { userId: user.id, error });
            return false;
        }
    }
    static async updatePassword(id, newPassword) {
        try {
            const saltRounds = 12;
            const password_hash = await bcrypt_1.default.hash(newPassword, saltRounds);
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                password_hash,
                password_reset_token: null,
                password_reset_expires: null,
                updated_at: new Date(),
            });
            if (result > 0) {
                logger_1.logger.info('密码更新成功', { userId: id });
                return true;
            }
            return false;
        }
        catch (error) {
            logger_1.logger.error('密码更新失败', { userId: id, error });
            throw error;
        }
    }
    static async setPasswordResetToken(email, token, expiresAt) {
        try {
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ email: email.toLowerCase() })
                .update({
                password_reset_token: token,
                password_reset_expires: expiresAt,
                updated_at: new Date(),
            });
            return result > 0;
        }
        catch (error) {
            logger_1.logger.error('设置密码重置令牌失败', { email, error });
            throw error;
        }
    }
    static async findByPasswordResetToken(token) {
        try {
            const user = await (0, database_1.db)(TABLE_NAME)
                .where({ password_reset_token: token })
                .where('password_reset_expires', '>', new Date())
                .first();
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('通过密码重置令牌查找用户失败', { error });
            throw error;
        }
    }
    static async setEmailVerificationToken(id, token) {
        try {
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                email_verification_token: token,
                updated_at: new Date(),
            });
            return result > 0;
        }
        catch (error) {
            logger_1.logger.error('设置邮箱验证令牌失败', { userId: id, error });
            throw error;
        }
    }
    static async verifyEmail(token) {
        try {
            const [user] = await (0, database_1.db)(TABLE_NAME)
                .where({ email_verification_token: token })
                .update({
                email_verified: true,
                email_verification_token: null,
                updated_at: new Date(),
            })
                .returning('*');
            if (user) {
                logger_1.logger.info('邮箱验证成功', { userId: user.id });
            }
            return user || null;
        }
        catch (error) {
            logger_1.logger.error('邮箱验证失败', { error });
            throw error;
        }
    }
    static async updateLastLogin(id) {
        try {
            await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                last_login_at: new Date(),
                updated_at: new Date(),
            });
        }
        catch (error) {
            logger_1.logger.error('更新最后登录时间失败', { userId: id, error });
        }
    }
    static async getStats(id) {
        try {
            const user = await (0, database_1.db)(TABLE_NAME).where({ id }).first();
            if (!user) {
                throw new Error('用户不存在');
            }
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
        }
        catch (error) {
            logger_1.logger.error('获取用户统计失败', { userId: id, error });
            throw error;
        }
    }
    static async getBasicStats(id) {
        try {
            const tables = ['annotations', 'comments', 'payments'];
            const existingTables = [];
            for (const table of tables) {
                try {
                    await database_1.db.raw(`SELECT 1 FROM ${table} LIMIT 1`);
                    existingTables.push(table);
                }
                catch (error) {
                    logger_1.logger.warn(`表 ${table} 不存在，将跳过相关统计`);
                }
            }
            if (existingTables.length === 0) {
                return {
                    total_annotations: 0,
                    total_comments: 0,
                    total_payments: 0,
                    reputation_score: 0,
                };
            }
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
            const result = await database_1.db.raw(`
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
        }
        catch (error) {
            logger_1.logger.error('获取基本统计失败，返回默认值', { userId: id, error });
            return {
                total_annotations: 0,
                total_comments: 0,
                total_payments: 0,
                reputation_score: 0,
            };
        }
    }
    static async getSocialStats(id) {
        try {
            const stats = {
                followers_count: 0,
                following_count: 0,
                likes_received: 0,
                likes_given: 0,
                favorites_count: 0,
                shares_count: 0
            };
            try {
                const followersResult = await (0, database_1.db)('user_follows')
                    .where('following_id', id)
                    .count('* as count');
                stats.followers_count = parseInt(followersResult[0]?.['count']) || 0;
                const followingResult = await (0, database_1.db)('user_follows')
                    .where('follower_id', id)
                    .count('* as count');
                stats.following_count = parseInt(followingResult[0]?.['count']) || 0;
            }
            catch (error) {
                logger_1.logger.warn('user_follows表不存在，跳过关注统计');
            }
            try {
                const likesGivenResult = await (0, database_1.db)('annotation_likes')
                    .where('user_id', id)
                    .count('* as count');
                stats.likes_given = parseInt(likesGivenResult[0]?.['count']) || 0;
                try {
                    const likesReceivedResult = await (0, database_1.db)('annotation_likes')
                        .join('annotations', 'annotation_likes.annotation_id', 'annotations.id')
                        .where('annotations.user_id', id)
                        .count('* as count');
                    stats.likes_received = parseInt(likesReceivedResult[0]?.['count']) || 0;
                }
                catch (error) {
                    logger_1.logger.warn('annotations表不存在，跳过收到的点赞统计');
                }
            }
            catch (error) {
                logger_1.logger.warn('annotation_likes表不存在，跳过点赞统计');
            }
            try {
                const favoritesResult = await (0, database_1.db)('user_favorites')
                    .where('user_id', id)
                    .count('* as count');
                stats.favorites_count = parseInt(favoritesResult[0]?.['count']) || 0;
            }
            catch (error) {
                logger_1.logger.warn('user_favorites表不存在，跳过收藏统计');
            }
            try {
                const sharesResult = await (0, database_1.db)('share_records')
                    .where('user_id', id)
                    .count('* as count');
                stats.shares_count = parseInt(sharesResult[0]?.['count']) || 0;
            }
            catch (error) {
                logger_1.logger.warn('share_records表不存在，跳过分享统计');
            }
            return stats;
        }
        catch (error) {
            logger_1.logger.error('获取社交统计失败', { userId: id, error });
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
    static async getActivityStats(id) {
        try {
            const now = new Date();
            const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
            const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            let weekly_posts = 0;
            let monthly_posts = 0;
            try {
                const weeklyResult = await (0, database_1.db)('annotations')
                    .where('user_id', id)
                    .where('created_at', '>=', weekAgo)
                    .count('* as count');
                weekly_posts = parseInt(weeklyResult[0]?.['count']) || 0;
                const monthlyResult = await (0, database_1.db)('annotations')
                    .where('user_id', id)
                    .where('created_at', '>=', monthAgo)
                    .count('* as count');
                monthly_posts = parseInt(monthlyResult[0]?.['count']) || 0;
            }
            catch (error) {
                logger_1.logger.warn('annotations表不存在，跳过活跃度统计');
            }
            const activity_score = weekly_posts * 10 + monthly_posts * 3;
            return {
                activity_score,
                weekly_posts,
                monthly_posts
            };
        }
        catch (error) {
            logger_1.logger.error('获取活跃度统计失败', { userId: id, error });
            return {
                activity_score: 0,
                weekly_posts: 0,
                monthly_posts: 0
            };
        }
    }
    static async getList(options = {}) {
        try {
            const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', search, role, status, } = options;
            let query = (0, database_1.db)(TABLE_NAME).select('*');
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
            const countResult = await query.clone().count('* as count');
            const total = parseInt(countResult[0].count, 10);
            const users = await query
                .orderBy(sortBy, sortOrder)
                .limit(limit)
                .offset((page - 1) * limit);
            return { users, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户列表失败', error);
            throw error;
        }
    }
    static async delete(id) {
        try {
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                status: 'deleted',
                updated_at: new Date(),
            });
            if (result > 0) {
                logger_1.logger.info('用户删除成功', { userId: id });
                return true;
            }
            return false;
        }
        catch (error) {
            logger_1.logger.error('用户删除失败', { userId: id, error });
            throw error;
        }
    }
    static async emailExists(email, excludeId) {
        try {
            let query = (0, database_1.db)(TABLE_NAME)
                .where({ email: email.toLowerCase() })
                .whereNot({ status: 'deleted' });
            if (excludeId) {
                query = query.whereNot({ id: excludeId });
            }
            const user = await query.first();
            return !!user;
        }
        catch (error) {
            logger_1.logger.error('检查邮箱是否存在失败', { email, error });
            throw error;
        }
    }
    static async usernameExists(username, excludeId) {
        try {
            let query = (0, database_1.db)(TABLE_NAME)
                .where({ username })
                .whereNot({ status: 'deleted' });
            if (excludeId) {
                query = query.whereNot({ id: excludeId });
            }
            const user = await query.first();
            return !!user;
        }
        catch (error) {
            logger_1.logger.error('检查用户名是否存在失败', { username, error });
            throw error;
        }
    }
}
exports.UserModel = UserModel;
exports.default = UserModel;
//# sourceMappingURL=User.js.map