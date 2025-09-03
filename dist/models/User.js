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
            const result = await database_1.db.raw(`
        SELECT 
          COALESCE(a.total_annotations, 0) as total_annotations,
          COALESCE(c.total_comments, 0) as total_comments,
          COALESCE(p.total_payments, 0) as total_payments,
          COALESCE(a.total_annotations * 10 + c.total_comments * 2, 0) as reputation_score
        FROM users u
        LEFT JOIN (
          SELECT user_id, COUNT(*) as total_annotations
          FROM annotations 
          WHERE status = 'approved'
          GROUP BY user_id
        ) a ON u.id = a.user_id
        LEFT JOIN (
          SELECT user_id, COUNT(*) as total_comments
          FROM comments 
          WHERE status = 'active'
          GROUP BY user_id
        ) c ON u.id = c.user_id
        LEFT JOIN (
          SELECT user_id, COUNT(*) as total_payments
          FROM payments 
          WHERE status = 'completed'
          GROUP BY user_id
        ) p ON u.id = p.user_id
        WHERE u.id = ?
      `, [id]);
            const stats = result[0];
            return {
                total_annotations: parseInt(stats.total_annotations) || 0,
                total_comments: parseInt(stats.total_comments) || 0,
                total_payments: parseInt(stats.total_payments) || 0,
                reputation_score: parseInt(stats.reputation_score) || 0,
            };
        }
        catch (error) {
            logger_1.logger.error('获取用户统计失败', { userId: id, error });
            throw error;
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