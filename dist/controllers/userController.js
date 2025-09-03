"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteUser = exports.updateUser = exports.getUsersList = exports.getUserById = exports.resetPassword = exports.forgotPassword = exports.changePassword = exports.updateProfile = exports.getProfile = exports.logout = exports.refreshToken = exports.login = exports.register = void 0;
const User_1 = require("@/models/User");
const auth_1 = require("@/middleware/auth");
const errorHandler_1 = require("@/middleware/errorHandler");
const errorHandler_2 = require("@/middleware/errorHandler");
const logger_1 = require("@/utils/logger");
const redis_1 = require("@/config/redis");
const crypto_1 = __importDefault(require("crypto"));
exports.register = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { email, password, username, displayName, university, graduation_year } = req.body;
    if (!email || !password || !username) {
        throw (0, errorHandler_1.createValidationError)('credentials', '邮箱、密码和用户名不能为空');
    }
    if (await User_1.UserModel.emailExists(email)) {
        throw (0, errorHandler_1.createConflictError)('邮箱已被注册');
    }
    if (await User_1.UserModel.usernameExists(username)) {
        throw (0, errorHandler_1.createConflictError)('用户名已被使用');
    }
    const userData = {
        email,
        password,
        username,
        display_name: displayName || username,
        university,
        graduation_year,
    };
    const user = await User_1.UserModel.create(userData);
    const accessToken = (0, auth_1.generateToken)({
        sub: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
    });
    const refreshToken = (0, auth_1.generateRefreshToken)(user.id);
    await redis_1.cacheService.set(`user:${user.id}`, JSON.stringify({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
    }), 3600);
    await redis_1.cacheService.set(`refresh_token:${user.id}`, refreshToken, 7 * 24 * 3600);
    logger_1.logger.info('用户注册成功', { userId: user.id, email: user.email });
    res.status(201).json({
        success: true,
        message: '注册成功',
        data: {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                university: user.university,
                graduation_year: user.graduation_year,
                role: user.role,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
            },
            tokens: {
                accessToken,
                refreshToken,
                expiresIn: '24h',
            },
        },
    });
});
exports.login = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        throw (0, errorHandler_1.createValidationError)('credentials', '邮箱和密码不能为空');
    }
    const user = await User_1.UserModel.findByEmail(email);
    if (!user) {
        throw (0, errorHandler_1.createAuthError)('邮箱或密码错误');
    }
    if (user.status !== 'active') {
        throw (0, errorHandler_1.createAuthError)('账户已被禁用');
    }
    const isValidPassword = await User_1.UserModel.verifyPassword(user, password);
    if (!isValidPassword) {
        throw (0, errorHandler_1.createAuthError)('邮箱或密码错误');
    }
    const accessToken = (0, auth_1.generateToken)({
        sub: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
    });
    const refreshToken = (0, auth_1.generateRefreshToken)(user.id);
    await redis_1.cacheService.set(`user:${user.id}`, JSON.stringify({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
    }), 3600);
    await redis_1.cacheService.set(`refresh_token:${user.id}`, refreshToken, 7 * 24 * 3600);
    await User_1.UserModel.updateLastLogin(user.id);
    logger_1.logger.info('用户登录成功', { userId: user.id, email: user.email });
    res.json({
        success: true,
        message: '登录成功',
        data: {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                role: user.role,
                emailVerified: user.email_verified,
                lastLoginAt: user.last_login_at,
            },
            tokens: {
                accessToken,
                refreshToken,
                expiresIn: '24h',
            },
        },
    });
});
exports.refreshToken = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { refreshToken: token } = req.body;
    if (!token) {
        throw (0, errorHandler_1.createAuthError)('刷新令牌缺失');
    }
    try {
        const payload = await (0, auth_1.verifyRefreshToken)(token);
        const cachedToken = await redis_1.cacheService.get(`refresh_token:${payload.sub}`);
        if (cachedToken !== token) {
            throw (0, errorHandler_1.createAuthError)('刷新令牌无效');
        }
        const user = await User_1.UserModel.findById(payload.sub);
        if (!user || user.status !== 'active') {
            throw (0, errorHandler_1.createAuthError)('用户不存在或已被禁用');
        }
        const accessToken = (0, auth_1.generateToken)({
            sub: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
        });
        res.json({
            success: true,
            message: '令牌刷新成功',
            data: {
                accessToken,
                expiresIn: '24h',
            },
        });
    }
    catch (error) {
        throw (0, errorHandler_1.createAuthError)('刷新令牌无效或已过期');
    }
});
exports.logout = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const token = req.headers.authorization?.substring(7);
    const userId = req.user?.id;
    if (token) {
        await (0, auth_1.blacklistToken)(token);
    }
    if (userId) {
        await redis_1.cacheService.del(`refresh_token:${userId}`);
        await redis_1.cacheService.del(`user:${userId}`);
        logger_1.logger.info('用户登出成功', { userId });
    }
    res.json({
        success: true,
        message: '登出成功',
    });
});
exports.getProfile = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const user = await User_1.UserModel.findById(userId);
    if (!user) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    const stats = await User_1.UserModel.getStats(userId);
    res.json({
        success: true,
        data: {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                bio: user.bio,
                avatarUrl: user.avatar_url,
                role: user.role,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at,
            },
            stats,
        },
    });
});
exports.updateProfile = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { displayName, bio } = req.body;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const updateData = {};
    if (displayName !== undefined) {
        updateData.display_name = displayName;
    }
    if (bio !== undefined) {
        updateData.bio = bio;
    }
    const user = await User_1.UserModel.update(userId, updateData);
    if (!user) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    await redis_1.cacheService.set(`user:${userId}`, JSON.stringify({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
    }), 3600);
    res.json({
        success: true,
        message: '个人资料更新成功',
        data: {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                bio: user.bio,
                avatarUrl: user.avatar_url,
                role: user.role,
                updatedAt: user.updated_at,
            },
        },
    });
});
exports.changePassword = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
        throw (0, errorHandler_1.createValidationError)('password', '当前密码和新密码不能为空');
    }
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const user = await User_1.UserModel.findById(userId);
    if (!user) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    const isValidPassword = await User_1.UserModel.verifyPassword(user, currentPassword);
    if (!isValidPassword) {
        throw (0, errorHandler_1.createAuthError)('当前密码错误');
    }
    const success = await User_1.UserModel.updatePassword(userId, newPassword);
    if (!success) {
        throw new errorHandler_1.AppError('密码更新失败', 500);
    }
    logger_1.logger.info('用户密码更新成功', { userId });
    res.json({
        success: true,
        message: '密码更新成功',
    });
});
exports.forgotPassword = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { email } = req.body;
    if (!email) {
        throw (0, errorHandler_1.createValidationError)('email', '邮箱不能为空');
    }
    const user = await User_1.UserModel.findByEmail(email);
    if (!user) {
        res.json({
            success: true,
            message: '如果邮箱存在，重置链接已发送',
        });
        return;
    }
    const resetToken = crypto_1.default.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000);
    await User_1.UserModel.setPasswordResetToken(email, resetToken, resetExpires);
    logger_1.logger.info('密码重置令牌生成', { userId: user.id, email });
    res.json({
        success: true,
        message: '重置链接已发送到您的邮箱',
    });
});
exports.resetPassword = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { token, password } = req.body;
    if (!token || !password) {
        throw (0, errorHandler_1.createValidationError)('token', '重置令牌和新密码不能为空');
    }
    const user = await User_1.UserModel.findByPasswordResetToken(token);
    if (!user) {
        throw (0, errorHandler_1.createAuthError)('重置令牌无效或已过期');
    }
    const success = await User_1.UserModel.updatePassword(user.id, password);
    if (!success) {
        throw new errorHandler_1.AppError('密码重置失败', 500);
    }
    logger_1.logger.info('密码重置成功', { userId: user.id });
    res.json({
        success: true,
        message: '密码重置成功',
    });
});
exports.getUserById = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '用户ID不能为空');
    }
    const user = await User_1.UserModel.findById(id);
    if (!user) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    const stats = await User_1.UserModel.getStats(id);
    res.json({
        success: true,
        data: {
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                bio: user.bio,
                avatarUrl: user.avatar_url,
                createdAt: user.created_at,
            },
            stats,
        },
    });
});
exports.getUsersList = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', search, role, status, } = req.query;
    const options = {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        sortBy: sortBy,
        sortOrder: sortOrder,
    };
    if (search) {
        options.search = search;
    }
    if (role) {
        options.role = role;
    }
    if (status) {
        options.status = status;
    }
    const { users, total } = await User_1.UserModel.getList(options);
    res.json({
        success: true,
        data: {
            users: users.map(user => ({
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                role: user.role,
                status: user.status,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at,
            })),
            pagination: {
                page: parseInt(page, 10),
                limit: parseInt(limit, 10),
                total,
                pages: Math.ceil(total / parseInt(limit, 10)),
            },
        },
    });
});
exports.updateUser = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    const { status, role } = req.body;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '用户ID不能为空');
    }
    const updateData = {};
    if (status !== undefined) {
        updateData.status = status;
    }
    if (role !== undefined) {
        updateData.role = role;
    }
    const user = await User_1.UserModel.update(id, updateData);
    if (!user) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    await redis_1.cacheService.del(`user:${id}`);
    logger_1.logger.info('管理员更新用户信息', {
        adminId: req.user?.id || 'unknown',
        targetUserId: id,
        changes: updateData,
    });
    res.json({
        success: true,
        message: '用户信息更新成功',
        data: {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                displayName: user.display_name,
                role: user.role,
                status: user.status,
                updatedAt: user.updated_at,
            },
        },
    });
});
exports.deleteUser = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { id } = req.params;
    if (!id) {
        throw (0, errorHandler_1.createValidationError)('id', '用户ID不能为空');
    }
    const success = await User_1.UserModel.delete(id);
    if (!success) {
        throw (0, errorHandler_1.createNotFoundError)('用户不存在');
    }
    await redis_1.cacheService.del(`user:${id}`);
    await redis_1.cacheService.del(`refresh_token:${id}`);
    logger_1.logger.info('管理员删除用户', {
        adminId: req.user?.id || 'unknown',
        targetUserId: id,
    });
    res.json({
        success: true,
        message: '用户删除成功',
    });
});
exports.default = {
    register: exports.register,
    login: exports.login,
    refreshToken: exports.refreshToken,
    logout: exports.logout,
    getProfile: exports.getProfile,
    updateProfile: exports.updateProfile,
    changePassword: exports.changePassword,
    forgotPassword: exports.forgotPassword,
    resetPassword: exports.resetPassword,
    getUserById: exports.getUserById,
    getUsersList: exports.getUsersList,
    updateUser: exports.updateUser,
    deleteUser: exports.deleteUser,
};
//# sourceMappingURL=userController.js.map