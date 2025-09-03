"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rateLimitByUser = exports.blacklistToken = exports.verifyRefreshToken = exports.generateRefreshToken = exports.generateToken = exports.requireOwnership = exports.requireModerator = exports.requireAdmin = exports.requireRole = exports.optionalAuthMiddleware = exports.authMiddleware = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = require("../config/config");
const errorHandler_1 = require("./errorHandler");
const logger_1 = require("../utils/logger");
const redis_1 = require("../config/redis");
const extractToken = (req) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }
    if (req.cookies && req.cookies.token) {
        return req.cookies.token;
    }
    return null;
};
const verifyToken = (token) => {
    return new Promise((resolve, reject) => {
        jsonwebtoken_1.default.verify(token, config_1.config.jwt.secret, (err, decoded) => {
            if (err) {
                reject(err);
            }
            else {
                resolve(decoded);
            }
        });
    });
};
const isTokenBlacklisted = async (token) => {
    try {
        const blacklisted = await redis_1.cacheService.get(`blacklist:${token}`);
        return blacklisted === 'true';
    }
    catch (error) {
        logger_1.logger.error('检查令牌黑名单失败:', error);
        return false;
    }
};
const authMiddleware = async (req, _res, next) => {
    try {
        const token = extractToken(req);
        if (!token) {
            throw (0, errorHandler_1.createAuthError)('访问令牌缺失');
        }
        if (await isTokenBlacklisted(token)) {
            throw (0, errorHandler_1.createAuthError)('访问令牌已失效');
        }
        const payload = await verifyToken(token);
        const userKey = `user:${payload.sub}`;
        const cachedUser = await redis_1.cacheService.get(userKey);
        if (!cachedUser) {
            logger_1.logger.warn(`用户 ${payload.sub} 不在缓存中`);
        }
        req.user = {
            id: payload.sub,
            email: payload.email,
            username: payload.username,
            role: payload.role,
        };
        next();
    }
    catch (error) {
        next(error);
    }
};
exports.authMiddleware = authMiddleware;
const optionalAuthMiddleware = async (req, _res, next) => {
    try {
        const token = extractToken(req);
        if (!token) {
            return next();
        }
        if (await isTokenBlacklisted(token)) {
            return next();
        }
        const payload = await verifyToken(token);
        req.user = {
            id: payload.sub,
            email: payload.email,
            username: payload.username,
            role: payload.role,
        };
        next();
    }
    catch (error) {
        next();
    }
};
exports.optionalAuthMiddleware = optionalAuthMiddleware;
const requireRole = (roles) => {
    return (req, _res, next) => {
        if (!req.user) {
            throw (0, errorHandler_1.createAuthError)('用户未认证');
        }
        const userRole = req.user.role;
        const allowedRoles = Array.isArray(roles) ? roles : [roles];
        if (!allowedRoles.includes(userRole)) {
            throw (0, errorHandler_1.createForbiddenError)('权限不足');
        }
        next();
    };
};
exports.requireRole = requireRole;
exports.requireAdmin = (0, exports.requireRole)('admin');
exports.requireModerator = (0, exports.requireRole)(['moderator', 'admin']);
const requireOwnership = (getResourceUserId) => {
    return async (req, _res, next) => {
        try {
            if (!req.user) {
                throw (0, errorHandler_1.createAuthError)('用户未认证');
            }
            const resourceUserId = await getResourceUserId(req);
            if (req.user.role === 'admin') {
                return next();
            }
            if (req.user.id !== resourceUserId) {
                throw (0, errorHandler_1.createForbiddenError)('只能访问自己的资源');
            }
            next();
        }
        catch (error) {
            next(error);
        }
    };
};
exports.requireOwnership = requireOwnership;
const generateToken = (payload) => {
    return jsonwebtoken_1.default.sign(payload, config_1.config.jwt.secret, {
        expiresIn: config_1.config.jwt.expiresIn,
    });
};
exports.generateToken = generateToken;
const generateRefreshToken = (userId) => {
    return jsonwebtoken_1.default.sign({ sub: userId }, config_1.config.jwt.refreshSecret, {
        expiresIn: config_1.config.jwt.refreshExpiresIn,
    });
};
exports.generateRefreshToken = generateRefreshToken;
const verifyRefreshToken = (token) => {
    return new Promise((resolve, reject) => {
        jsonwebtoken_1.default.verify(token, config_1.config.jwt.refreshSecret, (err, decoded) => {
            if (err) {
                reject(err);
            }
            else {
                resolve(decoded);
            }
        });
    });
};
exports.verifyRefreshToken = verifyRefreshToken;
const blacklistToken = async (token) => {
    try {
        const decoded = jsonwebtoken_1.default.decode(token);
        if (decoded && decoded.exp) {
            const ttl = decoded.exp - Math.floor(Date.now() / 1000);
            if (ttl > 0) {
                await redis_1.cacheService.set(`blacklist:${token}`, 'true', ttl);
            }
        }
    }
    catch (error) {
        logger_1.logger.error('令牌加入黑名单失败:', error);
        throw error;
    }
};
exports.blacklistToken = blacklistToken;
const rateLimitByUser = (maxRequests, windowMs) => {
    return async (req, res, next) => {
        try {
            const userId = req.user?.id || req.ip;
            const key = `rate_limit:user:${userId}`;
            const current = await redis_1.cacheService.incr(key);
            if (current === 1) {
                await redis_1.cacheService.expire(key, Math.ceil(windowMs / 1000));
            }
            if (current > maxRequests) {
                throw new errorHandler_1.AppError('请求过于频繁，请稍后再试', 429, 'RATE_LIMIT_EXCEEDED');
            }
            res.setHeader('X-RateLimit-Limit', maxRequests);
            res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - current));
            res.setHeader('X-RateLimit-Reset', new Date(Date.now() + windowMs).toISOString());
            next();
        }
        catch (error) {
            next(error);
        }
    };
};
exports.rateLimitByUser = rateLimitByUser;
exports.default = exports.authMiddleware;
//# sourceMappingURL=auth.js.map