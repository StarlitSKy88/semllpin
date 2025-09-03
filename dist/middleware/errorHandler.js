"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRateLimitError = exports.createConflictError = exports.createNotFoundError = exports.createForbiddenError = exports.createAuthError = exports.createValidationError = exports.notFoundHandler = exports.asyncHandler = exports.errorHandler = exports.AppError = void 0;
const logger_1 = require("../utils/logger");
const config_1 = require("../config/config");
class AppError extends Error {
    constructor(message, statusCode = 500, code, isOperational = true) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        if (code) {
            this.code = code;
        }
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.AppError = AppError;
const sendErrorResponse = (res, error, req) => {
    const errorResponse = {
        success: false,
        error: {
            code: error.code || 'INTERNAL_SERVER_ERROR',
            message: error.message,
        },
        timestamp: new Date().toISOString(),
    };
    if (config_1.config.nodeEnv === 'development' && error.stack) {
        errorResponse.error.stack = error.stack;
    }
    const logData = {
        requestId: req.id,
        method: req.method,
        url: req.url,
        statusCode: error.statusCode,
        message: error.message,
        stack: error.stack,
    };
    if (req.user?.id) {
        logData.userId = req.user.id;
    }
    logger_1.logger.error('API Error:', logData);
    res.status(error.statusCode).json(errorResponse);
};
const handleDatabaseError = (error) => {
    if (error.code === '23505') {
        return new AppError('数据已存在', 409, 'DUPLICATE_ENTRY');
    }
    if (error.code === '23503') {
        return new AppError('关联数据不存在', 400, 'FOREIGN_KEY_VIOLATION');
    }
    if (error.code === '23502') {
        return new AppError('必填字段不能为空', 400, 'REQUIRED_FIELD_MISSING');
    }
    if (error.code === '42P01') {
        return new AppError('数据表不存在', 500, 'TABLE_NOT_FOUND');
    }
    return new AppError('数据库操作失败', 500, 'DATABASE_ERROR');
};
const handleValidationError = (error) => {
    const messages = error.details?.map((detail) => detail.message).join(', ');
    return new AppError(`数据验证失败: ${messages}`, 400, 'VALIDATION_ERROR');
};
const handleJWTError = (error) => {
    if (error.name === 'JsonWebTokenError') {
        return new AppError('无效的访问令牌', 401, 'INVALID_TOKEN');
    }
    if (error.name === 'TokenExpiredError') {
        return new AppError('访问令牌已过期', 401, 'TOKEN_EXPIRED');
    }
    return new AppError('令牌验证失败', 401, 'TOKEN_ERROR');
};
const handleMulterError = (error) => {
    if (error.code === 'LIMIT_FILE_SIZE') {
        return new AppError('文件大小超出限制', 400, 'FILE_TOO_LARGE');
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
        return new AppError('文件数量超出限制', 400, 'TOO_MANY_FILES');
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        return new AppError('不支持的文件类型', 400, 'UNSUPPORTED_FILE_TYPE');
    }
    return new AppError('文件上传失败', 400, 'FILE_UPLOAD_ERROR');
};
const handleCastError = (_error) => {
    return new AppError('无效的数据格式', 400, 'INVALID_DATA_FORMAT');
};
const errorHandler = (error, req, res, _next) => {
    let appError;
    if (error instanceof AppError) {
        appError = error;
    }
    else {
        if (error.name === 'ValidationError') {
            appError = handleValidationError(error);
        }
        else if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            appError = handleJWTError(error);
        }
        else if (error.code && typeof error.code === 'string') {
            if (error.code.startsWith('23') || error.code.startsWith('42')) {
                appError = handleDatabaseError(error);
            }
            else if (error.code.startsWith('LIMIT_')) {
                appError = handleMulterError(error);
            }
            else {
                appError = new AppError('服务器内部错误', 500, 'INTERNAL_SERVER_ERROR');
            }
        }
        else if (error.name === 'CastError') {
            appError = handleCastError(error);
        }
        else {
            appError = new AppError(config_1.config.nodeEnv === 'development' ? error.message : '服务器内部错误', 500, 'INTERNAL_SERVER_ERROR');
        }
    }
    sendErrorResponse(res, appError, req);
};
exports.errorHandler = errorHandler;
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};
exports.asyncHandler = asyncHandler;
const notFoundHandler = (req, _res, next) => {
    const error = new AppError(`路由 ${req.originalUrl} 不存在`, 404, 'ROUTE_NOT_FOUND');
    next(error);
};
exports.notFoundHandler = notFoundHandler;
const createValidationError = (field, message) => {
    return new AppError(`${field}: ${message}`, 400, 'VALIDATION_ERROR');
};
exports.createValidationError = createValidationError;
const createAuthError = (message = '未授权访问') => {
    return new AppError(message, 401, 'UNAUTHORIZED');
};
exports.createAuthError = createAuthError;
const createForbiddenError = (message = '权限不足') => {
    return new AppError(message, 403, 'FORBIDDEN');
};
exports.createForbiddenError = createForbiddenError;
const createNotFoundError = (resource = '资源') => {
    return new AppError(`${resource}不存在`, 404, 'NOT_FOUND');
};
exports.createNotFoundError = createNotFoundError;
const createConflictError = (message) => {
    return new AppError(message, 409, 'CONFLICT');
};
exports.createConflictError = createConflictError;
const createRateLimitError = () => {
    return new AppError('请求过于频繁，请稍后再试', 429, 'RATE_LIMIT_EXCEEDED');
};
exports.createRateLimitError = createRateLimitError;
exports.default = exports.errorHandler;
//# sourceMappingURL=errorHandler.js.map