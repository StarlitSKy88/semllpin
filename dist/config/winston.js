"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = exports.httpLogger = exports.errorLogger = exports.businessLogger = void 0;
const winston_1 = __importDefault(require("winston"));
const path_1 = __importDefault(require("path"));
const config_1 = require("./config");
const levels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
};
const colors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
};
winston_1.default.addColors(colors);
const format = winston_1.default.format.combine(winston_1.default.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json(), winston_1.default.format.printf((info) => {
    const { timestamp, level, message, stack, ...meta } = info;
    const filteredMeta = filterSensitiveData(meta);
    return JSON.stringify({
        timestamp,
        level,
        message,
        ...(stack ? { stack } : {}),
        ...filteredMeta,
    });
}));
function filterSensitiveData(data) {
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
    if (typeof data !== 'object' || data === null) {
        return data;
    }
    const filtered = { ...data };
    for (const field of sensitiveFields) {
        if (field in filtered) {
            filtered[field] = '[REDACTED]';
        }
    }
    for (const key in filtered) {
        if (typeof filtered[key] === 'object' && filtered[key] !== null) {
            filtered[key] = filterSensitiveData(filtered[key]);
        }
    }
    return filtered;
}
const transports = [];
if (config_1.config.nodeEnv === 'development') {
    transports.push(new winston_1.default.transports.Console({
        format: winston_1.default.format.combine(winston_1.default.format.colorize({ all: true }), winston_1.default.format.simple()),
    }));
}
const logDir = path_1.default.join(process.cwd(), 'logs');
transports.push(new winston_1.default.transports.File({
    filename: path_1.default.join(logDir, 'error.log'),
    level: 'error',
    maxsize: 10 * 1024 * 1024,
    maxFiles: 5,
    format,
}));
transports.push(new winston_1.default.transports.File({
    filename: path_1.default.join(logDir, 'combined.log'),
    maxsize: 10 * 1024 * 1024,
    maxFiles: 10,
    format,
}));
transports.push(new winston_1.default.transports.File({
    filename: path_1.default.join(logDir, 'http.log'),
    level: 'http',
    maxsize: 10 * 1024 * 1024,
    maxFiles: 7,
    format,
}));
transports.push(new winston_1.default.transports.File({
    filename: path_1.default.join(logDir, 'business.log'),
    maxsize: 10 * 1024 * 1024,
    maxFiles: 30,
    format,
}));
const logger = winston_1.default.createLogger({
    level: config_1.config.nodeEnv === 'development' ? 'debug' : 'info',
    levels,
    format,
    transports,
    exitOnError: false,
});
exports.logger = logger;
exports.businessLogger = {
    userAction: (userId, action, details) => {
        logger.info('User action', {
            category: 'user_action',
            userId,
            action,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    payment: (userId, amount, status, details) => {
        logger.info('Payment transaction', {
            category: 'payment',
            userId,
            amount,
            status,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    annotation: (userId, annotationId, action, details) => {
        logger.info('Annotation activity', {
            category: 'annotation',
            userId,
            annotationId,
            action,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    lbsReward: (userId, annotationId, reward, details) => {
        logger.info('LBS reward', {
            category: 'lbs_reward',
            userId,
            annotationId,
            reward,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    security: (event, userId, details) => {
        logger.warn('Security event', {
            category: 'security',
            event,
            userId,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    performance: (operation, duration, details) => {
        logger.info('Performance metric', {
            category: 'performance',
            operation,
            duration,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
};
exports.errorLogger = {
    apiError: (error, req, details) => {
        logger.error('API Error', {
            category: 'api_error',
            message: error.message,
            stack: error.stack,
            url: req.url,
            method: req.method,
            userId: req.user?.id,
            requestId: req.id,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    dbError: (error, operation, details) => {
        logger.error('Database Error', {
            category: 'db_error',
            message: error.message,
            stack: error.stack,
            operation,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    externalError: (service, error, details) => {
        logger.error('External Service Error', {
            category: 'external_error',
            service,
            message: error.message,
            stack: error.stack,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
    systemError: (error, context, details) => {
        logger.error('System Error', {
            category: 'system_error',
            message: error.message,
            stack: error.stack,
            context,
            details: filterSensitiveData(details),
            timestamp: new Date().toISOString(),
        });
    },
};
exports.httpLogger = {
    request: (req, res, responseTime) => {
        logger.http('HTTP Request', {
            category: 'http_request',
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            responseTime,
            userAgent: req.get('User-Agent'),
            ip: req.ip,
            userId: req.user?.id,
            requestId: req.id,
            timestamp: new Date().toISOString(),
        });
    },
};
exports.default = logger;
//# sourceMappingURL=winston.js.map