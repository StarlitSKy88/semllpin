"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityMiddleware = exports.securityLogger = exports.validateFileUpload = exports.fileUploadSecurity = exports.generateCSRFToken = exports.csrfProtection = exports.suspiciousActivityDetection = exports.ipWhitelist = exports.handleValidationErrors = exports.sqlInjectionProtection = exports.xssProtection = exports.securityHeaders = exports.loginRateLimit = exports.strictRateLimit = exports.basicRateLimit = exports.securityConfig = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const helmet_1 = __importDefault(require("helmet"));
const express_validator_1 = require("express-validator");
const xss_1 = __importDefault(require("xss"));
const logger_1 = require("../utils/logger");
const cache_1 = require("../config/cache");
exports.securityConfig = {
    rateLimit: {
        windowMs: 15 * 60 * 1000,
        max: 100,
        message: {
            success: false,
            error: {
                code: 'RATE_LIMIT_EXCEEDED',
                message: 'Too many requests from this IP, please try again later.',
            },
        },
        standardHeaders: true,
        legacyHeaders: false,
    },
    helmet: {
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ['\'self\''],
                styleSrc: ['\'self\'', '\'unsafe-inline\'', 'https://fonts.googleapis.com'],
                fontSrc: ['\'self\'', 'https://fonts.gstatic.com'],
                imgSrc: ['\'self\'', 'data:', 'https:'],
                scriptSrc: ['\'self\''],
                connectSrc: ['\'self\'', 'https://api.stripe.com'],
                frameSrc: ['\'none\''],
                objectSrc: ['\'none\''],
                mediaSrc: ['\'self\''],
                workerSrc: ['\'self\''],
            },
        },
        crossOriginEmbedderPolicy: false,
    },
    xss: {
        whiteList: {
            a: ['href', 'title'],
            abbr: ['title'],
            address: [],
            area: ['shape', 'coords', 'href', 'alt'],
            article: [],
            aside: [],
            audio: ['autoplay', 'controls', 'loop', 'preload', 'src'],
            b: [],
            bdi: ['dir'],
            bdo: ['dir'],
            big: [],
            blockquote: ['cite'],
            br: [],
            caption: [],
            center: [],
            cite: [],
            code: [],
            col: ['align', 'valign', 'span', 'width'],
            colgroup: ['align', 'valign', 'span', 'width'],
            dd: [],
            del: ['datetime'],
            details: ['open'],
            div: [],
            dl: [],
            dt: [],
            em: [],
            font: ['color', 'size', 'face'],
            footer: [],
            h1: [],
            h2: [],
            h3: [],
            h4: [],
            h5: [],
            h6: [],
            header: [],
            hr: [],
            i: [],
            img: ['src', 'alt', 'title', 'width', 'height'],
            ins: ['datetime'],
            li: [],
            mark: [],
            nav: [],
            ol: [],
            p: [],
            pre: [],
            s: [],
            section: [],
            small: [],
            span: [],
            sub: [],
            sup: [],
            strong: [],
            table: ['width', 'border', 'align', 'valign'],
            tbody: ['align', 'valign'],
            td: ['width', 'rowspan', 'colspan', 'align', 'valign'],
            tfoot: ['align', 'valign'],
            th: ['width', 'rowspan', 'colspan', 'align', 'valign'],
            thead: ['align', 'valign'],
            tr: ['rowspan', 'align', 'valign'],
            tt: [],
            u: [],
            ul: [],
            video: ['autoplay', 'controls', 'loop', 'preload', 'src', 'height', 'width'],
        },
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script'],
    },
};
exports.basicRateLimit = (0, express_rate_limit_1.default)(exports.securityConfig.rateLimit);
exports.strictRateLimit = (0, express_rate_limit_1.default)({
    ...exports.securityConfig.rateLimit,
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        error: {
            code: 'STRICT_RATE_LIMIT_EXCEEDED',
            message: 'Too many sensitive requests from this IP, please try again later.',
        },
    },
});
exports.loginRateLimit = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        error: {
            code: 'LOGIN_RATE_LIMIT_EXCEEDED',
            message: 'Too many login attempts from this IP, please try again later.',
        },
    },
    skipSuccessfulRequests: true,
});
exports.securityHeaders = (0, helmet_1.default)(exports.securityConfig.helmet);
const xssProtection = (req, _res, next) => {
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body);
    }
    if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query);
    }
    if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObject(req.params);
    }
    next();
};
exports.xssProtection = xssProtection;
function sanitizeObject(obj) {
    if (typeof obj === 'string') {
        return (0, xss_1.default)(obj, exports.securityConfig.xss);
    }
    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject);
    }
    if (obj && typeof obj === 'object') {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            sanitized[key] = sanitizeObject(value);
        }
        return sanitized;
    }
    return obj;
}
exports.sqlInjectionProtection = [
    (0, express_validator_1.body)('*').custom((value) => {
        if (typeof value === 'string') {
            const sqlPatterns = [
                /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
                /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
                /(script|javascript|vbscript|onload|onerror|onclick)/i,
            ];
            for (const pattern of sqlPatterns) {
                if (pattern.test(value)) {
                    throw new Error('Invalid input detected');
                }
            }
        }
        return true;
    }),
    (0, express_validator_1.query)('*').custom((value) => {
        if (typeof value === 'string') {
            const sqlPatterns = [
                /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
                /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
            ];
            for (const pattern of sqlPatterns) {
                if (pattern.test(value)) {
                    throw new Error('Invalid query parameter');
                }
            }
        }
        return true;
    }),
];
const handleValidationErrors = (req, res, next) => {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        logger_1.logger.warn('Validation failed', {
            ip: req.ip,
            url: req.originalUrl,
            errors: errors.array(),
        });
        return res.status(400).json({
            success: false,
            error: {
                code: 'VALIDATION_ERROR',
                message: 'Invalid input data',
                details: errors.array(),
            },
        });
    }
    next();
};
exports.handleValidationErrors = handleValidationErrors;
const ipWhitelist = (allowedIPs) => {
    return (req, res, next) => {
        const clientIP = req.ip || req.connection.remoteAddress || '';
        if (!allowedIPs.includes(clientIP)) {
            logger_1.logger.warn('IP not in whitelist', {
                ip: clientIP,
                url: req.originalUrl,
            });
            return res.status(403).json({
                success: false,
                error: {
                    code: 'IP_NOT_ALLOWED',
                    message: 'Access denied from this IP address',
                },
            });
        }
        next();
    };
};
exports.ipWhitelist = ipWhitelist;
const suspiciousActivityDetection = async (req, res, next) => {
    const clientIP = req.ip || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';
    const url = req.originalUrl;
    const isBlacklisted = await cache_1.cache.get(`blacklist:${clientIP}`);
    if (isBlacklisted) {
        logger_1.logger.warn('Blacklisted IP detected', { ip: clientIP, url });
        return res.status(403).json({
            success: false,
            error: {
                code: 'IP_BLACKLISTED',
                message: 'Access denied',
            },
        });
    }
    const suspiciousUserAgents = [
        /bot/i,
        /crawler/i,
        /spider/i,
        /scraper/i,
        /curl/i,
        /wget/i,
    ];
    const isSuspiciousUA = suspiciousUserAgents.some(pattern => pattern.test(userAgent));
    if (isSuspiciousUA && !url.includes('/api/health')) {
        logger_1.logger.warn('Suspicious User-Agent detected', {
            ip: clientIP,
            userAgent,
            url,
        });
        const suspiciousCount = await cache_1.cache.incr(`suspicious:${clientIP}`, 3600);
        if (suspiciousCount > 10) {
            await cache_1.cache.set(`blacklist:${clientIP}`, true, 3600);
            logger_1.logger.warn('IP temporarily blacklisted due to suspicious activity', { ip: clientIP });
        }
    }
    next();
};
exports.suspiciousActivityDetection = suspiciousActivityDetection;
const csrfProtection = (req, res, next) => {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const token = req.headers['x-csrf-token'] || req.body._csrf;
        const sessionToken = req.session?.csrfToken;
        if (!token || !sessionToken || token !== sessionToken) {
            logger_1.logger.warn('CSRF token validation failed', {
                ip: req.ip,
                url: req.originalUrl,
                method: req.method,
            });
            return res.status(403).json({
                success: false,
                error: {
                    code: 'CSRF_TOKEN_INVALID',
                    message: 'Invalid CSRF token',
                },
            });
        }
    }
    next();
};
exports.csrfProtection = csrfProtection;
const generateCSRFToken = () => {
    return require('crypto').randomBytes(32).toString('hex');
};
exports.generateCSRFToken = generateCSRFToken;
exports.fileUploadSecurity = {
    allowedMimeTypes: [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'video/mp4',
        'video/webm',
        'application/pdf',
    ],
    maxFileSize: 10 * 1024 * 1024,
    checkFileType: (mimetype) => {
        return exports.fileUploadSecurity.allowedMimeTypes.includes(mimetype);
    },
    checkFileSize: (size) => {
        return size <= exports.fileUploadSecurity.maxFileSize;
    },
    generateSafeFilename: (originalName) => {
        const ext = originalName.split('.').pop()?.toLowerCase() || '';
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 15);
        return `${timestamp}_${random}.${ext}`;
    },
};
const validateFileUpload = (req, res, next) => {
    if (req.file) {
        const { mimetype, size } = req.file;
        if (!exports.fileUploadSecurity.checkFileType(mimetype)) {
            return res.status(400).json({
                success: false,
                error: {
                    code: 'INVALID_FILE_TYPE',
                    message: 'File type not allowed',
                },
            });
        }
        if (!exports.fileUploadSecurity.checkFileSize(size)) {
            return res.status(400).json({
                success: false,
                error: {
                    code: 'FILE_TOO_LARGE',
                    message: 'File size exceeds limit',
                },
            });
        }
    }
    next();
};
exports.validateFileUpload = validateFileUpload;
const securityLogger = (req, res, next) => {
    const startTime = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logData = {
            ip: req.ip,
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            userAgent: req.get('User-Agent'),
            duration,
            timestamp: new Date().toISOString(),
        };
        if (res.statusCode >= 400) {
            logger_1.logger.warn('Security event', logData);
        }
        else {
            logger_1.logger.info('Security log', logData);
        }
    });
    next();
};
exports.securityLogger = securityLogger;
exports.securityMiddleware = {
    basicRateLimit: exports.basicRateLimit,
    strictRateLimit: exports.strictRateLimit,
    loginRateLimit: exports.loginRateLimit,
    securityHeaders: exports.securityHeaders,
    xssProtection: exports.xssProtection,
    sqlInjectionProtection: exports.sqlInjectionProtection,
    handleValidationErrors: exports.handleValidationErrors,
    ipWhitelist: exports.ipWhitelist,
    suspiciousActivityDetection: exports.suspiciousActivityDetection,
    csrfProtection: exports.csrfProtection,
    generateCSRFToken: exports.generateCSRFToken,
    fileUploadSecurity: exports.fileUploadSecurity,
    validateFileUpload: exports.validateFileUpload,
    securityLogger: exports.securityLogger,
};
exports.default = exports.securityMiddleware;
//# sourceMappingURL=security.js.map