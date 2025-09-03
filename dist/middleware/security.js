"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityLogger = exports.corsConfig = exports.validateInput = exports.fileUploadRateLimit = exports.strictRateLimit = exports.apiRateLimit = exports.securityHeaders = void 0;
const helmet_1 = __importDefault(require("helmet"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
exports.securityHeaders = (0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            scriptSrc: ["'self'", "https://js.stripe.com", "https://www.paypal.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https:", "data:"],
            connectSrc: ["'self'", "https://api.stripe.com", "https://api.paypal.com", "wss://"],
            frameSrc: ["'self'", "https://js.stripe.com", "https://www.paypal.com"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});
exports.apiRateLimit = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
exports.strictRateLimit = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        error: 'Too many attempts, please try again later.',
        code: 'STRICT_RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
exports.fileUploadRateLimit = (0, express_rate_limit_1.default)({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: {
        error: 'Too many file uploads, please try again later.',
        code: 'FILE_UPLOAD_RATE_LIMIT_EXCEEDED'
    },
});
const validateInput = (req, res, next) => {
    if (req.body && JSON.stringify(req.body).length > 1024 * 1024) {
        return res.status(400).json({
            error: 'Request body too large',
            code: 'PAYLOAD_TOO_LARGE'
        });
    }
    const sanitizeValue = (value) => {
        if (typeof value === 'string') {
            return value
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;')
                .replace(/\//g, '&#x2F;');
        }
        if (typeof value === 'object' && value !== null) {
            const sanitized = Array.isArray(value) ? [] : {};
            for (const key in value) {
                sanitized[key] = sanitizeValue(value[key]);
            }
            return sanitized;
        }
        return value;
    };
    if (req.body) {
        req.body = sanitizeValue(req.body);
    }
    if (req.query) {
        req.query = sanitizeValue(req.query);
    }
    next();
};
exports.validateInput = validateInput;
exports.corsConfig = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            'https://smellpin.vercel.app',
        ];
        if (!origin)
            return callback(null, true);
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(new Error('Not allowed by CORS policy'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
};
const securityLogger = (req, res, next) => {
    const startTime = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logData = {
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            statusCode: res.statusCode,
            duration,
            timestamp: new Date().toISOString(),
        };
        if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) {
            console.warn('Security Event:', logData);
        }
    });
    next();
};
exports.securityLogger = securityLogger;
exports.default = {
    securityHeaders: exports.securityHeaders,
    apiRateLimit: exports.apiRateLimit,
    strictRateLimit: exports.strictRateLimit,
    fileUploadRateLimit: exports.fileUploadRateLimit,
    validateInput: exports.validateInput,
    corsConfig: exports.corsConfig,
    securityLogger: exports.securityLogger
};
//# sourceMappingURL=security.js.map