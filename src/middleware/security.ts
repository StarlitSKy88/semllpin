import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from '../config/config';

// 安全头中间件
export const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            scriptSrc: ["'self'", "https://www.paypal.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https:", "data:"],
            connectSrc: ["'self'", "https://api.paypal.com", "wss://"],
            frameSrc: ["'self'", "https://www.paypal.com"],
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

// API速率限制
export const apiRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 100, // 每个IP最多100个请求
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// 严格的API速率限制 (登录、注册等敏感操作)
export const strictRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 5, // 每个IP最多5次尝试
    message: {
        error: 'Too many attempts, please try again later.',
        code: 'STRICT_RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// 文件上传速率限制
export const fileUploadRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1小时
    max: 10, // 每小时最多10次文件上传
    message: {
        error: 'Too many file uploads, please try again later.',
        code: 'FILE_UPLOAD_RATE_LIMIT_EXCEEDED'
    },
});

// 输入验证中间件
export const validateInput = (req: Request, res: Response, next: NextFunction): void => {
    // 检查请求体大小
    if (req.body && JSON.stringify(req.body).length > 1024 * 1024) { // 1MB
        res.status(400).json({
            error: 'Request body too large',
            code: 'PAYLOAD_TOO_LARGE'
        });
        return;
    }
    
    // 基本XSS过滤
    const sanitizeValue = (value: any): any => {
        if (typeof value === 'string') {
            return value
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;')
                .replace(/\//g, '&#x2F;');
        }
        if (typeof value === 'object' && value !== null) {
            const sanitized: any = Array.isArray(value) ? [] : {};
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

// CORS安全配置
export const corsConfig = {
    origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            'https://smellpin.vercel.app',
            // 添加生产域名
        ];
        
        // 允许无origin的请求(例如移动应用)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS policy'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
};

// 请求日志中间件(安全相关)
export const securityLogger = (req: Request, res: Response, next: NextFunction) => {
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
        
        // 记录可疑活动
        if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) {
            console.warn('Security Event:', logData);
        }
    });
    
    next();
};

export default {
    securityHeaders,
    apiRateLimit,
    strictRateLimit,
    fileUploadRateLimit,
    validateInput,
    corsConfig,
    securityLogger
};
