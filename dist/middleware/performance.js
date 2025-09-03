"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compressionConfig = exports.rateLimiter = exports.optimizeQuery = exports.clearCache = exports.cacheMiddleware = exports.getPerformanceStats = exports.performanceMonitor = void 0;
const logger_1 = require("../utils/logger");
const recentMetrics = [];
const MAX_METRICS_HISTORY = 1000;
const performanceMonitor = (req, res, next) => {
    const startTime = Date.now();
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    req.requestId = requestId;
    res.on('finish', () => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;
        const memoryUsage = process.memoryUsage();
        const userAgent = req.get('User-Agent');
        const clientIp = req.ip || req.connection.remoteAddress;
        const metrics = {
            requestId,
            method: req.method,
            url: req.originalUrl || req.url,
            statusCode: res.statusCode,
            responseTime,
            memoryUsage,
            timestamp: new Date(),
            ...(userAgent && { userAgent }),
            ...(clientIp && { ip: clientIp }),
        };
        recentMetrics.push(metrics);
        if (recentMetrics.length > MAX_METRICS_HISTORY) {
            recentMetrics.shift();
        }
        if (responseTime > 1000) {
            logger_1.logger.warn('Slow API request detected', {
                requestId,
                method: req.method,
                url: req.originalUrl,
                responseTime,
                statusCode: res.statusCode,
            });
        }
        if (res.statusCode >= 400) {
            logger_1.logger.error('API error response', {
                requestId,
                method: req.method,
                url: req.originalUrl,
                statusCode: res.statusCode,
                responseTime,
            });
        }
        logger_1.logger.info('API request completed', {
            requestId,
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            responseTime,
            memoryUsage: {
                rss: Math.round(memoryUsage.rss / 1024 / 1024),
                heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
                heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
            },
        });
    });
    next();
};
exports.performanceMonitor = performanceMonitor;
const getPerformanceStats = () => {
    const now = Date.now();
    const last5Minutes = recentMetrics.filter(m => now - m.timestamp.getTime() < 5 * 60 * 1000);
    const last1Hour = recentMetrics.filter(m => now - m.timestamp.getTime() < 60 * 60 * 1000);
    const calculateStats = (metrics) => {
        if (metrics.length === 0) {
            return {
                count: 0,
                avgResponseTime: 0,
                minResponseTime: 0,
                maxResponseTime: 0,
                errorRate: 0,
                avgMemoryUsage: 0,
            };
        }
        const responseTimes = metrics.map(m => m.responseTime);
        const errors = metrics.filter(m => m.statusCode >= 400);
        const memoryUsages = metrics.map(m => m.memoryUsage.heapUsed);
        return {
            count: metrics.length,
            avgResponseTime: Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length),
            minResponseTime: Math.min(...responseTimes),
            maxResponseTime: Math.max(...responseTimes),
            errorRate: Math.round((errors.length / metrics.length) * 100 * 100) / 100,
            avgMemoryUsage: Math.round(memoryUsages.reduce((a, b) => a + b, 0) / memoryUsages.length / 1024 / 1024),
        };
    };
    return {
        last5Minutes: calculateStats(last5Minutes),
        last1Hour: calculateStats(last1Hour),
        total: calculateStats(recentMetrics),
        slowestEndpoints: recentMetrics
            .sort((a, b) => b.responseTime - a.responseTime)
            .slice(0, 10)
            .map(m => ({
            url: m.url,
            method: m.method,
            responseTime: m.responseTime,
            timestamp: m.timestamp,
        })),
    };
};
exports.getPerformanceStats = getPerformanceStats;
const cacheMiddleware = (ttlSeconds = 300) => {
    return async (req, res, next) => {
        if (req.method !== 'GET') {
            return next();
        }
        const cacheKey = `cache:${req.originalUrl || req.url}:${JSON.stringify(req.query)}`;
        try {
            const cached = global.cache?.[cacheKey];
            if (cached && Date.now() - cached.timestamp < ttlSeconds * 1000) {
                logger_1.logger.info('Cache hit', { url: req.originalUrl, cacheKey });
                return res.json(cached.data);
            }
            const originalJson = res.json;
            res.json = function (data) {
                if (res.statusCode === 200) {
                    if (!global.cache) {
                        global.cache = {};
                    }
                    global.cache[cacheKey] = {
                        data,
                        timestamp: Date.now(),
                    };
                    logger_1.logger.info('Response cached', { url: req.originalUrl, cacheKey });
                }
                return originalJson.call(this, data);
            };
            next();
        }
        catch (error) {
            logger_1.logger.error('Cache middleware error', { error: error.message, url: req.originalUrl });
            next();
        }
    };
};
exports.cacheMiddleware = cacheMiddleware;
const clearCache = (pattern) => {
    if (!global.cache) {
        return;
    }
    if (pattern) {
        const keys = Object.keys(global.cache);
        keys.forEach(key => {
            if (key.includes(pattern)) {
                delete global.cache[key];
            }
        });
        logger_1.logger.info('Cache cleared with pattern', { pattern });
    }
    else {
        global.cache = {};
        logger_1.logger.info('All cache cleared');
    }
};
exports.clearCache = clearCache;
const optimizeQuery = (req, _res, next) => {
    req.queryHints = {
        useIndex: (tableName, indexName) => {
            return `/*+ USE_INDEX(${tableName}, ${indexName}) */`;
        },
        forceIndex: (tableName, indexName) => {
            return `/*+ FORCE_INDEX(${tableName}, ${indexName}) */`;
        },
        limit: (count) => {
            return Math.min(count, 100);
        },
    };
    next();
};
exports.optimizeQuery = optimizeQuery;
const requestCounts = new Map();
const rateLimiter = (maxRequests = 100, windowMs = 60000) => {
    return (req, res, next) => {
        const clientId = req.ip || 'unknown';
        const now = Date.now();
        const clientData = requestCounts.get(clientId);
        if (!clientData || now > clientData.resetTime) {
            requestCounts.set(clientId, {
                count: 1,
                resetTime: now + windowMs,
            });
            return next();
        }
        if (clientData.count >= maxRequests) {
            logger_1.logger.warn('Rate limit exceeded', {
                clientId,
                count: clientData.count,
                maxRequests,
            });
            return res.status(429).json({
                success: false,
                error: {
                    code: 'RATE_LIMIT_EXCEEDED',
                    message: 'Too many requests, please try again later',
                },
                retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
            });
        }
        clientData.count++;
        requestCounts.set(clientId, clientData);
        res.set({
            'X-RateLimit-Limit': maxRequests.toString(),
            'X-RateLimit-Remaining': (maxRequests - clientData.count).toString(),
            'X-RateLimit-Reset': new Date(clientData.resetTime).toISOString(),
        });
        next();
    };
};
exports.rateLimiter = rateLimiter;
setInterval(() => {
    const now = Date.now();
    for (const [clientId, data] of requestCounts.entries()) {
        if (now > data.resetTime) {
            requestCounts.delete(clientId);
        }
    }
}, 60000);
exports.compressionConfig = {
    filter: (req, _res) => {
        if (req.headers['content-type']?.startsWith('image/') ||
            req.headers['content-type']?.startsWith('video/')) {
            return false;
        }
        return true;
    },
    threshold: 1024,
    level: 6,
};
//# sourceMappingURL=performance.js.map