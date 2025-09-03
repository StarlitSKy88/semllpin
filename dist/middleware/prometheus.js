"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordBusinessMetrics = exports.metrics = exports.metricsHandler = exports.prometheusMiddleware = void 0;
const prom_client_1 = __importDefault(require("prom-client"));
const logger_1 = require("../utils/logger");
const os_1 = __importDefault(require("os"));
const register = new prom_client_1.default.Registry();
prom_client_1.default.collectDefaultMetrics({
    register,
    prefix: 'smellpin_',
    gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});
const httpRequestsTotal = new prom_client_1.default.Counter({
    name: 'smellpin_http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code', 'user_agent'],
    registers: [register],
});
const httpRequestDuration = new prom_client_1.default.Histogram({
    name: 'smellpin_http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
    registers: [register],
});
const activeUsers = new prom_client_1.default.Gauge({
    name: 'smellpin_active_users',
    help: 'Number of active users',
    registers: [register],
});
const databaseConnections = new prom_client_1.default.Gauge({
    name: 'smellpin_database_connections_total',
    help: 'Total number of database connections',
    labelNames: ['state'],
    registers: [register],
});
const redisConnections = new prom_client_1.default.Gauge({
    name: 'smellpin_redis_connections_total',
    help: 'Total number of Redis connections',
    labelNames: ['state'],
    registers: [register],
});
const annotationsCreated = new prom_client_1.default.Counter({
    name: 'smellpin_annotations_created_total',
    help: 'Total number of annotations created',
    labelNames: ['country', 'intensity_level'],
    registers: [register],
});
const lbsRewards = new prom_client_1.default.Counter({
    name: 'smellpin_lbs_rewards_total',
    help: 'Total number of LBS rewards distributed',
    labelNames: ['reward_type', 'location_type'],
    registers: [register],
});
const paymentSuccess = new prom_client_1.default.Counter({
    name: 'smellpin_payments_total',
    help: 'Total number of payment attempts',
    labelNames: ['status', 'payment_method'],
    registers: [register],
});
const websocketConnections = new prom_client_1.default.Gauge({
    name: 'smellpin_websocket_connections',
    help: 'Number of active WebSocket connections',
    registers: [register],
});
const errorRate = new prom_client_1.default.Counter({
    name: 'smellpin_errors_total',
    help: 'Total number of errors',
    labelNames: ['error_type', 'endpoint'],
    registers: [register],
});
const systemResources = new prom_client_1.default.Gauge({
    name: 'smellpin_system_resources',
    help: 'System resource usage',
    labelNames: ['resource_type'],
    registers: [register],
});
setInterval(() => {
    try {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        const loadAvg = os_1.default.loadavg();
        systemResources.set({ resource_type: 'memory_heap_used' }, memUsage['heapUsed'] / 1024 / 1024);
        systemResources.set({ resource_type: 'memory_heap_total' }, memUsage['heapTotal'] / 1024 / 1024);
        systemResources.set({ resource_type: 'memory_rss' }, memUsage['rss'] / 1024 / 1024);
        systemResources.set({ resource_type: 'cpu_user' }, cpuUsage['user'] / 1000000);
        systemResources.set({ resource_type: 'cpu_system' }, cpuUsage['system'] / 1000000);
        systemResources.set({ resource_type: 'load_avg_1m' }, loadAvg[0] || 0);
        systemResources.set({ resource_type: 'load_avg_5m' }, loadAvg[1] || 0);
        systemResources.set({ resource_type: 'load_avg_15m' }, loadAvg[2] || 0);
    }
    catch (error) {
        logger_1.logger.error('更新系统资源指标失败:', error);
    }
}, 30000);
const prometheusMiddleware = (req, res, next) => {
    const startTime = Date.now();
    res.locals['startTime'] = startTime;
    res.on('finish', () => {
        try {
            const duration = (Date.now() - startTime) / 1000;
            const route = req.route?.path || req.path || 'unknown';
            const method = req.method;
            const statusCode = res.statusCode.toString();
            const userAgent = req.get('User-Agent') || 'unknown';
            httpRequestsTotal.inc({
                method,
                route,
                status_code: statusCode,
                user_agent: userAgent.substring(0, 50),
            });
            httpRequestDuration.observe({ method, route, status_code: statusCode }, duration);
            if (res.statusCode >= 400) {
                const errorType = res.statusCode >= 500 ? 'server_error' : 'client_error';
                errorRate.inc({
                    error_type: errorType,
                    endpoint: route,
                });
            }
        }
        catch (error) {
            logger_1.logger.error('Prometheus指标记录失败:', error);
        }
    });
    next();
};
exports.prometheusMiddleware = prometheusMiddleware;
const metricsHandler = async (_req, res) => {
    try {
        res.set('Content-Type', register.contentType);
        const metrics = await register.metrics();
        res.end(metrics);
    }
    catch (error) {
        logger_1.logger.error('获取Prometheus指标失败:', error);
        res.status(500).json({
            success: false,
            error: {
                code: 'METRICS_ERROR',
                message: '获取监控指标失败',
            },
        });
    }
};
exports.metricsHandler = metricsHandler;
exports.metrics = {
    httpRequestsTotal,
    httpRequestDuration,
    activeUsers,
    databaseConnections,
    redisConnections,
    annotationsCreated,
    lbsRewards,
    paymentSuccess,
    websocketConnections,
    errorRate,
    systemResources,
    register,
};
exports.recordBusinessMetrics = {
    annotationCreated: (country, intensityLevel) => {
        annotationsCreated.inc({ country, intensity_level: intensityLevel });
    },
    lbsReward: (rewardType, locationType) => {
        lbsRewards.inc({ reward_type: rewardType, location_type: locationType });
    },
    payment: (status, paymentMethod) => {
        paymentSuccess.inc({ status, payment_method: paymentMethod });
    },
    updateActiveUsers: (count) => {
        activeUsers.set(count);
    },
    updateWebSocketConnections: (count) => {
        websocketConnections.set(count);
    },
    updateDatabaseConnections: (active, idle, waiting) => {
        databaseConnections.set({ state: 'active' }, active);
        databaseConnections.set({ state: 'idle' }, idle);
        databaseConnections.set({ state: 'waiting' }, waiting);
    },
    updateRedisConnections: (connected, disconnected) => {
        redisConnections.set({ state: 'connected' }, connected);
        redisConnections.set({ state: 'disconnected' }, disconnected);
    },
};
exports.default = {
    prometheusMiddleware: exports.prometheusMiddleware,
    metricsHandler: exports.metricsHandler,
    metrics: exports.metrics,
    recordBusinessMetrics: exports.recordBusinessMetrics,
};
//# sourceMappingURL=prometheus.js.map