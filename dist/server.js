"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const path_1 = __importDefault(require("path"));
const uuid_1 = require("uuid");
const http_1 = require("http");
const config_1 = require("./config/config");
const logger_1 = require("./utils/logger");
const enhancedErrorHandler_1 = require("./middleware/enhancedErrorHandler");
const notFoundHandler_1 = require("./middleware/notFoundHandler");
const prometheus_1 = require("./middleware/prometheus");
const healthService_1 = require("./services/healthService");
const routes_1 = __importDefault(require("./routes"));
const monitorRoutes_1 = __importDefault(require("./routes/monitorRoutes"));
const performanceRoutes_1 = __importDefault(require("./routes/performanceRoutes"));
const database_1 = require("./config/database");
const redis_1 = require("./config/redis");
const database_connection_monitor_1 = require("./services/database-connection-monitor");
const database_health_1 = __importDefault(require("./routes/database-health"));
const gracefulShutdown_1 = require("./utils/gracefulShutdown");
const websocketService_1 = __importDefault(require("./services/websocketService"));
const websocketManager_1 = require("./services/websocketManager");
const advancedPerformanceMonitor_1 = require("./middleware/advancedPerformanceMonitor");
const advancedRateLimiter_1 = require("./middleware/advancedRateLimiter");
class Server {
    constructor() {
        this.app = (0, express_1.default)();
        this.port = config_1.config.port;
        this.server = (0, http_1.createServer)(this.app);
        (0, websocketManager_1.setWebSocketService)(websocketService_1.default);
        this.initializeMiddlewares();
        this.initializeRoutes();
        this.initializeErrorHandling();
    }
    initializeMiddlewares() {
        this.app.use((0, helmet_1.default)({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
                    scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com', 'https://www.paypal.com'],
                    imgSrc: ["'self'", 'data:', 'https:', 'blob:'],
                    connectSrc: ["'self'", 'https://api.stripe.com', 'https://api.paypal.com', 'https://api-m.sandbox.paypal.com'],
                    frameSrc: ["'self'", 'https://js.stripe.com', 'https://www.paypal.com'],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    workerSrc: ["'self'", 'blob:'],
                    childSrc: ["'self'"],
                    formAction: ["'self'"],
                    upgradeInsecureRequests: config_1.config.nodeEnv === 'production' ? [] : null,
                },
            },
            crossOriginEmbedderPolicy: false,
            strictTransportSecurity: config_1.config.nodeEnv === 'production' ? {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            } : false,
            referrerPolicy: {
                policy: 'origin-when-cross-origin'
            },
        }));
        this.app.use((_req, res, next) => {
            res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(), microphone=(), payment=(self), usb=(), bluetooth=(), ' +
                'magnetometer=(), gyroscope=(), accelerometer=(self), fullscreen=(self), autoplay=(self)');
            next();
        });
        this.app.use((0, cors_1.default)({
            origin: config_1.config.cors.origin,
            credentials: config_1.config.cors.credentials,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        }));
        const rateLimiter = process.env['LOAD_TEST_MODE'] === 'true'
            ? advancedRateLimiter_1.loadTestRateLimiter
            : (process.env['NODE_ENV'] === 'production' ? advancedRateLimiter_1.productionRateLimiter : advancedRateLimiter_1.loadTestRateLimiter);
        this.app.use('/api', rateLimiter.middleware());
        this.app.use(express_1.default.json({ limit: '10mb' }));
        this.app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
        if (config_1.config.nodeEnv !== 'test') {
            this.app.use((0, morgan_1.default)('combined', {
                stream: {
                    write: (message) => logger_1.logger.info(message.trim()),
                },
            }));
        }
        this.app.use((req, res, next) => {
            req.id = (0, uuid_1.v4)();
            res.setHeader('X-Request-ID', req.id);
            next();
        });
        this.app.use(advancedPerformanceMonitor_1.advancedPerformanceMonitor.middleware());
        this.app.use(prometheus_1.prometheusMiddleware);
        this.app.use('/uploads', express_1.default.static(path_1.default.join(process.cwd(), 'uploads')));
        this.app.use('/static', express_1.default.static(path_1.default.join(process.cwd(), 'public')));
    }
    initializeRoutes() {
        this.app.get('/metrics', prometheus_1.metricsHandler);
        this.app.get('/health', (_req, res) => {
            res.status(200).json({
                success: true,
                data: {
                    status: 'ok',
                    timestamp: new Date().toISOString(),
                    uptime: process.uptime(),
                    environment: config_1.config.nodeEnv,
                    version: process.env['npm_package_version'] || '1.0.0',
                },
                message: '服务运行正常',
            });
        });
        this.app.use('/', routes_1.default);
        this.app.use('/api/monitor', monitorRoutes_1.default);
        this.app.use('/api/performance', performanceRoutes_1.default);
        this.app.use('/api/health', database_health_1.default);
        if (config_1.config.nodeEnv === 'production') {
            this.app.use(express_1.default.static('public'));
            this.app.get('*', (_req, res) => {
                const path = require('path');
                res.sendFile(path.join(__dirname, '../public/index.html'));
            });
        }
    }
    initializeErrorHandling() {
        this.app.use(notFoundHandler_1.notFoundHandler);
        this.app.use(enhancedErrorHandler_1.enhancedErrorHandler);
    }
    async start() {
        try {
            await (0, database_1.connectDatabase)();
            logger_1.logger.info('数据库连接成功');
            database_connection_monitor_1.databaseConnectionMonitor.startMonitoring(15000);
            logger_1.logger.info('🔍 Database connection monitoring started');
            await (0, redis_1.connectRedis)();
            logger_1.logger.info('Redis连接成功');
            this.server.listen(this.port, async () => {
                logger_1.logger.info(`服务器启动成功，端口: ${this.port}`);
                logger_1.logger.info(`环境: ${config_1.config.nodeEnv}`);
                logger_1.logger.info(`API版本: ${config_1.config.API_VERSION}`);
                logger_1.logger.info(`Health check: http://localhost:${this.port}/health`);
                logger_1.logger.info(`Metrics: http://localhost:${this.port}/metrics`);
                try {
                    await healthService_1.healthService.initialize();
                    logger_1.logger.info('Health service initialized successfully');
                }
                catch (error) {
                    logger_1.logger.error('Failed to initialize health service', { error });
                }
            });
            logger_1.logger.info('WebSocket服务初始化成功');
            database_connection_monitor_1.databaseConnectionMonitor.on('alert', (alert) => {
                logger_1.logger.error('🚨 Database Alert:', alert);
            });
            (0, gracefulShutdown_1.gracefulShutdown)(this.server, async () => {
                database_connection_monitor_1.databaseConnectionMonitor.stopMonitoring();
                logger_1.logger.info('Database monitoring stopped.');
                try {
                    await healthService_1.healthService.cleanup();
                    logger_1.logger.info('Health service cleaned up.');
                }
                catch (error) {
                    logger_1.logger.error('Error cleaning up health service', { error });
                }
            });
        }
        catch (error) {
            logger_1.logger.error('服务器启动失败:', error);
            process.exit(1);
        }
    }
    getApp() {
        return this.app;
    }
}
if (require.main === module) {
    const server = new Server();
    server.start().catch(error => {
        logger_1.logger.error('启动服务器时发生错误:', error);
        process.exit(1);
    });
}
exports.default = Server;
//# sourceMappingURL=server.js.map