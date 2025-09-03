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
const compression_1 = __importDefault(require("compression"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const path_1 = __importDefault(require("path"));
const uuid_1 = require("uuid");
const http_1 = require("http");
const config_1 = require("./config/config");
const logger_1 = require("./utils/logger");
const errorHandler_1 = require("./middleware/errorHandler");
const notFoundHandler_1 = require("./middleware/notFoundHandler");
const prometheus_1 = require("./middleware/prometheus");
const healthService_1 = require("./services/healthService");
const routes_1 = __importDefault(require("./routes"));
const monitorRoutes_1 = __importDefault(require("./routes/monitorRoutes"));
const database_1 = require("./config/database");
const redis_1 = require("./config/redis");
const gracefulShutdown_1 = require("./utils/gracefulShutdown");
const websocketService_1 = __importDefault(require("./services/websocketService"));
const websocketManager_1 = require("./services/websocketManager");
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
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", 'data:', 'https:'],
                },
            },
            crossOriginEmbedderPolicy: false,
        }));
        this.app.use((0, cors_1.default)({
            origin: config_1.config.cors.origin,
            credentials: config_1.config.cors.credentials,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        }));
        const limiter = (0, express_rate_limit_1.default)({
            windowMs: config_1.config.rateLimit.windowMs,
            max: config_1.config.rateLimit.maxRequests,
            message: {
                success: false,
                error: {
                    code: 'RATE_LIMIT_EXCEEDED',
                    message: '请求过于频繁，请稍后再试',
                },
                timestamp: new Date().toISOString(),
            },
            standardHeaders: true,
            legacyHeaders: false,
        });
        this.app.use('/api', limiter);
        this.app.use(express_1.default.json({ limit: '10mb' }));
        this.app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
        this.app.use((0, compression_1.default)());
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
        this.app.use(prometheus_1.prometheusMiddleware);
        this.app.use('/uploads', express_1.default.static(path_1.default.join(process.cwd(), 'uploads')));
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
        this.app.use(errorHandler_1.errorHandler);
    }
    async start() {
        try {
            await (0, database_1.connectDatabase)();
            logger_1.logger.info('数据库连接成功');
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
            (0, gracefulShutdown_1.gracefulShutdown)(this.server, async () => {
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