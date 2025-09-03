"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateMetrics = exports.healthRouter = void 0;
const express_1 = require("express");
const logger_1 = require("../utils/logger");
const healthService_1 = require("../services/healthService");
const healthService_2 = require("../services/healthService");
const database_1 = __importDefault(require("../config/database"));
const redis_1 = require("../config/redis");
const fs_1 = require("fs");
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const router = (0, express_1.Router)();
exports.healthRouter = router;
const globalMetrics = {
    totalRequests: 0,
    activeConnections: 0,
    totalErrors: 0,
    startTime: Date.now(),
};
const updateMetrics = {
    incrementRequests: () => globalMetrics.totalRequests++,
    incrementErrors: () => globalMetrics.totalErrors++,
    setActiveConnections: (count) => globalMetrics.activeConnections = count,
};
exports.updateMetrics = updateMetrics;
async function checkDatabaseHealth() {
    const startTime = Date.now();
    try {
        const result = await database_1.default.raw('SELECT 1 as health_check, NOW() as current_time');
        const responseTime = Date.now() - startTime;
        if (result.rows && result.rows.length > 0) {
            return {
                status: responseTime < 1000 ? 'healthy' : 'degraded',
                responseTime,
                details: {
                    connected: true,
                    serverTime: result.rows[0].current_time,
                },
            };
        }
        else {
            return {
                status: 'unhealthy',
                responseTime,
                error: 'Database query returned no results',
            };
        }
    }
    catch (error) {
        return {
            status: 'unhealthy',
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : 'Unknown database error',
        };
    }
}
async function checkRedisHealth() {
    const startTime = Date.now();
    try {
        const redisClient = (0, redis_1.getRedisClient)();
        const testKey = `health_check_${Date.now()}`;
        const testValue = 'ok';
        await redisClient.set(testKey, testValue, 'EX', 10);
        const result = await redisClient.get(testKey);
        await redisClient.del(testKey);
        const responseTime = Date.now() - startTime;
        if (result === testValue) {
            return {
                status: responseTime < 500 ? 'healthy' : 'degraded',
                responseTime,
                details: {
                    connected: true,
                    keyspace: await redisClient.info('keyspace'),
                },
            };
        }
        else {
            return {
                status: 'unhealthy',
                responseTime,
                error: 'Redis test key-value operation failed',
            };
        }
    }
    catch (error) {
        return {
            status: 'unhealthy',
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : 'Unknown Redis error',
        };
    }
}
async function checkFilesystemHealth() {
    const startTime = Date.now();
    try {
        const tempDir = os.tmpdir();
        const testFile = path.join(tempDir, `health_check_${Date.now()}.tmp`);
        const testContent = 'health check test';
        await fs_1.promises.writeFile(testFile, testContent);
        const readContent = await fs_1.promises.readFile(testFile, 'utf8');
        await fs_1.promises.unlink(testFile);
        const responseTime = Date.now() - startTime;
        if (readContent === testContent) {
            await fs_1.promises.stat(tempDir);
            return {
                status: responseTime < 100 ? 'healthy' : 'degraded',
                responseTime,
                details: {
                    tempDir,
                    writable: true,
                    readable: true,
                },
            };
        }
        else {
            return {
                status: 'unhealthy',
                responseTime,
                error: 'Filesystem read/write test failed',
            };
        }
    }
    catch (error) {
        return {
            status: 'unhealthy',
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : 'Unknown filesystem error',
        };
    }
}
function checkMemoryHealth() {
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memUsagePercent = (usedMem / totalMem) * 100;
    let status = 'healthy';
    if (memUsagePercent > 90) {
        status = 'unhealthy';
    }
    else if (memUsagePercent > 80) {
        status = 'degraded';
    }
    return {
        status,
        details: {
            rss: Math.round(memUsage.rss / 1024 / 1024),
            heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
            heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
            external: Math.round(memUsage.external / 1024 / 1024),
            systemTotal: Math.round(totalMem / 1024 / 1024),
            systemFree: Math.round(freeMem / 1024 / 1024),
            systemUsagePercent: Math.round(memUsagePercent * 100) / 100,
        },
    };
}
function checkCpuHealth() {
    const cpus = os.cpus();
    const loadAvg = os.loadavg();
    const load1min = loadAvg[0];
    const cpuCount = cpus.length;
    const cpuUsagePercent = load1min ? (load1min / cpuCount) * 100 : 0;
    let status = 'healthy';
    if (cpuUsagePercent > 90) {
        status = 'unhealthy';
    }
    else if (cpuUsagePercent > 80) {
        status = 'degraded';
    }
    return {
        status,
        details: {
            cores: cpuCount,
            model: cpus[0]?.model || 'Unknown',
            loadAverage: {
                '1min': Math.round((loadAvg[0] || 0) * 100) / 100,
                '5min': Math.round((loadAvg[1] || 0) * 100) / 100,
                '15min': Math.round((loadAvg[2] || 0) * 100) / 100,
            },
            usagePercent: Math.round(cpuUsagePercent * 100) / 100,
        },
    };
}
function calculateOverallStatus(services) {
    const statuses = Object.values(services).map(service => service.status);
    if (statuses.includes('unhealthy')) {
        return 'unhealthy';
    }
    if (statuses.includes('degraded')) {
        return 'degraded';
    }
    return 'healthy';
}
router.get('/', async (_req, res) => {
    try {
        const healthData = await healthService_1.healthService.getSystemHealth();
        const statusCode = healthData.status === healthService_2.HealthStatus.HEALTHY ? 200 :
            healthData.status === healthService_2.HealthStatus.DEGRADED ? 200 : 503;
        res.status(statusCode).json({
            success: healthData.status !== healthService_2.HealthStatus.UNHEALTHY,
            data: healthData,
            message: healthData.status === healthService_2.HealthStatus.HEALTHY ? '服务运行正常' :
                healthData.status === healthService_2.HealthStatus.DEGRADED ? '服务运行降级' : '服务异常',
        });
    }
    catch (error) {
        logger_1.logger.error('Health check failed', { error });
        res.status(500).json({
            success: false,
            error: 'Health check failed',
            message: '健康检查失败',
        });
    }
});
router.get('/detailed', async (_req, res) => {
    try {
        const startTime = Date.now();
        const [database, redis, filesystem] = await Promise.all([
            checkDatabaseHealth(),
            checkRedisHealth(),
            checkFilesystemHealth(),
        ]);
        const memory = checkMemoryHealth();
        const cpu = checkCpuHealth();
        const services = { database, redis, filesystem, memory, cpu };
        const overallStatus = calculateOverallStatus(services);
        const uptime = Math.floor((Date.now() - globalMetrics.startTime) / 1000);
        const errorRate = globalMetrics.totalRequests > 0
            ? (globalMetrics.totalErrors / globalMetrics.totalRequests) * 100
            : 0;
        const healthStatus = {
            status: overallStatus,
            timestamp: new Date().toISOString(),
            version: process.env['APP_VERSION'] || '1.0.0',
            environment: process.env['NODE_ENV'] || 'development',
            uptime,
            services,
            metrics: {
                totalRequests: globalMetrics.totalRequests,
                activeConnections: globalMetrics.activeConnections,
                responseTime: Date.now() - startTime,
                errorRate: Math.round(errorRate * 100) / 100,
            },
        };
        const httpStatus = overallStatus === 'healthy' ? 200 :
            overallStatus === 'degraded' ? 200 : 503;
        res.status(httpStatus).json({
            code: httpStatus,
            message: `System is ${overallStatus}`,
            data: healthStatus,
        });
    }
    catch (error) {
        res.status(503).json({
            code: 503,
            message: 'Health check failed',
            data: {
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: error instanceof Error ? error.message : 'Unknown error',
            },
        });
    }
});
router.get('/simple', async (_req, res) => {
    try {
        const healthData = await healthService_1.healthService.getSimpleHealth();
        const statusCode = healthData.status === healthService_2.HealthStatus.HEALTHY ? 200 : 503;
        res.status(statusCode).json({
            status: healthData.status,
            timestamp: healthData.timestamp,
        });
    }
    catch (error) {
        logger_1.logger.error('Simple health check failed', { error });
        res.status(500).json({
            status: healthService_2.HealthStatus.UNHEALTHY,
            timestamp: new Date().toISOString(),
        });
    }
});
router.get('/simple-legacy', async (_req, res) => {
    try {
        const healthData = await healthService_1.healthService.getSystemHealth();
        const dbComponent = healthData.services['database'];
        const redisComponent = healthData.services['redis'];
        const isHealthy = dbComponent?.status === 'healthy' &&
            redisComponent?.status === 'healthy';
        if (isHealthy) {
            res.status(200).json({ status: 'ok' });
        }
        else {
            res.status(503).json({ status: 'error' });
        }
    }
    catch (error) {
        res.status(503).json({ status: 'error' });
    }
});
router.get('/ready', async (_req, res) => {
    try {
        const readinessData = await healthService_1.healthService.getReadinessStatus();
        const statusCode = readinessData.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json(readinessData);
    }
    catch (error) {
        logger_1.logger.error('Readiness check failed', { error });
        res.status(503).json({
            ready: false,
            components: ['system'],
        });
    }
});
router.get('/ready-legacy', async (_req, res) => {
    try {
        const readinessData = await healthService_1.healthService.getLastHealthCheck();
        const statusCode = readinessData?.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json({
            status: readinessData?.status === 'healthy' ? 'ready' : 'not ready',
            timestamp: new Date().toISOString(),
        });
    }
    catch (error) {
        res.status(503).json({
            status: 'not ready',
            error: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString(),
        });
    }
});
router.get('/live', async (_req, res) => {
    try {
        const livenessData = await healthService_1.healthService.getLivenessStatus();
        const statusCode = livenessData.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json(livenessData);
    }
    catch (error) {
        logger_1.logger.error('Liveness check failed', { error });
        res.status(503).json({
            alive: false,
        });
    }
});
router.get('/live-legacy', (_req, res) => {
    res.status(200).json({ status: 'alive' });
});
router.get('/info', (_req, res) => {
    try {
        const systemInfo = healthService_1.healthService.getSystemInfo();
        res.status(200).json({
            success: true,
            data: systemInfo,
            message: '系统信息获取成功',
        });
    }
    catch (error) {
        logger_1.logger.error('System info check failed', { error });
        res.status(500).json({
            success: false,
            error: 'System info check failed',
            message: '系统信息获取失败',
        });
    }
});
router.get('/info-legacy', (_req, res) => {
    const systemInfo = {
        node: {
            version: process.version,
            platform: process.platform,
            arch: process.arch,
            pid: process.pid,
            uptime: process.uptime(),
        },
        os: {
            type: os.type(),
            release: os.release(),
            hostname: os.hostname(),
            totalmem: os.totalmem(),
            freemem: os.freemem(),
            cpus: os.cpus().length,
        },
        app: {
            name: process.env['APP_NAME'] || 'SmellPin',
            version: process.env['APP_VERSION'] || '1.0.0',
            environment: process.env['NODE_ENV'] || 'development',
            port: process.env['PORT'] || 3000,
        },
    };
    res.json({
        code: 200,
        message: 'System information',
        data: systemInfo,
    });
});
router.get('/db', async (_req, res) => {
    try {
        const healthData = await healthService_1.healthService.getSystemHealth();
        const dbComponent = healthData.services['database'];
        const statusCode = dbComponent?.status === healthService_2.HealthStatus.HEALTHY ? 200 :
            dbComponent?.status === healthService_2.HealthStatus.DEGRADED ? 200 : 503;
        res.status(statusCode).json({
            success: dbComponent?.status !== healthService_2.HealthStatus.UNHEALTHY,
            data: healthData,
            message: dbComponent?.status === healthService_2.HealthStatus.HEALTHY ? '数据库连接正常' :
                dbComponent?.status === healthService_2.HealthStatus.DEGRADED ? '数据库连接降级' : '数据库连接异常',
        });
    }
    catch (error) {
        logger_1.logger.error('Database health check failed', { error });
        res.status(500).json({
            success: false,
            error: 'Database health check failed',
            message: '数据库健康检查失败',
        });
    }
});
router.get('/redis', async (_req, res) => {
    try {
        const healthData = await healthService_1.healthService.getSystemHealth();
        const redisComponent = healthData.services['redis'];
        const statusCode = redisComponent?.status === healthService_2.HealthStatus.HEALTHY ? 200 :
            redisComponent?.status === healthService_2.HealthStatus.DEGRADED ? 200 : 503;
        res.status(statusCode).json({
            success: redisComponent?.status !== healthService_2.HealthStatus.UNHEALTHY,
            data: healthData,
            message: redisComponent?.status === healthService_2.HealthStatus.HEALTHY ? 'Redis连接正常' :
                redisComponent?.status === healthService_2.HealthStatus.DEGRADED ? 'Redis连接降级' : 'Redis连接异常',
        });
    }
    catch (error) {
        logger_1.logger.error('Redis health check failed', { error });
        res.status(500).json({
            success: false,
            error: 'Redis health check failed',
            message: 'Redis健康检查失败',
        });
    }
});
//# sourceMappingURL=health.js.map