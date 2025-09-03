"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.healthService = exports.HealthStatus = void 0;
const logger_1 = require("../utils/logger");
const isTestEnv = (process.env['NODE_ENV'] === 'test') || (typeof process.env['JEST_WORKER_ID'] !== 'undefined');
var HealthStatus;
(function (HealthStatus) {
    HealthStatus["HEALTHY"] = "healthy";
    HealthStatus["DEGRADED"] = "degraded";
    HealthStatus["UNHEALTHY"] = "unhealthy";
})(HealthStatus || (exports.HealthStatus = HealthStatus = {}));
class HealthService {
    constructor() {
        this.healthChecks = new Map();
        this.lastHealthCheck = null;
        this.healthCheckInterval = null;
        this.startPeriodicHealthCheck();
    }
    registerHealthCheck(serviceName, checkFunction) {
        this.healthChecks.set(serviceName, checkFunction);
        logger_1.logger.info(`Health check registered for service: ${serviceName}`);
    }
    unregisterHealthCheck(serviceName) {
        this.healthChecks.delete(serviceName);
        logger_1.logger.info(`Health check unregistered for service: ${serviceName}`);
    }
    async performHealthCheck() {
        const startTime = Date.now();
        const services = {};
        const healthCheckPromises = Array.from(this.healthChecks.entries()).map(async ([serviceName, checkFunction]) => {
            try {
                const result = await Promise.race([
                    checkFunction(),
                    this.createTimeoutPromise(5000),
                ]);
                services[serviceName] = {
                    ...result,
                    lastCheck: new Date().toISOString(),
                };
            }
            catch (error) {
                services[serviceName] = {
                    status: HealthStatus.UNHEALTHY,
                    error: error instanceof Error ? error.message : 'Unknown error',
                    lastCheck: new Date().toISOString(),
                };
            }
        });
        await Promise.all(healthCheckPromises);
        const overallStatus = this.calculateOverallStatus(services);
        const healthInfo = {
            status: overallStatus,
            timestamp: new Date().toISOString(),
            version: process.env['npm_package_version'] || '1.0.0',
            environment: process.env['NODE_ENV'] || 'development',
            uptime: Math.floor((Date.now() - (process.uptime() * 1000)) / 1000),
            services,
            metrics: {
                healthCheckDuration: Date.now() - startTime,
            },
        };
        this.lastHealthCheck = healthInfo;
        return healthInfo;
    }
    getLastHealthCheck() {
        return this.lastHealthCheck;
    }
    calculateOverallStatus(services) {
        const statuses = Object.values(services).map(service => service.status);
        if (statuses.includes(HealthStatus.UNHEALTHY)) {
            return HealthStatus.UNHEALTHY;
        }
        if (statuses.includes(HealthStatus.DEGRADED)) {
            return HealthStatus.DEGRADED;
        }
        return HealthStatus.HEALTHY;
    }
    createTimeoutPromise(timeout) {
        return new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error(`Health check timeout after ${timeout}ms`));
            }, timeout);
        });
    }
    startPeriodicHealthCheck() {
        if (isTestEnv) {
            return;
        }
        const interval = setInterval(async () => {
            try {
                await this.performHealthCheck();
            }
            catch (error) {
                logger_1.logger.error('Periodic health check failed', { error });
            }
        }, 30000);
        const maybeUnref = interval.unref;
        if (typeof maybeUnref === 'function') {
            maybeUnref.call(interval);
        }
        this.healthCheckInterval = interval;
    }
    stopPeriodicHealthCheck() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
        }
    }
    async checkServiceHealth(serviceName) {
        const checkFunction = this.healthChecks.get(serviceName);
        if (!checkFunction) {
            return null;
        }
        try {
            const result = await checkFunction();
            return {
                ...result,
                lastCheck: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                status: HealthStatus.UNHEALTHY,
                error: error instanceof Error ? error.message : 'Unknown error',
                lastCheck: new Date().toISOString(),
            };
        }
    }
    async getSystemHealth() {
        return this.performHealthCheck();
    }
    async getSimpleHealth() {
        const health = await this.performHealthCheck();
        return {
            status: health.status,
            timestamp: health.timestamp,
        };
    }
    async getReadinessStatus() {
        return this.performHealthCheck();
    }
    async getLivenessStatus() {
        return {
            status: HealthStatus.HEALTHY,
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
        };
    }
    getSystemInfo() {
        return {
            platform: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            pid: process.pid,
            ppid: process.ppid,
            cwd: process.cwd(),
            execPath: process.execPath,
            version: process.env['npm_package_version'] || '1.0.0',
        };
    }
    async initialize() {
        logger_1.logger.info('Initializing health service...');
        await this.performHealthCheck();
        logger_1.logger.info('Health service initialized successfully');
    }
    async cleanup() {
        logger_1.logger.info('Cleaning up health service...');
        this.stopPeriodicHealthCheck();
        this.healthChecks.clear();
        this.lastHealthCheck = null;
        logger_1.logger.info('Health service cleaned up successfully');
    }
}
exports.healthService = new HealthService();
exports.default = exports.healthService;
//# sourceMappingURL=healthService.js.map