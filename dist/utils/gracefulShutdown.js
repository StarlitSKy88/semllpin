"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GracefulShutdown = void 0;
exports.gracefulShutdown = gracefulShutdown;
const logger_1 = require("./logger");
const database_1 = require("../config/database");
const redis_1 = require("../config/redis");
class GracefulShutdown {
    constructor(server) {
        this.isShuttingDown = false;
        this.shutdownTimeout = 30000;
        this.cleanupCallbacks = [];
        this.server = server;
        this.setupSignalHandlers();
    }
    addCleanupCallback(callback) {
        this.cleanupCallbacks.push(callback);
    }
    setupSignalHandlers() {
        process.on('SIGTERM', () => {
            logger_1.logger.info('收到 SIGTERM 信号，开始优雅关闭...');
            this.shutdown('SIGTERM');
        });
        process.on('SIGINT', () => {
            logger_1.logger.info('收到 SIGINT 信号，开始优雅关闭...');
            this.shutdown('SIGINT');
        });
        process.on('uncaughtException', (error) => {
            logger_1.logger.error('未捕获的异常:', error);
            this.shutdown('uncaughtException');
        });
        process.on('unhandledRejection', (reason, promise) => {
            logger_1.logger.error('未处理的 Promise 拒绝:', { reason, promise });
            this.shutdown('unhandledRejection');
        });
    }
    async shutdown(signal) {
        if (this.isShuttingDown) {
            logger_1.logger.warn('已经在关闭过程中，忽略重复信号');
            return;
        }
        this.isShuttingDown = true;
        logger_1.logger.info(`开始优雅关闭 (信号: ${signal})`);
        const shutdownTimer = setTimeout(() => {
            logger_1.logger.error('优雅关闭超时，强制退出');
            process.exit(1);
        }, this.shutdownTimeout);
        try {
            if (this.server) {
                await new Promise((resolve, reject) => {
                    this.server.close((err) => {
                        if (err) {
                            logger_1.logger.error('关闭服务器时出错:', err);
                            reject(err);
                        }
                        else {
                            logger_1.logger.info('HTTP 服务器已关闭');
                            resolve();
                        }
                    });
                });
            }
            try {
                await (0, database_1.disconnectDatabase)();
                logger_1.logger.info('数据库连接已关闭');
            }
            catch (error) {
                logger_1.logger.error('关闭数据库连接时出错:', error);
            }
            try {
                await (0, redis_1.disconnectRedis)();
                logger_1.logger.info('Redis 连接已关闭');
            }
            catch (error) {
                logger_1.logger.error('关闭 Redis 连接时出错:', error);
            }
            for (const callback of this.cleanupCallbacks) {
                try {
                    await callback();
                }
                catch (error) {
                    logger_1.logger.error('执行清理回调时出错:', error);
                }
            }
            await this.waitForActiveConnections();
            clearTimeout(shutdownTimer);
            logger_1.logger.info('优雅关闭完成');
            process.exit(0);
        }
        catch (error) {
            clearTimeout(shutdownTimer);
            logger_1.logger.error('优雅关闭过程中出错:', error);
            process.exit(1);
        }
    }
    async waitForActiveConnections() {
        return new Promise((resolve) => {
            setTimeout(() => {
                logger_1.logger.info('等待活跃连接完成');
                resolve();
            }, 1000);
        });
    }
    setShutdownTimeout(timeout) {
        this.shutdownTimeout = timeout;
    }
}
exports.GracefulShutdown = GracefulShutdown;
function gracefulShutdown(server, cleanupCallback) {
    const shutdown = new GracefulShutdown(server);
    if (cleanupCallback) {
        shutdown.addCleanupCallback(cleanupCallback);
    }
    return shutdown;
}
exports.default = gracefulShutdown;
//# sourceMappingURL=gracefulShutdown.js.map