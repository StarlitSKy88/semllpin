import { logger } from './logger';
import { disconnectDatabase } from '../config/database';
import { disconnectRedis } from '../config/redis';

/**
 * 优雅关闭处理器
 * 在应用程序关闭时清理资源
 */
export class GracefulShutdown {
  private isShuttingDown = false;
  private server: any;
  private shutdownTimeout = 30000; // 30秒超时
  private cleanupCallbacks: Array<() => Promise<void>> = [];

  constructor(server: any) {
    this.server = server;
    this.setupSignalHandlers();
  }

  /**
   * 添加清理回调函数
   */
  public addCleanupCallback(callback: () => Promise<void>): void {
    this.cleanupCallbacks.push(callback);
  }

  /**
   * 设置信号处理器
   */
  private setupSignalHandlers(): void {
    // 处理 SIGTERM 信号 (Docker, Kubernetes)
    process.on('SIGTERM', () => {
      logger.info('收到 SIGTERM 信号，开始优雅关闭...');
      this.shutdown('SIGTERM');
    });

    // 处理 SIGINT 信号 (Ctrl+C)
    process.on('SIGINT', () => {
      logger.info('收到 SIGINT 信号，开始优雅关闭...');
      this.shutdown('SIGINT');
    });

    // 处理未捕获的异常
    process.on('uncaughtException', (error) => {
      logger.error('未捕获的异常:', error);
      this.shutdown('uncaughtException');
    });

    // 处理未处理的 Promise 拒绝
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('未处理的 Promise 拒绝:', { reason, promise });
      this.shutdown('unhandledRejection');
    });
  }

  /**
   * 执行优雅关闭
   */
  private async shutdown(signal: string): Promise<void> {
    if (this.isShuttingDown) {
      logger.warn('已经在关闭过程中，忽略重复信号');
      return;
    }

    this.isShuttingDown = true;
    logger.info(`开始优雅关闭 (信号: ${signal})`);

    // 设置关闭超时
    const shutdownTimer = setTimeout(() => {
      logger.error('优雅关闭超时，强制退出');
      process.exit(1);
    }, this.shutdownTimeout);

    try {
      // 1. 停止接受新的连接
      if (this.server) {
        await new Promise<void>((resolve, reject) => {
          this.server.close((err: any) => {
            if (err) {
              logger.error('关闭服务器时出错:', err);
              reject(err);
            } else {
              logger.info('HTTP 服务器已关闭');
              resolve();
            }
          });
        });
      }

      // 2. 关闭数据库连接
      try {
        await disconnectDatabase();
        logger.info('数据库连接已关闭');
      } catch (error) {
        logger.error('关闭数据库连接时出错:', error);
      }

      // 3. 关闭 Redis 连接
      try {
        await disconnectRedis();
        logger.info('Redis 连接已关闭');
      } catch (error) {
        logger.error('关闭 Redis 连接时出错:', error);
      }

      // 4. 执行自定义清理回调
      for (const callback of this.cleanupCallbacks) {
        try {
          await callback();
        } catch (error) {
          logger.error('执行清理回调时出错:', error);
        }
      }

      // 5. 等待正在处理的请求完成
      await this.waitForActiveConnections();

      clearTimeout(shutdownTimer);
      logger.info('优雅关闭完成');
      process.exit(0);
    } catch (error) {
      clearTimeout(shutdownTimer);
      logger.error('优雅关闭过程中出错:', error);
      process.exit(1);
    }
  }

  /**
   * 等待活跃连接完成
   */
  private async waitForActiveConnections(): Promise<void> {
    return new Promise((resolve) => {
      // 简单的等待逻辑，实际项目中可能需要更复杂的连接跟踪
      setTimeout(() => {
        logger.info('等待活跃连接完成');
        resolve();
      }, 1000);
    });
  }

  /**
   * 设置关闭超时时间
   */
  public setShutdownTimeout(timeout: number): void {
    this.shutdownTimeout = timeout;
  }
}

/**
 * 创建优雅关闭处理器
 */
export function gracefulShutdown(server: any, cleanupCallback?: () => Promise<void>): GracefulShutdown {
  const shutdown = new GracefulShutdown(server);
  if (cleanupCallback) {
    shutdown.addCleanupCallback(cleanupCallback);
  }
  return shutdown;
}

/**
 * 默认导出
 */
export default gracefulShutdown;
