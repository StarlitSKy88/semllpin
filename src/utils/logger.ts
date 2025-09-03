/**
 * 日志工具
 * 提供统一的日志记录功能
 */

import { config } from '../config/config';

// 日志级别
enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

class Logger {
  private logLevel: LogLevel;

  constructor() {
    this.logLevel = this.getLogLevel(config.LOG_LEVEL);
  }

  private getLogLevel(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case 'error':
        return LogLevel.ERROR;
      case 'warn':
        return LogLevel.WARN;
      case 'info':
        return LogLevel.INFO;
      case 'debug':
        return LogLevel.DEBUG;
      default:
        return LogLevel.INFO;
    }
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level.toUpperCase()}: ${message}${metaStr}`;
  }

  private log(level: LogLevel, levelName: string, message: string, meta?: any): void {
    if (level <= this.logLevel) {
      const formattedMessage = this.formatMessage(levelName, message, meta);

      switch (level) {
        case LogLevel.ERROR:
          console.error(formattedMessage);
          break;
        case LogLevel.WARN:
          console.warn(formattedMessage);
          break;
        case LogLevel.INFO:
          console.info(formattedMessage);
          break;
        case LogLevel.DEBUG:
          console.debug(formattedMessage);
          break;
      }
    }
  }

  error(message: string, meta?: any): void {
    this.log(LogLevel.ERROR, 'error', message, meta);
  }

  warn(message: string, meta?: any): void {
    this.log(LogLevel.WARN, 'warn', message, meta);
  }

  info(message: string, meta?: any): void {
    this.log(LogLevel.INFO, 'info', message, meta);
  }

  debug(message: string, meta?: any): void {
    this.log(LogLevel.DEBUG, 'debug', message, meta);
  }
}

export const logger = new Logger();
export default logger;
