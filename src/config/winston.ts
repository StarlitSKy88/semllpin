import winston from 'winston';
import path from 'path';
import { config } from './config';

// 定义日志级别
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// 定义日志级别颜色
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// 添加颜色到winston
winston.addColors(colors);

// 定义日志格式
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => {
    const { timestamp, level, message, stack, ...meta } = info;

    // 过滤敏感信息
    const filteredMeta = filterSensitiveData(meta);

    return JSON.stringify({
      timestamp,
      level,
      message,
      ...(stack ? { stack } : {}),
      ...filteredMeta,
    });
  }),
);

// 过滤敏感数据
function filterSensitiveData(data: any): any {
  const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];

  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const filtered = { ...data };

  for (const field of sensitiveFields) {
    if (field in filtered) {
      filtered[field] = '[REDACTED]';
    }
  }

  // 递归处理嵌套对象
  for (const key in filtered) {
    if (typeof filtered[key] === 'object' && filtered[key] !== null) {
      filtered[key] = filterSensitiveData(filtered[key]);
    }
  }

  return filtered;
}

// 定义传输器
const transports: winston.transport[] = [];

// 控制台传输器（开发环境）
if (config.nodeEnv === 'development') {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize({ all: true }),
        winston.format.simple(),
      ),
    }),
  );
}

// 文件传输器
const logDir = path.join(process.cwd(), 'logs');

// 错误日志文件
transports.push(
  new winston.transports.File({
    filename: path.join(logDir, 'error.log'),
    level: 'error',
    maxsize: 10 * 1024 * 1024, // 10MB
    maxFiles: 5,
    format,
  }),
);

// 组合日志文件
transports.push(
  new winston.transports.File({
    filename: path.join(logDir, 'combined.log'),
    maxsize: 10 * 1024 * 1024, // 10MB
    maxFiles: 10,
    format,
  }),
);

// HTTP请求日志文件
transports.push(
  new winston.transports.File({
    filename: path.join(logDir, 'http.log'),
    level: 'http',
    maxsize: 10 * 1024 * 1024, // 10MB
    maxFiles: 7,
    format,
  }),
);

// 业务日志文件
transports.push(
  new winston.transports.File({
    filename: path.join(logDir, 'business.log'),
    maxsize: 10 * 1024 * 1024, // 10MB
    maxFiles: 30,
    format,
  }),
);

// 创建logger实例
const logger = winston.createLogger({
  level: config.nodeEnv === 'development' ? 'debug' : 'info',
  levels,
  format,
  transports,
  exitOnError: false,
});

// 业务日志记录器
export const businessLogger = {
  // 用户行为日志
  userAction: (userId: string, action: string, details: any) => {
    logger.info('User action', {
      category: 'user_action',
      userId,
      action,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 支付日志
  payment: (userId: string, amount: number, status: string, details: any) => {
    logger.info('Payment transaction', {
      category: 'payment',
      userId,
      amount,
      status,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 标注日志
  annotation: (userId: string, annotationId: string, action: string, details: any) => {
    logger.info('Annotation activity', {
      category: 'annotation',
      userId,
      annotationId,
      action,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // LBS奖励日志
  lbsReward: (userId: string, annotationId: string, reward: number, details: any) => {
    logger.info('LBS reward', {
      category: 'lbs_reward',
      userId,
      annotationId,
      reward,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 安全事件日志
  security: (event: string, userId?: string, details?: any) => {
    logger.warn('Security event', {
      category: 'security',
      event,
      userId,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 性能日志
  performance: (operation: string, duration: number, details: any) => {
    logger.info('Performance metric', {
      category: 'performance',
      operation,
      duration,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },
};

// 错误日志记录器
export const errorLogger = {
  // API错误
  apiError: (error: Error, req: any, details?: any) => {
    logger.error('API Error', {
      category: 'api_error',
      message: error.message,
      stack: error.stack,
      url: req.url,
      method: req.method,
      userId: req.user?.id,
      requestId: req.id,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 数据库错误
  dbError: (error: Error, operation: string, details?: any) => {
    logger.error('Database Error', {
      category: 'db_error',
      message: error.message,
      stack: error.stack,
      operation,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 外部服务错误
  externalError: (service: string, error: Error, details?: any) => {
    logger.error('External Service Error', {
      category: 'external_error',
      service,
      message: error.message,
      stack: error.stack,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },

  // 系统错误
  systemError: (error: Error, context: string, details?: any) => {
    logger.error('System Error', {
      category: 'system_error',
      message: error.message,
      stack: error.stack,
      context,
      details: filterSensitiveData(details),
      timestamp: new Date().toISOString(),
    });
  },
};

// HTTP请求日志记录器
export const httpLogger = {
  request: (req: any, res: any, responseTime: number) => {
    logger.http('HTTP Request', {
      category: 'http_request',
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id,
      requestId: req.id,
      timestamp: new Date().toISOString(),
    });
  },
};

export { logger };
export default logger;
