import dotenv from 'dotenv';

// 加载环境变量
dotenv.config();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
// TypeScript unused imports removed
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createServer } from 'http';
import { config } from './config/config';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/errorHandler';
import { enhancedErrorHandler } from './middleware/enhancedErrorHandler';
import { notFoundHandler } from './middleware/notFoundHandler';
import { prometheusMiddleware, metricsHandler } from './middleware/prometheus';
import { healthService } from './services/healthService';
import routes from './routes';
import monitorRoutes from './routes/monitorRoutes';
import performanceRoutes from './routes/performanceRoutes';
import { connectDatabase } from './config/database';
import { connectRedis } from './config/redis';
import { databaseConnectionMonitor } from './services/database-connection-monitor';
import databaseHealthRoutes from './routes/database-health';
import { gracefulShutdown } from './utils/gracefulShutdown';
import websocketService from './services/websocketService';
import { setWebSocketService } from './services/websocketManager';
// import { advancedCompressionMiddleware } from './middleware/compressionMiddleware';
import { advancedPerformanceMonitor } from './middleware/advancedPerformanceMonitor';
import { loadTestRateLimiter, productionRateLimiter } from './middleware/advancedRateLimiter';
import { concurrencyOptimizer, highLoadConcurrencyOptimizer } from './middleware/concurrencyOptimizer';
import { loadBalancer } from './middleware/loadBalancer';

class Server {
  private app: express.Application;
  private port: number;
  private server: any;
  constructor() {
    this.app = express();
    this.port = config.port;
    this.server = createServer(this.app);
    // 设置全局WebSocket服务实例
    setWebSocketService(websocketService);
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    // Enhanced Security middleware with comprehensive headers
    this.app.use(helmet({
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
          upgradeInsecureRequests: config.nodeEnv === 'production' ? [] : null,
        },
      },
      crossOriginEmbedderPolicy: false,
      strictTransportSecurity: config.nodeEnv === 'production' ? {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      } : false,
      referrerPolicy: {
        policy: 'origin-when-cross-origin'
      },
    }));

    // Custom Permissions-Policy header middleware
    this.app.use((_req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Permissions-Policy', 
        'geolocation=(self), camera=(), microphone=(), payment=(self), usb=(), bluetooth=(), ' +
        'magnetometer=(), gyroscope=(), accelerometer=(self), fullscreen=(self), autoplay=(self)'
      );
      next();
    });

    // CORS configuration
    this.app.use(cors({
      origin: config.cors.origin,
      credentials: config.cors.credentials,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    }));

    // Load balancer (temporarily disabled for testing)
    // this.app.use(loadBalancer.middleware());

    // Concurrency optimization (temporarily disabled for testing)
    // const concurrency = process.env['NODE_ENV'] === 'production' && process.env['HIGH_LOAD'] === 'true' 
    //   ? highLoadConcurrencyOptimizer 
    //   : concurrencyOptimizer;
    // this.app.use(concurrency.middleware());

    // Advanced rate limiting - optimized for load testing and production
    const rateLimiter = process.env['LOAD_TEST_MODE'] === 'true' 
      ? loadTestRateLimiter 
      : (process.env['NODE_ENV'] === 'production' ? productionRateLimiter : loadTestRateLimiter);
    this.app.use('/api', rateLimiter.middleware());

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Advanced compression middleware - replace basic compression
    // this.app.use(advancedCompressionMiddleware.middleware());

    // Logging middleware
    if (config.nodeEnv !== 'test') {
      this.app.use(morgan('combined', {
        stream: {
          write: (message: string) => logger.info(message.trim()),
        },
      }));
    }

    // Request ID middleware
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      req.id = uuidv4();
      res.setHeader('X-Request-ID', req.id);
      next();
    });

    // Advanced performance monitoring middleware
    this.app.use(advancedPerformanceMonitor.middleware());

    // Prometheus监控中间件
    this.app.use(prometheusMiddleware);

    // Static file serving for uploaded media and static resources
    this.app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));
    this.app.use('/static', express.static(path.join(process.cwd(), 'public')));
  }

  private initializeRoutes(): void {
    // Prometheus metrics endpoint
    this.app.get('/metrics', metricsHandler);

    // Health check endpoint
    this.app.get('/health', (_req: Request, res: Response) => {
      res.status(200).json({
        success: true,
        data: {
          status: 'ok',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          environment: config.nodeEnv,
          version: process.env['npm_package_version'] || '1.0.0',
        },
        message: '服务运行正常',
      });
    });

    // API routes
    this.app.use('/', routes);
    this.app.use('/api/monitor', monitorRoutes);
    this.app.use('/api/performance', performanceRoutes);
    this.app.use('/api/health', databaseHealthRoutes);

    // Serve static files in production
    if (config.nodeEnv === 'production') {
      this.app.use(express.static('public'));
      
      // Serve frontend app for any non-API routes
      this.app.get('*', (_req: Request, res: Response) => {
        const path = require('path');
        res.sendFile(path.join(__dirname, '../public/index.html'));
      });
    }
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use(notFoundHandler);
    
    // Enhanced error handler (replaces basic error handler)
    this.app.use(enhancedErrorHandler);
  }

  public async start(): Promise<void> {
    try {
      // Connect to database
      await connectDatabase();
      logger.info('数据库连接成功');
      
      // Start database connection monitoring
      databaseConnectionMonitor.startMonitoring(15000); // Monitor every 15 seconds
      logger.info('🔍 Database connection monitoring started');

      // Connect to Redis
      await connectRedis();
      logger.info('Redis连接成功');

      // PayPal service initialization commented out temporarily
      // Initialize PayPal service later when needed

      // Start server
      this.server.listen(this.port, async () => {
        logger.info(`服务器启动成功，端口: ${this.port}`);
        logger.info(`环境: ${config.nodeEnv}`);
        logger.info(`API版本: ${config.API_VERSION}`);
        logger.info(`Health check: http://localhost:${this.port}/health`);
        logger.info(`Metrics: http://localhost:${this.port}/metrics`);
        
        // 初始化健康检查服务
        try {
          await healthService.initialize();
          logger.info('Health service initialized successfully');
        } catch (error) {
          logger.error('Failed to initialize health service', { error });
        }
      });

      // WebSocket service is already initialized in constructor
       logger.info('WebSocket服务初始化成功');

      // Setup alert handling
      databaseConnectionMonitor.on('alert', (alert) => {
        logger.error('🚨 Database Alert:', alert);
        // Here you could integrate with external alerting systems
        // like PagerDuty, Slack, or email notifications
      });
      
      // Graceful shutdown
      gracefulShutdown(this.server, async () => {
        // Stop database monitoring
        databaseConnectionMonitor.stopMonitoring();
        logger.info('Database monitoring stopped.');
        
        // 清理健康检查服务
        try {
          await healthService.cleanup();
          logger.info('Health service cleaned up.');
        } catch (error) {
          logger.error('Error cleaning up health service', { error });
        }
      });

    } catch (error) {
      logger.error('服务器启动失败:', error);
      process.exit(1);
    }
  }

  public getApp(): express.Application {
    return this.app;
  }
}

// Start server if this file is run directly
if (require.main === module) {
  const server = new Server();
  server.start().catch(error => {
    logger.error('启动服务器时发生错误:', error);
    process.exit(1);
  });
}

export default Server;

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      id: string;
      user?: {
        id: string;
        email: string;
        username: string;
        role: string;
      };
    }
  }
}
