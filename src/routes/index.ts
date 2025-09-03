import { Router } from 'express';
import userRoutes from './userRoutes';
import annotationRoutes from './annotationRoutes';
import paymentRoutes from './paymentRoutes';
import mediaRoutes from './mediaRoutes';
import lbsRoutes from './lbsRoutes';
import geocodingRoutes from './geocoding';

import searchRoutes from './searchRoutes';
import socialRoutes from './socialRoutes';
import commentRoutes from './commentRoutes';
import followRoutes from './followRoutes';
import walletRoutes from './walletRoutes';
import shareRoutes from './shareRoutes';
import interactionRoutes from './interactionRoutes';
import adminRoutes from './adminRoutes';

// 新增的增强社交功能路由
import feedRoutes from './feedRoutes';
import recommendationRoutes from './recommendationRoutes';
import profileRoutes from './profileRoutes';
import moderationRoutes from './moderationRoutes';

// 错误监控路由
import errorMonitoringRoutes from './errorMonitoringRoutes';

// 数据库性能监控路由 (临时禁用)
// import databasePerformanceRoutes from './databasePerformanceRoutes';

import { logger } from '@/utils/logger';

const router = Router();

// API version prefix
const API_VERSION = '/api/v1';

// Health check endpoint
router.get('/health', (_req, res) => {
  res.json({
    success: true,
    message: 'SmellPin API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

router.get(`${API_VERSION}/health`, (_req, res) => {
  res.json({
    success: true,
    message: 'SmellPin API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

// API routes
router.use(`${API_VERSION}/users`, userRoutes);
router.use(`${API_VERSION}/auth`, userRoutes); // 为了兼容前端的auth路径
router.use(`${API_VERSION}/annotations`, annotationRoutes);
router.use(`${API_VERSION}/payments`, paymentRoutes);
router.use(`${API_VERSION}/media`, mediaRoutes);
router.use(`${API_VERSION}/lbs`, lbsRoutes);
router.use(`${API_VERSION}/geocoding`, geocodingRoutes);

router.use(`${API_VERSION}/search`, searchRoutes);
router.use(`${API_VERSION}/social`, socialRoutes);
router.use(`${API_VERSION}`, commentRoutes);
router.use(`${API_VERSION}/users`, followRoutes);
router.use(`${API_VERSION}/wallet`, walletRoutes);
router.use(`${API_VERSION}`, shareRoutes);
router.use(`${API_VERSION}/interactions`, interactionRoutes);
router.use(`${API_VERSION}/admin`, adminRoutes);

// 增强社交功能路由
router.use(`${API_VERSION}`, feedRoutes);
router.use(`${API_VERSION}/recommendations`, recommendationRoutes);
router.use(`${API_VERSION}`, profileRoutes);
router.use(`${API_VERSION}/moderation`, moderationRoutes);

// 错误监控路由
router.use(`${API_VERSION}/errors`, errorMonitoringRoutes);

// 数据库性能监控路由 (临时禁用)
// router.use(`${API_VERSION}/database/performance`, databasePerformanceRoutes);

// API documentation endpoint (public route)
router.get('/api/docs', (_req, res) => {
  res.json({
    success: true,
    message: 'SmellPin API Documentation',
    version: '1.0.0',
  });
});

router.get(`${API_VERSION}/docs`, (_req, res) => {
  res.json({
    success: true,
    message: 'SmellPin API Documentation',
    version: '1.0.0',
    endpoints: {
      users: {
        'POST /api/v1/users/register': '用户注册',
        'POST /api/v1/users/login': '用户登录',
        'POST /api/v1/users/logout': '用户登出',
        'POST /api/v1/users/refresh-token': '刷新访问令牌',
        'POST /api/v1/users/forgot-password': '忘记密码',
        'POST /api/v1/users/reset-password': '重置密码',
        'GET /api/v1/users/profile/me': '获取当前用户资料',
        'PUT /api/v1/users/profile': '更新用户资料',
        'PUT /api/v1/users/password': '修改密码',
        'GET /api/v1/users/:id': '获取用户公开资料',
        'GET /api/v1/users': '获取用户列表（管理员）',
        'PUT /api/v1/users/:id': '更新用户信息（管理员）',
        'DELETE /api/v1/users/:id': '删除用户（管理员）',
      },
      annotations: {
        'GET /api/v1/annotations/list': '获取标注列表',
        'GET /api/v1/annotations/map': '获取地图数据',
        'GET /api/v1/annotations/nearby': '获取附近标注',
        'GET /api/v1/annotations/stats': '获取标注统计',
        'GET /api/v1/annotations/:id': '获取标注详情',
        'POST /api/v1/annotations': '创建标注',
        'PUT /api/v1/annotations/:id': '更新标注',
        'DELETE /api/v1/annotations/:id': '删除标注',
        'POST /api/v1/annotations/:id/like': '点赞标注',
        'DELETE /api/v1/annotations/:id/like': '取消点赞',
        'GET /api/v1/annotations/user/me': '获取我的标注',
        'PUT /api/v1/annotations/:id/moderate': '审核标注（管理员）',
      },
    },
    authentication: {
      type: 'Bearer Token',
      header: 'Authorization: Bearer <token>',
      description: '大部分API需要在请求头中包含有效的JWT令牌',
    },
    rateLimit: {
      description: '不同端点有不同的限流策略',
      examples: {
        register: '每15分钟最多5次请求',
        login: '每15分钟最多10次请求',
        annotations: '每小时最多10个标注',
        likes: '每小时最多100次点赞/取消点赞',
      },
    },
    responseFormat: {
      success: {
        success: true,
        message: 'string',
        data: 'object',
      },
      error: {
        success: false,
        message: 'string',
        error: {
          code: 'string',
          details: 'object',
        },
      },
    },
  });
});

// Log all API requests
router.use((req, _res, next) => {
  logger.info('API请求', {
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    userId: (req as any).user?.id,
  });
  next();
});

export default router;
