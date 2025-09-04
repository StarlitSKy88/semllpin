import { Request, Response, NextFunction } from 'express';
import { AnnotationModel, CreateAnnotationData, UpdateAnnotationData, AnnotationFilters } from '../models/Annotation';
import {
  AppError,
  createValidationError,
  createAuthError,
  createNotFoundError,
  createForbiddenError,
} from '../middleware/errorHandler';
import { asyncHandler } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import { cacheService } from '../config/redis';
import { db } from '../config/database';
import { config } from '../config/config';
// import { optimizedQueryService } from '../services/optimizedQueryService';
// import { advancedCacheService, CacheConfigs } from '../services/advancedCacheService';

// Get detailed annotation with all related data
export const getAnnotationDetails = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const userId = req.user?.id;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  try {
    // 从数据库获取注释详情
    const annotation = await AnnotationModel.findById(id);
    if (!annotation) {
      throw createNotFoundError('标注不存在');
    }
    const result = { annotation };
    
    logger.info('获取标注详情', {
      annotationId: id,
      userId,
      fromCache: false
    });

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.error('获取标注详情失败', {
      annotationId: id,
      userId,
      error: error instanceof Error ? error.message : String(error)
    });
    if (error instanceof Error && error.message === 'Annotation not found') {
      throw createNotFoundError('标注不存在');
    }
    throw error;
  }
});

// Get pending annotations for moderation
export const getPendingAnnotations = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    page = 1,
    limit = 20,
    sortBy = 'created_at',
    sortOrder = 'desc',
  } = req.query;

  // 获取待审核标注
  const annotations = await AnnotationModel.getList({
    page: Number(page),
    limit: Number(limit),
    sortBy: sortBy as string,
    sortOrder: sortOrder as 'asc' | 'desc',
    filters: { status: 'pending' },
  });

  // 获取总数
  const totalResult = await db('annotations')
    .where('status', 'pending')
    .count('* as count')
    .first();

  const total = Number(totalResult?.['count'] || 0);

  logger.info('获取待审核标注列表', {
    page: Number(page),
    limit: Number(limit),
    total,
  });

  res.json({
    success: true,
    data: {
      annotations,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / Number(limit)),
      },
    },
  });
});

// Batch moderate annotations
export const batchModerateAnnotations = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { annotationIds, action, reason } = req.body;
  const moderatorId = req.user?.id;

  if (!moderatorId) {
    throw createAuthError('管理员未认证');
  }

  if (!annotationIds || !Array.isArray(annotationIds) || annotationIds.length === 0) {
    throw createValidationError('annotationIds', '标注ID列表不能为空');
  }

  if (!['approve', 'reject', 'flag'].includes(action)) {
    throw createValidationError('action', '无效的审核操作');
  }

  const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'flagged';

  // 批量更新标注状态
  const updateData: any = {
    status,
    moderated_by: moderatorId,
    moderated_at: new Date(),
    updated_at: new Date(),
  };

  if (reason) {
    updateData.moderation_reason = reason;
  }

  await db('annotations')
    .whereIn('id', annotationIds)
    .where('status', 'pending')
    .update(updateData);

  // 清除相关缓存
  for (const id of annotationIds) {
    await cacheService.del(`annotation:${id}`);
  }

  logger.info('批量审核标注', {
    moderatorId,
    annotationIds,
    action,
    reason,
  });

  res.json({
    success: true,
    message: `成功${action === 'approve' ? '通过' : action === 'reject' ? '拒绝' : '标记'}${annotationIds.length}个标注`,
    data: {
      processedCount: annotationIds.length,
      action,
      status,
    },
  });
});

// Get moderation statistics
export const getModerationStats = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { timeRange = '7d' } = req.query;

  const dateFilter = new Date();
  switch (timeRange) {
    case '1d':
      dateFilter.setDate(dateFilter.getDate() - 1);
      break;
    case '7d':
      dateFilter.setDate(dateFilter.getDate() - 7);
      break;
    case '30d':
      dateFilter.setDate(dateFilter.getDate() - 30);
      break;
    default:
      dateFilter.setDate(dateFilter.getDate() - 7);
  }

  // 获取各状态的统计
  const stats = await db('annotations')
    .select('status')
    .count('* as count')
    .where('created_at', '>=', dateFilter)
    .groupBy('status');

  // 获取付费标注统计
  const paidStats = await db('annotations')
    .join('payments', 'annotations.id', 'payments.annotation_id')
    .select('payments.status as payment_status')
    .count('* as count')
    .where('annotations.created_at', '>=', dateFilter)
    .groupBy('payments.status');

  // 获取审核员活动统计
  const moderatorStats = await db('annotations')
    .select('moderated_by')
    .count('* as count')
    .whereNotNull('moderated_by')
    .where('moderated_at', '>=', dateFilter)
    .groupBy('moderated_by');

  const result = {
    timeRange,
    annotationStats: stats.reduce((acc: any, stat: any) => {
      acc[stat.status] = Number(stat.count);
      return acc;
    }, {}),
    paymentStats: paidStats.reduce((acc: any, stat: any) => {
      acc[stat.payment_status] = Number(stat.count);
      return acc;
    }, {}),
    moderatorActivity: moderatorStats.map((stat: any) => ({
      moderatorId: stat.moderated_by,
      count: Number(stat.count),
    })),
  };

  logger.info('获取审核统计', { timeRange });

  res.json({
    success: true,
    data: result,
  });
});

// Handle successful payment and create annotation
export const handlePaidAnnotationSuccess = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { sessionId } = req.body;

  if (!sessionId) {
    throw createValidationError('sessionId', '支付会话ID不能为空');
  }

  // 获取 PayPal 订单信息
  const paymentRecord = await db('payments')
    .where('payment_intent_id', sessionId)
    .first();

  if (!paymentRecord || paymentRecord.status !== 'completed') {
    throw createValidationError('payment', '支付未完成');
  }

  // 从支付记录中获取标注信息
  const metadata = paymentRecord.metadata || {};
  if (!metadata.annotationData) {
    throw createValidationError('session', '无效的支付订单');
  }

  const annotationData: CreateAnnotationData = {
    user_id: paymentRecord.user_id,
    latitude: metadata.annotationData.latitude,
    longitude: metadata.annotationData.longitude,
    smell_intensity: metadata.annotationData.smellIntensity,
    description: metadata.annotationData.description || '',
    media_files: metadata.annotationData.mediaFiles || [],
  };

  // 创建标注
  const annotation = await AnnotationModel.create(annotationData);

  // 更新支付记录
  await db('payments')
    .where('payment_intent_id', sessionId)
    .update({
      annotation_id: annotation.id,
      status: 'completed',
      processed_at: new Date(),
      updated_at: new Date(),
    });

  // 缓存标注
  await cacheService.set(
    `annotation:${annotation.id}`,
    JSON.stringify(annotation),
    3600,
  );

  logger.info('付费恶搞标注创建成功', {
    annotationId: annotation.id,
    userId: paymentRecord.user_id,
    sessionId,
    amount: paymentRecord.amount,
  });

  res.status(201).json({
    success: true,
    message: '付费恶搞标注创建成功',
    data: {
      annotation: {
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        status: annotation.status,
        isPaid: true,
        mediaFiles: annotation.media_files,
        createdAt: annotation.created_at,
      },
      payment: {
        sessionId,
        amount: paymentRecord.amount,
        currency: paymentRecord.currency.toLowerCase(),
      },
    },
  });
});

// Create paid prank annotation
export const createPaidPrankAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const {
    latitude,
    longitude,
    smellIntensity,
    description,
    mediaFiles,
    amount,
    currency = 'usd',
    paymentDescription,
  } = req.body;

  // 验证支付金额
  if (!amount || amount < 1 || amount > 100) {
    throw createValidationError('amount', '支付金额必须在 $1-$100 之间');
  }

  // 创建 PayPal 支付订单
  const paypalPaymentController = require('./paypalPaymentController');
  const orderData = {
    intent: 'CAPTURE',
    purchase_units: [{
      amount: {
        currency_code: currency.toUpperCase(),
        value: amount.toString(),
      },
      description: paymentDescription || `创建恶搞标注 - 臭味强度: ${smellIntensity}`,
      custom_id: JSON.stringify({
        userId,
        latitude,
        longitude,
        smellIntensity,
        description,
        mediaFiles,
        type: 'prank_annotation',
      }),
    }],
    application_context: {
      return_url: `${process.env['FRONTEND_URL'] || 'http://localhost:5176'}/prank-success`,
      cancel_url: `${process.env['FRONTEND_URL'] || 'http://localhost:5176'}/map`,
    },
  };
  
  const order = await paypalPaymentController.createOrder(orderData);

  // 记录支付会话到数据库
  const dbClient = process.env['DB_CLIENT'] || 'sqlite3';

  if (dbClient === 'postgresql') {
    await db('payments').insert({
      user_id: userId,
      amount,
      currency: currency.toUpperCase(),
      payment_method: 'paypal',
      payment_intent_id: order.id,
      status: 'pending',
      description: paymentDescription || `恶搞标注创建 - 臭味强度: ${smellIntensity}`,
      metadata: {
        orderId: order.id,
        annotationData: {
          latitude,
          longitude,
          smellIntensity,
          description,
          mediaFiles,
        },
      },
      created_at: new Date(),
      updated_at: new Date(),
    });
  } else {
    // SQLite compatible
    await db('payments').insert({
      id: require('uuid').v4(),
      user_id: userId,
      amount,
      currency: currency.toUpperCase(),
      payment_method: 'paypal',
      payment_intent_id: order.id,
      status: 'pending',
      description: paymentDescription || `恶搞标注创建 - 臭味强度: ${smellIntensity}`,
      created_at: new Date(),
      updated_at: new Date(),
    });
  }

  logger.info('付费恶搞标注支付订单创建成功', {
    orderId: order.id,
    userId,
    amount,
    currency,
  });

  res.status(201).json({
    success: true,
    message: '支付订单创建成功',
    data: {
      orderId: order.id,
      paymentUrl: order.links.find((link: any) => link.rel === 'approve')?.href,
      amount,
      currency,
    },
  });
});

// Create new annotation
export const createAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const { latitude, longitude, smellIntensity, description, mediaFiles } = req.body;

  const annotationData: CreateAnnotationData = {
    user_id: userId,
    latitude,
    longitude,
    smell_intensity: smellIntensity,
    description,
    media_files: mediaFiles,
  };

  const annotation = await AnnotationModel.create(annotationData);

  // Cache the new annotation
  await cacheService.set(
    `annotation:${annotation.id}`,
    JSON.stringify(annotation),
    3600, // 1 hour
  );

  logger.info('标注创建成功', {
    annotationId: annotation.id,
    userId,
    intensity: annotation.smell_intensity,
  });

  res.status(201).json({
    success: true,
    message: '标注创建成功',
    data: {
      annotation: {
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        status: annotation.status,
        mediaFiles: annotation.media_files,
        createdAt: annotation.created_at,
      },
    },
  });
});

// Get annotation by ID
export const getAnnotationById = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  // Try to get from cache first
  const cached = await cacheService.get(`annotation:${id}`);
  if (cached) {
    try {
      const annotation = JSON.parse(cached);

      // Increment view count asynchronously
      AnnotationModel.incrementViewCount(id).catch((error: any) => {
        logger.error('增加浏览次数失败', { annotationId: id, error });
      });

      res.json({
        success: true,
        data: { annotation },
      });
      return;
    } catch (parseError) {
      logger.error('缓存数据解析失败', { annotationId: id, cached, error: parseError });
      // Clear invalid cache and continue to fetch from database
      await cacheService.del(`annotation:${id}`);
    }
  }

  const annotation = await AnnotationModel.findById(id);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Cache the annotation
  await cacheService.set(
    `annotation:${id}`,
    JSON.stringify(annotation),
    3600, // 1 hour
  );

  // Increment view count asynchronously
  AnnotationModel.incrementViewCount(id).catch((error: any) => {
    logger.error('增加浏览次数失败', { annotationId: id, error });
  });

  res.json({
    success: true,
    data: {
      annotation: {
        id: annotation.id,
        userId: annotation.user_id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        country: annotation.country,
        region: annotation.region,
        city: annotation.city,
        status: annotation.status,
        mediaFiles: annotation.media_files,
        viewCount: annotation.view_count,
        likeCount: annotation.like_count,
        commentCount: annotation.comment_count,
        createdAt: annotation.created_at,
        updatedAt: annotation.updated_at,
      },
    },
  });
});

// Update annotation
export const updateAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const userId = req.user?.id;
  const userRole = req.user?.role;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const annotation = await AnnotationModel.findById(id);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Check ownership or admin/moderator role
  if (annotation.user_id !== userId && userRole !== 'admin' && userRole !== 'moderator') {
    throw createForbiddenError('只能修改自己的标注');
  }

  const { smellIntensity, description } = req.body;

  const updateData: UpdateAnnotationData = {};

  if (smellIntensity !== undefined) {
    updateData.smell_intensity = smellIntensity;
  }

  if (description !== undefined) {
    updateData.description = description;
  }

  const updatedAnnotation = await AnnotationModel.update(id, updateData);
  if (!updatedAnnotation) {
    throw createNotFoundError('标注不存在');
  }

  // Clear cache
  await cacheService.del(`annotation:${id}`);

  logger.info('标注更新成功', { annotationId: id, userId });

  res.json({
    success: true,
    message: '标注更新成功',
    data: {
      annotation: {
        id: updatedAnnotation.id,
        latitude: updatedAnnotation.latitude,
        longitude: updatedAnnotation.longitude,
        smellIntensity: updatedAnnotation.smell_intensity,
        description: updatedAnnotation.description,
        status: updatedAnnotation.status,
        mediaFiles: updatedAnnotation.media_files,
        updatedAt: updatedAnnotation.updated_at,
      },
    },
  });
});

// Get annotations list
export const getAnnotationsList = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    page = 1,
    limit = 20,
    sortBy = 'created_at',
    sortOrder = 'desc',
    latitude,
    longitude,
    radius = 1000,
    intensityMin,
    intensityMax,
    country,
    region,
    city,
    startDate,
    endDate,
  } = req.query;

  const filters: AnnotationFilters = {};

  if (latitude && longitude) {
    filters.latitude = parseFloat(latitude as string);
    filters.longitude = parseFloat(longitude as string);
    filters.radius = parseInt(radius as string, 10);
  }

  if (intensityMin) {
    filters.intensityMin = parseInt(intensityMin as string, 10);
  }

  if (intensityMax) {
    filters.intensityMax = parseInt(intensityMax as string, 10);
  }

  if (country) {
    filters.country = country as string;
  }

  if (region) {
    filters.region = region as string;
  }

  if (city) {
    filters.city = city as string;
  }

  if (startDate) {
    filters.startDate = new Date(startDate as string);
  }

  if (endDate) {
    filters.endDate = new Date(endDate as string);
  }

  const { annotations, total } = await AnnotationModel.getList({
    page: parseInt(page as string, 10),
    limit: parseInt(limit as string, 10),
    sortBy: sortBy as string,
    sortOrder: sortOrder as 'asc' | 'desc',
    filters,
  });

  res.json({
    success: true,
    data: {
      annotations: annotations.map(annotation => ({
        id: annotation.id,
        userId: annotation.user_id,
        username: (annotation as any).username,
        displayName: (annotation as any).display_name,
        avatarUrl: (annotation as any).avatar_url,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        country: annotation.country,
        region: annotation.region,
        city: annotation.city,
        status: annotation.status,
        mediaFiles: annotation.media_files,
        viewCount: annotation.view_count,
        likeCount: annotation.like_count,
        commentCount: annotation.comment_count,
        createdAt: annotation.created_at,
      })),
      pagination: {
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        total,
        pages: Math.ceil(total / parseInt(limit as string, 10)),
      },
    },
  });
});

// Get map data
export const getMapData = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    north,
    south,
    east,
    west,
    zoom = 10,
    intensityMin,
    intensityMax,
  } = req.query;

  if (!north || !south || !east || !west) {
    throw createValidationError('bounds', '地图边界参数缺失');
  }

  const bounds = {
    north: parseFloat(north as string),
    south: parseFloat(south as string),
    east: parseFloat(east as string),
    west: parseFloat(west as string),
  };

  const options: any = {
    zoom: parseInt(zoom as string, 10),
  };

  if (intensityMin) {
    options.intensityMin = parseInt(intensityMin as string, 10);
  }

  if (intensityMax) {
    options.intensityMax = parseInt(intensityMax as string, 10);
  }

  // Create cache key based on bounds and options
  const cacheKey = `map_data:${JSON.stringify({ bounds, options })}`;

  // Try to get from cache first
  const cached = await cacheService.get(cacheKey);
  if (cached) {
    try {
      const cachedData = JSON.parse(cached);
      res.json({
        success: true,
        data: {
          annotations: cachedData,
        },
      });
      return;
    } catch (parseError) {
      logger.warn('缓存数据解析失败，将重新获取数据', { cacheKey, error: parseError });
      // 清除无效缓存
      await cacheService.del(cacheKey);
    }
  }

  const annotations = await AnnotationModel.getMapData(bounds, options);

  // Cache the result for 5 minutes
  await cacheService.set(cacheKey, JSON.stringify(annotations), 300);

  res.json({
    success: true,
    data: {
      annotations: annotations.map(annotation => ({
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        createdAt: annotation.created_at,
      })),
    },
  });
});

// Get nearby annotations
export const getNearbyAnnotations = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    latitude,
    longitude,
    radius = 1000,
    limit = 10,
  } = req.query;

  if (!latitude || !longitude) {
    throw createValidationError('coordinates', '经纬度参数缺失');
  }

  const annotations = await AnnotationModel.getNearby(
    parseFloat(latitude as string),
    parseFloat(longitude as string),
    parseInt(radius as string, 10),
    parseInt(limit as string, 10),
  );

  res.json({
    success: true,
    data: {
      annotations: annotations.map(annotation => ({
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        distance: (annotation as any).distance,
        createdAt: annotation.created_at,
      })),
    },
  });
});

// Like annotation
export const likeAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const userId = req.user?.id;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  // Check if annotation exists
  const annotation = await AnnotationModel.findById(id);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Check if user already liked this annotation
  const likeKey = `like:${userId}:${id}`;
  const alreadyLiked = await cacheService.get(likeKey);

  if (alreadyLiked) {
    throw createValidationError('like', '已经点赞过了');
  }

  // Increment like count
  await AnnotationModel.incrementLikeCount(id);

  // Mark as liked
  await cacheService.set(likeKey, 'true', 24 * 3600); // 24 hours

  // Clear annotation cache
  await cacheService.del(`annotation:${id}`);

  logger.info('标注点赞成功', { annotationId: id, userId });

  res.json({
    success: true,
    message: '点赞成功',
  });
});

// Unlike annotation
export const unlikeAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const userId = req.user?.id;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  // Check if annotation exists
  const annotation = await AnnotationModel.findById(id);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Check if user liked this annotation
  const likeKey = `like:${userId}:${id}`;
  const alreadyLiked = await cacheService.get(likeKey);

  if (!alreadyLiked) {
    throw createValidationError('like', '还没有点赞');
  }

  // Decrement like count
  await AnnotationModel.decrementLikeCount(id);

  // Remove like mark
  await cacheService.del(likeKey);

  // Clear annotation cache
  await cacheService.del(`annotation:${id}`);

  logger.info('标注取消点赞成功', { annotationId: id, userId });

  res.json({
    success: true,
    message: '取消点赞成功',
  });
});

// Get user's annotations
export const getUserAnnotations = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const {
    page = 1,
    limit = 20,
    status,
  } = req.query;

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const options: any = {
    page: parseInt(page as string, 10),
    limit: parseInt(limit as string, 10),
  };

  if (status) {
    options.status = status as string;
  }

  const { annotations, total } = await AnnotationModel.getUserAnnotations(userId, options);

  res.json({
    success: true,
    data: {
      annotations: annotations.map(annotation => ({
        id: annotation.id,
        latitude: annotation.latitude,
        longitude: annotation.longitude,
        smellIntensity: annotation.smell_intensity,
        description: annotation.description,
        status: annotation.status,
        mediaFiles: annotation.media_files,
        viewCount: annotation.view_count,
        likeCount: annotation.like_count,
        commentCount: annotation.comment_count,
        createdAt: annotation.created_at,
        updatedAt: annotation.updated_at,
      })),
      pagination: {
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        total,
        pages: Math.ceil(total / parseInt(limit as string, 10)),
      },
    },
  });
});

// Get annotation statistics
export const getAnnotationStats = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    userId,
    startDate,
    endDate,
  } = req.query;

  const filters: AnnotationFilters = {};

  if (userId) {
    filters.userId = userId as string;
  }

  if (startDate) {
    filters.startDate = new Date(startDate as string);
  }

  if (endDate) {
    filters.endDate = new Date(endDate as string);
  }

  // Create cache key
  const cacheKey = `stats:annotations:${JSON.stringify(filters)}`;

  // Try to get from cache first
  const cached = await cacheService.get(cacheKey);
  if (cached) {
    res.json({
      success: true,
      data: JSON.parse(cached),
    });
    return;
  }

  const stats = await AnnotationModel.getStats(filters);

  // Cache the result for 10 minutes
  await cacheService.set(cacheKey, JSON.stringify(stats), 600);

  res.json({
    success: true,
    data: stats,
  });
});

// Delete annotation
export const deleteAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const userId = req.user?.id;
  const userRole = req.user?.role;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const annotation = await AnnotationModel.findById(id);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Check ownership or admin/moderator role
  if (annotation.user_id !== userId && userRole !== 'admin' && userRole !== 'moderator') {
    throw createForbiddenError('只能删除自己的标注');
  }

  const success = await AnnotationModel.delete(id);
  if (!success) {
    throw new AppError('标注删除失败', 500);
  }

  // Clear cache
  await cacheService.del(`annotation:${id}`);

  logger.info('标注删除成功', { annotationId: id, userId });

  res.json({
    success: true,
    message: '标注删除成功',
  });
});

// Admin: Moderate annotation
export const moderateAnnotation = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const { status, reason } = req.body;
  const moderatorId = req.user?.id;

  if (!id) {
    throw createValidationError('id', '标注ID不能为空');
  }

  if (!moderatorId) {
    throw createAuthError('用户未认证');
  }

  const annotation = await AnnotationModel.moderate(id, status, moderatorId, reason);
  if (!annotation) {
    throw createNotFoundError('标注不存在');
  }

  // Clear cache
  await cacheService.del(`annotation:${id}`);

  logger.info('标注审核完成', {
    annotationId: id,
    moderatorId,
    status,
    reason,
  });

  res.json({
    success: true,
    message: '标注审核完成',
    data: {
      annotation: {
        id: annotation.id,
        status: annotation.status,
        moderationReason: annotation.moderation_reason,
        moderatedBy: annotation.moderated_by,
        moderatedAt: annotation.moderated_at,
      },
    },
  });
});

export default {
  createAnnotation,
  createPaidPrankAnnotation,
  handlePaidAnnotationSuccess,
  getAnnotationDetails,
  getPendingAnnotations,
  batchModerateAnnotations,
  getModerationStats,
  getAnnotationById,
  updateAnnotation,
  getAnnotationsList,
  getMapData,
  getNearbyAnnotations,
  likeAnnotation,
  unlikeAnnotation,
  getUserAnnotations,
  getAnnotationStats,
  deleteAnnotation,
  moderateAnnotation,
};
