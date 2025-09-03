import { Router } from 'express';
import annotationController from '@/controllers/annotationController';
import { body } from 'express-validator';
import { authMiddleware, requireModerator, optionalAuthMiddleware } from '@/middleware/auth';
import { validateRequest, annotationSchemas, adminSchemas } from '@/middleware/validation';

const router = Router();

// Public routes
router.get('/list',
  optionalAuthMiddleware,
  validateRequest(annotationSchemas.getList),
  annotationController.getAnnotationsList,
);

router.get('/map',
  optionalAuthMiddleware,
  validateRequest(annotationSchemas.getMapData),
  annotationController.getMapData,
);

router.get('/nearby',
  optionalAuthMiddleware,
  annotationController.getNearbyAnnotations,
);

router.get('/stats',
  optionalAuthMiddleware,
  annotationController.getAnnotationStats,
);

router.get('/:id/details',
  optionalAuthMiddleware,
  annotationController.getAnnotationDetails as any,
);

router.get('/:id',
  optionalAuthMiddleware,
  validateRequest(annotationSchemas.getById),
  annotationController.getAnnotationById,
);

// Protected routes
router.use(authMiddleware);

router.post('/',
  validateRequest(annotationSchemas.create),
  annotationController.createAnnotation,
);

// 付费恶搞标注
router.post('/paid-prank',
  body('latitude').isFloat({ min: -90, max: 90 }).withMessage('纬度必须在-90到90之间'),
  body('longitude').isFloat({ min: -180, max: 180 }).withMessage('经度必须在-180到180之间'),
  body('smellIntensity').isInt({ min: 1, max: 10 }).withMessage('臭味强度必须在1-10之间'),
  body('description').optional().isLength({ max: 500 }).withMessage('描述不能超过500字符'),
  body('amount').isFloat({ min: 1, max: 100 }).withMessage('支付金额必须在$1-$100之间'),
  body('currency').optional().isIn(['usd', 'eur', 'gbp', 'cny']).withMessage('不支持的货币类型'),
  body('mediaFiles').optional().isArray().withMessage('媒体文件必须是数组'),
  body('paymentDescription').optional().isLength({ max: 200 }).withMessage('支付描述不能超过200字符'),
  validateRequest,
  annotationController.createPaidPrankAnnotation as any,
);

// 处理支付成功后创建标注
router.post('/paid-success',
  body('sessionId').notEmpty().withMessage('支付会话ID不能为空'),
  validateRequest,
  annotationController.handlePaidAnnotationSuccess as any,
);

router.put('/:id',
  validateRequest(annotationSchemas.update),
  annotationController.updateAnnotation,
);

router.delete('/:id',
  annotationController.deleteAnnotation,
);

router.post('/:id/like',
  annotationController.likeAnnotation,
);

router.delete('/:id/like',
  annotationController.unlikeAnnotation,
);

router.get('/user/me',
  annotationController.getUserAnnotations,
);

// Admin routes
router.put('/:id/moderate',
  requireModerator,
  validateRequest(adminSchemas.moderateAnnotation),
  annotationController.moderateAnnotation,
);

// 获取待审核标注列表
router.get('/pending',
  requireModerator,
  annotationController.getPendingAnnotations as any,
);

// 批量审核标注
router.post('/batch-moderate',
  requireModerator,
  body('annotationIds').isArray().withMessage('标注ID列表必须是数组'),
  body('action').isIn(['approve', 'reject', 'flag']).withMessage('无效的审核操作'),
  body('reason').optional().isLength({ max: 500 }).withMessage('审核原因不能超过500字符'),
  validateRequest,
  annotationController.batchModerateAnnotations as any,
);

// 获取审核统计
router.get('/moderation-stats',
  requireModerator,
  annotationController.getModerationStats as any,
);

export default router;
