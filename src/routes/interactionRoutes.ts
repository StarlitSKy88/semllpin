import { Router } from 'express';
import { body, query, param } from 'express-validator';
import { authMiddleware, optionalAuthMiddleware } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import {
  likeAnnotation,
  unlikeAnnotation,
  favoriteAnnotation,
  unfavoriteAnnotation,
  getInteractionStats,
  getUserLikes,
  getUserFavorites,
  getUserActivityStats,
  getPopularContent,
  LikeType,
  FavoriteType,
} from '../controllers/interactionController';

const router = Router();

// 点赞相关路由
router.post('/like',
  authMiddleware,
  [
    body('targetId')
      .notEmpty()
      .withMessage('目标ID不能为空'),
    body('targetType')
      .isIn(Object.values(LikeType))
      .withMessage('无效的点赞类型'),
  ],
  validateRequest,
  likeAnnotation,
);

router.delete('/like',
  authMiddleware,
  [
    body('targetId')
      .notEmpty()
      .withMessage('目标ID不能为空'),
    body('targetType')
      .isIn(Object.values(LikeType))
      .withMessage('无效的点赞类型'),
  ],
  validateRequest,
  unlikeAnnotation,
);

// 收藏相关路由
router.post('/favorite',
  authMiddleware,
  [
    body('targetId')
      .notEmpty()
      .withMessage('目标ID不能为空'),
    body('targetType')
      .isIn(Object.values(FavoriteType))
      .withMessage('无效的收藏类型'),
  ],
  validateRequest,
  favoriteAnnotation,
);

router.delete('/favorite',
  authMiddleware,
  [
    body('targetId')
      .notEmpty()
      .withMessage('目标ID不能为空'),
    body('targetType')
      .isIn(Object.values(FavoriteType))
      .withMessage('无效的收藏类型'),
  ],
  validateRequest,
  unfavoriteAnnotation,
);

// 获取互动统计
router.get('/stats/:targetType/:targetId',
  optionalAuthMiddleware,
  [
    param('targetId')
      .notEmpty()
      .withMessage('目标ID不能为空'),
    param('targetType')
      .notEmpty()
      .withMessage('目标类型不能为空'),
  ],
  validateRequest,
  getInteractionStats,
);

// 获取用户点赞历史
router.get('/likes',
  authMiddleware,
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1-100之间'),
    query('targetType')
      .optional()
      .isIn(Object.values(LikeType))
      .withMessage('无效的点赞类型'),
  ],
  validateRequest,
  getUserLikes,
);

// 获取用户收藏列表
router.get('/favorites',
  authMiddleware,
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1-100之间'),
    query('targetType')
      .optional()
      .isIn(Object.values(FavoriteType))
      .withMessage('无效的收藏类型'),
  ],
  validateRequest,
  getUserFavorites,
);

// 获取用户活跃度统计
router.get('/activity/stats',
  authMiddleware,
  [
    query('timeRange')
      .optional()
      .isIn(['1d', '7d', '30d', 'all'])
      .withMessage('无效的时间范围'),
  ],
  validateRequest,
  getUserActivityStats,
);

// 获取热门内容
router.get('/popular',
  [
    query('targetType')
      .optional()
      .isIn([...Object.values(LikeType), ...Object.values(FavoriteType)])
      .withMessage('无效的内容类型'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 50 })
      .withMessage('限制数量必须在1-50之间'),
    query('timeRange')
      .optional()
      .isIn(['1d', '7d', '30d', 'all'])
      .withMessage('无效的时间范围'),
  ],
  validateRequest,
  getPopularContent as any,
);

export default router;
