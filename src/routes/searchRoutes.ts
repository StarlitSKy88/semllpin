import express, { Request, Response } from 'express';
import { body, query } from 'express-validator';
import { authMiddleware } from '@/middleware/auth';
import { validationResult } from 'express-validator';

// 验证错误处理中间件
const handleValidationErrors = (req: Request, res: Response, next: Function) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  return next();
};
import searchController from '@/controllers/searchController';
import db from '@/config/database';

const router = express.Router();

// Search annotations by location
router.get('/location',
  [
    query('latitude')
      .optional()
      .isFloat({ min: -90, max: 90 })
      .withMessage('纬度必须在-90到90之间'),
    query('longitude')
      .optional()
      .isFloat({ min: -180, max: 180 })
      .withMessage('经度必须在-180到180之间'),
    query('lat')
      .optional()
      .isFloat({ min: -90, max: 90 })
      .withMessage('纬度必须在-90到90之间'),
    query('lng')
      .optional()
      .isFloat({ min: -180, max: 180 })
      .withMessage('经度必须在-180到180之间'),
    query('radius')
      .optional()
      .isInt({ min: 100, max: 50000 })
      .withMessage('搜索半径必须在100到50000米之间'),
    query('smellIntensity.min')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最小臭味等级必须在1到10之间'),
    query('smellIntensity.max')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最大臭味等级必须在1到10之间'),
    query('category')
      .optional()
      .isLength({ min: 1, max: 50 })
      .withMessage('类别名称长度必须在1到50个字符之间'),
    query('keyword')
      .optional()
      .isLength({ min: 1, max: 100 })
      .withMessage('关键词长度必须在1到100个字符之间'),
    query('sortBy')
      .optional()
      .isIn(['distance', 'smell_intensity', 'created_at', 'popularity'])
      .withMessage('排序字段必须是distance、smell_intensity、created_at或popularity'),
    query('sortOrder')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('排序方向必须是asc或desc'),
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1到100之间'),
  ],
  (req: any, res: any, next: any) => {
    // Custom validation: ensure at least one set of coordinates is provided
    const hasLatLng = req.query.lat && req.query.lng;
    const hasLatitudeLongitude = req.query.latitude && req.query.longitude;

    if (!hasLatLng && !hasLatitudeLongitude) {
      return res.status(400).json({
        code: 400,
        message: '必须提供坐标参数：lat/lng 或 latitude/longitude',
        data: null,
      });
    }

    next();
  },
  handleValidationErrors,
  searchController.searchAnnotationsByLocation as any,
);

// Search annotations by content
router.get('/content',
  [
    query('keyword')
      .isLength({ min: 1, max: 100 })
      .withMessage('搜索关键词长度必须在1到100个字符之间'),
    query('category')
      .optional()
      .isLength({ min: 1, max: 50 })
      .withMessage('类别名称长度必须在1到50个字符之间'),
    query('smellIntensity.min')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最小臭味等级必须在1到10之间'),
    query('smellIntensity.max')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最大臭味等级必须在1到10之间'),
    query('sortBy')
      .optional()
      .isIn(['relevance', 'smell_intensity', 'created_at', 'popularity'])
      .withMessage('排序字段必须是relevance、smell_intensity、created_at或popularity'),
    query('sortOrder')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('排序方向必须是asc或desc'),
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1到100之间'),
  ],
  handleValidationErrors,
  searchController.searchAnnotationsByContent as any,
);

// Get popular search terms
router.get('/popular-terms',
  searchController.getPopularSearchTerms,
);

// Advanced search
router.post('/advanced',
  authMiddleware, // Require authentication for advanced search
  [
    body('latitude')
      .optional()
      .isFloat({ min: -90, max: 90 })
      .withMessage('纬度必须在-90到90之间'),
    body('longitude')
      .optional()
      .isFloat({ min: -180, max: 180 })
      .withMessage('经度必须在-180到180之间'),
    body('radius')
      .optional()
      .isInt({ min: 100, max: 50000 })
      .withMessage('搜索半径必须在100到50000米之间'),
    body('keyword')
      .optional()
      .isLength({ min: 1, max: 100 })
      .withMessage('关键词长度必须在1到100个字符之间'),
    body('category')
      .optional()
      .isLength({ min: 1, max: 50 })
      .withMessage('类别名称长度必须在1到50个字符之间'),
    body('smellIntensity.min')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最小臭味等级必须在1到10之间'),
    body('smellIntensity.max')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('最大臭味等级必须在1到10之间'),
    body('dateRange.start')
      .optional()
      .isISO8601()
      .withMessage('开始日期格式不正确'),
    body('dateRange.end')
      .optional()
      .isISO8601()
      .withMessage('结束日期格式不正确'),
    body('hasMedia')
      .optional()
      .isBoolean()
      .withMessage('媒体过滤器必须为布尔值'),
    body('sortBy')
      .optional()
      .isIn(['distance', 'smell_intensity', 'created_at', 'popularity'])
      .withMessage('排序字段必须是distance、smell_intensity、created_at或popularity'),
    body('sortOrder')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('排序方向必须是asc或desc'),
    body('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    body('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1到100之间'),
  ],
  handleValidationErrors,
  searchController.advancedSearch,
);

// Search suggestions endpoint
router.get('/suggestions',
  [
    query('q')
      .isLength({ min: 1, max: 50 })
      .withMessage('搜索查询长度必须在1到50个字符之间'),
    query('type')
      .optional()
      .isIn(['location', 'category', 'user'])
      .withMessage('建议类型必须是location、category或user'),
  ],
  handleValidationErrors,
  (async (req: Request, res: Response) => {
    // Search suggestions implementation
    const { q, type = 'all' } = req.query;

    try {
      const suggestions: any = {};

      if (type === 'all' || type === 'location') {
        suggestions.locations = await db('annotations')
          .select('location_name')
          .distinct()
          .where('location_name', 'like', `%${q}%`)
          .whereNotNull('location_name')
          .limit(5);
      }

      if (type === 'all' || type === 'category') {
        suggestions.categories = await db('annotations')
          .select('category')
          .distinct()
          .where('category', 'like', `%${q}%`)
          .whereNotNull('category')
          .limit(5);
      }

      if (type === 'all' || type === 'user') {
        suggestions.users = await db('users')
          .select('username', 'display_name')
          .where(function (this: any) {
            this.where('username', 'like', `%${q}%`)
              .orWhere('display_name', 'like', `%${q}%`);
          })
          .where('status', 'active')
          .limit(5);
      }

      res.json({
        success: true,
        message: '搜索建议获取成功',
        data: suggestions,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: '搜索建议获取失败',
        error: error.message,
      });
    }
  }) as any,
);

// Search history endpoint (for authenticated users)
router.get('/history',
  authMiddleware,
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须为正整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 50 })
      .withMessage('每页数量必须在1到50之间'),
  ],
  handleValidationErrors,
  (async (req: Request, res: Response) => {
    // Search history implementation
    const userId = req.user?.id;
    const { page = 1, limit = 20 } = req.query;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: '用户未认证',
      });
      return;
    }

    try {
      // This would require a search_history table in a real implementation
      // For now, return empty results
      res.json({
        success: true,
        message: '搜索历史获取成功',
        data: {
          history: [],
          pagination: {
            page: parseInt(page as string),
            limit: parseInt(limit as string),
            total: 0,
            totalPages: 0,
          },
        },
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: '搜索历史获取失败',
        error: error.message,
      });
    }
  }) as any,
);

export default router;
