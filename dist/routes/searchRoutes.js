"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const express_validator_1 = require("express-validator");
const auth_1 = require("@/middleware/auth");
const express_validator_2 = require("express-validator");
const handleValidationErrors = (req, res, next) => {
    const errors = (0, express_validator_2.validationResult)(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }
    return next();
};
const searchController_1 = __importDefault(require("@/controllers/searchController"));
const database_1 = __importDefault(require("@/config/database"));
const router = express_1.default.Router();
router.get('/location', [
    (0, express_validator_1.query)('latitude')
        .optional()
        .isFloat({ min: -90, max: 90 })
        .withMessage('纬度必须在-90到90之间'),
    (0, express_validator_1.query)('longitude')
        .optional()
        .isFloat({ min: -180, max: 180 })
        .withMessage('经度必须在-180到180之间'),
    (0, express_validator_1.query)('lat')
        .optional()
        .isFloat({ min: -90, max: 90 })
        .withMessage('纬度必须在-90到90之间'),
    (0, express_validator_1.query)('lng')
        .optional()
        .isFloat({ min: -180, max: 180 })
        .withMessage('经度必须在-180到180之间'),
    (0, express_validator_1.query)('radius')
        .optional()
        .isInt({ min: 100, max: 50000 })
        .withMessage('搜索半径必须在100到50000米之间'),
    (0, express_validator_1.query)('smellIntensity.min')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最小臭味等级必须在1到10之间'),
    (0, express_validator_1.query)('smellIntensity.max')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最大臭味等级必须在1到10之间'),
    (0, express_validator_1.query)('category')
        .optional()
        .isLength({ min: 1, max: 50 })
        .withMessage('类别名称长度必须在1到50个字符之间'),
    (0, express_validator_1.query)('keyword')
        .optional()
        .isLength({ min: 1, max: 100 })
        .withMessage('关键词长度必须在1到100个字符之间'),
    (0, express_validator_1.query)('sortBy')
        .optional()
        .isIn(['distance', 'smell_intensity', 'created_at', 'popularity'])
        .withMessage('排序字段必须是distance、smell_intensity、created_at或popularity'),
    (0, express_validator_1.query)('sortOrder')
        .optional()
        .isIn(['asc', 'desc'])
        .withMessage('排序方向必须是asc或desc'),
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1到100之间'),
], (req, res, next) => {
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
}, handleValidationErrors, searchController_1.default.searchAnnotationsByLocation);
router.get('/content', [
    (0, express_validator_1.query)('keyword')
        .isLength({ min: 1, max: 100 })
        .withMessage('搜索关键词长度必须在1到100个字符之间'),
    (0, express_validator_1.query)('category')
        .optional()
        .isLength({ min: 1, max: 50 })
        .withMessage('类别名称长度必须在1到50个字符之间'),
    (0, express_validator_1.query)('smellIntensity.min')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最小臭味等级必须在1到10之间'),
    (0, express_validator_1.query)('smellIntensity.max')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最大臭味等级必须在1到10之间'),
    (0, express_validator_1.query)('sortBy')
        .optional()
        .isIn(['relevance', 'smell_intensity', 'created_at', 'popularity'])
        .withMessage('排序字段必须是relevance、smell_intensity、created_at或popularity'),
    (0, express_validator_1.query)('sortOrder')
        .optional()
        .isIn(['asc', 'desc'])
        .withMessage('排序方向必须是asc或desc'),
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1到100之间'),
], handleValidationErrors, searchController_1.default.searchAnnotationsByContent);
router.get('/popular-terms', searchController_1.default.getPopularSearchTerms);
router.post('/advanced', auth_1.authMiddleware, [
    (0, express_validator_1.body)('latitude')
        .optional()
        .isFloat({ min: -90, max: 90 })
        .withMessage('纬度必须在-90到90之间'),
    (0, express_validator_1.body)('longitude')
        .optional()
        .isFloat({ min: -180, max: 180 })
        .withMessage('经度必须在-180到180之间'),
    (0, express_validator_1.body)('radius')
        .optional()
        .isInt({ min: 100, max: 50000 })
        .withMessage('搜索半径必须在100到50000米之间'),
    (0, express_validator_1.body)('keyword')
        .optional()
        .isLength({ min: 1, max: 100 })
        .withMessage('关键词长度必须在1到100个字符之间'),
    (0, express_validator_1.body)('category')
        .optional()
        .isLength({ min: 1, max: 50 })
        .withMessage('类别名称长度必须在1到50个字符之间'),
    (0, express_validator_1.body)('smellIntensity.min')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最小臭味等级必须在1到10之间'),
    (0, express_validator_1.body)('smellIntensity.max')
        .optional()
        .isInt({ min: 1, max: 10 })
        .withMessage('最大臭味等级必须在1到10之间'),
    (0, express_validator_1.body)('dateRange.start')
        .optional()
        .isISO8601()
        .withMessage('开始日期格式不正确'),
    (0, express_validator_1.body)('dateRange.end')
        .optional()
        .isISO8601()
        .withMessage('结束日期格式不正确'),
    (0, express_validator_1.body)('hasMedia')
        .optional()
        .isBoolean()
        .withMessage('媒体过滤器必须为布尔值'),
    (0, express_validator_1.body)('sortBy')
        .optional()
        .isIn(['distance', 'smell_intensity', 'created_at', 'popularity'])
        .withMessage('排序字段必须是distance、smell_intensity、created_at或popularity'),
    (0, express_validator_1.body)('sortOrder')
        .optional()
        .isIn(['asc', 'desc'])
        .withMessage('排序方向必须是asc或desc'),
    (0, express_validator_1.body)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.body)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1到100之间'),
], handleValidationErrors, searchController_1.default.advancedSearch);
router.get('/suggestions', [
    (0, express_validator_1.query)('q')
        .isLength({ min: 1, max: 50 })
        .withMessage('搜索查询长度必须在1到50个字符之间'),
    (0, express_validator_1.query)('type')
        .optional()
        .isIn(['location', 'category', 'user'])
        .withMessage('建议类型必须是location、category或user'),
], handleValidationErrors, (async (req, res) => {
    const { q, type = 'all' } = req.query;
    try {
        const suggestions = {};
        if (type === 'all' || type === 'location') {
            suggestions.locations = await (0, database_1.default)('annotations')
                .select('location_name')
                .distinct()
                .where('location_name', 'like', `%${q}%`)
                .whereNotNull('location_name')
                .limit(5);
        }
        if (type === 'all' || type === 'category') {
            suggestions.categories = await (0, database_1.default)('annotations')
                .select('category')
                .distinct()
                .where('category', 'like', `%${q}%`)
                .whereNotNull('category')
                .limit(5);
        }
        if (type === 'all' || type === 'user') {
            suggestions.users = await (0, database_1.default)('users')
                .select('username', 'display_name')
                .where(function () {
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
    }
    catch (error) {
        res.status(500).json({
            success: false,
            message: '搜索建议获取失败',
            error: error.message,
        });
    }
}));
router.get('/history', auth_1.authMiddleware, [
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 50 })
        .withMessage('每页数量必须在1到50之间'),
], handleValidationErrors, (async (req, res) => {
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
        res.json({
            success: true,
            message: '搜索历史获取成功',
            data: {
                history: [],
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: 0,
                    totalPages: 0,
                },
            },
        });
    }
    catch (error) {
        res.status(500).json({
            success: false,
            message: '搜索历史获取失败',
            error: error.message,
        });
    }
}));
exports.default = router;
//# sourceMappingURL=searchRoutes.js.map