"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const auth_1 = require("../middleware/auth");
const validation_1 = require("../middleware/validation");
const interactionController_1 = require("../controllers/interactionController");
const router = (0, express_1.Router)();
router.post('/like', auth_1.authMiddleware, [
    (0, express_validator_1.body)('targetId')
        .notEmpty()
        .withMessage('目标ID不能为空'),
    (0, express_validator_1.body)('targetType')
        .isIn(Object.values(interactionController_1.LikeType))
        .withMessage('无效的点赞类型'),
], validation_1.validateRequest, interactionController_1.likeAnnotation);
router.delete('/like', auth_1.authMiddleware, [
    (0, express_validator_1.body)('targetId')
        .notEmpty()
        .withMessage('目标ID不能为空'),
    (0, express_validator_1.body)('targetType')
        .isIn(Object.values(interactionController_1.LikeType))
        .withMessage('无效的点赞类型'),
], validation_1.validateRequest, interactionController_1.unlikeAnnotation);
router.post('/favorite', auth_1.authMiddleware, [
    (0, express_validator_1.body)('targetId')
        .notEmpty()
        .withMessage('目标ID不能为空'),
    (0, express_validator_1.body)('targetType')
        .isIn(Object.values(interactionController_1.FavoriteType))
        .withMessage('无效的收藏类型'),
], validation_1.validateRequest, interactionController_1.favoriteAnnotation);
router.delete('/favorite', auth_1.authMiddleware, [
    (0, express_validator_1.body)('targetId')
        .notEmpty()
        .withMessage('目标ID不能为空'),
    (0, express_validator_1.body)('targetType')
        .isIn(Object.values(interactionController_1.FavoriteType))
        .withMessage('无效的收藏类型'),
], validation_1.validateRequest, interactionController_1.unfavoriteAnnotation);
router.get('/stats/:targetType/:targetId', auth_1.optionalAuthMiddleware, [
    (0, express_validator_1.param)('targetId')
        .notEmpty()
        .withMessage('目标ID不能为空'),
    (0, express_validator_1.param)('targetType')
        .notEmpty()
        .withMessage('目标类型不能为空'),
], validation_1.validateRequest, interactionController_1.getInteractionStats);
router.get('/likes', auth_1.authMiddleware, [
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1-100之间'),
    (0, express_validator_1.query)('targetType')
        .optional()
        .isIn(Object.values(interactionController_1.LikeType))
        .withMessage('无效的点赞类型'),
], validation_1.validateRequest, interactionController_1.getUserLikes);
router.get('/favorites', auth_1.authMiddleware, [
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须为正整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1-100之间'),
    (0, express_validator_1.query)('targetType')
        .optional()
        .isIn(Object.values(interactionController_1.FavoriteType))
        .withMessage('无效的收藏类型'),
], validation_1.validateRequest, interactionController_1.getUserFavorites);
router.get('/activity/stats', auth_1.authMiddleware, [
    (0, express_validator_1.query)('timeRange')
        .optional()
        .isIn(['1d', '7d', '30d', 'all'])
        .withMessage('无效的时间范围'),
], validation_1.validateRequest, interactionController_1.getUserActivityStats);
router.get('/popular', [
    (0, express_validator_1.query)('targetType')
        .optional()
        .isIn([...Object.values(interactionController_1.LikeType), ...Object.values(interactionController_1.FavoriteType)])
        .withMessage('无效的内容类型'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 50 })
        .withMessage('限制数量必须在1-50之间'),
    (0, express_validator_1.query)('timeRange')
        .optional()
        .isIn(['1d', '7d', '30d', 'all'])
        .withMessage('无效的时间范围'),
], validation_1.validateRequest, interactionController_1.getPopularContent);
exports.default = router;
//# sourceMappingURL=interactionRoutes.js.map