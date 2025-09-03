"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const userRoutes_1 = __importDefault(require("./userRoutes"));
const annotationRoutes_1 = __importDefault(require("./annotationRoutes"));
const paymentRoutes_1 = __importDefault(require("./paymentRoutes"));
const mediaRoutes_1 = __importDefault(require("./mediaRoutes"));
const lbsRoutes_1 = __importDefault(require("./lbsRoutes"));
const geocoding_1 = __importDefault(require("./geocoding"));
const searchRoutes_1 = __importDefault(require("./searchRoutes"));
const socialRoutes_1 = __importDefault(require("./socialRoutes"));
const commentRoutes_1 = __importDefault(require("./commentRoutes"));
const followRoutes_1 = __importDefault(require("./followRoutes"));
const walletRoutes_1 = __importDefault(require("./walletRoutes"));
const shareRoutes_1 = __importDefault(require("./shareRoutes"));
const interactionRoutes_1 = __importDefault(require("./interactionRoutes"));
const adminRoutes_1 = __importDefault(require("./adminRoutes"));
const feedRoutes_1 = __importDefault(require("./feedRoutes"));
const recommendationRoutes_1 = __importDefault(require("./recommendationRoutes"));
const profileRoutes_1 = __importDefault(require("./profileRoutes"));
const moderationRoutes_1 = __importDefault(require("./moderationRoutes"));
const errorMonitoringRoutes_1 = __importDefault(require("./errorMonitoringRoutes"));
const logger_1 = require("@/utils/logger");
const router = (0, express_1.Router)();
const API_VERSION = '/api/v1';
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
router.use(`${API_VERSION}/users`, userRoutes_1.default);
router.use(`${API_VERSION}/auth`, userRoutes_1.default);
router.use(`${API_VERSION}/annotations`, annotationRoutes_1.default);
router.use(`${API_VERSION}/payments`, paymentRoutes_1.default);
router.use(`${API_VERSION}/media`, mediaRoutes_1.default);
router.use(`${API_VERSION}/lbs`, lbsRoutes_1.default);
router.use(`${API_VERSION}/geocoding`, geocoding_1.default);
router.use(`${API_VERSION}/search`, searchRoutes_1.default);
router.use(`${API_VERSION}/social`, socialRoutes_1.default);
router.use(`${API_VERSION}`, commentRoutes_1.default);
router.use(`${API_VERSION}/users`, followRoutes_1.default);
router.use(`${API_VERSION}/wallet`, walletRoutes_1.default);
router.use(`${API_VERSION}`, shareRoutes_1.default);
router.use(`${API_VERSION}/interactions`, interactionRoutes_1.default);
router.use(`${API_VERSION}/admin`, adminRoutes_1.default);
router.use(`${API_VERSION}`, feedRoutes_1.default);
router.use(`${API_VERSION}/recommendations`, recommendationRoutes_1.default);
router.use(`${API_VERSION}`, profileRoutes_1.default);
router.use(`${API_VERSION}/moderation`, moderationRoutes_1.default);
router.use(`${API_VERSION}/errors`, errorMonitoringRoutes_1.default);
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
router.use((req, _res, next) => {
    logger_1.logger.info('API请求', {
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.id,
    });
    next();
});
exports.default = router;
//# sourceMappingURL=index.js.map