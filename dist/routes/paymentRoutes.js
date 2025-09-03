"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("@/middleware/auth");
const validation_1 = require("@/middleware/validation");
const express_validator_1 = require("express-validator");
const paymentController_1 = __importDefault(require("@/controllers/paymentController"));
const router = (0, express_1.Router)();
router.post('/create', auth_1.authMiddleware, [
    (0, express_validator_1.body)('amount')
        .isFloat({ min: 0.01, max: 10000 })
        .withMessage('支付金额必须在 $0.01-$10000 之间'),
    (0, express_validator_1.body)('currency')
        .optional()
        .isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CNY', 'HKD', 'SGD', 'KRW'])
        .withMessage('不支持的货币类型'),
    (0, express_validator_1.body)('description')
        .notEmpty()
        .withMessage('支付描述不能为空')
        .isLength({ max: 500 })
        .withMessage('描述不能超过500个字符'),
    (0, express_validator_1.body)('annotationId')
        .optional()
        .isString()
        .withMessage('标注ID必须是字符串'),
    (0, express_validator_1.body)('paymentMethod')
        .isIn(['paypal'])
        .withMessage('支付方式必须是 paypal'),
], validation_1.validateRequest, paymentController_1.default.createPaymentSession);
router.post('/capture', auth_1.authMiddleware, [
    (0, express_validator_1.body)('orderId')
        .notEmpty()
        .withMessage('订单ID不能为空')
        .isString()
        .withMessage('订单ID必须是字符串'),
    (0, express_validator_1.body)('payerId')
        .notEmpty()
        .withMessage('支付者ID不能为空')
        .isString()
        .withMessage('支付者ID必须是字符串'),
    (0, express_validator_1.body)('paymentMethod')
        .optional()
        .isIn(['stripe', 'paypal'])
        .withMessage('支付方式必须是 stripe 或 paypal'),
], validation_1.validateRequest, paymentController_1.default.getPaymentSession);
router.post('/create-session', auth_1.authMiddleware, [
    (0, express_validator_1.body)('prankId')
        .notEmpty()
        .withMessage('恶搞标注ID不能为空')
        .isString()
        .withMessage('恶搞标注ID必须是字符串'),
    (0, express_validator_1.body)('amount')
        .isFloat({ min: 1, max: 100 })
        .withMessage('支付金额必须在 $1-$100 之间'),
    (0, express_validator_1.body)('currency')
        .optional()
        .isIn(['usd', 'eur', 'gbp', 'cny'])
        .withMessage('不支持的货币类型'),
    (0, express_validator_1.body)('description')
        .optional()
        .isLength({ max: 500 })
        .withMessage('描述不能超过500个字符'),
], validation_1.validateRequest, paymentController_1.default.createPaymentSession);
router.get('/session/:sessionId', auth_1.authMiddleware, [
    (0, express_validator_1.param)('sessionId')
        .notEmpty()
        .withMessage('会话ID不能为空')
        .isString()
        .withMessage('会话ID必须是字符串'),
], validation_1.validateRequest, paymentController_1.default.getPaymentSession);
router.post('/webhook', paymentController_1.default.handleStripeWebhook);
router.get('/history', auth_1.authMiddleware, [
    (0, express_validator_1.query)('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('页码必须是大于0的整数'),
    (0, express_validator_1.query)('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('每页数量必须在1-100之间'),
], validation_1.validateRequest, paymentController_1.default.getUserPayments);
router.post('/refund', auth_1.authMiddleware, [
    (0, express_validator_1.body)('paymentIntentId')
        .notEmpty()
        .withMessage('支付意图ID不能为空')
        .isString()
        .withMessage('支付意图ID必须是字符串'),
    (0, express_validator_1.body)('reason')
        .optional()
        .isIn([
        'duplicate',
        'fraudulent',
        'requested_by_customer',
        'expired_uncaptured_charge',
    ])
        .withMessage('无效的退款原因'),
], validation_1.validateRequest, paymentController_1.default.requestRefund);
router.get('/stats', auth_1.authMiddleware, [
    (0, express_validator_1.query)('timeRange')
        .optional()
        .isIn(['7d', '30d', '90d', '1y'])
        .withMessage('无效的时间范围'),
    (0, express_validator_1.query)('groupBy')
        .optional()
        .isIn(['hour', 'day', 'week', 'month'])
        .withMessage('无效的分组方式'),
], validation_1.validateRequest, paymentController_1.default.getPaymentStats);
router.get('/balance-report', auth_1.authMiddleware, [
    (0, express_validator_1.query)('timeRange')
        .optional()
        .isIn(['7d', '30d', '90d', '1y'])
        .withMessage('无效的时间范围'),
], validation_1.validateRequest, paymentController_1.default.getBalanceReport);
router.post('/retry-failed', auth_1.authMiddleware, [
    (0, express_validator_1.body)('paymentIds')
        .isArray()
        .withMessage('支付ID列表必须是数组'),
    (0, express_validator_1.body)('maxRetries')
        .optional()
        .isInt({ min: 1, max: 5 })
        .withMessage('最大重试次数必须在1-5之间'),
], validation_1.validateRequest, paymentController_1.default.retryFailedPayments);
router.get('/health', auth_1.authMiddleware, paymentController_1.default.getPaymentHealth);
router.post('/batch-refund', auth_1.authMiddleware, [
    (0, express_validator_1.body)('refundRequests')
        .isArray()
        .withMessage('退款请求列表必须是数组'),
    (0, express_validator_1.body)('refundRequests.*.paymentId')
        .notEmpty()
        .withMessage('支付ID不能为空'),
    (0, express_validator_1.body)('refundRequests.*.amount')
        .optional()
        .isFloat({ min: 0.01 })
        .withMessage('退款金额必须大于0.01'),
    (0, express_validator_1.body)('refundRequests.*.reason')
        .optional()
        .isIn(['duplicate', 'fraudulent', 'requested_by_customer'])
        .withMessage('无效的退款原因'),
], validation_1.validateRequest, paymentController_1.default.batchProcessRefunds);
router.post('/auto-refund', auth_1.authMiddleware, paymentController_1.default.processAutoRefunds);
router.get('/refund-analysis', auth_1.authMiddleware, [
    (0, express_validator_1.query)('timeRange')
        .optional()
        .isIn(['7d', '30d', '90d'])
        .withMessage('无效的时间范围'),
], validation_1.validateRequest, paymentController_1.default.getRefundAnalysis);
exports.default = router;
//# sourceMappingURL=paymentRoutes.js.map