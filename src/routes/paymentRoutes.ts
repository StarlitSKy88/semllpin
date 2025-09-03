import { Router } from 'express';
import { authMiddleware } from '@/middleware/auth';
import { validateRequest } from '@/middleware/validation';
import { body, param, query } from 'express-validator';
import paymentController from '@/controllers/paymentController';

const router = Router();

// PayPal支付路由
// 创建PayPal支付订单
router.post(
  '/create',
  authMiddleware,
  [
    body('amount')
      .isFloat({ min: 0.01, max: 10000 })
      .withMessage('支付金额必须在 $0.01-$10000 之间'),
    body('currency')
      .optional()
      .isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CNY', 'HKD', 'SGD', 'KRW'])
      .withMessage('不支持的货币类型'),
    body('description')
      .notEmpty()
      .withMessage('支付描述不能为空')
      .isLength({ max: 500 })
      .withMessage('描述不能超过500个字符'),
    body('annotationId')
      .optional()
      .isString()
      .withMessage('标注ID必须是字符串'),
    body('paymentMethod')
      .isIn(['paypal'])
      .withMessage('支付方式必须是 paypal'),
  ],
  validateRequest,
  paymentController.createPaymentSession,
);

// 捕获PayPal支付
router.post(
  '/capture',
  authMiddleware,
  [
    body('orderId')
      .notEmpty()
      .withMessage('订单ID不能为空')
      .isString()
      .withMessage('订单ID必须是字符串'),
    body('payerId')
      .notEmpty()
      .withMessage('支付者ID不能为空')
      .isString()
      .withMessage('支付者ID必须是字符串'),
    body('paymentMethod')
      .optional()
      .isIn(['stripe', 'paypal'])
      .withMessage('支付方式必须是 stripe 或 paypal'),
  ],
  validateRequest,
  paymentController.getPaymentSession,
);

// Stripe支付路由（现有）
// 创建支付会话
router.post(
  '/create-session',
  authMiddleware,
  [
    body('prankId')
      .notEmpty()
      .withMessage('恶搞标注ID不能为空')
      .isString()
      .withMessage('恶搞标注ID必须是字符串'),
    body('amount')
      .isFloat({ min: 1, max: 100 })
      .withMessage('支付金额必须在 $1-$100 之间'),
    body('currency')
      .optional()
      .isIn(['usd', 'eur', 'gbp', 'cny'])
      .withMessage('不支持的货币类型'),
    body('description')
      .optional()
      .isLength({ max: 500 })
      .withMessage('描述不能超过500个字符'),
  ],
  validateRequest,
  paymentController.createPaymentSession,
);

// 获取支付会话状态
router.get(
  '/session/:sessionId',
  authMiddleware,
  [
    param('sessionId')
      .notEmpty()
      .withMessage('会话ID不能为空')
      .isString()
      .withMessage('会话ID必须是字符串'),
  ],
  validateRequest,
  paymentController.getPaymentSession,
);

// Stripe Webhook 处理（不需要认证）
router.post(
  '/webhook',
  // 注意：这个路由不使用 authenticateToken 中间件
  // 因为它是 Stripe 服务器调用的
  paymentController.handleStripeWebhook,
);

// 获取用户支付历史
router.get(
  '/history',
  authMiddleware,
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('页码必须是大于0的整数'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('每页数量必须在1-100之间'),
  ],
  validateRequest,
  paymentController.getUserPayments,
);

// 申请退款
router.post(
  '/refund',
  authMiddleware,
  [
    body('paymentIntentId')
      .notEmpty()
      .withMessage('支付意图ID不能为空')
      .isString()
      .withMessage('支付意图ID必须是字符串'),
    body('reason')
      .optional()
      .isIn([
        'duplicate',
        'fraudulent',
        'requested_by_customer',
        'expired_uncaptured_charge',
      ])
      .withMessage('无效的退款原因'),
  ],
  validateRequest,
  paymentController.requestRefund,
);

// 获取支付统计报表
router.get(
  '/stats',
  authMiddleware,
  [
    query('timeRange')
      .optional()
      .isIn(['7d', '30d', '90d', '1y'])
      .withMessage('无效的时间范围'),
    query('groupBy')
      .optional()
      .isIn(['hour', 'day', 'week', 'month'])
      .withMessage('无效的分组方式'),
  ],
  validateRequest,
  paymentController.getPaymentStats,
);

// 获取平台收支平衡报告（仅管理员）
router.get(
  '/balance-report',
  authMiddleware,
  [
    query('timeRange')
      .optional()
      .isIn(['7d', '30d', '90d', '1y'])
      .withMessage('无效的时间范围'),
  ],
  validateRequest,
  paymentController.getBalanceReport,
);

// 批量重试失败支付（仅管理员）
router.post(
  '/retry-failed',
  authMiddleware,
  [
    body('paymentIds')
      .isArray()
      .withMessage('支付ID列表必须是数组'),
    body('maxRetries')
      .optional()
      .isInt({ min: 1, max: 5 })
      .withMessage('最大重试次数必须在1-5之间'),
  ],
  validateRequest,
  paymentController.retryFailedPayments,
);

// 支付健康检查（仅管理员）
router.get(
  '/health',
  authMiddleware,
  paymentController.getPaymentHealth,
);

// 批量处理退款（仅管理员）
router.post(
  '/batch-refund',
  authMiddleware,
  [
    body('refundRequests')
      .isArray()
      .withMessage('退款请求列表必须是数组'),
    body('refundRequests.*.paymentId')
      .notEmpty()
      .withMessage('支付ID不能为空'),
    body('refundRequests.*.amount')
      .optional()
      .isFloat({ min: 0.01 })
      .withMessage('退款金额必须大于0.01'),
    body('refundRequests.*.reason')
      .optional()
      .isIn(['duplicate', 'fraudulent', 'requested_by_customer'])
      .withMessage('无效的退款原因'),
  ],
  validateRequest,
  paymentController.batchProcessRefunds,
);

// 处理自动退款（仅管理员）
router.post(
  '/auto-refund',
  authMiddleware,
  paymentController.processAutoRefunds,
);

// 获取退款分析（仅管理员）
router.get(
  '/refund-analysis',
  authMiddleware,
  [
    query('timeRange')
      .optional()
      .isIn(['7d', '30d', '90d'])
      .withMessage('无效的时间范围'),
  ],
  validateRequest,
  paymentController.getRefundAnalysis,
);

export default router;
