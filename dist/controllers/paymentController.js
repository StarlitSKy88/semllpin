"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRefundAnalysis = exports.processAutoRefunds = exports.batchProcessRefunds = exports.getPaymentHealth = exports.retryFailedPayments = exports.getBalanceReport = exports.getPaymentStats = exports.requestRefund = exports.getUserPayments = exports.handleStripeWebhook = exports.getPaymentSession = exports.createPaymentSession = void 0;
const errorHandler_1 = require("../middleware/errorHandler");
const errorHandler_2 = require("../middleware/errorHandler");
const logger_1 = require("../utils/logger");
const redis_1 = require("../config/redis");
const stripe_1 = __importDefault(require("stripe"));
const config_1 = require("../config/config");
const database_1 = require("../config/database");
const paymentService_1 = require("../services/paymentService");
const stripe = new stripe_1.default(config_1.config.payment.stripe.secretKey, {
    apiVersion: '2023-10-16',
});
const validatePaymentAmount = (amount, currency = 'usd') => {
    const limits = {
        usd: { min: 1, max: 1000 },
        cny: { min: 6, max: 6000 },
        eur: { min: 1, max: 900 },
    };
    const limit = limits[currency] || limits.usd;
    if (!amount || typeof amount !== 'number' || amount < limit.min || amount > limit.max) {
        throw (0, errorHandler_1.createValidationError)('amount', `支付金额必须在 ${limit.min}-${limit.max} ${currency.toUpperCase()} 之间`);
    }
};
const checkDuplicatePayment = async (userId, annotationId) => {
    const existingPayment = await (0, database_1.db)('payments')
        .where({
        user_id: userId,
        annotation_id: annotationId,
        status: 'completed',
    })
        .first();
    if (existingPayment) {
        throw (0, errorHandler_1.createValidationError)('payment', '该标注已经支付过了');
    }
};
const validateAnnotationForPayment = async (annotationId) => {
    const annotation = await (0, database_1.db)('annotations')
        .where('id', annotationId)
        .first();
    if (!annotation) {
        throw (0, errorHandler_1.createValidationError)('annotation', '标注不存在');
    }
    if (annotation.status === 'active') {
        throw (0, errorHandler_1.createValidationError)('annotation', '该标注已经激活，无需重复支付');
    }
    if (annotation.status === 'deleted' || annotation.status === 'banned') {
        throw (0, errorHandler_1.createValidationError)('annotation', '该标注不可用');
    }
    return annotation;
};
exports.createPaymentSession = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    if (!userId) {
        throw (0, errorHandler_1.createAuthError)('用户未认证');
    }
    const { prankId, amount, currency = 'usd', description } = req.body;
    if (!prankId) {
        throw (0, errorHandler_1.createValidationError)('prankId', '标注ID不能为空');
    }
    validatePaymentAmount(amount, currency);
    await validateAnnotationForPayment(prankId);
    await checkDuplicatePayment(userId, prankId);
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency,
                        product_data: {
                            name: '恶搞标注支付',
                            description: description || `为恶搞标注 ${prankId} 支付`,
                            images: ['https://your-domain.com/prank-icon.png'],
                        },
                        unit_amount: amount * 100,
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${config_1.config.frontendUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${config_1.config.frontendUrl}/payment/cancel`,
            metadata: {
                userId,
                prankId,
                amount: amount.toString(),
            },
        });
        const sessionData = {
            prankId,
            amount,
            currency,
            description: description || `恶搞标注支付 - ${prankId}`,
        };
        await redis_1.cacheService.set(`payment_session:${session.id}`, JSON.stringify(sessionData), 3600);
        logger_1.logger.info('支付会话创建成功', {
            sessionId: session.id,
            userId,
            prankId,
            amount,
        });
        res.status(201).json({
            success: true,
            data: {
                sessionId: session.id,
                url: session.url,
            },
            message: '支付会话创建成功',
        });
    }
    catch (error) {
        logger_1.logger.error('创建支付会话失败', { error: error.message, userId, prankId });
        throw new errorHandler_1.AppError('创建支付会话失败', 500);
    }
});
exports.getPaymentSession = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const { sessionId } = req.params;
    if (!sessionId) {
        throw (0, errorHandler_1.createValidationError)('sessionId', '会话ID不能为空');
    }
    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const cachedData = await redis_1.cacheService.get(`payment_session:${sessionId}`);
        const sessionData = cachedData ? JSON.parse(cachedData) : null;
        res.json({
            success: true,
            data: {
                id: session.id,
                status: session.payment_status,
                amount: session.amount_total ? session.amount_total / 100 : null,
                currency: session.currency,
                customerEmail: session.customer_details?.email,
                metadata: session.metadata,
                ...sessionData,
            },
            message: '获取支付会话成功',
        });
    }
    catch (error) {
        logger_1.logger.error('获取支付会话失败', { error: error.message, sessionId });
        throw new errorHandler_1.AppError('获取支付会话失败', 500);
    }
});
exports.handleStripeWebhook = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const sig = req.headers['stripe-signature'];
    if (!sig) {
        throw (0, errorHandler_1.createValidationError)('signature', 'Stripe 签名缺失');
    }
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, config_1.config.payment.stripe.webhookSecret);
    }
    catch (error) {
        logger_1.logger.error('Webhook 签名验证失败', { error: error.message });
        throw (0, errorHandler_1.createValidationError)('signature', 'Webhook 签名验证失败');
    }
    switch (event.type) {
        case 'checkout.session.completed':
            await handlePaymentSuccess(event.data.object);
            break;
        case 'checkout.session.expired':
            await handlePaymentExpired(event.data.object);
            break;
        case 'payment_intent.payment_failed':
            await handlePaymentFailed(event.data.object);
            break;
        default:
            logger_1.logger.info('未处理的 Webhook 事件类型', { type: event.type });
    }
    res.json({ received: true });
});
const handlePaymentSuccess = async (session) => {
    const { userId, prankId, amount } = session.metadata;
    if (!userId || !prankId || !amount) {
        logger_1.logger.error('支付成功事件缺少必要的元数据', { sessionId: session.id, metadata: session.metadata });
        throw new Error('支付元数据不完整');
    }
    if (session.payment_status !== 'paid') {
        logger_1.logger.error('支付状态异常', { sessionId: session.id, paymentStatus: session.payment_status });
        throw new Error('支付状态异常');
    }
    try {
        await database_1.db.transaction(async (trx) => {
            const existingPayment = await paymentService_1.PaymentService.findByStripeSessionId(session.id);
            const paymentData = {
                user_id: userId,
                annotation_id: prankId,
                amount: parseFloat(amount),
                currency: session.currency || 'usd',
                payment_method: 'stripe',
                payment_intent_id: session.id,
                transaction_id: session.payment_intent,
                status: 'completed',
                description: `恶搞标注支付 - ${prankId}`,
                metadata: {
                    stripe_session_id: session.id,
                    stripe_payment_intent_id: session.payment_intent,
                    completed_at: new Date().toISOString(),
                },
                processed_at: new Date(),
            };
            if (existingPayment) {
                await paymentService_1.PaymentService.updateStatus(existingPayment.id, 'completed', paymentData);
            }
            else {
                await paymentService_1.PaymentService.create(paymentData);
            }
            if (prankId) {
                const annotation = await trx('annotations')
                    .where('id', prankId)
                    .first();
                if (!annotation) {
                    throw new Error(`标注 ${prankId} 不存在`);
                }
                if (annotation.status === 'active') {
                    logger_1.logger.warn('标注已经激活', { annotationId: prankId });
                }
                else {
                    await trx('annotations')
                        .where('id', prankId)
                        .update({
                        status: 'active',
                        activated_at: new Date(),
                        updated_at: new Date(),
                    });
                    logger_1.logger.info('标注激活成功', { annotationId: prankId });
                }
            }
        });
        logger_1.logger.info('支付成功处理完成', {
            sessionId: session.id,
            userId,
            prankId,
            amount,
        });
        await redis_1.cacheService.del(`payment_session:${session.id}`);
    }
    catch (error) {
        logger_1.logger.error('处理支付成功事件失败', { error: error.message, sessionId: session.id });
        throw error;
    }
};
const handlePaymentExpired = async (session) => {
    logger_1.logger.info('支付会话过期', { sessionId: session.id });
    await redis_1.cacheService.del(`payment_session:${session.id}`);
};
const handlePaymentFailed = async (paymentIntent) => {
    logger_1.logger.error('支付失败', {
        paymentIntentId: paymentIntent.id,
        error: paymentIntent.last_payment_error,
    });
};
const getUserPayments = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        const { page = 1, limit = 20, status, startDate, endDate, } = req.query;
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const options = {
            page: pageNum,
            limit: limitNum,
        };
        if (status) {
            options.status = status;
        }
        if (startDate) {
            options.startDate = new Date(startDate);
        }
        if (endDate) {
            options.endDate = new Date(endDate);
        }
        const { payments, total } = await paymentService_1.PaymentService.getUserPayments(userId, options);
        const totalPages = Math.ceil(total / limitNum);
        res.json({
            code: 200,
            message: '获取支付历史成功',
            data: {
                payments,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    total,
                    totalPages,
                },
            },
        });
    }
    catch (error) {
        logger_1.logger.error('获取用户支付历史失败', { error });
        res.status(500).json({
            code: 500,
            message: '获取支付历史失败',
            error: error instanceof Error ? error.message : '未知错误',
        });
    }
};
exports.getUserPayments = getUserPayments;
const validateRefundEligibility = (payment) => {
    if (payment.status !== 'completed') {
        throw (0, errorHandler_1.createValidationError)('payment', '只有已完成的支付才能申请退款');
    }
    if (payment.status === 'refunded') {
        throw (0, errorHandler_1.createValidationError)('payment', '该支付已经退款');
    }
    const paymentDate = new Date(payment.created_at);
    const now = new Date();
    const daysDiff = Math.floor((now.getTime() - paymentDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDiff > 30) {
        throw (0, errorHandler_1.createValidationError)('payment', '支付超过30天，无法申请退款');
    }
    if (payment.refund_amount && payment.refund_amount > 0) {
        throw (0, errorHandler_1.createValidationError)('payment', '该支付已有退款记录');
    }
};
const requestRefund = async (req, res) => {
    try {
        const { paymentId } = req.params;
        const { reason, amount } = req.body;
        const userId = req.user?.id;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        if (!reason) {
            throw (0, errorHandler_1.createValidationError)('reason', '退款原因不能为空');
        }
        const payment = await paymentService_1.PaymentService.findById(paymentId);
        if (!payment || payment.user_id !== userId) {
            throw new errorHandler_1.AppError('支付记录不存在', 404);
        }
        await validateRefundEligibility(payment);
        const refundAmount = amount || payment.amount;
        if (refundAmount <= 0 || refundAmount > (payment.amount - (payment.refund_amount || 0))) {
            throw (0, errorHandler_1.createValidationError)('INVALID_REFUND_AMOUNT', '退款金额无效');
        }
        const refundResult = await paymentService_1.PaymentService.processRefund(paymentId, refundAmount, reason);
        if (!refundResult) {
            throw new errorHandler_1.AppError('退款处理失败', 500);
        }
        logger_1.logger.info('退款处理成功', {
            paymentId,
            userId,
            refundAmount,
            refundId: refundResult.id,
        });
        res.json({
            code: 200,
            message: '退款申请成功',
            data: {
                refund_id: refundResult.id,
                amount: refundAmount,
                status: refundResult.status,
                estimated_arrival: '5-10个工作日',
            },
        });
    }
    catch (error) {
        logger_1.logger.error('退款申请失败', { error, paymentId: req.params['paymentId'] });
        if (error instanceof stripe_1.default.errors.StripeError) {
            res.status(400).json({
                code: 400,
                message: `退款失败: ${error.message}`,
            });
        }
        else {
            res.status(500).json({
                code: 500,
                message: '退款申请失败',
                error: error instanceof Error ? error.message : '未知错误',
            });
        }
    }
};
exports.requestRefund = requestRefund;
const getPaymentStats = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        const { period = '30d' } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        switch (period) {
            case '7d':
                startDate.setDate(startDate.getDate() - 7);
                break;
            case '30d':
                startDate.setDate(startDate.getDate() - 30);
                break;
            case '90d':
                startDate.setDate(startDate.getDate() - 90);
                break;
            case '1y':
                startDate.setFullYear(startDate.getFullYear() - 1);
                break;
            default:
                startDate.setDate(startDate.getDate() - 30);
        }
        const stats = await paymentService_1.PaymentService.getPaymentStats({
            userId,
            startDate,
            endDate,
        });
        res.json({
            code: 200,
            message: '获取支付统计成功',
            data: {
                period,
                ...stats,
            },
        });
    }
    catch (error) {
        logger_1.logger.error('获取支付统计失败', { error });
        res.status(500).json({
            code: 500,
            message: '获取支付统计失败',
            error: error instanceof Error ? error.message : '未知错误',
        });
    }
};
exports.getPaymentStats = getPaymentStats;
exports.getBalanceReport = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const { timeRange = '30d' } = req.query;
    const dateFilter = new Date();
    switch (timeRange) {
        case '7d':
            dateFilter.setDate(dateFilter.getDate() - 7);
            break;
        case '30d':
            dateFilter.setDate(dateFilter.getDate() - 30);
            break;
        case '90d':
            dateFilter.setDate(dateFilter.getDate() - 90);
            break;
        case '1y':
            dateFilter.setFullYear(dateFilter.getFullYear() - 1);
            break;
        default:
            dateFilter.setDate(dateFilter.getDate() - 30);
    }
    const db = require('@/config/database').db;
    const revenue = await db('payments')
        .select(db.raw('SUM(amount) as gross_revenue'), db.raw('SUM(fee_amount) as platform_fees'), db.raw('SUM(net_amount) as net_revenue'), db.raw('COUNT(*) as total_transactions'))
        .where('status', 'succeeded')
        .where('created_at', '>=', dateFilter)
        .first();
    const refunds = await db('payments')
        .select(db.raw('SUM(refund_amount) as total_refunds'), db.raw('COUNT(*) as refund_count'))
        .whereNotNull('refund_amount')
        .where('refund_amount', '>', 0)
        .where('created_at', '>=', dateFilter)
        .first();
    const userStats = await db('payments')
        .select(db.raw('COUNT(DISTINCT user_id) as active_users'), db.raw('AVG(amount) as avg_transaction'))
        .where('status', 'succeeded')
        .where('created_at', '>=', dateFilter)
        .first();
    const dailyTrends = await db('payments')
        .select(db.raw('DATE(created_at) as date'), db.raw('SUM(amount) as daily_revenue'), db.raw('SUM(fee_amount) as daily_fees'), db.raw('COUNT(*) as daily_transactions'))
        .where('status', 'succeeded')
        .where('created_at', '>=', dateFilter)
        .groupBy(db.raw('DATE(created_at)'))
        .orderBy('date');
    const grossRevenue = Number(revenue?.gross_revenue || 0);
    const platformFees = Number(revenue?.platform_fees || 0);
    const totalRefunds = Number(refunds?.total_refunds || 0);
    const netProfit = platformFees - totalRefunds;
    const profitMargin = grossRevenue > 0 ? (netProfit / grossRevenue) * 100 : 0;
    const result = {
        timeRange,
        reportDate: new Date().toISOString(),
        revenue: {
            grossRevenue,
            platformFees,
            netRevenue: Number(revenue?.net_revenue || 0),
            totalTransactions: Number(revenue?.total_transactions || 0),
        },
        refunds: {
            totalRefunds,
            refundCount: Number(refunds?.refund_count || 0),
            refundRate: revenue?.total_transactions > 0
                ? (Number(refunds?.refund_count || 0) / Number(revenue.total_transactions)) * 100
                : 0,
        },
        profitability: {
            netProfit,
            profitMargin,
            averageTransactionValue: Number(userStats?.avg_transaction || 0),
        },
        userMetrics: {
            activeUsers: Number(userStats?.active_users || 0),
            revenuePerUser: userStats?.active_users > 0
                ? grossRevenue / Number(userStats.active_users)
                : 0,
        },
        trends: dailyTrends.map((trend) => ({
            date: trend.date,
            revenue: Number(trend.daily_revenue),
            fees: Number(trend.daily_fees),
            transactions: Number(trend.daily_transactions),
        })),
    };
    logger_1.logger.info('生成平台收支平衡报告', {
        userId,
        timeRange,
        grossRevenue,
        netProfit,
        profitMargin,
    });
    res.json({
        success: true,
        data: result,
    });
});
exports.retryFailedPayments = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const { paymentIds, maxRetries = 3 } = req.body;
    if (!paymentIds || !Array.isArray(paymentIds) || paymentIds.length === 0) {
        throw (0, errorHandler_1.createValidationError)('paymentIds', '支付ID列表不能为空');
    }
    const db = require('@/config/database').db;
    const failedPayments = await db('payments')
        .whereIn('id', paymentIds)
        .whereIn('status', ['failed', 'canceled', 'requires_action'])
        .where('retry_count', '<', maxRetries);
    const results = [];
    for (const payment of failedPayments) {
        try {
            const paymentIntent = await stripe.paymentIntents.create({
                amount: Math.round(payment.amount * 100),
                currency: payment.currency,
                metadata: {
                    paymentId: payment.id,
                    userId: payment.user_id,
                    annotationId: payment.annotation_id || '',
                    retryAttempt: (payment.retry_count || 0) + 1,
                },
                description: payment.description || '恶搞标注支付重试',
            });
            await db('payments')
                .where('id', payment.id)
                .update({
                payment_intent_id: paymentIntent.id,
                status: 'pending',
                retry_count: (payment.retry_count || 0) + 1,
                updated_at: new Date(),
            });
            results.push({
                paymentId: payment.id,
                status: 'retry_initiated',
                paymentIntentId: paymentIntent.id,
                clientSecret: paymentIntent.client_secret,
            });
            logger_1.logger.info('支付重试成功', {
                paymentId: payment.id,
                paymentIntentId: paymentIntent.id,
                retryCount: (payment.retry_count || 0) + 1,
            });
        }
        catch (error) {
            logger_1.logger.error('支付重试失败', {
                paymentId: payment.id,
                error: error.message,
            });
            results.push({
                paymentId: payment.id,
                status: 'retry_failed',
                error: error.message,
            });
        }
    }
    res.json({
        success: true,
        message: `处理了${results.length}个支付重试请求`,
        data: {
            processedCount: results.length,
            results,
        },
    });
});
exports.getPaymentHealth = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const db = require('@/config/database').db;
    const last24h = new Date();
    last24h.setHours(last24h.getHours() - 24);
    const healthStats = await db('payments')
        .select('status')
        .count('* as count')
        .where('created_at', '>=', last24h)
        .groupBy('status');
    const totalPayments = healthStats.reduce((sum, stat) => sum + Number(stat.count), 0);
    const successfulPayments = healthStats.find((stat) => stat.status === 'succeeded')?.count || 0;
    const successRate = totalPayments > 0 ? (Number(successfulPayments) / totalPayments) * 100 : 0;
    const pendingRetries = await db('payments')
        .whereIn('status', ['failed', 'canceled', 'requires_action'])
        .where('retry_count', '<', 3)
        .where('created_at', '>=', last24h)
        .count('* as count')
        .first();
    const stalePending = new Date();
    stalePending.setHours(stalePending.getHours() - 2);
    const stalePayments = await db('payments')
        .where('status', 'pending')
        .where('created_at', '<', stalePending)
        .count('* as count')
        .first();
    const recentErrors = await db('payments')
        .select('id', 'status', 'created_at', 'metadata')
        .whereIn('status', ['failed', 'canceled'])
        .where('created_at', '>=', last24h)
        .orderBy('created_at', 'desc')
        .limit(10);
    let stripeHealth = 'unknown';
    try {
        await stripe.accounts.retrieve();
        stripeHealth = 'healthy';
    }
    catch (error) {
        stripeHealth = 'unhealthy';
        logger_1.logger.error('Stripe连接检查失败', { error });
    }
    const healthScore = Math.min(100, Math.max(0, successRate * 0.7 +
        (totalPayments > 0 ? 30 : 0) -
        (Number(pendingRetries?.count || 0) * 2) -
        (Number(stalePayments?.count || 0) * 5)));
    const result = {
        timestamp: new Date().toISOString(),
        healthScore: Math.round(healthScore),
        status: healthScore >= 80 ? 'healthy' : healthScore >= 60 ? 'warning' : 'critical',
        metrics: {
            successRate: Math.round(successRate * 100) / 100,
            totalPayments24h: totalPayments,
            successfulPayments24h: Number(successfulPayments),
            pendingRetries: Number(pendingRetries?.count || 0),
            stalePayments: Number(stalePayments?.count || 0),
        },
        statusBreakdown: healthStats.map((stat) => ({
            status: stat.status,
            count: Number(stat.count),
            percentage: totalPayments > 0 ? Math.round((Number(stat.count) / totalPayments) * 10000) / 100 : 0,
        })),
        stripeHealth,
        recentErrors: recentErrors.map((error) => ({
            id: error.id,
            status: error.status,
            createdAt: error.created_at,
            metadata: error.metadata,
        })),
        recommendations: [
            ...(successRate < 80 ? ['支付成功率偏低，建议检查支付配置'] : []),
            ...(Number(pendingRetries?.count || 0) > 5 ? ['有较多失败支付需要重试'] : []),
            ...(Number(stalePayments?.count || 0) > 0 ? ['有支付长时间处于pending状态，建议检查'] : []),
            ...(stripeHealth !== 'healthy' ? ['Stripe连接异常，请检查API密钥'] : []),
        ],
    };
    logger_1.logger.info('支付健康检查', {
        healthScore,
        successRate,
        totalPayments,
        stripeHealth,
    });
    res.json({
        success: true,
        data: result,
    });
});
exports.batchProcessRefunds = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const { refundRequests } = req.body;
    if (!refundRequests || !Array.isArray(refundRequests) || refundRequests.length === 0) {
        throw (0, errorHandler_1.createValidationError)('refundRequests', '退款请求列表不能为空');
    }
    const db = require('@/config/database').db;
    const results = [];
    for (const request of refundRequests) {
        const { paymentId, amount, reason = 'requested_by_customer' } = request;
        try {
            const payment = await db('payments')
                .where('id', paymentId)
                .where('status', 'succeeded')
                .first();
            if (!payment) {
                results.push({
                    paymentId,
                    status: 'failed',
                    error: '支付记录不存在或状态不正确',
                });
                continue;
            }
            const refundAmount = amount || payment.amount;
            const alreadyRefunded = payment.refund_amount || 0;
            const maxRefundable = payment.amount - alreadyRefunded;
            if (refundAmount > maxRefundable) {
                results.push({
                    paymentId,
                    status: 'failed',
                    error: `退款金额超过可退款额度 (最大: ${maxRefundable})`,
                });
                continue;
            }
            const validReason = ['duplicate', 'fraudulent', 'requested_by_customer'].includes(reason)
                ? reason
                : 'requested_by_customer';
            const refund = await stripe.refunds.create({
                payment_intent: payment.payment_intent_id,
                amount: Math.round(refundAmount * 100),
                reason: validReason,
                metadata: {
                    paymentId: payment.id,
                    processedBy: userId,
                    originalAmount: payment.amount.toString(),
                },
            });
            await db('payments')
                .where('id', paymentId)
                .update({
                refund_amount: alreadyRefunded + refundAmount,
                refund_reason: reason,
                status: refundAmount >= payment.amount ? 'refunded' : 'partially_refunded',
                updated_at: new Date(),
            });
            results.push({
                paymentId,
                status: 'success',
                refundId: refund.id,
                refundAmount,
                refundStatus: refund.status,
            });
            logger_1.logger.info('批量退款成功', {
                paymentId,
                refundId: refund.id,
                refundAmount,
                processedBy: userId,
            });
        }
        catch (error) {
            logger_1.logger.error('批量退款失败', {
                paymentId,
                error: error.message,
            });
            results.push({
                paymentId,
                status: 'failed',
                error: error.message,
            });
        }
    }
    const successCount = results.filter(r => r.status === 'success').length;
    const failedCount = results.filter(r => r.status === 'failed').length;
    res.json({
        success: true,
        message: `批量退款处理完成: ${successCount}成功, ${failedCount}失败`,
        data: {
            totalProcessed: results.length,
            successCount,
            failedCount,
            results,
        },
    });
});
exports.processAutoRefunds = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const db = require('@/config/database').db;
    const autoRefundCandidates = [];
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const unusedPaidAnnotations = await db('payments')
        .join('annotations', 'payments.annotation_id', 'annotations.id')
        .where('payments.status', 'succeeded')
        .where('payments.created_at', '<', sevenDaysAgo)
        .where('annotations.status', 'pending')
        .whereNull('payments.refund_amount')
        .select('payments.*', 'annotations.status as annotation_status');
    for (const payment of unusedPaidAnnotations) {
        autoRefundCandidates.push({
            paymentId: payment.id,
            reason: 'expired_uncaptured_charge',
            amount: payment.amount,
            rule: '7天未审核自动退款',
        });
    }
    const rejectedAnnotations = await db('payments')
        .join('annotations', 'payments.annotation_id', 'annotations.id')
        .where('payments.status', 'succeeded')
        .where('annotations.status', 'rejected')
        .whereNull('payments.refund_amount')
        .select('payments.*', 'annotations.status as annotation_status');
    for (const payment of rejectedAnnotations) {
        autoRefundCandidates.push({
            paymentId: payment.id,
            reason: 'requested_by_customer',
            amount: payment.amount,
            rule: '标注被拒绝自动退款',
        });
    }
    const processedRefunds = [];
    for (const candidate of autoRefundCandidates) {
        try {
            const payment = await db('payments')
                .where('id', candidate.paymentId)
                .first();
            if (!payment || payment.refund_amount) {
                continue;
            }
            const validReason = ['duplicate', 'fraudulent', 'requested_by_customer'].includes(candidate.reason)
                ? candidate.reason
                : 'requested_by_customer';
            const refund = await stripe.refunds.create({
                payment_intent: payment.payment_intent_id,
                amount: Math.round(candidate.amount * 100),
                reason: validReason,
                metadata: {
                    paymentId: payment.id,
                    autoRefund: 'true',
                    rule: candidate.rule,
                    processedBy: 'system',
                },
            });
            await db('payments')
                .where('id', candidate.paymentId)
                .update({
                refund_amount: candidate.amount,
                refund_reason: candidate.reason,
                status: 'refunded',
                updated_at: new Date(),
            });
            processedRefunds.push({
                paymentId: candidate.paymentId,
                refundId: refund.id,
                amount: candidate.amount,
                rule: candidate.rule,
                status: 'success',
            });
            logger_1.logger.info('自动退款成功', {
                paymentId: candidate.paymentId,
                refundId: refund.id,
                rule: candidate.rule,
            });
        }
        catch (error) {
            logger_1.logger.error('自动退款失败', {
                paymentId: candidate.paymentId,
                error: error.message,
            });
            processedRefunds.push({
                paymentId: candidate.paymentId,
                rule: candidate.rule,
                status: 'failed',
                error: error.message,
            });
        }
    }
    res.json({
        success: true,
        message: `自动退款处理完成，处理了${processedRefunds.length}个退款`,
        data: {
            candidatesFound: autoRefundCandidates.length,
            processedCount: processedRefunds.length,
            successCount: processedRefunds.filter(r => r.status === 'success').length,
            processedRefunds,
        },
    });
});
exports.getRefundAnalysis = (0, errorHandler_2.asyncHandler)(async (req, res, _next) => {
    const userId = req.user?.id;
    const isAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';
    if (!userId || !isAdmin) {
        throw (0, errorHandler_1.createAuthError)('需要管理员权限');
    }
    const { timeRange = '30d' } = req.query;
    const dateFilter = new Date();
    switch (timeRange) {
        case '7d':
            dateFilter.setDate(dateFilter.getDate() - 7);
            break;
        case '30d':
            dateFilter.setDate(dateFilter.getDate() - 30);
            break;
        case '90d':
            dateFilter.setDate(dateFilter.getDate() - 90);
            break;
        default:
            dateFilter.setDate(dateFilter.getDate() - 30);
    }
    const db = require('@/config/database').db;
    const refundStats = await db('payments')
        .select(db.raw('COUNT(*) as total_refunds'), db.raw('SUM(refund_amount) as total_refund_amount'), db.raw('AVG(refund_amount) as avg_refund_amount'))
        .whereNotNull('refund_amount')
        .where('refund_amount', '>', 0)
        .where('updated_at', '>=', dateFilter)
        .first();
    const refundByReason = await db('payments')
        .select('refund_reason')
        .count('* as count')
        .sum('refund_amount as total_amount')
        .whereNotNull('refund_amount')
        .where('refund_amount', '>', 0)
        .where('updated_at', '>=', dateFilter)
        .groupBy('refund_reason');
    const refundTrends = await db('payments')
        .select(db.raw('DATE(updated_at) as date'), db.raw('COUNT(*) as daily_refunds'), db.raw('SUM(refund_amount) as daily_refund_amount'))
        .whereNotNull('refund_amount')
        .where('refund_amount', '>', 0)
        .where('updated_at', '>=', dateFilter)
        .groupBy(db.raw('DATE(updated_at)'))
        .orderBy('date');
    const totalPayments = await db('payments')
        .count('* as count')
        .where('status', 'succeeded')
        .where('created_at', '>=', dateFilter)
        .first();
    const refundRate = Number(totalPayments?.count || 0) > 0
        ? (Number(refundStats?.total_refunds || 0) / Number(totalPayments.count)) * 100
        : 0;
    const result = {
        timeRange,
        summary: {
            totalRefunds: Number(refundStats?.total_refunds || 0),
            totalRefundAmount: Number(refundStats?.total_refund_amount || 0),
            averageRefundAmount: Number(refundStats?.avg_refund_amount || 0),
            refundRate: Math.round(refundRate * 100) / 100,
        },
        refundByReason: refundByReason.map((item) => ({
            reason: item.refund_reason,
            count: Number(item.count),
            totalAmount: Number(item.total_amount),
            percentage: Number(refundStats?.total_refunds || 0) > 0
                ? Math.round((Number(item.count) / Number(refundStats.total_refunds)) * 10000) / 100
                : 0,
        })),
        trends: refundTrends.map((trend) => ({
            date: trend.date,
            refunds: Number(trend.daily_refunds),
            amount: Number(trend.daily_refund_amount),
        })),
    };
    logger_1.logger.info('获取退款分析', {
        userId,
        timeRange,
        totalRefunds: result.summary.totalRefunds,
        refundRate,
    });
    res.json({
        success: true,
        data: result,
    });
});
exports.default = {
    createPaymentSession: exports.createPaymentSession,
    getPaymentSession: exports.getPaymentSession,
    handleStripeWebhook: exports.handleStripeWebhook,
    getUserPayments: exports.getUserPayments,
    requestRefund: exports.requestRefund,
    getPaymentStats: exports.getPaymentStats,
    getBalanceReport: exports.getBalanceReport,
    retryFailedPayments: exports.retryFailedPayments,
    getPaymentHealth: exports.getPaymentHealth,
    batchProcessRefunds: exports.batchProcessRefunds,
    processAutoRefunds: exports.processAutoRefunds,
    getRefundAnalysis: exports.getRefundAnalysis,
};
//# sourceMappingURL=paymentController.js.map