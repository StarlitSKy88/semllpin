"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaymentModel = void 0;
const uuid_1 = require("uuid");
const database_1 = require("@/config/database");
const logger_1 = require("@/utils/logger");
const TABLE_NAME = 'payments';
class PaymentModel {
    static async create(paymentData) {
        try {
            const normalizedData = {
                id: (0, uuid_1.v4)(),
                user_id: paymentData.userId || paymentData.user_id,
                annotation_id: paymentData.annotationId || paymentData.annotation_id,
                amount: paymentData.amount,
                currency: paymentData.currency,
                payment_method: paymentData.method || paymentData.payment_method,
                payment_intent_id: paymentData.paymentIntentId || paymentData.payment_intent_id || paymentData.stripePaymentIntentId,
                session_id: paymentData.sessionId || paymentData.session_id || paymentData.stripeSessionId || paymentData.paypalOrderId,
                description: paymentData.description,
                metadata: JSON.stringify(paymentData.metadata || {}),
                status: paymentData.status || 'pending',
            };
            const [payment] = await (0, database_1.db)(TABLE_NAME)
                .insert(normalizedData)
                .returning('*');
            payment.metadata = JSON.parse(payment.metadata || '{}');
            logger_1.logger.info('支付记录创建成功', {
                paymentId: payment.id,
                userId: payment.user_id,
                amount: payment.amount,
                method: payment.payment_method,
            });
            return payment;
        }
        catch (error) {
            logger_1.logger.error('支付记录创建失败', error);
            throw error;
        }
    }
    static async findById(id) {
        try {
            const payment = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .first();
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('查找支付记录失败', { paymentId: id, error });
            throw error;
        }
    }
    static async findByStripeSessionId(sessionId) {
        try {
            const payment = await (0, database_1.db)(TABLE_NAME)
                .where({ session_id: sessionId })
                .first();
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('通过Stripe会话ID查找支付记录失败', { sessionId, error });
            throw error;
        }
    }
    static async findByStripePaymentIntentId(paymentIntentId) {
        try {
            const payment = await (0, database_1.db)(TABLE_NAME)
                .where({ payment_intent_id: paymentIntentId })
                .first();
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('通过Stripe支付意图ID查找支付记录失败', { paymentIntentId, error });
            throw error;
        }
    }
    static async findByPayPalOrderId(orderId) {
        try {
            const payment = await (0, database_1.db)(TABLE_NAME)
                .where({ session_id: orderId })
                .where({ payment_method: 'paypal' })
                .first();
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('通过PayPal订单ID查找支付记录失败', { orderId, error });
            throw error;
        }
    }
    static async updateStatus(id, updateData) {
        try {
            const updatePayload = {
                ...updateData,
                updated_at: new Date(),
            };
            if (updateData.metadata) {
                updatePayload.metadata = JSON.stringify(updateData.metadata);
            }
            if (updateData.status === 'completed' && !updateData.processed_at) {
                updatePayload.processed_at = new Date();
            }
            const [payment] = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update(updatePayload)
                .returning('*');
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
                logger_1.logger.info('支付状态更新成功', {
                    paymentId: id,
                    status: updateData.status,
                });
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('支付状态更新失败', { paymentId: id, error });
            throw error;
        }
    }
    static async getUserPayments(userId, options = {}) {
        try {
            const { page = 1, limit = 20, status, startDate, endDate, sortBy = 'created_at', sortOrder = 'desc', } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .select('payments.*', 'annotations.description as annotation_description', 'annotations.latitude', 'annotations.longitude')
                .leftJoin('annotations', 'payments.annotation_id', 'annotations.id')
                .where('payments.user_id', userId);
            if (status) {
                query = query.where('payments.status', status);
            }
            if (startDate) {
                query = query.where('payments.created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('payments.created_at', '<=', endDate);
            }
            const countResult = await query.clone().count('payments.id as count');
            const total = parseInt(countResult[0].count, 10);
            const payments = await query
                .orderBy(`payments.${sortBy}`, sortOrder)
                .limit(limit)
                .offset((page - 1) * limit);
            payments.forEach(payment => {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            });
            return { payments, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户支付历史失败', { userId, error });
            throw error;
        }
    }
    static async getPaymentStats(options = {}) {
        try {
            const { startDate, endDate, userId } = options;
            let query = (0, database_1.db)(TABLE_NAME).where('status', 'completed');
            if (userId) {
                query = query.where('user_id', userId);
            }
            if (startDate) {
                query = query.where('created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('created_at', '<=', endDate);
            }
            const [basicStats] = await query.clone()
                .sum('amount as total_revenue')
                .count('* as total_transactions')
                .avg('amount as average_amount');
            const totalRevenue = parseFloat(basicStats?.['total_revenue'] || '0');
            const totalTransactions = parseInt(basicStats?.['total_transactions'] || '0', 10);
            const averageAmount = parseFloat(basicStats?.['average_amount'] || '0');
            const [allPayments] = await (0, database_1.db)(TABLE_NAME)
                .count('* as total')
                .where(function () {
                if (userId) {
                    this.where('user_id', userId);
                }
                if (startDate) {
                    this.where('created_at', '>=', startDate);
                }
                if (endDate) {
                    this.where('created_at', '<=', endDate);
                }
            });
            const totalAllPayments = parseInt(String(allPayments?.['total'] || '0'), 10);
            const successRate = totalAllPayments > 0 ? (totalTransactions / totalAllPayments) * 100 : 0;
            const [refundStats] = await query.clone()
                .count('* as refund_count')
                .where('status', 'refunded');
            const refundCount = parseInt(String(refundStats?.['refund_count'] || '0'), 10);
            const refundRate = totalTransactions > 0 ? (refundCount / totalTransactions) * 100 : 0;
            const monthlyResults = await query.clone()
                .select(database_1.db.raw('DATE_TRUNC(\'month\', created_at) as month'))
                .sum('amount as revenue')
                .count('* as transactions')
                .groupBy(database_1.db.raw('DATE_TRUNC(\'month\', created_at)'))
                .orderBy('month', 'desc')
                .limit(12);
            const monthlyData = monthlyResults.map((row) => ({
                month: new Date(row.month).toISOString().substring(0, 7),
                revenue: parseFloat(row.revenue || '0'),
                transactions: parseInt(row.transactions || '0', 10),
            }));
            return {
                total_revenue: Math.round(totalRevenue * 100) / 100,
                total_transactions: totalTransactions,
                average_amount: Math.round(averageAmount * 100) / 100,
                success_rate: Math.round(successRate * 100) / 100,
                refund_rate: Math.round(refundRate * 100) / 100,
                monthly_data: monthlyData,
            };
        }
        catch (error) {
            logger_1.logger.error('获取支付统计失败', error);
            throw error;
        }
    }
    static async processRefund(id, refundAmount, reason) {
        try {
            const [payment] = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                status: 'refunded',
                refund_amount: refundAmount,
                refund_reason: reason,
                updated_at: new Date(),
            })
                .returning('*');
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
                logger_1.logger.info('退款处理成功', {
                    paymentId: id,
                    refundAmount,
                    reason,
                });
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('退款处理失败', { paymentId: id, error });
            throw error;
        }
    }
    static async checkDuplicatePayment(userId, annotationId, amount, timeWindow = 300000) {
        try {
            const cutoffTime = new Date(Date.now() - timeWindow);
            const payment = await (0, database_1.db)(TABLE_NAME)
                .where({
                user_id: userId,
                annotation_id: annotationId,
                amount,
            })
                .where('created_at', '>=', cutoffTime)
                .whereIn('status', ['pending', 'processing', 'completed'])
                .first();
            if (payment) {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            }
            return payment || null;
        }
        catch (error) {
            logger_1.logger.error('检查重复支付失败', { userId, annotationId, error });
            throw error;
        }
    }
    static async getPaymentMethodStats(options = {}) {
        try {
            const { startDate, endDate } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .select('payment_method')
                .count('* as transaction_count')
                .sum('amount as total_revenue')
                .groupBy('payment_method');
            if (startDate) {
                query = query.where('created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('created_at', '<=', endDate);
            }
            const results = await query;
            const statsWithSuccessRate = await Promise.all(results.map(async (result) => {
                const [successCount] = await (0, database_1.db)(TABLE_NAME)
                    .count('* as success_count')
                    .where('payment_method', result.payment_method)
                    .where('status', 'completed')
                    .where(function () {
                    if (startDate) {
                        this.where('created_at', '>=', startDate);
                    }
                    if (endDate) {
                        this.where('created_at', '<=', endDate);
                    }
                });
                const totalCount = parseInt(result.transaction_count, 10);
                const successCountNum = parseInt(String(successCount?.['success_count'] || '0'), 10);
                const successRate = totalCount > 0 ? (successCountNum / totalCount) * 100 : 0;
                return {
                    payment_method: result.payment_method,
                    transaction_count: totalCount,
                    total_revenue: parseFloat(result.total_revenue || '0'),
                    success_rate: Math.round(successRate * 100) / 100,
                };
            }));
            return statsWithSuccessRate;
        }
        catch (error) {
            logger_1.logger.error('获取支付方式统计失败', error);
            throw error;
        }
    }
    static async getList(options = {}) {
        try {
            const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc', status, paymentMethod, startDate, endDate, search, } = options;
            let query = (0, database_1.db)(TABLE_NAME)
                .select('payments.*', 'users.username', 'users.email', 'annotations.description as annotation_description')
                .leftJoin('users', 'payments.user_id', 'users.id')
                .leftJoin('annotations', 'payments.annotation_id', 'annotations.id');
            if (status) {
                query = query.where('payments.status', status);
            }
            if (paymentMethod) {
                query = query.where('payments.payment_method', paymentMethod);
            }
            if (startDate) {
                query = query.where('payments.created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('payments.created_at', '<=', endDate);
            }
            if (search) {
                query = query.where(function () {
                    this.where('users.username', 'ilike', `%${search}%`)
                        .orWhere('users.email', 'ilike', `%${search}%`)
                        .orWhere('payments.transaction_id', 'ilike', `%${search}%`)
                        .orWhere('payments.payment_intent_id', 'ilike', `%${search}%`);
                });
            }
            const countResult = await query.clone().count('payments.id as count');
            const total = parseInt(countResult[0].count, 10);
            const payments = await query
                .orderBy(`payments.${sortBy}`, sortOrder)
                .limit(limit)
                .offset((page - 1) * limit);
            payments.forEach(payment => {
                payment.metadata = JSON.parse(payment.metadata || '{}');
            });
            return { payments, total };
        }
        catch (error) {
            logger_1.logger.error('获取支付列表失败', error);
            throw error;
        }
    }
    static async delete(id) {
        try {
            const result = await (0, database_1.db)(TABLE_NAME)
                .where({ id })
                .update({
                status: 'cancelled',
                updated_at: new Date(),
            });
            if (result > 0) {
                logger_1.logger.info('支付记录删除成功', { paymentId: id });
                return true;
            }
            return false;
        }
        catch (error) {
            logger_1.logger.error('支付记录删除失败', { paymentId: id, error });
            throw error;
        }
    }
}
exports.PaymentModel = PaymentModel;
exports.default = PaymentModel;
//# sourceMappingURL=Payment.js.map