"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletController = void 0;
const logger_1 = require("../utils/logger");
const database_1 = require("../config/database");
const cache_1 = require("../config/cache");
const walletService_1 = require("../services/walletService");
class WalletController {
    async getWallet(req, res) {
        try {
            const userId = req.user.id;
            const cacheKey = `wallet:${userId}`;
            const cachedData = await cache_1.cache.get(cacheKey);
            if (cachedData) {
                res.json({
                    success: true,
                    data: typeof cachedData === 'string' ? JSON.parse(cachedData) : {},
                    message: '获取钱包信息成功',
                });
                return;
            }
            const wallet = await walletService_1.WalletService.getOrCreateWallet(userId);
            const stats = await walletService_1.WalletService.getWalletStats(userId);
            const walletData = {
                balance: wallet.balance,
                totalIncome: stats.total_income,
                totalExpense: stats.total_expense,
                lbsRewards: 0,
                pendingRewards: 0,
                currency: wallet.currency,
            };
            await cache_1.cache.set(cacheKey, JSON.stringify(walletData), 300);
            logger_1.logger.info(`获取用户钱包信息: ${userId}`);
            res.json({
                success: true,
                data: walletData,
                message: '获取钱包信息成功',
            });
        }
        catch (error) {
            logger_1.logger.error('获取钱包信息失败:', error);
            res.status(500).json({
                success: false,
                message: '获取钱包信息失败',
                error: error.message,
            });
        }
    }
    async getTransactionHistory(req, res) {
        try {
            const userId = req.user.id;
            const { page = 1, limit = 10, type, status, search, } = req.query;
            const filters = {};
            if (type) {
                filters.type = type;
            }
            if (status) {
                filters.status = status;
            }
            if (search) {
                filters.search = search;
            }
            const pageNum = parseInt(page);
            const limitNum = parseInt(limit);
            const result = await walletService_1.WalletService.getUserTransactions(userId, {
                page: pageNum,
                limit: limitNum,
                ...filters,
            });
            logger_1.logger.info(`获取用户交易历史: ${userId}, 页码: ${page}, 条数: ${limit}`);
            res.json({
                success: true,
                data: result,
                message: '获取交易历史成功',
            });
        }
        catch (error) {
            logger_1.logger.error('获取交易历史失败:', error);
            res.status(500).json({
                success: false,
                message: '获取交易历史失败',
                error: error.message,
            });
        }
    }
    async getTransactionSummary(req, res) {
        try {
            const userId = req.user.id;
            const { type, status, dateRange } = req.query;
            const filters = {};
            if (type) {
                filters.type = type;
            }
            if (status) {
                filters.status = status;
            }
            if (dateRange) {
                const range = dateRange;
                const now = new Date();
                let startDate;
                switch (range) {
                    case '7d':
                        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                        break;
                    case '30d':
                        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                        break;
                    case '90d':
                        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                        break;
                    default:
                        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                }
                filters.startDate = startDate;
            }
            const summary = await walletService_1.WalletService.getWalletStats(userId, filters);
            logger_1.logger.info(`获取用户交易统计: ${userId}`);
            res.json({
                success: true,
                data: summary,
                message: '获取交易统计成功',
            });
        }
        catch (error) {
            logger_1.logger.error('获取交易统计失败:', error);
            res.status(500).json({
                success: false,
                message: '获取交易统计失败',
                error: error.message,
            });
        }
    }
    async exportTransactions(req, res) {
        try {
            const userId = req.user.id;
            const { format = 'csv', startDate, endDate, type } = req.query;
            let whereClause = 'WHERE user_id = $1';
            const queryParams = [userId];
            let paramIndex = 2;
            if (startDate) {
                whereClause += ` AND created_at >= $${paramIndex}`;
                queryParams.push(startDate);
                paramIndex++;
            }
            if (endDate) {
                whereClause += ` AND created_at <= $${paramIndex}`;
                queryParams.push(endDate);
                paramIndex++;
            }
            if (type && type !== 'all') {
                whereClause += ` AND type = $${paramIndex}`;
                queryParams.push(type);
                paramIndex++;
            }
            const query = `
        SELECT 
          created_at,
          type,
          amount,
          currency,
          status,
          description,
          stripe_session_id
        FROM transactions 
        ${whereClause}
        ORDER BY created_at DESC
      `;
            const result = await database_1.db.raw(query, queryParams);
            const transactions = result.rows;
            if (format === 'csv') {
                const csvHeaders = ['Date', 'Type', 'Amount', 'Currency', 'Status', 'Description', 'Reference'];
                const csvRows = transactions.map((transaction) => [
                    new Date(transaction.created_at).toISOString().split('T')[0],
                    transaction.type,
                    `$${parseFloat(transaction.amount).toFixed(2)}`,
                    transaction.currency.toUpperCase(),
                    transaction.status,
                    transaction.description || '',
                    transaction.stripe_session_id || '',
                ]);
                const csvData = [csvHeaders.join(','), ...csvRows.map((row) => row.join(','))].join('\n');
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', `attachment; filename="transactions_${userId}_${new Date().toISOString().split('T')[0]}.csv"`);
                res.send(csvData);
            }
            else {
                res.json({
                    success: true,
                    data: transactions,
                    message: '导出交易记录成功',
                });
            }
            logger_1.logger.info(`导出交易记录: 用户${userId}, 格式${format}, 记录数${transactions.length}`);
        }
        catch (error) {
            logger_1.logger.error('导出交易记录失败:', error);
            res.status(500).json({
                success: false,
                message: '导出交易记录失败',
                error: error.message,
            });
        }
    }
    async createTopUpSession(req, res) {
        try {
            const userId = req.user.id;
            const { amount, paymentMethod = 'stripe', currency = 'usd', description } = req.body;
            if (!amount || amount < 5 || amount > 1000) {
                res.status(400).json({
                    success: false,
                    message: '充值金额必须在 $5-$1000 之间',
                });
                return;
            }
            const stripe = require('stripe')(process.env['STRIPE_SECRET_KEY']);
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [
                    {
                        price_data: {
                            currency: currency.toLowerCase(),
                            product_data: {
                                name: description || `钱包充值 $${amount}`,
                                description: '钱包余额充值',
                            },
                            unit_amount: Math.round(amount * 100),
                        },
                        quantity: 1,
                    },
                ],
                mode: 'payment',
                success_url: `${process.env['FRONTEND_URL']}/wallet/topup/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env['FRONTEND_URL']}/wallet/topup/cancel`,
                metadata: {
                    userId,
                    type: 'topup',
                    amount: amount.toString(),
                },
            });
            const sessionInfo = {
                id: session.id,
                userId,
                type: 'topup',
                amount,
                currency,
                description: description || `钱包充值 $${amount}`,
                status: 'pending',
                createdAt: new Date(),
            };
            await cache_1.cache.set(`topup_session:${session.id}`, JSON.stringify(sessionInfo), 3600);
            logger_1.logger.info(`创建充值会话: ${userId}, 金额: $${amount}, 会话ID: ${session.id}`);
            res.json({
                success: true,
                data: {
                    id: session.id,
                    url: session.url,
                    amount,
                    currency,
                    description: description || `钱包充值 $${amount}`,
                    paymentMethod,
                    userId,
                },
                message: '创建充值会话成功',
            });
        }
        catch (error) {
            logger_1.logger.error('创建充值会话失败:', error);
            res.status(500).json({
                success: false,
                message: '创建充值会话失败',
                error: error.message,
            });
        }
    }
    async handleTopUpSuccess(req, res) {
        try {
            const { sessionId } = req.body;
            const userId = req.user.id;
            const stripe = require('stripe')(process.env['STRIPE_SECRET_KEY']);
            const session = await stripe.checkout.sessions.retrieve(sessionId);
            if (!session || session.payment_status !== 'paid') {
                res.status(400).json({
                    success: false,
                    message: '支付会话无效或未完成支付',
                });
                return;
            }
            const sessionInfoStr = await cache_1.cache.get(`topup_session:${sessionId}`);
            if (!sessionInfoStr) {
                res.status(400).json({
                    success: false,
                    message: '会话信息已过期',
                });
                return;
            }
            const sessionInfo = typeof sessionInfoStr === 'string' ? JSON.parse(sessionInfoStr) : {};
            if (sessionInfo.userId !== userId) {
                res.status(403).json({
                    success: false,
                    message: '用户身份验证失败',
                });
                return;
            }
            const wallet = await walletService_1.WalletService.getOrCreateWallet(userId);
            const transactionData = {
                user_id: userId,
                wallet_id: wallet.id,
                type: 'deposit',
                amount: sessionInfo.amount,
                description: sessionInfo.description,
                external_transaction_id: sessionId,
            };
            const transaction = await walletService_1.WalletService.createTransaction(transactionData);
            await cache_1.cache.del(`topup_session:${sessionId}`);
            await cache_1.cache.del(`wallet:${userId}`);
            const updatedWallet = await walletService_1.WalletService.getUserWallet(userId);
            logger_1.logger.info(`充值成功: 用户${userId}, 金额$${sessionInfo.amount}, 交易ID: ${transaction.id}`);
            res.json({
                success: true,
                data: {
                    transactionId: transaction.id,
                    amount: sessionInfo.amount,
                    currency: sessionInfo.currency,
                    newBalance: updatedWallet?.balance || 0,
                },
                message: '充值成功',
            });
        }
        catch (error) {
            logger_1.logger.error('处理充值成功失败:', error);
            res.status(500).json({
                success: false,
                message: '处理充值成功失败',
                error: error.message,
            });
        }
    }
    async getLBSRewards(req, res) {
        try {
            const userId = req.user.id;
            const { page = 1, limit = 10 } = req.query;
            const pageNum = parseInt(page);
            const limitNum = parseInt(limit);
            const filters = { type: 'reward' };
            const result = await walletService_1.WalletService.getUserTransactions(userId, {
                page: pageNum,
                limit: limitNum,
                ...filters,
            });
            const rewards = result.transactions.map((transaction) => ({
                id: transaction.id,
                type: transaction.type,
                amount: transaction.amount,
                description: transaction.description,
                location: transaction.prankId ? '标注位置' : '未知位置',
                createdAt: transaction.createdAt,
            }));
            logger_1.logger.info(`获取用户LBS奖励: ${userId}`);
            res.json({
                success: true,
                data: {
                    rewards,
                    total: result.total,
                    page: pageNum,
                    limit: limitNum,
                },
                message: '获取LBS奖励记录成功',
            });
        }
        catch (error) {
            logger_1.logger.error('获取LBS奖励记录失败:', error);
            res.status(500).json({
                success: false,
                message: '获取LBS奖励记录失败',
                error: error.message,
            });
        }
    }
}
exports.WalletController = WalletController;
exports.default = new WalletController();
//# sourceMappingURL=walletController.js.map