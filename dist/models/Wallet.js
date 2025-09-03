"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletModel = void 0;
const uuid_1 = require("uuid");
const database_1 = require("@/config/database");
const logger_1 = require("@/utils/logger");
const WALLETS_TABLE = 'wallets';
const TRANSACTIONS_TABLE = 'transactions';
const LBS_REWARDS_TABLE = 'lbs_rewards';
class WalletModel {
    static async createWallet(walletData) {
        try {
            const [wallet] = await (0, database_1.db)(WALLETS_TABLE)
                .insert({
                id: (0, uuid_1.v4)(),
                user_id: walletData.user_id,
                balance: 0,
                frozen_balance: 0,
                currency: walletData.currency || 'CNY',
                status: 'active',
                total_income: 0,
                total_expense: 0,
            })
                .returning('*');
            logger_1.logger.info('钱包创建成功', {
                walletId: wallet.id,
                userId: wallet.user_id,
            });
            return wallet;
        }
        catch (error) {
            logger_1.logger.error('钱包创建失败', error);
            throw error;
        }
    }
    static async getUserWallet(userId) {
        try {
            const wallet = await (0, database_1.db)(WALLETS_TABLE)
                .where({ user_id: userId, status: 'active' })
                .first();
            return wallet || null;
        }
        catch (error) {
            logger_1.logger.error('获取用户钱包失败', { userId, error });
            throw error;
        }
    }
    static async getOrCreateWallet(userId) {
        try {
            let wallet = await this.getUserWallet(userId);
            if (!wallet) {
                wallet = await this.createWallet({ user_id: userId });
            }
            return wallet;
        }
        catch (error) {
            logger_1.logger.error('获取或创建用户钱包失败', { userId, error });
            throw error;
        }
    }
    static async createTransaction(transactionData) {
        return await database_1.db.transaction(async (trx) => {
            try {
                const wallet = await trx(WALLETS_TABLE)
                    .where({ id: transactionData.wallet_id })
                    .forUpdate()
                    .first();
                if (!wallet) {
                    throw new Error('钱包不存在');
                }
                const balanceBefore = wallet.balance;
                const frozenBalanceBefore = wallet.frozen_balance;
                let balanceAfter = balanceBefore;
                let frozenBalanceAfter = frozenBalanceBefore;
                let totalIncomeUpdate = wallet.total_income;
                let totalExpenseUpdate = wallet.total_expense;
                switch (transactionData.type) {
                    case 'deposit':
                    case 'refund':
                    case 'reward':
                        balanceAfter = balanceBefore + transactionData.amount;
                        totalIncomeUpdate += transactionData.amount;
                        break;
                    case 'withdraw':
                    case 'payment':
                        if (balanceBefore < transactionData.amount) {
                            throw new Error('余额不足');
                        }
                        balanceAfter = balanceBefore - transactionData.amount;
                        totalExpenseUpdate += transactionData.amount;
                        break;
                    case 'freeze':
                        if (balanceBefore < transactionData.amount) {
                            throw new Error('余额不足，无法冻结');
                        }
                        balanceAfter = balanceBefore - transactionData.amount;
                        frozenBalanceAfter = frozenBalanceBefore + transactionData.amount;
                        break;
                    case 'unfreeze':
                        if (frozenBalanceBefore < transactionData.amount) {
                            throw new Error('冻结余额不足，无法解冻');
                        }
                        balanceAfter = balanceBefore + transactionData.amount;
                        frozenBalanceAfter = frozenBalanceBefore - transactionData.amount;
                        break;
                    default:
                        throw new Error(`不支持的交易类型: ${transactionData.type}`);
                }
                const [transaction] = await trx(TRANSACTIONS_TABLE)
                    .insert({
                    id: (0, uuid_1.v4)(),
                    user_id: transactionData.user_id,
                    wallet_id: transactionData.wallet_id,
                    type: transactionData.type,
                    amount: transactionData.amount,
                    balance_before: balanceBefore,
                    balance_after: balanceAfter,
                    frozen_balance_before: frozenBalanceBefore,
                    frozen_balance_after: frozenBalanceAfter,
                    status: 'completed',
                    description: transactionData.description,
                    related_id: transactionData.related_id,
                    payment_method: transactionData.payment_method,
                    external_transaction_id: transactionData.external_transaction_id,
                    metadata: JSON.stringify(transactionData.metadata || {}),
                    processed_at: new Date(),
                })
                    .returning('*');
                await trx(WALLETS_TABLE)
                    .where({ id: transactionData.wallet_id })
                    .update({
                    balance: balanceAfter,
                    frozen_balance: frozenBalanceAfter,
                    total_income: totalIncomeUpdate,
                    total_expense: totalExpenseUpdate,
                    updated_at: new Date(),
                });
                transaction.metadata = JSON.parse(transaction.metadata || '{}');
                logger_1.logger.info('交易创建成功', {
                    transactionId: transaction.id,
                    userId: transaction.user_id,
                    type: transaction.type,
                    amount: transaction.amount,
                    balanceAfter,
                });
                return transaction;
            }
            catch (error) {
                logger_1.logger.error('交易创建失败', error);
                throw error;
            }
        });
    }
    static async getUserTransactions(userId, options = {}) {
        try {
            const { page = 1, limit = 20, type, status, startDate, endDate, sortBy = 'created_at', sortOrder = 'desc', } = options;
            let query = (0, database_1.db)(TRANSACTIONS_TABLE)
                .where('user_id', userId);
            if (type) {
                query = query.where('type', type);
            }
            if (status) {
                query = query.where('status', status);
            }
            if (startDate) {
                query = query.where('created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('created_at', '<=', endDate);
            }
            const countResult = await query.clone().count('* as count');
            const total = parseInt(countResult[0].count, 10);
            const transactions = await query
                .orderBy(sortBy, sortOrder)
                .limit(limit)
                .offset((page - 1) * limit);
            transactions.forEach(transaction => {
                transaction.metadata = JSON.parse(transaction.metadata || '{}');
            });
            return { transactions, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户交易历史失败', { userId, error });
            throw error;
        }
    }
    static async getWalletStats(userId, options = {}) {
        try {
            const { startDate, endDate } = options;
            const wallet = await this.getUserWallet(userId);
            if (!wallet) {
                throw new Error('用户钱包不存在');
            }
            let transactionQuery = (0, database_1.db)(TRANSACTIONS_TABLE)
                .where('user_id', userId)
                .where('status', 'completed');
            if (startDate) {
                transactionQuery = transactionQuery.where('created_at', '>=', startDate);
            }
            if (endDate) {
                transactionQuery = transactionQuery.where('created_at', '<=', endDate);
            }
            const [countResult] = await transactionQuery.clone().count('* as count');
            const transactionCount = parseInt(countResult?.['count'] || '0', 10);
            const recentTransactions = await (0, database_1.db)(TRANSACTIONS_TABLE)
                .where('user_id', userId)
                .orderBy('created_at', 'desc')
                .limit(10);
            recentTransactions.forEach(transaction => {
                transaction.metadata = JSON.parse(transaction.metadata || '{}');
            });
            const monthlyResults = await transactionQuery.clone()
                .select(database_1.db.raw('DATE_TRUNC(\'month\', created_at) as month'))
                .select(database_1.db.raw('SUM(CASE WHEN type IN (\'deposit\', \'refund\', \'reward\') THEN amount ELSE 0 END) as income'))
                .select(database_1.db.raw('SUM(CASE WHEN type IN (\'withdraw\', \'payment\') THEN amount ELSE 0 END) as expense'))
                .groupBy(database_1.db.raw('DATE_TRUNC(\'month\', created_at)'))
                .orderBy('month', 'desc')
                .limit(12);
            const monthlyIncome = monthlyResults.map((row) => ({
                month: new Date(row.month).toISOString().substring(0, 7),
                income: parseFloat(row.income || '0'),
                expense: parseFloat(row.expense || '0'),
            }));
            return {
                total_balance: wallet.balance,
                total_income: wallet.total_income,
                total_expense: wallet.total_expense,
                transaction_count: transactionCount,
                recent_transactions: recentTransactions,
                monthly_income: monthlyIncome,
            };
        }
        catch (error) {
            logger_1.logger.error('获取钱包统计失败', { userId, error });
            throw error;
        }
    }
    static async processLBSReward(rewardData) {
        return await database_1.db.transaction(async (trx) => {
            try {
                const [reward] = await trx(LBS_REWARDS_TABLE)
                    .insert({
                    id: (0, uuid_1.v4)(),
                    user_id: rewardData.user_id,
                    annotation_id: rewardData.annotation_id,
                    reward_amount: rewardData.reward_amount,
                    latitude: rewardData.latitude,
                    longitude: rewardData.longitude,
                    distance: rewardData.distance,
                    reward_type: rewardData.reward_type,
                    status: 'pending',
                    discovered_at: new Date(),
                    expires_at: rewardData.expires_at,
                })
                    .returning('*');
                const wallet = await this.getOrCreateWallet(rewardData.user_id);
                const transaction = await this.createTransaction({
                    user_id: rewardData.user_id,
                    wallet_id: wallet.id,
                    type: 'reward',
                    amount: rewardData.reward_amount,
                    description: `LBS奖励 - ${rewardData.reward_type}`,
                    related_id: rewardData.annotation_id,
                    metadata: {
                        reward_id: reward.id,
                        reward_type: rewardData.reward_type,
                        distance: rewardData.distance,
                    },
                });
                await trx(LBS_REWARDS_TABLE)
                    .where({ id: reward.id })
                    .update({
                    transaction_id: transaction.id,
                    status: 'paid',
                    paid_at: new Date(),
                });
                reward.transaction_id = transaction.id;
                reward.status = 'paid';
                reward.paid_at = new Date();
                logger_1.logger.info('LBS奖励处理成功', {
                    rewardId: reward.id,
                    userId: rewardData.user_id,
                    amount: rewardData.reward_amount,
                    type: rewardData.reward_type,
                });
                return reward;
            }
            catch (error) {
                logger_1.logger.error('LBS奖励处理失败', error);
                throw error;
            }
        });
    }
    static async checkBalance(userId, amount) {
        try {
            const wallet = await this.getUserWallet(userId);
            return wallet ? wallet.balance >= amount : false;
        }
        catch (error) {
            logger_1.logger.error('检查用户余额失败', { userId, error });
            throw error;
        }
    }
    static async freezeFunds(userId, amount, description, relatedId) {
        try {
            const wallet = await this.getOrCreateWallet(userId);
            return await this.createTransaction({
                user_id: userId,
                wallet_id: wallet.id,
                type: 'freeze',
                amount,
                description: description || '资金冻结',
                related_id: relatedId,
            });
        }
        catch (error) {
            logger_1.logger.error('冻结资金失败', { userId, amount, error });
            throw error;
        }
    }
    static async unfreezeFunds(userId, amount, description, relatedId) {
        try {
            const wallet = await this.getOrCreateWallet(userId);
            return await this.createTransaction({
                user_id: userId,
                wallet_id: wallet.id,
                type: 'unfreeze',
                amount,
                description: description || '资金解冻',
                related_id: relatedId,
            });
        }
        catch (error) {
            logger_1.logger.error('解冻资金失败', { userId, amount, error });
            throw error;
        }
    }
    static async getUserLBSRewards(userId, options = {}) {
        try {
            const { page = 1, limit = 20, status, rewardType, startDate, endDate, } = options;
            let query = (0, database_1.db)(LBS_REWARDS_TABLE)
                .select('lbs_rewards.*', 'annotations.description as annotation_description', 'annotations.smell_intensity')
                .leftJoin('annotations', 'lbs_rewards.annotation_id', 'annotations.id')
                .where('lbs_rewards.user_id', userId);
            if (status) {
                query = query.where('lbs_rewards.status', status);
            }
            if (rewardType) {
                query = query.where('lbs_rewards.reward_type', rewardType);
            }
            if (startDate) {
                query = query.where('lbs_rewards.created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('lbs_rewards.created_at', '<=', endDate);
            }
            const countResult = await query.clone().count('lbs_rewards.id as count');
            const total = parseInt(countResult[0].count, 10);
            const rewards = await query
                .orderBy('lbs_rewards.created_at', 'desc')
                .limit(limit)
                .offset((page - 1) * limit);
            return { rewards, total };
        }
        catch (error) {
            logger_1.logger.error('获取用户LBS奖励失败', { userId, error });
            throw error;
        }
    }
    static async getTransactionById(id) {
        try {
            const transaction = await (0, database_1.db)(TRANSACTIONS_TABLE)
                .where({ id })
                .first();
            if (transaction) {
                transaction.metadata = JSON.parse(transaction.metadata || '{}');
            }
            return transaction || null;
        }
        catch (error) {
            logger_1.logger.error('获取交易记录失败', { transactionId: id, error });
            throw error;
        }
    }
    static async getLBSRewardById(id) {
        try {
            const reward = await (0, database_1.db)(LBS_REWARDS_TABLE)
                .where({ id })
                .first();
            return reward || null;
        }
        catch (error) {
            logger_1.logger.error('获取LBS奖励记录失败', { rewardId: id, error });
            throw error;
        }
    }
    static async updateWalletStatus(userId, status) {
        try {
            const [wallet] = await (0, database_1.db)(WALLETS_TABLE)
                .where({ user_id: userId })
                .update({
                status,
                updated_at: new Date(),
            })
                .returning('*');
            if (wallet) {
                logger_1.logger.info('钱包状态更新成功', {
                    userId,
                    status,
                });
            }
            return wallet || null;
        }
        catch (error) {
            logger_1.logger.error('钱包状态更新失败', { userId, error });
            throw error;
        }
    }
}
exports.WalletModel = WalletModel;
exports.default = WalletModel;
//# sourceMappingURL=Wallet.js.map