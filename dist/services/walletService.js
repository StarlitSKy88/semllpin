"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletService = void 0;
const Wallet_1 = require("@/models/Wallet");
const logger_1 = require("@/utils/logger");
class WalletService {
    static async createWallet(walletData) {
        return await Wallet_1.WalletModel.createWallet(walletData);
    }
    static async getUserWallet(userId) {
        return await Wallet_1.WalletModel.getUserWallet(userId);
    }
    static async getOrCreateWallet(userId) {
        return await Wallet_1.WalletModel.getOrCreateWallet(userId);
    }
    static async createTransaction(transactionData) {
        return await Wallet_1.WalletModel.createTransaction(transactionData);
    }
    static async getUserTransactions(userId, options = {}) {
        return await Wallet_1.WalletModel.getUserTransactions(userId, options);
    }
    static async getWalletStats(userId, options = {}) {
        return await Wallet_1.WalletModel.getWalletStats(userId, options);
    }
    static async processLBSReward(userId, annotationId, rewardAmount, latitude, longitude, distance, rewardType = 'discovery') {
        try {
            const rewardData = {
                user_id: userId,
                annotation_id: annotationId,
                reward_amount: rewardAmount,
                latitude,
                longitude,
                distance,
                reward_type: rewardType,
                expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            };
            return await Wallet_1.WalletModel.processLBSReward(rewardData);
        }
        catch (error) {
            logger_1.logger.error('LBS奖励处理失败', { userId, annotationId, error });
            throw error;
        }
    }
    static async checkBalance(userId, amount) {
        return await Wallet_1.WalletModel.checkBalance(userId, amount);
    }
    static async freezeFunds(userId, amount, description, relatedId) {
        return await Wallet_1.WalletModel.freezeFunds(userId, amount, description, relatedId);
    }
    static async unfreezeFunds(userId, amount, description, relatedId) {
        return await Wallet_1.WalletModel.unfreezeFunds(userId, amount, description, relatedId);
    }
    static async getUserLBSRewards(userId, options = {}) {
        return await Wallet_1.WalletModel.getUserLBSRewards(userId, options);
    }
    static async getTransactionById(id) {
        return await Wallet_1.WalletModel.getTransactionById(id);
    }
    static async getLBSRewardById(id) {
        return await Wallet_1.WalletModel.getLBSRewardById(id);
    }
    static async updateWalletStatus(userId, status) {
        return await Wallet_1.WalletModel.updateWalletStatus(userId, status);
    }
}
exports.WalletService = WalletService;
exports.default = WalletService;
//# sourceMappingURL=walletService.js.map