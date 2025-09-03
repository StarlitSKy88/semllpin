import { WalletModel, Wallet, Transaction, CreateWalletData, CreateTransactionData, WalletStats, LBSReward, CreateLBSRewardData } from '@/models/Wallet';
import { logger } from '@/utils/logger';

// Re-export types for backward compatibility
export { Wallet, Transaction, CreateWalletData, CreateTransactionData, WalletStats, LBSReward, CreateLBSRewardData };

// 钱包服务类
export class WalletService {

  /**
   * 创建钱包
   */
  static async createWallet(walletData: CreateWalletData): Promise<Wallet> {
    return await WalletModel.createWallet(walletData);
  }

  /**
   * 获取用户钱包
   */
  static async getUserWallet(userId: string): Promise<Wallet | null> {
    return await WalletModel.getUserWallet(userId);
  }

  /**
   * 获取或创建用户钱包
   */
  static async getOrCreateWallet(userId: string): Promise<Wallet> {
    return await WalletModel.getOrCreateWallet(userId);
  }

  /**
   * 创建交易记录
   */
  static async createTransaction(transactionData: CreateTransactionData): Promise<Transaction> {
    return await WalletModel.createTransaction(transactionData);
  }

  /**
   * 获取用户交易历史
   */
  static async getUserTransactions(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      type?: string;
      status?: string;
      startDate?: Date;
      endDate?: Date;
      sortBy?: string;
      sortOrder?: 'asc' | 'desc';
    } = {},
  ): Promise<{ transactions: Transaction[]; total: number }> {
    return await WalletModel.getUserTransactions(userId, options);
  }

  /**
   * 获取钱包统计数据
   */
  static async getWalletStats(
    userId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<WalletStats> {
    return await WalletModel.getWalletStats(userId, options);
  }

  /**
   * 处理LBS奖励
   */
  static async processLBSReward(
    userId: string,
    annotationId: string,
    rewardAmount: number,
    latitude: number,
    longitude: number,
    distance: number,
    rewardType: 'discovery' | 'proximity' | 'engagement' = 'discovery',
  ): Promise<LBSReward> {
    try {
      const rewardData: CreateLBSRewardData = {
        user_id: userId,
        annotation_id: annotationId,
        reward_amount: rewardAmount,
        latitude,
        longitude,
        distance,
        reward_type: rewardType,
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
      };

      return await WalletModel.processLBSReward(rewardData);
    } catch (error) {
      logger.error('LBS奖励处理失败', { userId, annotationId, error });
      throw error;
    }
  }

  /**
   * 检查余额是否充足
   */
  static async checkBalance(userId: string, amount: number): Promise<boolean> {
    return await WalletModel.checkBalance(userId, amount);
  }

  /**
   * 冻结资金
   */
  static async freezeFunds(
    userId: string,
    amount: number,
    description?: string,
    relatedId?: string,
  ): Promise<Transaction> {
    return await WalletModel.freezeFunds(userId, amount, description, relatedId);
  }

  /**
   * 解冻资金
   */
  static async unfreezeFunds(
    userId: string,
    amount: number,
    description?: string,
    relatedId?: string,
  ): Promise<Transaction> {
    return await WalletModel.unfreezeFunds(userId, amount, description, relatedId);
  }

  /**
   * 获取用户LBS奖励
   */
  static async getUserLBSRewards(
    userId: string,
    options: {
      page?: number;
      limit?: number;
      status?: string;
      rewardType?: string;
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<{ rewards: LBSReward[]; total: number }> {
    return await WalletModel.getUserLBSRewards(userId, options);
  }

  /**
   * 根据ID获取交易
   */
  static async getTransactionById(id: string): Promise<Transaction | null> {
    return await WalletModel.getTransactionById(id);
  }

  /**
   * 根据ID获取LBS奖励
   */
  static async getLBSRewardById(id: string): Promise<LBSReward | null> {
    return await WalletModel.getLBSRewardById(id);
  }

  /**
   * 更新钱包状态
   */
  static async updateWalletStatus(
    userId: string,
    status: 'active' | 'frozen' | 'closed',
  ): Promise<Wallet | null> {
    return await WalletModel.updateWalletStatus(userId, status);
  }
}

export default WalletService;
