import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { logger } from '@/utils/logger';

export interface Wallet {
  id: string;
  user_id: string;
  balance: number;
  frozen_balance: number;
  currency: string;
  status: 'active' | 'frozen' | 'closed';
  total_income: number;
  total_expense: number;
  created_at: Date;
  updated_at: Date;
}

export interface Transaction {
  id: string;
  user_id: string;
  wallet_id: string;
  type: 'deposit' | 'withdraw' | 'payment' | 'refund' | 'reward' | 'freeze' | 'unfreeze';
  amount: number;
  balance_before: number;
  balance_after: number;
  frozen_balance_before: number;
  frozen_balance_after: number;
  status: 'pending' | 'completed' | 'failed' | 'cancelled';
  description?: string;
  related_id?: string; // Related payment, annotation, or other entity ID
  payment_method?: string;
  external_transaction_id?: string;
  metadata?: Record<string, any>;
  processed_at?: Date;
  created_at: Date;
  updated_at: Date;
}

export interface LBSReward {
  id: string;
  user_id: string;
  annotation_id: string;
  transaction_id?: string;
  reward_amount: number;
  latitude: number;
  longitude: number;
  distance: number;
  reward_type: 'discovery' | 'proximity' | 'engagement';
  status: 'pending' | 'paid' | 'expired' | 'cancelled';
  discovered_at: Date;
  paid_at?: Date;
  expires_at: Date;
  created_at: Date;
  updated_at: Date;
}

export interface CreateWalletData {
  user_id: string;
  currency?: string;
}

export interface CreateTransactionData {
  user_id: string;
  wallet_id: string;
  type: 'deposit' | 'withdraw' | 'payment' | 'refund' | 'reward' | 'freeze' | 'unfreeze';
  amount: number;
  description?: string;
  related_id?: string | undefined;
  payment_method?: string;
  external_transaction_id?: string;
  metadata?: Record<string, any>;
}

export interface CreateLBSRewardData {
  user_id: string;
  annotation_id: string;
  reward_amount: number;
  latitude: number;
  longitude: number;
  distance: number;
  reward_type: 'discovery' | 'proximity' | 'engagement';
  expires_at: Date;
}

export interface WalletStats {
  total_balance: number;
  total_income: number;
  total_expense: number;
  transaction_count: number;
  recent_transactions: Transaction[];
  monthly_income: Array<{
    month: string;
    income: number;
    expense: number;
  }>;
}

const WALLETS_TABLE = 'wallets';
const TRANSACTIONS_TABLE = 'transactions';
const LBS_REWARDS_TABLE = 'lbs_rewards';

export class WalletModel {
  // Create a new wallet
  static async createWallet(walletData: CreateWalletData): Promise<Wallet> {
    try {
      const [wallet] = await db(WALLETS_TABLE)
        .insert({
          id: uuidv4(),
          user_id: walletData.user_id,
          balance: 0,
          frozen_balance: 0,
          currency: walletData.currency || 'CNY',
          status: 'active',
          total_income: 0,
          total_expense: 0,
        })
        .returning('*');

      logger.info('钱包创建成功', {
        walletId: wallet.id,
        userId: wallet.user_id,
      });

      return wallet;
    } catch (error) {
      logger.error('钱包创建失败', error);
      throw error;
    }
  }

  // Get user wallet
  static async getUserWallet(userId: string): Promise<Wallet | null> {
    try {
      const wallet = await db(WALLETS_TABLE)
        .where({ user_id: userId, status: 'active' })
        .first();

      return wallet || null;
    } catch (error) {
      logger.error('获取用户钱包失败', { userId, error });
      throw error;
    }
  }

  // Get or create user wallet
  static async getOrCreateWallet(userId: string): Promise<Wallet> {
    try {
      let wallet = await this.getUserWallet(userId);

      if (!wallet) {
        wallet = await this.createWallet({ user_id: userId });
      }

      return wallet;
    } catch (error) {
      logger.error('获取或创建用户钱包失败', { userId, error });
      throw error;
    }
  }

  // Create a transaction (with wallet balance update)
  static async createTransaction(transactionData: CreateTransactionData): Promise<Transaction> {
    return await db.transaction(async (trx) => {
      try {
        // Get current wallet state
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

        // Calculate new balances based on transaction type
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

        // Create transaction record
        const [transaction] = await trx(TRANSACTIONS_TABLE)
          .insert({
            id: uuidv4(),
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

        // Update wallet balances
        await trx(WALLETS_TABLE)
          .where({ id: transactionData.wallet_id })
          .update({
            balance: balanceAfter,
            frozen_balance: frozenBalanceAfter,
            total_income: totalIncomeUpdate,
            total_expense: totalExpenseUpdate,
            updated_at: new Date(),
          });

        // Parse metadata back to object
        transaction.metadata = JSON.parse(transaction.metadata || '{}');

        logger.info('交易创建成功', {
          transactionId: transaction.id,
          userId: transaction.user_id,
          type: transaction.type,
          amount: transaction.amount,
          balanceAfter,
        });

        return transaction;
      } catch (error) {
        logger.error('交易创建失败', error);
        throw error;
      }
    });
  }

  // Get user transactions with pagination and filters
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
    try {
      const {
        page = 1,
        limit = 20,
        type,
        status,
        startDate,
        endDate,
        sortBy = 'created_at',
        sortOrder = 'desc',
      } = options;

      let query = db(TRANSACTIONS_TABLE)
        .where('user_id', userId);

      // Apply filters
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

      // Get total count
      const countResult = await query.clone().count('* as count');
      const total = parseInt((countResult[0] as any).count as string, 10);

      // Apply pagination and sorting
      const transactions = await query
        .orderBy(sortBy, sortOrder)
        .limit(limit)
        .offset((page - 1) * limit);

      // Parse metadata for each transaction
      transactions.forEach(transaction => {
        transaction.metadata = JSON.parse(transaction.metadata || '{}');
      });

      return { transactions, total };
    } catch (error) {
      logger.error('获取用户交易历史失败', { userId, error });
      throw error;
    }
  }

  // Get wallet statistics
  static async getWalletStats(
    userId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<WalletStats> {
    try {
      const { startDate, endDate } = options;

      // Get wallet info
      const wallet = await this.getUserWallet(userId);
      if (!wallet) {
        throw new Error('用户钱包不存在');
      }

      let transactionQuery = db(TRANSACTIONS_TABLE)
        .where('user_id', userId)
        .where('status', 'completed');

      if (startDate) {
        transactionQuery = transactionQuery.where('created_at', '>=', startDate);
      }

      if (endDate) {
        transactionQuery = transactionQuery.where('created_at', '<=', endDate);
      }

      // Get transaction count
      const [countResult] = await transactionQuery.clone().count('* as count');
      const transactionCount = parseInt(countResult?.['count'] as string || '0', 10);

      // Get recent transactions
      const recentTransactions = await db(TRANSACTIONS_TABLE)
        .where('user_id', userId)
        .orderBy('created_at', 'desc')
        .limit(10);

      // Parse metadata for recent transactions
      recentTransactions.forEach(transaction => {
        transaction.metadata = JSON.parse(transaction.metadata || '{}');
      });

      // Get monthly income/expense data
      const monthlyResults = await transactionQuery.clone()
        .select(db.raw('DATE_TRUNC(\'month\', created_at) as month'))
        .select(db.raw('SUM(CASE WHEN type IN (\'deposit\', \'refund\', \'reward\') THEN amount ELSE 0 END) as income'))
        .select(db.raw('SUM(CASE WHEN type IN (\'withdraw\', \'payment\') THEN amount ELSE 0 END) as expense'))
        .groupBy(db.raw('DATE_TRUNC(\'month\', created_at)'))
        .orderBy('month', 'desc')
        .limit(12);

      const monthlyIncome = monthlyResults.map((row: any) => ({
        month: new Date(row.month).toISOString().substring(0, 7), // YYYY-MM
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
    } catch (error) {
      logger.error('获取钱包统计失败', { userId, error });
      throw error;
    }
  }

  // Process LBS reward
  static async processLBSReward(rewardData: CreateLBSRewardData): Promise<LBSReward> {
    return await db.transaction(async (trx) => {
      try {
        // Create LBS reward record
        const [reward] = await trx(LBS_REWARDS_TABLE)
          .insert({
            id: uuidv4(),
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

        // Get or create user wallet
        const wallet = await this.getOrCreateWallet(rewardData.user_id);

        // Create reward transaction
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

        // Update reward with transaction ID and mark as paid
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

        logger.info('LBS奖励处理成功', {
          rewardId: reward.id,
          userId: rewardData.user_id,
          amount: rewardData.reward_amount,
          type: rewardData.reward_type,
        });

        return reward;
      } catch (error) {
        logger.error('LBS奖励处理失败', error);
        throw error;
      }
    });
  }

  // Check user balance
  static async checkBalance(userId: string, amount: number): Promise<boolean> {
    try {
      const wallet = await this.getUserWallet(userId);
      return wallet ? wallet.balance >= amount : false;
    } catch (error) {
      logger.error('检查用户余额失败', { userId, error });
      throw error;
    }
  }

  // Freeze funds
  static async freezeFunds(
    userId: string,
    amount: number,
    description?: string,
    relatedId?: string,
  ): Promise<Transaction> {
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
    } catch (error) {
      logger.error('冻结资金失败', { userId, amount, error });
      throw error;
    }
  }

  // Unfreeze funds
  static async unfreezeFunds(
    userId: string,
    amount: number,
    description?: string,
    relatedId?: string,
  ): Promise<Transaction> {
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
    } catch (error) {
      logger.error('解冻资金失败', { userId, amount, error });
      throw error;
    }
  }

  // Get LBS rewards for user
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
    try {
      const {
        page = 1,
        limit = 20,
        status,
        rewardType,
        startDate,
        endDate,
      } = options;

      let query = db(LBS_REWARDS_TABLE)
        .select(
          'lbs_rewards.*',
          'annotations.description as annotation_description',
          'annotations.smell_intensity',
        )
        .leftJoin('annotations', 'lbs_rewards.annotation_id', 'annotations.id')
        .where('lbs_rewards.user_id', userId);

      // Apply filters
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

      // Get total count
      const countResult = await query.clone().count('lbs_rewards.id as count');
      const total = parseInt((countResult[0] as any).count as string, 10);

      // Apply pagination
      const rewards = await query
        .orderBy('lbs_rewards.created_at', 'desc')
        .limit(limit)
        .offset((page - 1) * limit);

      return { rewards, total };
    } catch (error) {
      logger.error('获取用户LBS奖励失败', { userId, error });
      throw error;
    }
  }

  // Get transaction by ID
  static async getTransactionById(id: string): Promise<Transaction | null> {
    try {
      const transaction = await db(TRANSACTIONS_TABLE)
        .where({ id })
        .first();

      if (transaction) {
        transaction.metadata = JSON.parse(transaction.metadata || '{}');
      }

      return transaction || null;
    } catch (error) {
      logger.error('获取交易记录失败', { transactionId: id, error });
      throw error;
    }
  }

  // Get LBS reward by ID
  static async getLBSRewardById(id: string): Promise<LBSReward | null> {
    try {
      const reward = await db(LBS_REWARDS_TABLE)
        .where({ id })
        .first();

      return reward || null;
    } catch (error) {
      logger.error('获取LBS奖励记录失败', { rewardId: id, error });
      throw error;
    }
  }

  // Update wallet status
  static async updateWalletStatus(
    userId: string,
    status: 'active' | 'frozen' | 'closed',
  ): Promise<Wallet | null> {
    try {
      const [wallet] = await db(WALLETS_TABLE)
        .where({ user_id: userId })
        .update({
          status,
          updated_at: new Date(),
        })
        .returning('*');

      if (wallet) {
        logger.info('钱包状态更新成功', {
          userId,
          status,
        });
      }

      return wallet || null;
    } catch (error) {
      logger.error('钱包状态更新失败', { userId, error });
      throw error;
    }
  }
}

export default WalletModel;
