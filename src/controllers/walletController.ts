import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { db } from '../config/database';
import { cache } from '../config/cache';
import { WalletService } from '../services/walletService';

// 定义认证请求接口
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}

interface WalletData {
  balance: number;
  totalIncome: number;
  totalExpense: number;
  lbsRewards: number;
  pendingRewards: number;
  currency: string;
}

class WalletController {
  // 获取钱包信息
  async getWallet(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      // 检查缓存
      const cacheKey = `wallet:${userId}`;
      const cachedData = await cache.get(cacheKey);
      if (cachedData) {
        res.json({
          success: true,
          data: typeof cachedData === 'string' ? JSON.parse(cachedData) : {},
          message: '获取钱包信息成功',
        });
        return;
      }

      // 使用WalletService获取钱包信息
      const wallet = await WalletService.getOrCreateWallet(userId);
      const stats = await WalletService.getWalletStats(userId);

      const walletData: WalletData = {
        balance: wallet.balance,
        totalIncome: stats.total_income,
        totalExpense: stats.total_expense,
        lbsRewards: 0, // TODO: 实现LBS奖励统计
        pendingRewards: 0, // TODO: 实现待处理奖励统计
        currency: wallet.currency,
      };

      // 缓存结果（5分钟）
      await cache.set(cacheKey, JSON.stringify(walletData), 300);

      logger.info(`获取用户钱包信息: ${userId}`);

      res.json({
        success: true,
        data: walletData,
        message: '获取钱包信息成功',
      });
    } catch (error: any) {
      logger.error('获取钱包信息失败:', error);
      res.status(500).json({
        success: false,
        message: '获取钱包信息失败',
        error: error.message,
      });
    }
  }

  // 获取交易历史
  async getTransactionHistory(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const {
        page = 1,
        limit = 10,
        type,
        status,
        search,
      } = req.query;

      // 构建过滤条件
      const filters: any = {};
      if (type) {
        filters.type = type as string;
      }
      if (status) {
        filters.status = status as string;
      }
      if (search) {
        filters.search = search as string;
      }

      // 使用WalletService获取交易历史
      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);

      const result = await WalletService.getUserTransactions(
        userId,
        {
          page: pageNum,
          limit: limitNum,
          ...filters,
        },
      );

      logger.info(`获取用户交易历史: ${userId}, 页码: ${page}, 条数: ${limit}`);

      res.json({
        success: true,
        data: result,
        message: '获取交易历史成功',
      });
    } catch (error: any) {
      logger.error('获取交易历史失败:', error);
      res.status(500).json({
        success: false,
        message: '获取交易历史失败',
        error: error.message,
      });
    }
  }

  // 获取交易统计
  async getTransactionSummary(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const { type, status, dateRange } = req.query;

      // 构建过滤条件
      const filters: any = {};
      if (type) {
        filters.type = type as string;
      }
      if (status) {
        filters.status = status as string;
      }

      // 处理日期范围
      if (dateRange) {
        const range = dateRange as string;
        const now = new Date();
        let startDate: Date;

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

      // 使用WalletService获取统计数据
      const summary = await WalletService.getWalletStats(userId, filters);

      logger.info(`获取用户交易统计: ${userId}`);

      res.json({
        success: true,
        data: summary,
        message: '获取交易统计成功',
      });
    } catch (error: any) {
      logger.error('获取交易统计失败:', error);
      res.status(500).json({
        success: false,
        message: '获取交易统计失败',
        error: error.message,
      });
    }
  }

  // 导出交易记录
  async exportTransactions(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const { format = 'csv', startDate, endDate, type } = req.query;

      // 构建查询条件
      let whereClause = 'WHERE user_id = $1';
      const queryParams: any[] = [userId];
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

      // 查询交易记录
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

      const result = await db.raw(query, queryParams);
      const transactions = result.rows;

      if (format === 'csv') {
        // 生成CSV数据
        const csvHeaders = ['Date', 'Type', 'Amount', 'Currency', 'Status', 'Description', 'Reference'];
        const csvRows = transactions.map((transaction: any) => [
          new Date(transaction.created_at).toISOString().split('T')[0],
          transaction.type,
          `$${parseFloat(transaction.amount).toFixed(2)}`,
          transaction.currency.toUpperCase(),
          transaction.status,
          transaction.description || '',
          transaction.stripe_session_id || '',
        ]);

        const csvData = [csvHeaders.join(','), ...csvRows.map((row: any[]) => row.join(','))].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="transactions_${userId}_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csvData);
      } else {
        // 返回JSON格式
        res.json({
          success: true,
          data: transactions,
          message: '导出交易记录成功',
        });
      }

      logger.info(`导出交易记录: 用户${userId}, 格式${format}, 记录数${transactions.length}`);
    } catch (error: any) {
      logger.error('导出交易记录失败:', error);
      res.status(500).json({
        success: false,
        message: '导出交易记录失败',
        error: error.message,
      });
    }
  }

  // 创建充值会话
  async createTopUpSession(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const { amount, paymentMethod = 'stripe', currency = 'usd', description } = req.body;

      // 验证充值金额
      if (!amount || amount < 5 || amount > 1000) {
        res.status(400).json({
          success: false,
          message: '充值金额必须在 $5-$1000 之间',
        });
        return;
      }

      // 调用支付控制器创建充值会话
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
              unit_amount: Math.round(amount * 100), // Stripe使用分为单位
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

      // 缓存会话信息
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

      await cache.set(`topup_session:${session.id}`, JSON.stringify(sessionInfo), 3600); // 1小时过期

      logger.info(`创建充值会话: ${userId}, 金额: $${amount}, 会话ID: ${session.id}`);

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
    } catch (error: any) {
      logger.error('创建充值会话失败:', error);
      res.status(500).json({
        success: false,
        message: '创建充值会话失败',
        error: error.message,
      });
    }
  }

  // 处理充值成功回调
  async handleTopUpSuccess(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { sessionId } = req.body;
      const userId = req.user!.id;

      // 验证支付会话
      const stripe = require('stripe')(process.env['STRIPE_SECRET_KEY']);
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (!session || session.payment_status !== 'paid') {
        res.status(400).json({
          success: false,
          message: '支付会话无效或未完成支付',
        });
        return;
      }

      // 获取缓存的会话信息
      const sessionInfoStr = await cache.get(`topup_session:${sessionId}`);
      if (!sessionInfoStr) {
        res.status(400).json({
          success: false,
          message: '会话信息已过期',
        });
        return;
      }

      const sessionInfo = typeof sessionInfoStr === 'string' ? JSON.parse(sessionInfoStr) : {};

      // 验证用户ID匹配
      if (sessionInfo.userId !== userId) {
        res.status(403).json({
          success: false,
          message: '用户身份验证失败',
        });
        return;
      }

      // 获取用户钱包
      const wallet = await WalletService.getOrCreateWallet(userId);

      // 使用WalletService处理充值
      const transactionData = {
        user_id: userId,
        wallet_id: wallet.id,
        type: 'deposit' as const,
        amount: sessionInfo.amount,
        description: sessionInfo.description,
        external_transaction_id: sessionId,
      };

      const transaction = await WalletService.createTransaction(transactionData);

      // 清除缓存的会话信息
      await cache.del(`topup_session:${sessionId}`);

      // 清除用户钱包缓存
      await cache.del(`wallet:${userId}`);

      // 获取更新后的钱包余额
      const updatedWallet = await WalletService.getUserWallet(userId);

      logger.info(`充值成功: 用户${userId}, 金额$${sessionInfo.amount}, 交易ID: ${transaction.id}`);

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
    } catch (error: any) {
      logger.error('处理充值成功失败:', error);
      res.status(500).json({
        success: false,
        message: '处理充值成功失败',
        error: error.message,
      });
    }
  }

  // 获取LBS奖励记录
  async getLBSRewards(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const { page = 1, limit = 10 } = req.query;

      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);

      // 使用WalletService获取LBS奖励记录
      const filters = { type: 'reward' };
      const result = await WalletService.getUserTransactions(
        userId,
        {
          page: pageNum,
          limit: limitNum,
          ...filters,
        },
      );

      // 格式化奖励数据
      const rewards = result.transactions.map((transaction: any) => ({
        id: transaction.id,
        type: transaction.type,
        amount: transaction.amount,
        description: transaction.description,
        location: transaction.prankId ? '标注位置' : '未知位置',
        createdAt: transaction.createdAt,
      }));

      logger.info(`获取用户LBS奖励: ${userId}`);

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
    } catch (error: any) {
      logger.error('获取LBS奖励记录失败:', error);
      res.status(500).json({
        success: false,
        message: '获取LBS奖励记录失败',
        error: error.message,
      });
    }
  }

}

export default new WalletController();
export { WalletController };
